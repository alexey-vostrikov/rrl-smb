//! Kerberos over `ncacn_ip_tcp`: the ticket, and the per-message tokens that seal a call.
//!
//! The authenticated RPC a domain member uses is Kerberos, and this is the branch that serves it:
//! the SPNEGO offer carries an AP-REQ, the endpoint accepts it against a keytab, and from then on the
//! calls are sealed with RFC 4121 tokens — a sixteen-octet header in the verifier and the ciphertext
//! where the arguments would be. None of that can be reached without a KDC: the keytab is only useful
//! against a ticket whose key came from the realm that exported it.
//!
//! The stand is `scripts/test-kdc-kerberos.sh` in the `docker/kerberos-stand.Dockerfile` image, the
//! same one the SMB session-setup test uses. Without the `KRB5_TEST_*` variables this file returns at
//! its first line and reports nothing, so the plain gates neither need a KDC nor pass a test they did
//! not run.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::auth::{OID_KRB5, mech_type_list, parse_neg_resp, spnego_init};
use common::rpc::{NDR, PTYPE_BIND_ACK, PTYPE_RESPONSE, auth_of, bind_pdu, call_id, ptype, request_pdu, with_auth_level};
use smb_server::tcp::{Endpoint, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `drsuapi` 4.0.
const DRSUAPI: [u8; 20] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2, 4,
    0, 0, 0,
];

/// `1.2.840.48018.1.2.2`, Microsoft's own Kerberos OID, which a Windows client lists first.
const OID_KRB5_MS: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// `RPC_C_AUTHN_GSS_NEGOTIATE` and `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`.
const AUTH_GSS: u8 = 9;
const LEVEL_PRIVACY: u8 = 6;
/// `IDL_DRSCrackNames`.
const OPNUM_CRACK_NAMES: u16 = 12;

/// The stand's configuration, or `None` when no KDC was started.
struct Stand {
    realm: String,
    kdc: String,
    keytab: String,
    user: String,
    password: String,
    service: String,
}

impl Stand {
    fn from_env() -> Option<Stand> {
        Some(Stand {
            realm: std::env::var("KRB5_TEST_REALM").ok()?,
            kdc: std::env::var("KRB5_TEST_KDC").ok()?,
            keytab: std::env::var("KRB5_TEST_KEYTAB").ok()?,
            user: std::env::var("KRB5_TEST_USER").ok()?,
            password: std::env::var("KRB5_TEST_PASSWORD").ok()?,
            service: std::env::var("KRB5_TEST_SERVICE").ok()?,
        })
    }

    fn principal(&self, name: &str) -> krb5::Principal {
        krb5::Principal::parse_in_realm(name, &self.realm).expect("a principal")
    }

    /// A service ticket for the name this listener is reached under, and an initiator context for it.
    fn ticket(&self) -> (krb5::InitiatorContext, Vec<u8>) {
        let client = krb5::KdcClient::new(&self.realm, [self.kdc.as_str()]);
        let tgt = client
            .login_with_password(&self.principal(&self.user), &self.password)
            .expect("a ticket-granting ticket");
        let service = client
            .service_ticket(&tgt, &self.principal(&self.service))
            .expect("a service ticket");
        krb5::InitiatorContext::new(
            &service,
            krb5::initiator::GSS_C_MUTUAL_FLAG
                | krb5::initiator::GSS_C_INTEG_FLAG
                | krb5::initiator::GSS_C_CONF_FLAG,
        )
        .expect("an initiator context")
    }
}

/// Wraps a bare Kerberos mechanism token in the GSS framing, which is what `InitiatorContext` reads.
fn gss(token: &[u8]) -> Vec<u8> {
    let mut body = vec![0x06, 0x09];
    body.extend_from_slice(OID_KRB5);
    body.extend_from_slice(token);
    let mut out = vec![0x60];
    let n = body.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, (n & 0xff) as u8]);
    }
    out.extend_from_slice(&body);
    out
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("a local address")
        .port()
}

/// A listener that accepts tickets from `keytab`, and a client that reached it.
async fn started(keytab: &str) -> TcpStream {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("an address");
    let endpoint = Endpoint {
        addr,
        nb_domain: "AD".to_string(),
        dns_domain: "ad.example.com".to_string(),
        nb_computer: "SAMBA".to_string(),
        dns_computer: "samba.ad.example.com".to_string(),
        keytab: Some(keytab.into()),
        logon_users: None,
        publish: None,
        channel_state: None,
    };
    tokio::spawn(async move {
        let _ = serve(endpoint).await;
    });
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the listener at {addr} never accepted a connection");
}

async fn read_pdu(stream: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), read_pdu_inner(stream))
        .await
        .expect("the server answered nothing within five seconds")
}

async fn read_pdu_inner(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = [0_u8; 16];
    stream.read_exact(&mut head).await.expect("the header");
    let len = usize::from(u16::from_le_bytes([head[8], head[9]]));
    let mut rest = vec![0_u8; len - 16];
    if !rest.is_empty() {
        stream.read_exact(&mut rest).await.expect("the body");
    }
    let mut pdu = head.to_vec();
    pdu.extend_from_slice(&rest);
    pdu
}

/// A `DRSCrackNames` stub: the domain's canonical name wanted in NT4 form, as NDR writes it.
fn crack_names_stub() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0_u8; 20]); // policy handle, inline
    for word in [1_u32, 1, 0, 0, 0, 7, 2, 1, 1, 1, 1] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    let units: Vec<u16> = "ad.example.com/".encode_utf16().chain([0]).collect();
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// A ticket is accepted, and the call that follows is sealed with the context it established.
///
/// Three statements, each of which is a place this endpoint can be right about the parser and wrong
/// about the protocol. The offer names the mechanism the client built its token for — Microsoft's own
/// spelling, which a Windows client lists first, and `supportedMech` has to echo it. The answer's state
/// is `accept-completed` with this server's default, so a client that is answered `accept-incomplete`
/// sends a round this server is not waiting for. And the seal: the client's first sealed call carries
/// an RFC 4121 header in the verifier and ciphertext where the arguments were, and the answer comes
/// back the same way — a server that answered in the clear leaves a client with a message it cannot
/// unwrap, reported as a security-package error with no field to say why.
#[tokio::test]
async fn a_ticket_is_accepted_and_the_call_after_it_is_sealed() {
    let Some(stand) = Stand::from_env() else {
        return;
    };
    let mut stream = started(&stand.keytab).await;
    let (mut initiator, ap_req) = stand.ticket();

    // The bind carries the AP-REQ as SPNEGO's mechanism token, with the mechanism the ticket was
    // built for named first.
    let blob = spnego_init(&mech_type_list(&[OID_KRB5_MS]), Some(&ap_req));
    let bind = with_auth_level(
        bind_pdu(1, 4280, &[(0, DRSUAPI, NDR)]),
        AUTH_GSS,
        LEVEL_PRIVACY,
        0,
        &blob,
    );
    stream.write_all(&bind).await.expect("the bind");
    let ack = read_pdu(&mut stream).await;
    assert_eq!(ptype(&ack), PTYPE_BIND_ACK, "a bind_ack: {ack:02x?}");
    let (auth_type, level, _, token) = auth_of(&ack).expect("the answer carries the AP-REP");
    assert_eq!((auth_type, level), (AUTH_GSS, LEVEL_PRIVACY));

    let resp = parse_neg_resp(&token);
    let state = resp.state.expect("a state");
    assert!(
        state == 0 || state == 1,
        "accept-completed (0) or accept-incomplete (1), not {state}"
    );
    assert_eq!(
        resp.mech.as_deref(),
        Some(OID_KRB5_MS),
        "RFC 4178 §4.2.2: the target names the mechanism the client chose"
    );
    let ap_rep = resp.token.expect("the AP-REP");
    assert_eq!(
        ap_rep.first(),
        Some(&0x6f),
        "the mechanism's own token, which is the DER AP-REP and not the GSS envelope"
    );
    // The client's side: the AP-REP verifies, which is what proves the acceptor held the service's
    // key from the realm rather than a guess.
    //
    // The framing is two layers and this endpoint answers with the inner one. RFC 2743's mechanism
    // token is `TOK_ID` (two octets, `0x02 0x00` for an AP-REP) followed by the message; this
    // transport sends `mechToken` as the message alone, which is what Samba and MIT put there. So the
    // client puts the envelope and the id back before handing it to `step` — and handing it the bare
    // AP-REP reads the DER tag `0x6f` as a `TOK_ID`, reported as "unexpected GSS token id [6f, 58]".
    let mut framed = vec![0x02_u8, 0x00];
    framed.extend_from_slice(&ap_rep);
    initiator.step(&gss(&framed)).expect("the AP-REP verifies");
    assert!(initiator.is_established(), "mutual authentication completed");

    // The sealed call. The token's first sixteen octets go in the verifier and the rest where the
    // arguments would be — that split is the transport's, not Kerberos's.
    let send = initiator.per_message_tokens().expect("per-message tokens");
    let mut plain = crack_names_stub();
    // The authentication padding is inside the seal: MS-RPCE 2.2.2.11 counts it at the end of the
    // arguments, and at level 6 those octets are part of the ciphertext.
    plain.resize(plain.len().next_multiple_of(4), 0);
    let sealed = send.emit_wrap(0, &plain).expect("the call is sealed");
    let (header, body) = sealed.split_at(krb5::token::HEADER_LEN);
    let call = with_auth_level(
        request_pdu(2, 1 | 2, 0, OPNUM_CRACK_NAMES, body),
        AUTH_GSS,
        LEVEL_PRIVACY,
        0,
        header,
    );
    stream.write_all(&call).await.expect("the sealed call");

    let answer = read_pdu(&mut stream).await;
    assert_eq!(
        ptype(&answer),
        PTYPE_RESPONSE,
        "a sealed call is answered, not faulted: {answer:02x?}"
    );
    assert_eq!(call_id(&answer), 2);
    let (auth_type, level, _, answer_header) =
        auth_of(&answer).expect("the answer is sealed too");
    assert_eq!(
        (auth_type, level),
        (AUTH_GSS, LEVEL_PRIVACY),
        "a plaintext answer here is what a client reports as a security-package failure"
    );
    assert_eq!(
        answer_header.len(),
        krb5::token::HEADER_LEN,
        "the verifier carries the token's header and nothing else"
    );

    // Join the two halves the way the transport split them, and open the answer.
    let mut token = answer_header.to_vec();
    token.extend_from_slice(&answer[24..answer.len() - 8 - answer_header.len()]);
    let recv = initiator
        .per_message_tokens()
        .expect("the initiator's receiving tokens");
    let opened = recv.unwrap(&token).expect("the answer opens");
    assert_eq!(
        opened.seq, 0,
        "the acceptor's first answer, numbered from zero"
    );
    // The opened body is a `DRSCrackNames` answer: the union's level, and the two names the
    // conversion produces.
    assert_eq!(
        &opened.message[..4],
        &1u32.to_le_bytes(),
        "the answer starts with its level"
    );
    let utf16 = |text: &str| -> Vec<u8> {
        text.encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    };
    for expected in ["ad.example.com", "AD\\"] {
        let name = utf16(expected);
        assert!(
            opened
                .message
                .windows(name.len())
                .any(|window| window == name.as_slice()),
            "the opened answer carries {expected:?}"
        );
    }
}

/// A ticket for a service whose key this listener does not hold falls back to SPNEGO, not to a fault.
///
/// The ticket is for another principal, so the keytab has no key that opens it. What must not happen
/// is a binding that dies: the client is asked for NTLMSSP instead, which is the same answer an offer
/// that named no ticket gets, and is what lets a member that has no ticket for this name still call.
#[tokio::test]
async fn a_ticket_this_keytab_cannot_open_falls_back_to_spnego() {
    let Some(stand) = Stand::from_env() else {
        return;
    };
    let mut stream = started(&stand.keytab).await;

    // A ticket for a service in the same realm but a different name: the KDC issues it, and this
    // listener holds no key for it.
    let client = krb5::KdcClient::new(&stand.realm, [stand.kdc.as_str()]);
    let tgt = client
        .login_with_password(&stand.principal(&stand.user), &stand.password)
        .expect("a TGT");
    let other = stand.principal("cifs/elsewhere.ad.example.com");
    let Ok(service) = client.service_ticket(&tgt, &other) else {
        // The realm has no such principal, which settles the same question one step earlier.
        return;
    };
    let (_, ap_req) = krb5::InitiatorContext::new(&service, krb5::initiator::GSS_C_MUTUAL_FLAG)
        .expect("an initiator context");

    let blob = spnego_init(
        &mech_type_list(&[OID_KRB5_MS, &common::OID_NTLMSSP]),
        Some(&ap_req),
    );
    let bind = with_auth_level(
        bind_pdu(1, 4280, &[(0, DRSUAPI, NDR)]),
        AUTH_GSS,
        LEVEL_PRIVACY,
        0,
        &blob,
    );
    stream.write_all(&bind).await.expect("the bind");
    let ack = read_pdu(&mut stream).await;
    assert_eq!(ptype(&ack), PTYPE_BIND_ACK, "the association survives");
    let (_, _, _, token) = auth_of(&ack).expect("an answer with a token");
    let resp = parse_neg_resp(&token);
    assert_eq!(
        resp.state,
        Some(1),
        "accept-incomplete: the client is asked to continue with another mechanism"
    );
    assert_eq!(
        resp.mech.as_deref(),
        Some(&common::OID_NTLMSSP[..]),
        "and it is told which one"
    );
}
