//! The SPNEGO branches of the RPC authentication: what this endpoint answers, and what it refuses.
//!
//! `auth_answer` is one function with five kinds of verifier and four ways to give up on each, and
//! almost none of it is reachable from a client that behaves. The cases below are the ones a real
//! network produces: a mechanism this endpoint does not implement, an offer that lists no NTLMSSP, a
//! token whose shape is not SPNEGO's, a response token that is not NTLMSSP's, and an AUTHENTICATE that
//! arrives after the exchange this server asked for.
//!
//! Two behaviours are asserted throughout, and they are different from each other on purpose:
//!
//! * an offer this endpoint cannot use is answered **with a state**: `reject` when nothing in it can
//!   ever be accepted, `accept-incomplete` with `supportedMech` when the client merely started with
//!   another mechanism. RFC 4178 §4.2.2 makes that difference, and a client that reads `reject` for
//!   the second case gives up on an association that was only asking it to switch.
//! * a token this endpoint cannot read is answered with **no verifier at all**. A bind is still
//!   acknowledged — the alternative is a client that retries the whole association elsewhere — but
//!   the answer claims no authentication happened, which is the truth.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::auth::{OID_KRB5, mech_type_list, ntlm_negotiate, parse_neg_resp, spnego_init, spnego_resp};
use common::rpc::{NDR, PTYPE_BIND_ACK, auth_of, bind_pdu, ptype, with_auth_level};
use smb_server::tcp::{Endpoint, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `drsuapi` 4.0. Any interface would do: the bind is refused or accepted on its verifier, before the
/// context is examined.
const DRSUAPI: [u8; 20] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2, 4,
    0, 0, 0,
];

/// `RPC_C_AUTHN_GSS_NEGOTIATE`: the verifier is an SPNEGO token.
const AUTH_GSS: u8 = 9;
/// `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`.
const LEVEL_INTEGRITY: u8 = 5;

/// `NegState::Reject` and `NegState::AcceptIncomplete`, as `NegTokenResp` carries them.
const REJECT: u8 = 2;
const ACCEPT_INCOMPLETE: u8 = 1;

/// NTLMSSP's OID as OID content, which is what `supportedMech` carries.
const NTLMSSP_OID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("a local address")
        .port()
}

/// A listener on a fresh port and a client that reached it.
async fn started() -> TcpStream {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().expect("an address");
    let endpoint = Endpoint {
        addr,
        nb_domain: "AD".to_string(),
        dns_domain: "ad.example.com".to_string(),
        nb_computer: "SAMBA".to_string(),
        dns_computer: "samba.ad.example.com".to_string(),
        keytab: None,
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

/// Binds with `auth_type` and `token` in the verifier, and returns the answer's verifier if it has one.
async fn bind_with(auth_type: u8, token: &[u8]) -> Option<(u8, u8, Vec<u8>)> {
    let mut stream = started().await;
    let bind = with_auth_level(
        bind_pdu(1, 4280, &[(0, DRSUAPI, NDR)]),
        auth_type,
        LEVEL_INTEGRITY,
        1,
        token,
    );
    stream.write_all(&bind).await.expect("the bind");
    let answer = read_pdu(&mut stream).await;
    assert_eq!(
        ptype(&answer),
        PTYPE_BIND_ACK,
        "a bind is acknowledged whatever its verifier says: {answer:02x?}"
    );
    auth_of(&answer).map(|(auth_type, level, _, token)| (auth_type, level, token))
}

/// A `[APPLICATION 0]` envelope holding `body` verbatim, so a token can be built that is the right
/// shape outside and nonsense inside.
fn gss_envelope(body: &[u8]) -> Vec<u8> {
    let mut inner = vec![0x06, 0x09];
    inner.extend_from_slice(spnego_oid());
    inner.extend_from_slice(body);
    let mut out = vec![0x60];
    // DER definite length, short form only: every token here is well under 128 octets.
    assert!(inner.len() < 0x80, "a short token");
    out.push(inner.len() as u8);
    out.extend_from_slice(&inner);
    out
}

/// `1.3.6.1.5.5.2`, SPNEGO's own OID.
fn spnego_oid() -> &'static [u8] {
    &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]
}

/// An `NTLMSSP` message of `kind`, in the shape the server reads the kind from.
fn ntlmssp(kind: u32, len: usize) -> Vec<u8> {
    let mut out = b"NTLMSSP\x00".to_vec();
    out.extend_from_slice(&kind.to_le_bytes());
    out.resize(len.max(12), 0);
    out
}

/// A mechanism this endpoint has no acceptor for is answered with no verifier at all.
///
/// The bind is acknowledged, because a client that gets no answer retries the whole association
/// elsewhere; what the answer must not do is carry a token implying this server authenticated
/// something it never looked at.
#[tokio::test]
async fn a_mechanism_this_endpoint_cannot_answer_gets_no_verifier() {
    // 15 is `RPC_C_AUTHN_DEFAULT`, which no transport here implements; the branch is the same for
    // every number outside the three it knows.
    let verifier = bind_with(15, b"anything at all").await;
    assert!(
        verifier.is_none(),
        "an answer with a verifier claims an authentication: {verifier:?}"
    );
}

/// A verifier whose first octet is neither `0x60` nor `0xa1` is not an SPNEGO token.
///
/// `0x30` is a plausible mistake — it is the SEQUENCE that both SPNEGO tokens wrap — and a server
/// that read it as one would parse the envelope's contents as a `NegTokenInit`.
#[tokio::test]
async fn a_gss_token_of_an_unknown_shape_gets_no_verifier() {
    let token = vec![0x30, 0x03, 0x02, 0x01, 0x05];
    assert!(bind_with(AUTH_GSS, &token).await.is_none());
}

/// A `NegTokenInit` whose body does not parse is refused, not guessed at.
#[tokio::test]
async fn an_init_token_that_does_not_parse_gets_no_verifier() {
    // The right tag, and then octets that are not a mechanism list.
    let token = gss_envelope(&[0xde, 0xad, 0xbe, 0xef]);
    assert!(bind_with(AUTH_GSS, &token).await.is_none());
}

/// An offer that lists no NTLMSSP is rejected outright: this endpoint has nothing to offer it.
///
/// `reject` rather than `accept-incomplete`, because the decision does not depend on a later round: no
/// mechanism in the list can ever be accepted here.
#[tokio::test]
async fn an_offer_without_ntlmssp_is_rejected() {
    let token = spnego_init(&mech_type_list(&[OID_KRB5]), None);
    let (auth_type, _, answer) = bind_with(AUTH_GSS, &token)
        .await
        .expect("a rejection carries a token");
    assert_eq!(auth_type, AUTH_GSS);
    let resp = parse_neg_resp(&answer);
    assert_eq!(resp.state, Some(REJECT), "reject, not accept-incomplete");
    assert_eq!(
        resp.mech.as_deref(),
        Some(&NTLMSSP_OID[..]),
        "and it names what this endpoint would have accepted"
    );
}

/// An offer that starts with Kerberos but also lists NTLMSSP is answered `accept-incomplete`.
///
/// This is the branch that matters most and is easiest to get wrong: the client opened with a
/// mechanism this endpoint has no acceptor for, and RFC 4178 §4.2.2 has the target answer
/// `accept-incomplete` with `supportedMech` — the exchange continues, with the other mechanism. A
/// `reject` here ends an association that would have worked on the second round.
#[tokio::test]
async fn an_offer_whose_token_is_not_ntlmssp_is_answered_asking_for_it() {
    let mechs = mech_type_list(&[OID_KRB5, &NTLMSSP_OID]);
    // A mechanism token this endpoint has no acceptor for: it is not NTLMSSP's, so it is not read as
    // one.
    let token = spnego_init(&mechs, Some(&[0x6e, 0x01, 0x00]));
    let (_, _, answer) = bind_with(AUTH_GSS, &token)
        .await
        .expect("the exchange continues, so it carries a token");
    let resp = parse_neg_resp(&answer);
    assert_eq!(resp.state, Some(ACCEPT_INCOMPLETE));
    assert_eq!(
        resp.mech.as_deref(),
        Some(&NTLMSSP_OID[..]),
        "the client is told which mechanism to use"
    );
    assert!(
        resp.token.is_none(),
        "there is nothing to send back yet: the client has not sent a NEGOTIATE"
    );
}

/// A NEGOTIATE inside the init token is challenged at once: the client already chose NTLMSSP.
#[tokio::test]
async fn a_negotiate_inside_an_init_token_is_challenged() {
    let mechs = mech_type_list(&[&NTLMSSP_OID]);
    let token = spnego_init(&mechs, Some(&ntlm_negotiate(0xe2_08_82_17)));
    let (_, _, answer) = bind_with(AUTH_GSS, &token)
        .await
        .expect("a challenge comes back");
    let resp = parse_neg_resp(&answer);
    let challenge = resp.token.expect("the CHALLENGE is the answer's token");
    assert!(
        challenge.starts_with(b"NTLMSSP\x00"),
        "the answer to a NEGOTIATE is a CHALLENGE: {challenge:02x?}"
    );
    let kind = u32::from_le_bytes(challenge[8..12].try_into().expect("four octets"));
    assert_eq!(kind, 2, "CHALLENGE_MESSAGE, not another NEGOTIATE");
}

/// A `NegTokenResp` whose body does not parse is refused.
#[tokio::test]
async fn a_response_token_that_does_not_parse_gets_no_verifier() {
    let token = [0xa1, 0x04, 0xde, 0xad, 0xbe, 0xef];
    assert!(bind_with(AUTH_GSS, &token.to_vec()).await.is_none());
}

/// A NEGOTIATE that arrives in a `NegTokenResp` is challenged: this is the second half of the
/// exchange the previous test's answer started.
#[tokio::test]
async fn a_negotiate_in_a_response_token_is_challenged() {
    let token = spnego_resp(Some(&ntlm_negotiate(0xe2_08_82_17)), None);
    let (_, _, answer) = bind_with(AUTH_GSS, &token)
        .await
        .expect("a challenge comes back");
    let challenge = parse_neg_resp(&answer).token.expect("a token");
    assert!(challenge.starts_with(b"NTLMSSP\x00"));
    assert_eq!(
        u32::from_le_bytes(challenge[8..12].try_into().expect("four octets")),
        2,
        "CHALLENGE_MESSAGE"
    );
}

/// An AUTHENTICATE in a `NegTokenResp` is not answered: there is nothing left to say.
///
/// The association is authenticated from here on, and the client's next PDU is the call it was
/// authenticating for. An answer to this one — a fault, or a bare success — is what a client reports
/// as `RPC_S_INVALID_TAG` (0x6be) on its next send.
#[tokio::test]
async fn an_authenticate_in_a_response_token_is_not_answered() {
    let token = spnego_resp(Some(&ntlmssp(3, 64)), None);
    assert!(
        bind_with(AUTH_GSS, &token).await.is_none(),
        "nothing is owed to an AUTHENTICATE"
    );
}

/// A `NegTokenResp` carrying a token that is not NTLMSSP's is not answered either.
#[tokio::test]
async fn a_response_token_without_ntlmssp_is_not_answered() {
    let token = spnego_resp(Some(&[0x6e, 0x02, 0x01, 0x02]), None);
    assert!(bind_with(AUTH_GSS, &token).await.is_none());
}
