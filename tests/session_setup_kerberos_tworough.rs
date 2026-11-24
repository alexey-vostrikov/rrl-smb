//! The two-round Kerberos logon: `accept-incomplete`, then the closing message.
//!
//! Its own file, and therefore its own process, because the mode is a process-wide environment
//! variable (`RRL_SMB_KRB_TWOROUND`): one test binary cannot set it for one test and not for another
//! without racing. The one-round default lives in `tests/session_setup_kerberos.rs`.
//!
//! Both modes exist because both are real: a Windows client that is answered `accept-completed` in
//! one round is finished, and a client that is answered `accept-incomplete` sends a closing message
//! and refuses a session it never completed. `finish_kerberos` is the handler for that second
//! message, and nothing else reaches it.

// Same as the one-round file: a KDC issues the ticket, and the mode is read only where the
// mechanism is built.
#![cfg(feature = "krb5")]

mod common;

use common::auth::{
    OID_KRB5, gss, mech_type_list, parse_neg_resp, session_setup_token, spnego_init,
};
use common::{
    build_header, negotiate, parse_response_header, read_frame, session_setup_body, start_server,
    write_frame,
};
use smb_server::ntstatus::*;
use smb_server::wire::header::Command;
use smb_server::{Share, SmbServer};

/// `1.2.840.48018.1.2.2`, Microsoft's own Kerberos OID, which a Windows client lists first.
const OID_KRB5_MS: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// The two Kerberos spellings, Microsoft's first.
fn mech() -> Vec<u8> {
    mech_type_list(&[OID_KRB5_MS, OID_KRB5])
}

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
}

/// `accept-incomplete` first, then the closing message that completes the logon.
///
/// Three things this establishes that the one-round test cannot. The first answer is
/// `MORE_PROCESSING_REQUIRED` and names a session to continue on — a client that got `STATUS_SUCCESS`
/// here would not send the second message, and a server that never sends the AP-REP leaves it with a
/// context it cannot complete. The second message is answered with `STATUS_SUCCESS` on that same
/// session. And the AP-REP verifies on the client's side, which is what proves the acceptor had the
/// service's key from the realm rather than a guess.
#[tokio::test]
async fn a_member_completes_the_logon_in_two_rounds() {
    let Some(stand) = Stand::from_env() else {
        return;
    };
    // Set before the server is built: the handler reads it per message, and this file is its own
    // process, so nothing else in the suite sees it.
    // SAFETY: single-threaded setup, before any test task in this process starts.
    unsafe { std::env::set_var("RRL_SMB_KRB_TWOROUND", "1") };

    let td = tempfile::tempdir().expect("a temporary directory");
    let (addr, _task) = start_server(
        SmbServer::builder()
            .netbios_name("SAMBA")
            .dns_domain("ad.example.com")
            .domain_netbios("AD")
            .keytab(&stand.keytab)
            .share(Share::new("public", common::client::local(td.path())).public()),
    )
    .await;

    let client = krb5::KdcClient::new(&stand.realm, [stand.kdc.as_str()]);
    let tgt = client
        .login_with_password(&stand.principal(&stand.user), &stand.password)
        .expect("a TGT");
    let service = client
        .service_ticket(&tgt, &stand.principal(&stand.service))
        .expect("a service ticket");
    let (mut initiator, token) = krb5::InitiatorContext::new(
        &service,
        krb5::initiator::GSS_C_MUTUAL_FLAG
            | krb5::initiator::GSS_C_INTEG_FLAG
            | krb5::initiator::GSS_C_CONF_FLAG,
    )
    .expect("an initiator context");

    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;

    // The first message: the ticket, answered `accept-incomplete`.
    let blob = spnego_init(&mech(), Some(&token));
    let hdr = build_header(Command::SessionSetup, 1, 0, 0);
    write_frame(&mut s, &hdr, &session_setup_body(&blob, 0, 1, 0)).await;
    let frame = read_frame(&mut s).await;
    let (header, _) = parse_response_header(&frame);
    assert_eq!(
        header.channel_sequence_status, STATUS_MORE_PROCESSING_REQUIRED,
        "the first of two messages"
    );
    let session = header.session_id;
    assert_ne!(session, 0, "the answer names a session to continue on");

    // The AP-REP inside SPNEGO's `NegTokenResp`: unwrapping the envelope is the client's job, and
    // handing the Kerberos layer the envelope leaves it with a tag it does not know.
    let answer = session_setup_token(&frame);
    assert!(!answer.is_empty(), "the server sent no SPNEGO token");
    let ap_rep = parse_neg_resp(&answer)
        .token
        .expect("no AP-REP in the token");
    initiator.step(&gss(&ap_rep)).expect("the AP-REP verifies");

    // The closing message, on the same session: the client echoes the AP-REP, framed as GSS-API
    // sends it, which is what completes mutual authentication on both sides.
    let blob = spnego_init(&mech(), Some(&gss(&ap_rep)));
    // Flags 0: a nonzero flag here is `SMB2_SESSION_FLAG_BINDING` (MS-SMB2 2.2.5), which asks to
    // attach this logon to an existing session — this server refuses that, and the refusal
    // (`STATUS_REQUEST_NOT_ACCEPTED`) would then say nothing about the Kerberos exchange.
    let hdr = build_header(Command::SessionSetup, 2, session, 0);
    write_frame(&mut s, &hdr, &session_setup_body(&blob, 0, 1, 0)).await;
    let frame = read_frame(&mut s).await;
    let (header, _) = parse_response_header(&frame);
    assert_eq!(
        header.channel_sequence_status, STATUS_SUCCESS,
        "the second message completes the logon"
    );
    assert_eq!(header.session_id, session, "on the session it named");
    assert!(
        initiator.is_established(),
        "the client's side of the handshake is complete"
    );
}
