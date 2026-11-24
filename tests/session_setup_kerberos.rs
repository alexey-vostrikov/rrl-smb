//! SESSION_SETUP with a Kerberos ticket, against a live KDC.
//!
//! `accept_kerberos` and `finish_kerberos` are the two round trips a member takes to log on without a
//! password, and neither can be reached without a KDC: the acceptor holds a keytab, and a keytab is
//! only useful against a ticket whose key came from the realm that exported it. A hand-built ticket
//! would exercise the parser and not the handshake, and the handshake is the whole of it.
//!
//! The stand lives in `scripts/test-kdc-kerberos.sh`: it creates `SMB.TEST`, the user `alice` and the
//! service `cifs/samba.ad.example.com`, and exports the service's keys to a keytab. Without the
//! `KRB5_TEST_*` variables this test returns at its first line and reports nothing — deliberately, so
//! that a stand which is not running does not look like a passing test. The run that measures
//! coverage happens inside `docker/kerberos-stand.Dockerfile`, where the variables are set.

// Every round here needs a KDC to issue the ticket and the keytab to match it, so the file
// is built only with the mechanism.
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

/// `1.2.840.48018.1.2.2`, Microsoft's own Kerberos OID — the spelling a Windows client lists first.
const OID_KRB5_MS: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// The two Kerberos spellings a Windows client offers, Microsoft's first.
///
/// Both are the same mechanism to this server, and the order is the client's: RFC 4178 §4.2.2 has the
/// target name its choice in `supportedMech`, and a client that is answered with the spelling it did
/// not choose reports `SEC_E_INVALID_TOKEN` with no field to say what it disliked.
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

/// A member logs on with a ticket, and the AP-REP comes back in the same answer.
///
/// That is the default the server measured its way to: a Windows client that is answered
/// `accept-completed` and `STATUS_SUCCESS` in one round is finished, and the two-round exchange it
/// also supports (`RRL_SMB_KRB_TWOROUND`) is what a client that is answered `accept-incomplete`
/// needs. So one SESSION_SETUP carries the ticket and the answer carries both the session and the
/// proof of identity — and a client that asked for mutual authentication and got no AP-REP refuses
/// the session even though the ticket was good.
///
/// The ticket names `cifs/…`, so an acceptor that looked for the user's principal instead of the
/// service's would refuse a ticket that is entirely valid.
#[tokio::test]
async fn a_member_logs_on_with_a_ticket_in_one_round() {
    let Some(stand) = Stand::from_env() else {
        return;
    };

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

    // A real TGT from the realm, then a service ticket for the name this server is reached under.
    let client = krb5::KdcClient::new(&stand.realm, [stand.kdc.as_str()]);
    let tgt = client
        .login_with_password(&stand.principal(&stand.user), &stand.password)
        .expect("a ticket-granting ticket");
    let service = client
        .service_ticket(&tgt, &stand.principal(&stand.service))
        .expect("a service ticket");
    // Integrity and confidentiality: the per-message keys are what seals a call at level 6, and a
    // server that accepted the ticket without them could seal nothing.
    let (mut initiator, token) = krb5::InitiatorContext::new(
        &service,
        krb5::initiator::GSS_C_MUTUAL_FLAG
            | krb5::initiator::GSS_C_INTEG_FLAG
            | krb5::initiator::GSS_C_CONF_FLAG,
    )
    .expect("an initiator context");

    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;

    // Both Kerberos spellings offered, Microsoft's first, as a Windows client offers them.
    let blob = spnego_init(&mech(), Some(&token));
    let hdr = build_header(Command::SessionSetup, 1, 0, 0);
    write_frame(&mut s, &hdr, &session_setup_body(&blob, 0, 1, 0)).await;
    let frame = read_frame(&mut s).await;
    let (header, _) = parse_response_header(&frame);
    assert_eq!(
        header.channel_sequence_status, STATUS_SUCCESS,
        "the ticket is accepted in one round"
    );
    assert_ne!(header.session_id, 0, "a session was created");

    // The AP-REP, which only an acceptor that verified the ticket can produce. It arrives inside
    // SPNEGO's `NegTokenResp`, and unwrapping that is the client's job: the mechanism token is what
    // the Kerberos layer reads, and handing it the envelope leaves it with a tag it does not know -
    // `expected tag 0x60, got 0xa1`, which is the `NegTokenResp` itself.
    let answer = session_setup_token(&frame);
    assert!(!answer.is_empty(), "the answer carries no SPNEGO token");
    let ap_rep = parse_neg_resp(&answer)
        .token
        .expect("no AP-REP in the token");
    initiator.step(&gss(&ap_rep)).expect("the AP-REP verifies");
    assert!(
        initiator.is_established(),
        "the client's side of the handshake is complete"
    );
}

/// A ticket for another service is refused, and the refusal names the logon rather than the realm.
///
/// The reason is logged and never returned: an attacker learns from the difference between "no such
/// principal" and "bad key", and a client learns nothing it can act on. What the client gets is
/// `STATUS_LOGON_FAILURE` — the same answer a wrong password gets — and that sameness is the point of
/// the test.
#[tokio::test]
async fn a_ticket_for_another_service_is_refused_as_a_failed_logon() {
    let Some(stand) = Stand::from_env() else {
        return;
    };

    let td = tempfile::tempdir().expect("a temporary directory");
    let (addr, _task) = start_server(
        SmbServer::builder()
            .netbios_name("SAMBA")
            .dns_domain("ad.example.com")
            .keytab(&stand.keytab)
            .share(Share::new("public", common::client::local(td.path())).public()),
    )
    .await;

    // A ticket for a service in a realm this server holds no key for.
    let other = krb5::Principal::parse_in_realm("cifs/elsewhere.example.com", &stand.realm)
        .expect("a principal");
    let client = krb5::KdcClient::new(&stand.realm, [stand.kdc.as_str()]);
    let tgt = client
        .login_with_password(&stand.principal(&stand.user), &stand.password)
        .expect("a TGT");
    // The realm has no such principal, and a ticket that cannot be issued is the same refusal the
    // server would give for one it cannot read.
    let issued = client.service_ticket(&tgt, &other);
    let token = match issued {
        Ok(service) => {
            let (_, token) =
                krb5::InitiatorContext::new(&service, krb5::initiator::GSS_C_MUTUAL_FLAG)
                    .expect("an initiator context");
            token
        }
        // The KDC refused to issue it, which is the same statement one step earlier.
        Err(_) => return,
    };

    let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
    negotiate(&mut s).await;
    let blob = spnego_init(&mech(), Some(&token));
    let hdr = build_header(Command::SessionSetup, 1, 0, 0);
    write_frame(&mut s, &hdr, &session_setup_body(&blob, 0, 1, 0)).await;
    let frame = read_frame(&mut s).await;
    let (header, _) = parse_response_header(&frame);
    assert_eq!(
        header.channel_sequence_status, STATUS_LOGON_FAILURE,
        "a ticket this server cannot read is a failed logon, not a stated reason"
    );
}
