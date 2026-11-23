//! `ncacn_ip_tcp`: the endpoint this crate serves on a bare socket.
//!
//! Everything in this file goes through the real listener — `rpc::tcp::serve`, a bound port, a
//! connection, PDUs framed by `frag_length`. The unit tests inside `src/rpc/tcp.rs` call `answer()`
//! directly, which leaves the three things that only exist when there is a socket untested: the bind
//! (and what a port it cannot have does), the accept loop, and the reassembly of a PDU that arrives
//! in pieces.
//!
//! The endpoint speaks `drsuapi`, the endpoint mapper, `netlogon`, `lsarpc` and `samr`; only the
//! first two are exercised here, because the others need the state a directory hands over and are
//! reached through the same three code paths.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::auth::{AuthOptions, ntlm_authenticate, ntlm_negotiate, parse_challenge};
use common::rpc::{
    FIRST, LAST, NDR, PTYPE_BIND_ACK, PTYPE_FAULT, ack_results, assert_pdu, bind_pdu, call_id,
    fault_status, ptype, request_pdu,
};
use smb_server::tcp::{Endpoint, serve};
use smb_server::{LogonUsers, UserCreds};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `drsuapi` 4.0, 3542e351-4b06-11d1-ab04-00c04fc2dcd2 — the interface a Windows join asks for
/// after the mapper has named this port.
const DRSUAPI: [u8; 20] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
    4, 0, 0, 0,
];

/// The endpoint mapper 3.0, e1af8308-5d1f-11c9-91a4-08002b14a0fa.
const EPM: [u8; 20] = [
    0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
    3, 0, 0, 0,
];

/// `netlogon` 1.0, 12345678-1234-abcd-ef00-01234567cffb.
const NETLOGON: [u8; 20] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb,
    1, 0, 0, 0,
];

/// An interface nothing on this listener answers.
const UNKNOWN: [u8; 20] = [
    0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    1, 0, 0, 0,
];

/// `NCA_OP_RNG_ERROR`, what a call on an interface this listener does not answer gets.
const NCA_OP_RNG_ERROR: u32 = 0x1C01_0002;
/// `NCA_UNK_IF`, what a call on a context the bind rejected gets.
const NCA_UNK_IF: u32 = 0x1C01_0003;

/// A port no one holds, taken and released.
///
/// `serve` reports the address it bound only to its log, so the test picks the port and hands it
/// over. The window between release and rebind is a few microseconds, and a bind failure is reported
/// as a failed test rather than retried away.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    listener.local_addr().expect("a local address").port()
}

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint {
        addr,
        nb_domain: "AD".to_string(),
        dns_domain: "ad.example.com".to_string(),
        nb_computer: "SAMBA".to_string(),
        dns_computer: "samba.ad.example.com".to_string(),
        keytab: None,
        logon_users: None,
        publish: None,
        channel_state: None,
    }
}

/// Starts `endpoint` on a fresh port and returns an address and a connected client.
///
/// `serve` reports the address it bound only to its log, so the test picks the port and hands it over.
async fn started_with(mut endpoint: Endpoint) -> (SocketAddr, TcpStream) {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port())
        .parse()
        .expect("an address");
    endpoint.addr = addr;
    tokio::spawn(async move {
        let _ = serve(endpoint).await;
    });
    (addr, connect(addr).await)
}

/// A listener on a fresh port with nothing configured, and a connected client.
async fn started() -> (SocketAddr, TcpStream) {
    started_with(endpoint("127.0.0.1:0".parse().expect("an address"))).await
}

/// Connects, retrying while the bind inside the spawned task has not happened yet.
///
/// Fifty tries over half a second is far more than a bind needs, and the failure says the listener
/// never came up rather than that the test was slow.
async fn connect(addr: SocketAddr) -> TcpStream {
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the listener at {addr} never accepted a connection");
}

/// One PDU out, one PDU back.
async fn transceive(stream: &mut TcpStream, pdu: &[u8]) -> Vec<u8> {
    stream.write_all(pdu).await.expect("write");
    read_pdu(stream).await
}

/// A whole PDU, as framed by `frag_length`.
async fn read_pdu(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = [0_u8; 16];
    stream.read_exact(&mut head).await.expect("the header");
    let len = usize::from(u16::from_le_bytes([head[8], head[9]]));
    assert!(len >= 16, "a PDU shorter than its header: {len}");
    let mut rest = vec![0_u8; len - 16];
    if !rest.is_empty() {
        stream.read_exact(&mut rest).await.expect("the body");
    }
    let mut pdu = head.to_vec();
    pdu.extend_from_slice(&rest);
    assert_eq!(
        usize::from(u16::from_le_bytes([pdu[8], pdu[9]])),
        pdu.len(),
        "the frame is whole"
    );
    pdu
}

/// A bind, a call, and the interface this listener answers: the shape a client takes to `drsuapi`.
///
/// Two contexts in one bind is what Windows sends, and the answer has to carry a result per context
/// in the order they were offered — a client pairs them by position and a shorter answer reads as a
/// protocol error rather than "this interface is missing".
#[tokio::test]
async fn a_bind_and_a_call_survive_a_real_socket() {
    let (_addr, mut s) = started().await;

    let bind = bind_pdu(1, 4280, &[(0, DRSUAPI, NDR), (1, EPM, NDR)]);
    let ack = transceive(&mut s, &bind).await;
    assert_pdu(&ack, PTYPE_BIND_ACK);
    assert_eq!(call_id(&ack), 1);
    assert_eq!(
        ack_results(&ack),
        [(0, 0), (0, 0)],
        "both interfaces are carried, in the order they were offered"
    );

    // A call on a context this bind rejected. The interface is unknown here and the fault names it.
    //
    // The rejection is `local_limit_exceeded` (3) rather than `provider_rejection` (2), and that is
    // deliberate in the server: a client that reads 2 for an interface the server does not have
    // treats the answer as a broken bind and stops, where 3 says this one context is absent and the
    // rest of the association is fine.
    let mut second = connect(_addr).await;
    let bind = bind_pdu(3, 4280, &[(0, UNKNOWN, NDR)]);
    let ack = transceive(&mut second, &bind).await;
    assert_pdu(&ack, PTYPE_BIND_ACK);
    assert_eq!(
        ack_results(&ack),
        [(3, 3)],
        "an interface nothing here answers is rejected as this context alone"
    );

    let call = request_pdu(4, FIRST | LAST, 0, 0, &[]);
    let fault = transceive(&mut second, &call).await;
    assert_eq!(
        fault_status(&fault),
        NCA_UNK_IF,
        "a call on a rejected context is refused by number"
    );
}

/// A PDU split across two writes, and two PDUs in one: `frag_length` is the only frame.
///
/// TCP gives no message boundaries, so a server that answered per read would cut a large call in
/// half — and a client's bind and its first call often arrive together, in which case reading one PDU
/// per read leaves the call unanswered until the client gives up.
#[tokio::test]
async fn a_pdu_arrives_in_pieces_and_pdus_arrive_together() {
    let (_addr, mut s) = started().await;

    // Half the bind, then the rest: the answer must not come before the second write.
    let bind = bind_pdu(1, 4280, &[(0, DRSUAPI, NDR)]);
    let (head, tail) = bind.split_at(10);
    s.write_all(head).await.expect("the first half");
    // Nothing can arrive yet, and a read that returned would be an answer to half a PDU. The socket
    // is asked with a short timeout: silence is the expected outcome.
    let early = tokio::time::timeout(Duration::from_millis(120), read_pdu(&mut s)).await;
    assert!(
        early.is_err(),
        "the server answered a PDU it had not received in full"
    );
    s.write_all(tail).await.expect("the second half");
    let ack = read_pdu(&mut s).await;
    assert_pdu(&ack, PTYPE_BIND_ACK);
    assert_eq!(call_id(&ack), 1);

    // Two PDUs in one write, answered in order: the bind's answer and the call's fault. The bind
    // offers context 5, which this connection has not bound, so the call on it is dispatched to
    // nothing - context 0 is taken by the `drsuapi` bind above, and a second bind does not replace
    // it: contexts live for the connection, and a client that wants another uses `alter_context`.
    let second = bind_pdu(2, 4280, &[(5, UNKNOWN, NDR)]);
    let third = request_pdu(3, FIRST | LAST, 5, 0, &[]);
    let mut both = second.clone();
    both.extend_from_slice(&third);
    s.write_all(&both).await.expect("two PDUs at once");
    let first_answer = read_pdu(&mut s).await;
    assert_pdu(&first_answer, PTYPE_BIND_ACK);
    assert_eq!(call_id(&first_answer), 2);
    let second_answer = read_pdu(&mut s).await;
    assert_eq!(
        ptype(&second_answer),
        PTYPE_FAULT,
        "the second PDU is answered too, not lost with the first read"
    );
    assert_eq!(call_id(&second_answer), 3);
}

/// A port this listener cannot have is a startup error, not a silent fallback.
///
/// The process that starts an endpoint without a port is one a client cannot reach while the log
/// says it is running, so `serve` returns the bind error and the caller decides what to do with it.
#[tokio::test]
async fn a_port_already_held_is_reported_rather_than_worked_around() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let addr = held.local_addr().expect("a local address");

    let error = serve(endpoint(addr)).await.expect_err("the port is taken");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::AddrInUse,
        "the error names the port, not a generic failure: {error}"
    );
    drop(held);
}

/// Accounts for the NTLM logon, from the same source SMB uses.
#[derive(Debug)]
struct Directory;

impl LogonUsers for Directory {
    fn user(&self, account: &str) -> Option<UserCreds> {
        (account.eq_ignore_ascii_case("carol"))
            .then(|| UserCreds::from_password("correct horse battery staple"))
    }
}

/// The NTLM logon a member makes before it has a ticket: NEGOTIATE, CHALLENGE, AUTHENTICATE.
///
/// `netr_ServerAuthenticate3` over `ncacn_ip_tcp` is where a joined member proves its secure
/// channel, and it authenticates with `RPC_C_AUTHN_WINNT` rather than with a ticket: the domain has
/// issued the machine no ticket yet. Three PDUs, and the third is an `auth3` — which owes no answer
/// of its own, and answering it is what a client reports as `RPC_S_INVALID_TAG` (0x6be).
#[tokio::test]
async fn an_ntlm_logon_is_answered_over_tcp() {
    let mut endpoint = endpoint("127.0.0.1:0".parse().expect("an address"));
    endpoint.logon_users = Some(std::sync::Arc::new(Directory));
    let (_addr, mut s) = started_with(endpoint).await;

    // The bind carries the mechanism's first message in its verifier: `RPC_C_AUTHN_WINNT` (10) with
    // a raw NTLMSSP NEGOTIATE, no SPNEGO around it.
    let negotiate = ntlm_negotiate(0xe2_08_82_17);
    let bind = with_verifier(bind_pdu(1, 4280, &[(0, NETLOGON, NDR)]), 10, 5, &negotiate);
    let ack = transceive(&mut s, &bind).await;
    // Not `assert_pdu`: this answer carries a verifier, and that helper states the opposite. The
    // arm we hold is `auth_length != 0`, which is how a client knows to look for the sec_trailer.
    assert_eq!(ptype(&ack), PTYPE_BIND_ACK);
    assert_eq!(call_id(&ack), 1);
    let challenge = verifier_token(&ack);
    assert!(
        challenge.starts_with(b"NTLMSSP\x00"),
        "the answer to a NEGOTIATE is a CHALLENGE: {challenge:02x?}"
    );
    let (server_challenge, _) = parse_challenge(&challenge);
    assert_ne!(server_challenge, [0; 8], "a challenge, not a constant");

    // The AUTHENTICATE, in an `auth3`: no answer comes back, and the connection stays open for the
    // call it was authenticating for.
    let (authenticate, _key) = ntlm_authenticate(
        "carol",
        "correct horse battery staple",
        &negotiate,
        &challenge,
        AuthOptions::default(),
    );
    let auth3 = with_verifier(auth3_pdu(2), 10, 5, &authenticate);
    s.write_all(&auth3).await.expect("auth3");
    let early = tokio::time::timeout(Duration::from_millis(200), read_pdu(&mut s)).await;
    assert!(
        early.is_err(),
        "auth3 owes no answer, and an answer is a protocol error on the client's side"
    );

    // A call on the now authenticated association reaches the interface: `netlogon` has no channel
    // state on this listener, so the refusal is by number and comes from the dispatcher rather than
    // from the association.
    let call = request_pdu(3, FIRST | LAST, 0, 4, &[]);
    let answer = transceive(&mut s, &call).await;
    assert_eq!(
        fault_status(&answer),
        NCA_OP_RNG_ERROR,
        "the association was live enough to dispatch the call"
    );
}

/// A `netlogon` negotiate: the names a member announces, and the answer that names none.
///
/// `NL_AUTH_NEGOTIATE` (MS-NRPC 2.2.1.3.1) travels in the bind's verifier with `auth_type` 68, and
/// its flags describe the names in the *request*. The answer's flags are zero and its buffer is a
/// single `NULL`, because echoing the client's word back claims the answer carries names it does not —
/// which a Windows member reports as `SEC_E_INVALID_TOKEN` and never follows with the `auth3` that
/// would have proved the channel.
#[tokio::test]
async fn a_netlogon_negotiate_names_its_computer_and_the_answer_names_none() {
    let (_addr, mut s) = started().await;

    // Message type 0 (`NL_NEGOTIATE_REQUEST`), then the flag word: NetBIOS domain, NetBIOS computer,
    // DNS domain and the computer again as UTF-8 — the four a member announces.
    let flags: u32 = 0x01 | 0x02 | 0x04 | 0x10;
    let mut token = Vec::new();
    token.extend_from_slice(&0u32.to_le_bytes());
    token.extend_from_slice(&flags.to_le_bytes());
    for name in ["AD", "SAMBA", "ad.example.com", "SAMBA"] {
        token.extend_from_slice(name.as_bytes());
        token.push(0);
    }

    let bind = with_verifier(bind_pdu(1, 4280, &[(0, NETLOGON, NDR)]), 68, 5, &token);
    let ack = transceive(&mut s, &bind).await;
    assert_eq!(ptype(&ack), PTYPE_BIND_ACK);
    let answer = verifier_token(&ack);
    assert_eq!(
        answer,
        {
            let mut expected = 1u32.to_le_bytes().to_vec(); // NL_NEGOTIATE_RESPONSE
            expected.extend_from_slice(&[0u8; 8]);
            expected
        },
        "the answer is a response with no flags and a NULL buffer"
    );

    // The computer the negotiate named is the one the channel's key belongs to, and it was taken
    // from the NetBIOS form. A call on `netlogon` then fails by number - this listener has no channel
    // state - which is what makes the refusal distinguishable from an association that died.
    let call = request_pdu(2, FIRST | LAST, 0, 4, &[]);
    let fault = transceive(&mut s, &call).await;
    assert_eq!(fault_status(&fault), NCA_OP_RNG_ERROR);
}

/// `pdu` with an auth verifier naming `auth_type` and `level` (MS-RPCE 2.2.2.11).
fn with_verifier(mut pdu: Vec<u8>, auth_type: u8, level: u8, token: &[u8]) -> Vec<u8> {
    pdu.extend_from_slice(&[auth_type, level, 0, 0, 0, 0, 0, 0]);
    pdu.extend_from_slice(token);
    pdu[10..12].copy_from_slice(&(token.len() as u16).to_le_bytes());
    let len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&len.to_le_bytes());
    pdu
}

/// An `auth3` (packet type 16): a header and a verifier, nothing else.
fn auth3_pdu(call_id: u32) -> Vec<u8> {
    let mut out = vec![5, 0, 16, FIRST | LAST, 0x10, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&call_id.to_le_bytes());
    out
}

/// The token in a PDU's verifier, located by counting back `auth_length` and the sec_trailer.
fn verifier_token(pdu: &[u8]) -> Vec<u8> {
    let len = usize::from(u16::from_le_bytes([pdu[10], pdu[11]]));
    assert!(len > 0, "the answer carries no verifier: {pdu:02x?}");
    pdu[pdu.len() - len..].to_vec()
}
