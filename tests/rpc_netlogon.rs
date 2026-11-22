//! The `netlogon` pipe over SMB: a bind, a challenge, and what the dispatcher answers.
//!
//! The handlers under `rpc::netlogon` have unit tests of their own; what none of them reached is
//! the path a client actually takes — the named pipe, the association, the bind, the call. A
//! handler that answers correctly and a pipe that never delivers the call both look fine from the
//! handler's side, and only a client tells them apart.

mod common;

use common::client::Server;
use common::durable::SMB21;
use common::rpc::*;
use smb_server::ntstatus::*;
use smb_server::{Share, SmbServer};
use tempfile::TempDir;

/// `netlogon`'s abstract syntax: `12345778-1234-abcd-ef00-01234567cffb`, version **1**.
///
/// Version 1, like `samr` and unlike `lsarpc` at 0.0 — the family does not share it, and a bind that
/// gets it wrong is refused with a result a client reports as `{Buffer Too Small}` from the pipe it
/// had just opened, which names the buffer rather than the interface.
const NETLOGON: [u8; 20] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb,
    0x01, 0x00, 0x00, 0x00,
];

/// `NdrServerCall` for `netr_ServerReqChallenge`.
const OPNUM_SERVER_REQ_CHALLENGE: u16 = 4;
/// The opnum no version of this interface defines.
const OPNUM_UNKNOWN: u16 = 0xFFFF;

/// A server that names a domain, which is what a member expects to find.
///
/// The temporary directory comes back with the builder because the share's backend reads from it for
/// as long as the server lives: a `TempDir` dropped at the end of this function would take the
/// share's files with it and leave the server serving a directory that no longer exists.
fn builder() -> (smb_server::SmbServerBuilder, TempDir) {
    let td = tempfile::tempdir().expect("a temporary directory");
    let builder = SmbServer::builder()
        .dns_domain("ad.example.com")
        .domain_netbios("AD")
        .share(Share::new("public", common::client::local(td.path())).public());
    (builder, td)
}

async fn server() -> (Server, TempDir) {
    let (builder, td) = builder();
    (Server::start(builder).await, td)
}

/// `netr_ServerReqChallenge`: a unique pointer for the server's name, the name inline, the computer
/// name inline, then the client's eight-octet challenge.
fn challenge_request(client: &[u8; 8]) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, text: &str) {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for unit in &units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    let mut stub = Vec::new();
    stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    string(&mut stub, "\\\\samba.ad.example.com");
    string(&mut stub, "SAMBA");
    stub.extend_from_slice(client);
    stub
}

/// The pipe binds `netlogon`, a challenge is answered, and a call nobody implements is refused by
/// number.
///
/// Three statements about the transport rather than the handler: the bind is accepted for this
/// interface's syntax (the version is part of it, and the wrong one is refused here rather than in
/// the handler), a call reaches `rpc::netlogon::serve` and its answer comes back through the pipe,
/// and an opnum the interface does not define is refused by number — which a client reads as "no
/// such call" rather than as a broken server.
#[tokio::test]
async fn the_netlogon_pipe_binds_and_answers_a_challenge() {
    let (server, _td) = server().await;
    let mut c = ipc_client(server.addr, SMB21, None).await;

    let file_id = c
        .open_pipe("netlogon")
        .await
        .expect("the netlogon pipe opens")
        .file_id;

    // One context, and this interface's own syntax.
    let bind = bind_pdu(1, 4280, &[(0, NETLOGON, NDR)]);
    assert_eq!(c.pipe_write(file_id, &bind).await, STATUS_SUCCESS);
    let (status, ack) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_pdu(&ack, PTYPE_BIND_ACK);
    assert_eq!(
        ack_results(&ack),
        [(0, 0)],
        "the context was accepted under this syntax"
    );

    // `netr_ServerReqChallenge`: eight octets of challenge and a status, in that order.
    let client = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let (status, answer) = c
        .transceive(
            file_id,
            &request_pdu(
                2,
                FIRST | LAST,
                0,
                OPNUM_SERVER_REQ_CHALLENGE,
                &challenge_request(&client),
            ),
            4280,
        )
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_pdu(&answer, PTYPE_RESPONSE);
    assert_eq!(call_id(&answer), 2);
    // The status travels last, after the out parameters: a reply that put it first would be read as
    // a four-octet challenge and a status taken from the middle of the server's random value.
    let at = answer.len() - 4;
    assert_eq!(
        u32::from_le_bytes(answer[at..].try_into().expect("four octets")),
        0,
        "the call succeeded"
    );
    assert_ne!(
        &answer[at - 8..at],
        &[0u8; 8],
        "the server's own challenge is random"
    );

    // An opnum this interface does not define.
    let (status, fault) = c
        .transceive(
            file_id,
            &request_pdu(3, FIRST | LAST, 0, OPNUM_UNKNOWN, &[]),
            4280,
        )
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        fault_status(&fault),
        NCA_OP_RNG_ERROR,
        "refused by number, not by protocol error"
    );
}

/// A bind accepts the interfaces this server carries and rejects the rest, in one answer.
///
/// The realistic shape: a client offers several interfaces at once, and one of them is not this
/// server's. A single bad context must not cost the good ones — the answer carries a result per
/// context, and the calls on the accepted one still work. That is what makes an implementation that
/// refuses the whole bind distinguishable from one that refuses the one context it cannot serve.
#[tokio::test]
async fn a_bind_accepts_what_it_carries_and_rejects_what_it_does_not() {
    let (server, _td) = server().await;
    let mut c = ipc_client(server.addr, SMB21, None).await;
    let file_id = c.open_pipe("netlogon").await.expect("pipe").file_id;

    // An abstract syntax nothing here implements, with a made-up UUID.
    let unknown: [u8; 20] = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    let bind = bind_pdu(1, 4280, &[(0, NETLOGON, NDR), (1, unknown, NDR)]);
    assert_eq!(c.pipe_write(file_id, &bind).await, STATUS_SUCCESS);
    let (status, ack) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_pdu(&ack, PTYPE_BIND_ACK);
    // `(result, reason)` per context: acceptance, then a provider rejection whose reason is
    // `abstract_syntax_not_supported` (C706 12.6.3.2).
    assert_eq!(
        ack_results(&ack),
        [(0, 0), (2, 1)],
        "the interface it carries is accepted, the other is rejected at the provider"
    );

    // The accepted context is usable: a challenge on context 0 is answered.
    let client = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let (status, answer) = c
        .transceive(
            file_id,
            &request_pdu(
                2,
                FIRST | LAST,
                0,
                OPNUM_SERVER_REQ_CHALLENGE,
                &challenge_request(&client),
            ),
            4280,
        )
        .await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_pdu(&answer, PTYPE_RESPONSE);
}

/// A second bind on the same association is refused, and the refusal ends it.
///
/// C706 has one bind per association: the interface list is settled for the life of the connection,
/// and an alter_context is how more are added. A server that quietly re-bound would let a client
/// switch interfaces behind the calls already in flight, so the second bind is answered with a
/// `bind_nak` — which ends the association, and is why a client that needs another interface opens
/// another pipe rather than binding again.
#[tokio::test]
async fn a_second_bind_is_refused_and_ends_the_association() {
    let (server, _td) = server().await;
    let mut c = ipc_client(server.addr, SMB21, None).await;
    let file_id = c.open_pipe("netlogon").await.expect("pipe").file_id;

    let bind = bind_pdu(1, 4280, &[(0, NETLOGON, NDR)]);
    assert_eq!(c.pipe_write(file_id, &bind).await, STATUS_SUCCESS);
    let (status, ack) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_pdu(&ack, PTYPE_BIND_ACK);

    let again = bind_pdu(2, 4280, &[(0, NETLOGON, NDR)]);
    assert_eq!(c.pipe_write(file_id, &again).await, STATUS_SUCCESS);
    let (status, nak) = c.pipe_read(file_id, 4280).await;
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(
        ptype(&nak),
        PTYPE_BIND_NAK,
        "a second bind is a protocol error: {nak:02x?}"
    );
    assert_eq!(call_id(&nak), 2, "the nak answers the bind that caused it");
}
