//! Signed RPC: the NTLM signature a member puts on every call at integrity level.
//!
//! At `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` each PDU carries a sixteen-octet `NTLMSSP_MESSAGE_SIGNATURE`
//! in its verifier, and the answer carries one too. Nothing else about the call changes — the
//! arguments still travel in the clear — so this is the level where a server that signs wrongly is
//! not detected by a naive client: it verifies the arguments and reports nothing.
//!
//! Two things here are written independently of the crate, on purpose. The signing state is
//! `NtlmSign` in `tests/common/auth.rs`, a second implementation of MS-NLMP 3.4.4 keyed on the same
//! exported session key; and the range a signature covers is `SigStyle`, because MS-RPCE 2.2.2.11.1
//! leaves it implicit and two readings are in use. A test that borrowed either from the server would
//! be asking the code whether the code is right.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::auth::{
    AuthOptions, CLIENT_FLAGS, NtlmDir, NtlmSign, SigStyle, ntlm_authenticate, ntlm_negotiate,
};
use common::rpc::{
    FIRST, LAST, NDR, PTYPE_RESPONSE, auth_of, bind_pdu, call_id, ptype, request_pdu,
    with_auth_level,
};
use smb_server::tcp::{Endpoint, serve};
use smb_server::{LogonUsers, UserCreds};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `drsuapi` 4.0: the interface whose `DRSCrackNames` answers without any state, which is what makes
/// it usable as "some call that succeeds" here.
const DRSUAPI: [u8; 20] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
    4, 0, 0, 0,
];

/// `RPC_C_AUTHN_WINNT`: raw NTLMSSP, no SPNEGO around it.
const AUTH_WINNT: u8 = 10;
/// `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`: signed, not sealed.
const LEVEL_INTEGRITY: u8 = 5;
/// `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`: signed and sealed.
const LEVEL_PRIVACY: u8 = 6;
/// `IDL_DRSCrackNames` (MS-DRSR 4.1.4).
const OPNUM_CRACK_NAMES: u16 = 12;

const PASSWORD: &str = "correct horse battery staple";

/// The account the logon is checked against, as the directory would hand it over.
#[derive(Debug)]
struct Directory;

impl LogonUsers for Directory {
    fn user(&self, account: &str) -> Option<UserCreds> {
        (account.eq_ignore_ascii_case("carol")).then(|| UserCreds::from_password(PASSWORD))
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("a local address")
        .port()
}

/// A listener with the accounts, bound on a fresh port, and a client that has reached it.
async fn started() -> TcpStream {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port())
        .parse()
        .expect("an address");
    let endpoint = Endpoint {
        addr,
        nb_domain: "AD".to_string(),
        dns_domain: "ad.example.com".to_string(),
        nb_computer: "SAMBA".to_string(),
        dns_computer: "samba.ad.example.com".to_string(),
        keytab: None,
        logon_users: Some(std::sync::Arc::new(Directory)),
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

/// An `auth3` (packet type 16): a header and a verifier.
fn auth3(call_id_value: u32, token: &[u8], level: u8) -> Vec<u8> {
    let mut out = vec![5, 0, 16, FIRST | LAST, 0x10, 0, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(&call_id_value.to_le_bytes());
    with_auth_level(out, AUTH_WINNT, level, 0, token)
}

/// The bind and the logon, up to the point where the association is signed: returns the two signing
/// states, one per direction.
///
/// `level` is the association's, and it is fixed by the bind: `exchange.agreed` records the first
/// verifier it sees and every answer names that level, so a client that binds at integrity and then
/// sends a call at privacy gets an answer that says integrity — the server sealed nothing, because
/// the level it agreed to was the lower one.
async fn authenticated(stream: &mut TcpStream, level: u8) -> (NtlmSign, NtlmSign) {
    // The NEGOTIATE travels in the bind's verifier, which is the first message of the handshake.
    let negotiate = ntlm_negotiate(CLIENT_FLAGS);
    let bind = with_auth_level(
        bind_pdu(1, 4280, &[(0, DRSUAPI, NDR)]),
        AUTH_WINNT,
        level,
        0,
        &negotiate,
    );
    stream.write_all(&bind).await.expect("the bind");
    let ack = read_pdu(stream).await;
    assert_eq!(ptype(&ack), 12, "a bind_ack: {ack:02x?}");
    let (auth_type, answered_level, _, challenge) =
        auth_of(&ack).expect("the ack carries a challenge");
    assert_eq!(
        (auth_type, answered_level),
        (AUTH_WINNT, level),
        "the answer names the level the bind asked for"
    );
    assert!(
        challenge.starts_with(b"NTLMSSP\x00"),
        "the answer to a NEGOTIATE is a CHALLENGE"
    );

    // AUTHENTICATE in an `auth3`, which owes no answer of its own.
    let (authenticate, exported) = ntlm_authenticate(
        "carol",
        PASSWORD,
        &negotiate,
        &challenge,
        AuthOptions {
            flags: CLIENT_FLAGS,
            mic: true,
        },
    );
    stream
        .write_all(&auth3(2, &authenticate, level))
        .await
        .expect("auth3");
    let early = tokio::time::timeout(Duration::from_millis(200), read_pdu(stream)).await;
    assert!(
        early.is_err(),
        "auth3 owes no answer, and one would be a protocol error for the client"
    );

    // The two derived states. `CLIENT_FLAGS` negotiates `KEY_EXCH`, so each direction has its own
    // RC4 stream over the sealing key and the signature's checksum is masked with it.
    let send = NtlmSign::new(CLIENT_FLAGS, &exported, NtlmDir::ClientToServer)
        .expect("signing was negotiated");
    let recv = NtlmSign::new(CLIENT_FLAGS, &exported, NtlmDir::ServerToClient)
        .expect("signing was negotiated");
    (send, recv)
}

/// A `DRSCrackNames` stub: the domain's canonical name wanted in NT4 form.
///
/// Ten octets of handle and level, then the request's own fields, then the conformant array of one
/// name — a referent, its maximum, one pointer, and the string itself after them (NDR32).
fn crack_names_stub() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0_u8; 20]); // policy handle, inline
    for word in [1_u32, 1, 0, 0, 0, 7, 2, 1, 1, 1, 1] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    // The name as a conformant varying string: the maximum, the offset, the actual count, then the
    // UTF-16LE units and their terminator. Writing the units alone — which is what a stub built by
    // eye does — leaves the reader taking the first code unit for a maximum and finding no string at
    // all, and the answer then says there is no such mapping instead of naming one.
    //
    // `ad.example.com/` is the canonical name of the domain itself, the one conversion a controller
    // can always make.
    let units: Vec<u16> = "ad.example.com/".encode_utf16().chain([0]).collect();
    out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // max_count
    out.extend_from_slice(&0u32.to_le_bytes()); // offset
    out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // actual_count
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// A call at integrity level, signed the way `style` signs, answered with a signature of its own.
async fn signed_call(
    stream: &mut TcpStream,
    send: &mut NtlmSign,
    recv: &mut NtlmSign,
    style: SigStyle,
    call_id_value: u32,
) -> Vec<u8> {
    let plain = request_pdu(
        call_id_value,
        FIRST | LAST,
        0,
        OPNUM_CRACK_NAMES,
        &crack_names_stub(),
    );
    // The placeholder is part of the PDU while the signature over that PDU is computed, so the PDU is
    // built twice: once with sixteen zero octets, once with the signature in their place.
    let placeholder = with_auth_level(plain.clone(), AUTH_WINNT, LEVEL_INTEGRITY, 0, &[0_u8; 16]);
    let signature = send.mac(&style.message(&placeholder));
    let signed = with_auth_level(plain, AUTH_WINNT, LEVEL_INTEGRITY, 0, &signature);
    assert_eq!(
        signed.len(),
        placeholder.len(),
        "the signature occupies the placeholder's octets and changes no length"
    );
    stream.write_all(&signed).await.expect("the call");
    let answer = read_pdu(stream).await;
    // Not `assert_pdu`: it states that the PDU carries no verifier, and a signed answer has one.
    // What makes the answer whole is `frag_length`, which `read_pdu` already checked.
    assert_eq!(ptype(&answer), PTYPE_RESPONSE, "the call was answered");
    assert_eq!(&answer[..2], [5, 0], "version 5.0");
    assert_eq!(&answer[4..8], [0x10, 0, 0, 0], "little-endian");
    assert_eq!(call_id(&answer), call_id_value);

    let (auth_type, level, _, token) = auth_of(&answer).expect("the answer carries a signature");
    assert_eq!(
        (auth_type, level),
        (AUTH_WINNT, LEVEL_INTEGRITY),
        "the answer names the mechanism and level the association agreed"
    );
    assert_eq!(token.len(), 16, "a signature, not a token");

    // The server signed the answer in the same reading of the range that it accepted from the client:
    // a client verifies with what it sent, and a server that switched styles mid-association would be
    // accepted only by a client that read both.
    let mut expected = answer.clone();
    let at = expected.len() - 16;
    expected[at..].fill(0);
    let message = style.message(&expected);
    let mac = recv.mac(&message);
    assert_eq!(
        &token[..],
        &mac[..],
        "the answer's signature does not verify over the octets the client signed"
    );
    answer
}

/// A call signed over everything ahead of the signature, and an answer signed the same way.
///
/// This is the reading a Windows client uses: measured, the checksum of its first signed call matches
/// an HMAC over the header, the arguments and the `sec_trailer`, and over no other range.
#[tokio::test]
async fn a_call_signed_ahead_of_the_signature_is_answered_signed() {
    let mut stream = started().await;
    let (mut send, mut recv) = authenticated(&mut stream, LEVEL_INTEGRITY).await;
    signed_call(
        &mut stream,
        &mut send,
        &mut recv,
        SigStyle::BeforeSignature,
        3,
    )
    .await;
}

/// The other reading: the whole PDU, with the sixteen signature octets counted as zero.
///
/// A peer that signs this way is as consistent as one that signs the first way, and a server must
/// settle which it is from the first call rather than refuse it — there is no field in the PDU that
/// says, and the two differ only in whether sixteen zero octets are part of the input.
#[tokio::test]
async fn a_call_signed_over_the_whole_pdu_is_answered_the_same_way() {
    let mut stream = started().await;
    let (mut send, mut recv) = authenticated(&mut stream, LEVEL_INTEGRITY).await;
    signed_call(&mut stream, &mut send, &mut recv, SigStyle::Zeroed, 4).await;
}

/// A sealed call at privacy level: the arguments travel RC4'd, the signature is over the plaintext.
///
/// This is the level a Windows join uses for the calls that carry secrets, and the two ciphers have
/// an order that is not negotiable: the message consumes its length from the RC4 stream first, and
/// the checksum is masked with what the stream holds after that. A client that masked first would
/// produce a signature the server cannot verify — and the server, unable to tell a broken peer from
/// an attacker, answers nothing.
///
/// The signature covers the **plaintext** PDU: measured, the checksum of a Windows client's sealed
/// `DsBind` matches an HMAC over the header, the decrypted arguments and the `sec_trailer`, and over
/// the ciphertext it does not. So the octets the client signs are the ones it sent before sealing.
#[tokio::test]
async fn a_sealed_call_is_answered_sealed_and_signed() {
    let mut stream = started().await;
    let (mut send, mut recv) = authenticated(&mut stream, LEVEL_PRIVACY).await;

    // The seal carries a body that is a multiple of four: the server pads inside it, and a client
    // that sends an unaligned body has its padding land where its own signature expected arguments.
    let mut plain = crack_names_stub();
    plain.resize(plain.len().next_multiple_of(4), 0);
    let mut cipher = plain.clone();
    assert!(send.seal(&mut cipher), "the association can seal");

    // The PDU with the ciphertext on the wire and sixteen zero octets where the signature will go;
    // the same PDU with the plaintext in place is what the signature covers.
    let wire_pdu = with_auth_level(
        request_pdu(6, FIRST | LAST, 0, OPNUM_CRACK_NAMES, &cipher),
        AUTH_WINNT,
        LEVEL_PRIVACY,
        0,
        &[0_u8; 16],
    );
    let mut view = wire_pdu.clone();
    view[24..24 + plain.len()].copy_from_slice(&plain);
    let signature = send.mac(&SigStyle::BeforeSignature.message(&view));
    let signed = with_auth_level(
        request_pdu(6, FIRST | LAST, 0, OPNUM_CRACK_NAMES, &cipher),
        AUTH_WINNT,
        LEVEL_PRIVACY,
        0,
        &signature,
    );
    stream.write_all(&signed).await.expect("the sealed call");

    let answer = read_pdu(&mut stream).await;
    assert_eq!(
        ptype(&answer),
        PTYPE_RESPONSE,
        "the sealed call was answered"
    );
    let (auth_type, level, _, token) = auth_of(&answer).expect("the answer carries a signature");
    assert_eq!(
        (auth_type, level),
        (AUTH_WINNT, LEVEL_PRIVACY),
        "the answer stays at the level the association chose"
    );
    assert_eq!(token.len(), 16);

    // The answer's arguments are ciphertext: opened with the receiving stream, which advances by the
    // message before the checksum is unmasked.
    let at = 24;
    let end = answer.len() - 8 - 16;
    let mut body = answer[at..end].to_vec();
    assert!(
        body != crack_names_stub()[..body.len()],
        "the answer travels sealed, not in the clear"
    );
    assert!(recv.seal(&mut body), "the answer can be opened");
    // What the seal opened is a `DRSCrackNames` answer, not noise: the union's level, and the domain
    // name in UTF-16LE. Comparing it against the request would be comparing two different stubs — the
    // answer is the handler's, and the point here is that the cipher opened at all.
    assert_eq!(
        &body[..4],
        &1u32.to_le_bytes(),
        "the opened body starts with the answer's level"
    );
    // The answer carries the two names the conversion produces — the DNS name and the NetBIOS form a
    // client appends an account to — as conformant varying strings, so each is UTF-16LE behind a
    // three-word header.
    let utf16 = |text: &str| -> Vec<u8> {
        text.encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    };
    for expected in ["ad.example.com", "AD\\"] {
        let name = utf16(expected);
        assert!(
            body.windows(name.len())
                .any(|window| window == name.as_slice()),
            "the opened answer carries {expected:?}"
        );
    }

    let mut view = answer.clone();
    view[at..at + body.len()].copy_from_slice(&body);
    let mac = recv.mac(&SigStyle::BeforeSignature.message(&view));
    assert_eq!(
        &token[..],
        &mac[..],
        "the sealed answer's signature verifies"
    );
}

/// A signature that matches neither reading is refused, and the call is not answered.
///
/// The refusal is silence, which is what the association looks like from the client's side when its
/// own signing is broken: no fault code exists for "your MAC was wrong", and a fault would let an
/// attacker probe the key.
#[tokio::test]
async fn a_signature_that_matches_neither_reading_is_not_answered() {
    let mut stream = started().await;
    let (mut send, mut _recv) = authenticated(&mut stream, LEVEL_INTEGRITY).await;

    let plain = request_pdu(5, FIRST | LAST, 0, OPNUM_CRACK_NAMES, &crack_names_stub());
    // A well-formed signature at the right place, over the wrong message: one octet of the stub
    // differs, so neither reading of the PDU produces this checksum.
    let mut wrong = send.mac(b"not this PDU at all");
    wrong[4] ^= 0x01;
    let signed = with_auth_level(plain, AUTH_WINNT, LEVEL_INTEGRITY, 0, &wrong);
    stream.write_all(&signed).await.expect("the call");

    let answer = tokio::time::timeout(Duration::from_millis(300), read_pdu(&mut stream)).await;
    assert!(
        answer.is_err(),
        "a call whose signature does not hold must not be answered: {:02x?}",
        answer.ok()
    );
}
