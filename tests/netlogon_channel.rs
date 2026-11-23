//! The netlogon secure channel: the challenge, the credential, and the seal it turns on.
//!
//! A member proves its secure channel with `netr_ServerReqChallenge` and `netr_ServerAuthenticate3`,
//! and from that moment its calls are sealed with a key neither side sends: `channel.key`, derived
//! from the machine password's NT hash and the two challenges. Three things depend on getting that
//! exactly right and none of them is visible in a parse test — the credential arithmetic (AES-128-CFB8
//! over the client's half), the answer's `server_credential`, and the `NL_AUTH_SIGNATURE` blob that
//! wraps every later PDU.
//!
//! The client side here is written independently of the crate, from MS-NRPC 3.1.4: a test that called
//! the server's own `session_key_aes` and `credential_aes` to produce its input would agree with a
//! broken server. What is reused is nothing; what is shared is the specification.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::rpc::{
    FIRST, LAST, NDR, PTYPE_BIND_ACK, PTYPE_RESPONSE, auth_of, bind_pdu, call_id, ptype,
    request_pdu,
};
use smb_server::tcp::{ChannelState, Endpoint, serve};
use smb_server::{MachineAccount, MachineSecrets, SmbServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `netlogon` 1.0, 12345678-1234-abcd-ef00-01234567cffb.
const NETLOGON: [u8; 20] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb,
    1, 0, 0, 0,
];

/// `RPC_C_AUTHN_NETLOGON`: the verifier is an `NL_AUTH_MESSAGE` or an `NL_AUTH_SIGNATURE`.
const AUTH_NETLOGON: u8 = 68;
/// `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`: every PDU is sealed.
const LEVEL_PRIVACY: u8 = 6;

/// The calls this stand makes.
const OPNUM_SERVER_REQ_CHALLENGE: u16 = 4;
const OPNUM_DSR_GETDCNAME: u16 = 14;
const OPNUM_SERVER_AUTHENTICATE3: u16 = 26;

/// `NL_NEGOTIATE_REQUEST`.
const NL_NEGOTIATE_REQUEST: u32 = 0;
/// `NETLOGON_NEG_SUPPORTS_AES` (0x01000000) and `NETLOGON_NEG_AUTHENTICATED_RPC` (0x40000000),
/// both from MS-NRPC 2.2.1.3.1. The first is not bit zero — reading it as one has a client offer a
/// bit the server ignores, and the authenticate then answers `STATUS_NOT_SUPPORTED` for a channel
/// that was asked for correctly.
const NEG_SUPPORTS_AES: u32 = 0x0100_0000;
const NEG_AUTHENTICATED_RPC: u32 = 0x4000_0000;

const MACHINE_PASSWORD: &str = "samba-machine-password";
const MACHINE_ACCOUNT: &str = "SAMBA$";
const MACHINE_RID: u32 = 1104;

// --- the machine's secrets, as a directory would hand them over -------------------------------

/// The machine accounts this stand serves.
#[derive(Debug)]
struct Secrets(HashMap<String, MachineAccount>);

impl MachineSecrets for Secrets {
    fn machine(&self, account: &str) -> Option<MachineAccount> {
        self.0.get(&account.to_ascii_uppercase()).cloned()
    }
}

fn secrets() -> Secrets {
    let mut accounts = HashMap::new();
    accounts.insert(
        MACHINE_ACCOUNT.to_string(),
        MachineAccount {
            nt_hash: nt_hash(MACHINE_PASSWORD),
            rid: MACHINE_RID,
        },
    );
    Secrets(accounts)
}

/// MD4 of the password in UTF-16LE: `unicodePwd`'s own derivation.
fn nt_hash(password: &str) -> [u8; 16] {
    use md4::Digest as _;
    let units: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    md4::Md4::digest(&units).into()
}

// --- the client's half of the channel, from MS-NRPC 3.1.4 --------------------------------------

/// `SessionKey = HMAC_SHA256(NTProofStr, ClientChallenge || ServerChallenge)` (MS-NRPC 3.1.4.3.1).
fn session_key_aes(nt_hash: &[u8; 16], client: &[u8; 8], server: &[u8; 8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(nt_hash).expect("any key length");
    mac.update(client);
    mac.update(server);
    mac.finalize().into_bytes().into()
}

/// `ComputeNetlogonCredential` under an AES channel: AES-128-CFB8 with a zero IV.
///
/// Eight-bit segments over the first sixteen octets of the session key, and the feedback is the
/// ciphertext in both directions — which is why the same function computes the credential and checks
/// it.
fn credential_aes(input: &[u8; 8], session_key: &[u8; 32]) -> [u8; 8] {
    let mut out = *input;
    cfb8(&session_key[..16], &[0_u8; 16], &mut out, true);
    out
}

/// AES-128-CFB8 in place, one octet per block-cipher call.
fn cfb8(key: &[u8], iv: &[u8; 16], data: &mut [u8], encrypt: bool) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("a sixteen-octet key");
    let mut state = *iv;
    for octet in data.iter_mut() {
        let mut block = aes::Block::from(state);
        cipher.encrypt_block(&mut block);
        let keystream = block[0];
        if encrypt {
            *octet ^= keystream;
            state.copy_within(1.., 0);
            state[15] = *octet;
        } else {
            let arrived = *octet;
            *octet ^= keystream;
            state.copy_within(1.., 0);
            state[15] = arrived;
        }
    }
}

/// The sequence number as the wire carries it: `low32` then `high32`, both big-endian, with the
/// initiator bit on the high word.
fn sequence_blob(counter: u64, initiator: bool) -> [u8; 8] {
    let low = (counter & 0xFFFF_FFFF) as u32;
    let mut high = (counter >> 32) as u32;
    if initiator {
        high |= 0x8000_0000;
    }
    let mut blob = [0_u8; 8];
    blob[0..4].copy_from_slice(&low.to_be_bytes());
    blob[4..8].copy_from_slice(&high.to_be_bytes());
    blob
}

/// `HMAC_SHA256(session_key[..16], parts)`, truncated to eight octets.
fn checksum(session_key: &[u8; 32], parts: &[&[u8]]) -> [u8; 8] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&session_key[..16]).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    let full = mac.finalize().into_bytes();
    full[..8].try_into().expect("eight octets")
}

/// The sequence blob under AES-128-CFB8 with the checksum twice as the IV.
fn crypt_sequence(session_key: &[u8; 32], checksum: &[u8; 8], blob: &[u8; 8]) -> [u8; 8] {
    let mut iv = [0_u8; 16];
    iv[..8].copy_from_slice(checksum);
    iv[8..].copy_from_slice(checksum);
    let mut out = *blob;
    cfb8(&session_key[..16], &iv, &mut out, true);
    out
}

/// The body stream: key `session_key[i] ^ 0xF0`, IV the sequence blob twice, over confounder then
/// data — one stream for both, because the second part continues the first's cipher state.
fn transform_body(
    encrypt: bool,
    session_key: &[u8; 32],
    seq_num: &[u8; 8],
    confounder: &mut [u8; 8],
    data: &mut [u8],
) {
    let mut key = [0_u8; 16];
    for (index, octet) in key.iter_mut().enumerate() {
        *octet = session_key[index] ^ 0xF0;
    }
    let mut iv = [0_u8; 16];
    iv[..8].copy_from_slice(seq_num);
    iv[8..].copy_from_slice(seq_num);
    let mut both = Vec::with_capacity(8 + data.len());
    both.extend_from_slice(confounder);
    both.extend_from_slice(data);
    cfb8(&key, &iv, &mut both, encrypt);
    confounder.copy_from_slice(&both[..8]);
    data.copy_from_slice(&both[8..]);
}

/// The signature blob and the sealed body, in the order MS-NRPC 3.1.4.4.1 does them.
///
/// The confounder is a nonce with no rule behind it, so this stand uses a fixed one: it changes
/// nothing a verifier checks, and a deterministic PDU makes a failing signature reproducible.
fn seal(session_key: &[u8; 32], counter: u64, data: &mut [u8]) -> [u8; 56] {
    let mut header = [0_u8; 8];
    header[0..2].copy_from_slice(&19u16.to_le_bytes()); // NL_SIGN_HMAC_SHA256
    header[2..4].copy_from_slice(&26u16.to_le_bytes()); // NL_SEAL_AES128
    header[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());

    let mut confounder = [0xA5_u8; 8];
    let seq_plain = sequence_blob(counter, true);
    let sum = checksum(session_key, &[&header, &confounder, data]);
    // The order is not interchangeable: the body is sealed under the *plaintext* sequence blob, and
    // the blob itself travels encrypted under the checksum.
    transform_body(true, session_key, &seq_plain, &mut confounder, data);
    let seq_wire = crypt_sequence(session_key, &sum, &seq_plain);

    let mut sig = [0_u8; 56];
    sig[0..8].copy_from_slice(&header);
    sig[8..16].copy_from_slice(&seq_wire);
    sig[16..24].copy_from_slice(&sum);
    sig[24..32].copy_from_slice(&confounder);
    sig
}

/// Opens an answer sealed by the server, whose counter is the responder's.
fn unseal(session_key: &[u8; 32], counter: u64, sig: &[u8], data: &mut [u8]) -> Result<(), String> {
    if sig.len() < 32 {
        return Err(format!("a signature of {} octets", sig.len()));
    }
    let mut header = [0_u8; 8];
    header.copy_from_slice(&sig[0..8]);
    let sum: [u8; 8] = sig[16..24].try_into().expect("eight octets");
    let seq_wire: [u8; 8] = sig[8..16].try_into().expect("eight octets");
    let seq_plain = sequence_blob(counter, false);
    if crypt_sequence(session_key, &sum, &seq_plain) != seq_wire {
        return Err("the sequence number is not this one".to_string());
    }
    let mut confounder: [u8; 8] = sig[24..32].try_into().expect("eight octets");
    transform_body(false, session_key, &seq_plain, &mut confounder, data);
    let expected = checksum(session_key, &[&header, &confounder, data]);
    if expected != sum {
        return Err("the checksum does not match".to_string());
    }
    Ok(())
}

// --- the stand --------------------------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("a local address")
        .port()
}

/// A listener that answers `netlogon`, with `secrets` deciding whether it serves machine accounts.
async fn started_with(secrets: Option<Secrets>) -> TcpStream {
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port())
        .parse()
        .expect("an address");
    // The server is built for its state, not for its listener: `state()` is what the endpoint answers
    // secure channels on, and the `netlogon` endpoint below takes its own port.
    let mut builder = SmbServer::builder()
        .netbios_name("SAMBA")
        .dns_domain("ad.example.com")
        .domain_netbios("AD")
        .listen(addr);
    if let Some(secrets) = secrets {
        builder = builder.machine_secrets(Arc::new(secrets));
    }
    let server = builder.build().expect("build");
    let state = server.state();
    let endpoint = Endpoint {
        addr,
        nb_domain: "AD".to_string(),
        dns_domain: "ad.example.com".to_string(),
        nb_computer: "SAMBA".to_string(),
        dns_computer: "samba.ad.example.com".to_string(),
        keytab: None,
        logon_users: None,
        publish: None,
        channel_state: Some(ChannelState(state)),
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

async fn started() -> TcpStream {
    started_with(Some(secrets())).await
}

/// One whole PDU, or a panic: a test that waits forever reports nothing at all, and a server that
/// answered no octet looks the same as one that answered half.
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

/// A PDU with a verifier that carries `pad` octets of authentication padding.
fn with_verifier(mut pdu: Vec<u8>, auth_type: u8, level: u8, pad: u8, token: &[u8]) -> Vec<u8> {
    pdu.extend_from_slice(&[auth_type, level, pad, 0]);
    pdu.extend_from_slice(&0u32.to_le_bytes());
    pdu.extend_from_slice(token);
    pdu[10..12].copy_from_slice(&(token.len() as u16).to_le_bytes());
    let len = pdu.len() as u16;
    pdu[8..10].copy_from_slice(&len.to_le_bytes());
    pdu
}

/// `NL_AUTH_MESSAGE` naming the computer the channel belongs to (MS-NRPC 2.2.1.3.1).
fn negotiate_message() -> Vec<u8> {
    // The two name bits the buffer below answers: NetBIOS domain (0x01) then NetBIOS computer
    // (0x02). The buffer has no lengths and no separators, so a flag word that omits the domain bit
    // makes the first name read as the computer — and the channel is then looked up under `AD`
    // instead of the machine's own name, which is found by nobody.
    const NETBIOS_DOMAIN: u32 = 0x01;
    const NETBIOS_COMPUTER: u32 = 0x02;
    let flags = NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC | NETBIOS_DOMAIN | NETBIOS_COMPUTER;
    let mut out = Vec::new();
    out.extend_from_slice(&NL_NEGOTIATE_REQUEST.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(b"AD\0");
    // The channel is remembered under the name the authenticate named, which is the account's
    // without its trailing `$`.
    out.extend_from_slice(MACHINE_ACCOUNT.trim_end_matches('$').as_bytes());
    out.push(0);
    out
}

/// A stub written the way NDR marshals one: every four-octet field aligned, strings conformant.
///
/// Alignment is not a detail. A reader takes an eight-octet credential from `at.next_multiple_of(4)`,
/// so a stub that packed the fields without padding hands the server a challenge two octets off and
/// the credential it computes matches nothing — which arrives as `STATUS_ACCESS_DENIED` for a
/// password that is right. The same applies after a string of an odd number of units.
#[derive(Default)]
struct Stub(Vec<u8>);

impl Stub {
    fn align(&mut self, alignment: usize) {
        let at = self.0.len().next_multiple_of(alignment);
        self.0.resize(at, 0);
    }

    fn u16(&mut self, value: u16) -> &mut Self {
        self.align(2);
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn u32(&mut self, value: u32) -> &mut Self {
        self.align(4);
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn bytes(&mut self, data: &[u8]) -> &mut Self {
        self.align(4);
        self.0.extend_from_slice(data);
        self
    }

    /// A conformant varying string: the maximum, the offset, the actual count, then UTF-16LE.
    fn string(&mut self, text: &str) -> &mut Self {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        let count = units.len() as u32;
        self.u32(count).u32(0).u32(count);
        self.align(2);
        for unit in units {
            self.0.extend_from_slice(&unit.to_le_bytes());
        }
        self
    }

    fn finish(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// `netr_ServerReqChallenge`: the server's UNC, the computer's name, and the client's challenge.
fn challenge_stub(client: &[u8; 8]) -> Vec<u8> {
    let mut stub = Stub::default();
    stub.u32(1); // the referent of server_name
    stub.string("\\\\samba.ad.example.com");
    stub.string(MACHINE_ACCOUNT);
    stub.bytes(client);
    stub.finish()
}

/// `netr_ServerAuthenticate3`: the account, the channel type, the computer, the credential, flags.
fn authenticate3_stub(account: &str, credential: &[u8; 8], flags: u32) -> Vec<u8> {
    let mut stub = Stub::default();
    stub.u32(0); // server_name: a null pointer
    stub.string(account);
    stub.u16(2); // SEC_CHAN_WKSTA, a half word
    stub.string(account.trim_end_matches('$'));
    stub.bytes(credential);
    stub.u32(flags);
    stub.finish()
}

/// `DsrGetDcName`: every name is a null pointer, the GUID is absent, and the flags ask for a DC.
fn get_dc_name_stub() -> Vec<u8> {
    let mut stub = Stub::default();
    for _ in 0..4 {
        stub.u32(0); // a null `[in,unique]` string, then the absent GUID
    }
    stub.u32(1); // the flags
    stub.finish()
}

/// The bind with the negotiate in its verifier, which is what names the channel's computer.
async fn bind_with_negotiate(stream: &mut TcpStream) {
    let token = negotiate_message();
    let bind = with_verifier(
        bind_pdu(1, 4280, &[(0, NETLOGON, NDR)]),
        AUTH_NETLOGON,
        LEVEL_PRIVACY,
        0,
        &token,
    );
    stream.write_all(&bind).await.expect("the bind");
    let ack = read_pdu(stream).await;
    assert_eq!(ptype(&ack), PTYPE_BIND_ACK, "a bind_ack: {ack:02x?}");
    let (auth_type, _, _, answer) = auth_of(&ack).expect("the ack answers the negotiate");
    assert_eq!(auth_type, AUTH_NETLOGON);
    assert_eq!(
        answer,
        {
            let mut expected = 1u32.to_le_bytes().to_vec(); // NL_NEGOTIATE_RESPONSE
            expected.extend_from_slice(&[0u8; 8]);
            expected
        },
        "a response with no name flags and a NULL buffer"
    );
}

/// Asks for a challenge and returns the server's half, the channel key, and the AUTHENTICATE stub.
async fn prove_channel(
    stream: &mut TcpStream,
    client: [u8; 8],
    flags: u32,
) -> ([u8; 8], [u8; 32], Vec<u8>) {
    stream
        .write_all(&request_pdu(
            2,
            FIRST | LAST,
            0,
            OPNUM_SERVER_REQ_CHALLENGE,
            &challenge_stub(&client),
        ))
        .await
        .expect("the challenge");
    let answer = read_pdu(stream).await;
    assert_eq!(ptype(&answer), PTYPE_RESPONSE);
    let token = &answer[24..];
    let server: [u8; 8] = token[..8].try_into().expect("eight octets");
    let status = u32::from_le_bytes(token[8..12].try_into().expect("four octets"));
    assert_eq!(status, 0, "the challenge was served");

    let key = session_key_aes(&nt_hash(MACHINE_PASSWORD), &client, &server);
    let credential = credential_aes(&client, &key);
    (
        server,
        key,
        authenticate3_stub(MACHINE_ACCOUNT, &credential, flags),
    )
}

/// `netr_ServerAuthenticate3` answered: `(server_credential, flags, rid, status)`.
async fn authenticate(stream: &mut TcpStream, stub: &[u8]) -> ([u8; 8], u32, u32, u32) {
    stream
        .write_all(&request_pdu(
            3,
            FIRST | LAST,
            0,
            OPNUM_SERVER_AUTHENTICATE3,
            stub,
        ))
        .await
        .expect("the authenticate");
    let answer = read_pdu(stream).await;
    assert_eq!(ptype(&answer), PTYPE_RESPONSE, "a response, not a fault");
    let fields = &answer[24..];
    (
        fields[..8].try_into().expect("eight octets"),
        u32::from_le_bytes(fields[8..12].try_into().expect("four octets")),
        u32::from_le_bytes(fields[12..16].try_into().expect("four octets")),
        u32::from_le_bytes(fields[16..20].try_into().expect("four octets")),
    )
}

/// A member proves its channel and then calls on it sealed.
///
/// The four statements, each a place a server can look right and fail a real member. The challenge is
/// random and the credential the client sends is derived from it — a server that answered a constant
/// would pass a parser test and refuse every member. The answer's `server_credential` is the same
/// computation over the server's own half, and it is the only field a member uses to decide whether
/// the channel is mutual. `rid` is what the member writes into its own account record. And the call
/// that follows is sealed with a key nobody sent, so it verifies only if both sides derived the same
/// one.
#[tokio::test]
async fn a_member_proves_its_channel_and_calls_on_it_sealed() {
    let mut stream = started().await;
    bind_with_negotiate(&mut stream).await;

    let client = [0x11_u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let flags = NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC;
    let (server, key, stub) = prove_channel(&mut stream, client, flags).await;

    let (server_credential, answered_flags, rid, status) = authenticate(&mut stream, &stub).await;
    assert_eq!(status, 0, "the channel is proved");
    assert_eq!(rid, MACHINE_RID, "the member stores this as its own RID");
    assert_ne!(server_credential, [0_u8; 8], "a refusal sends eight zeros");
    assert_eq!(
        server_credential,
        credential_aes(&server, &key),
        "the answer is the same computation over the server's half"
    );
    assert_eq!(
        answered_flags & NEG_SUPPORTS_AES,
        NEG_SUPPORTS_AES,
        "the AES channel the client offered is the one that was proved"
    );

    // A sealed call on the proved channel: the arguments travel AES-CFB8'd under the channel key and
    // the verifier carries the signature over them.
    let mut stub = get_dc_name_stub();
    let pad = stub.len().next_multiple_of(4) - stub.len();
    stub.resize(stub.len() + pad, 0);
    let signature = seal(&key, 0, &mut stub);
    let call = with_verifier(
        request_pdu(4, FIRST | LAST, 0, OPNUM_DSR_GETDCNAME, &stub),
        AUTH_NETLOGON,
        LEVEL_PRIVACY,
        u8::try_from(pad).expect("a small pad"),
        &signature,
    );
    stream.write_all(&call).await.expect("the sealed call");

    let answer = read_pdu(&mut stream).await;
    assert_eq!(
        ptype(&answer),
        PTYPE_RESPONSE,
        "the sealed call was answered"
    );
    let (auth_type, level, _, token) = auth_of(&answer).expect("the answer is sealed too");
    assert_eq!(
        (auth_type, level),
        (AUTH_NETLOGON, LEVEL_PRIVACY),
        "a client reads a plaintext answer as a channel that stopped sealing"
    );
    let opened = answer[24..answer.len() - 8 - token.len()].to_vec();
    assert!(
        opened.len() >= 8,
        "the answer carries a body: {} octets",
        opened.len()
    );
    // Which counter the answer used is worth stating rather than assuming: each direction has its own
    // in MS-NRPC, and this server keeps one, so the answer to the call with counter 0 goes out with
    // the next value. The test opens with what the protocol says (0) and, failing that, with the
    // shared counter — and reports which it was, so a change in the server is visible here.
    let mut body = opened.clone();
    let counter = match unseal(&key, 0, &token, &mut body) {
        Ok(()) => 0,
        Err(first) => {
            body = opened;
            unseal(&key, 1, &token, &mut body).unwrap_or_else(|second| {
                panic!("the answer opens with neither counter: {first}; {second}")
            });
            1
        }
    };
    assert_eq!(
        counter, 1,
        "the answer's counter follows the call's, because this server keeps one for both directions"
    );
    assert!(
        body.len() > 8,
        "the opened answer is the DC's description, not eight octets: {}",
        body.len()
    );
}

/// A credential that does not match the machine's password is refused, and refused as access denied.
///
/// The status is not a detail: a member distinguishes "your password is wrong" from "this server does
/// not know you" by it, and answering `NO_SUCH_USER` for a wrong credential sends a client looking
/// for an account that exists.
#[tokio::test]
async fn a_credential_that_does_not_match_is_refused() {
    let mut stream = started().await;
    bind_with_negotiate(&mut stream).await;

    let client = [0x01_u8; 8];
    let flags = NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC;
    let (_server, _key, _stub) = prove_channel(&mut stream, client, flags).await;
    // The right shape, the wrong password behind it.
    let wrong_key = session_key_aes(&nt_hash("another password"), &client, &[0_u8; 8]);
    let bogus = credential_aes(&client, &wrong_key);
    let (server_credential, _, rid, status) = authenticate(
        &mut stream,
        &authenticate3_stub(MACHINE_ACCOUNT, &bogus, flags),
    )
    .await;
    assert_eq!(status, 0xC000_0022, "STATUS_ACCESS_DENIED");
    assert_eq!(server_credential, [0_u8; 8], "nothing was agreed");
    assert_eq!(rid, 0, "and no RID is handed out");
}

/// An account this server does not serve is refused by name.
#[tokio::test]
async fn an_unknown_account_is_refused_by_name() {
    let mut stream = started().await;
    bind_with_negotiate(&mut stream).await;

    let client = [0x02_u8; 8];
    let flags = NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC;
    let (_server, _key, _stub) = prove_channel(&mut stream, client, flags).await;
    // The credential of a member whose password is right but whose account this server does not
    // serve: the account name is the only field that differs, which is what makes the status a
    // statement about the account rather than about the arithmetic.
    let (_, _, _, status) = authenticate(
        &mut stream,
        &authenticate3_stub("GHOST$", &[0_u8; 8], flags),
    )
    .await;
    assert_eq!(status, 0xC000_0064, "STATUS_NO_SUCH_USER");
}

/// An authenticate before any challenge is refused as an invalid parameter, not as a bad password.
#[tokio::test]
async fn an_authenticate_before_a_challenge_is_refused() {
    let mut stream = started().await;
    bind_with_negotiate(&mut stream).await;

    let flags = NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC;
    let (_, _, _, status) = authenticate(
        &mut stream,
        &authenticate3_stub(MACHINE_ACCOUNT, &[0x33_u8; 8], flags),
    )
    .await;
    assert_eq!(
        status, 0xC000_000D,
        "STATUS_INVALID_PARAMETER: there is no challenge to answer"
    );
}

/// A listener with no machine accounts says so, rather than denying a password it never checked.
#[tokio::test]
async fn a_listener_without_machine_accounts_says_so() {
    let mut stream = started_with(None).await;
    bind_with_negotiate(&mut stream).await;

    let client = [0x04_u8; 8];
    let flags = NEG_SUPPORTS_AES | NEG_AUTHENTICATED_RPC;
    let (_server, _key, stub) = prove_channel(&mut stream, client, flags).await;
    let (_, _, _, status) = authenticate(&mut stream, &stub).await;
    assert_eq!(
        status, 0xC000_00BB,
        "STATUS_NOT_SUPPORTED: this endpoint has no directory to check against"
    );
}

/// A sealed call before the channel is proved is not answered at all.
///
/// The alternative — answering in the clear — is what a client reads as a downgrade, and the
/// alternative of answering a fault would tell an attacker which of the two things was missing.
#[tokio::test]
async fn a_sealed_call_before_the_channel_is_proved_is_not_answered() {
    let mut stream = started().await;
    bind_with_negotiate(&mut stream).await;

    let mut stub = get_dc_name_stub();
    stub.resize(stub.len().next_multiple_of(4), 0);
    let key = [0x5A_u8; 32];
    let signature = seal(&key, 0, &mut stub);
    let call = with_verifier(
        request_pdu(9, FIRST | LAST, 0, OPNUM_DSR_GETDCNAME, &stub),
        AUTH_NETLOGON,
        LEVEL_PRIVACY,
        0,
        &signature,
    );
    stream.write_all(&call).await.expect("the sealed call");

    let answer = tokio::time::timeout(Duration::from_millis(300), read_pdu(&mut stream)).await;
    assert!(
        answer.is_err(),
        "nothing came back: {:02x?}",
        answer.ok().map(|pdu| pdu.len())
    );
    assert_eq!(
        call_id(&call),
        9,
        "the call was sent and simply not answered"
    );
}
