//! netlogon: the secure channel a member establishes after its account exists.
//!
//! `net ads join` does not stop at creating the machine account. Once the account is there it opens
//! this pipe (`12345678-1234-abcd-ef00-0123456789ab` v1.0) **unauthenticated** - before any session
//! of its own - asks for a challenge, proves it holds the machine password, and then reads the
//! domain's own description of itself. Measured on the join stand: without this pipe the client
//! stops after the account was created and reports
//!
//! ```text
//! rpccli_setup_netlogon_creds_locked: failed to open noauth netlogon connection
//!     - NT_STATUS_OBJECT_NAME_NOT_FOUND
//! connect_to_domain_password_server: unable to open the domain client session
//! Failed to join domain: failed to verify domain membership after joining
//! ```
//!
//! which names a name and not the pipe that was missing.
//!
//! # The challenge, and the state it needs
//!
//! `netr_ServerReqChallenge` sends eight random octets; the server answers with eight of its own and
//! **remembers both**. Every later call on the same pipe is authenticated with a key derived from
//! the pair and the machine account's NT hash (`libcli/auth/credentials.c`,
//! `netlogon_creds_init_128bit`):
//!
//! ```text
//! session_key = HMAC_MD5(nt_hash, MD5(Z(4) || client_challenge || server_challenge))
//! ```
//!
//! so the state belongs to the pipe and not to the process: two pipes are two challenges, and a
//! challenge answered on one may not authenticate a call on another.
//!
//! # Where the line is drawn here
//!
//! `ReqChallenge` is answered, because it states nothing but a random number this server made.
//! `ServerAuthenticate3` is not: it compares a credential computed from the machine account's NT
//! hash, and this crate holds no directory to read one from - the daemon that owns the account
//! (`rust-rest-ldap`) does. Answering `success` without checking would tell a client its password
//! was right when nothing was compared, and the next call would fail on a channel that never
//! existed. The refusal names the missing piece in the log, once per call, so the next measurement
//! reads as a fact rather than as a mystery.

use crate::rpc::association::Fault;
use crate::rpc::ndr::{NdrReader, NdrWriter};
use crate::rpc::pdu::NCA_OP_RNG_ERROR;
use crate::server::{Caller, ServerState};

/// MS-ERREF: the call is understood and this server does not do it.
const NTSTATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// MS-ERREF: success.
const NTSTATUS_SUCCESS: u32 = 0x0000_0000;
/// MS-ERREF: the machine's credential did not match its password.
const NTSTATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// MS-ERREF: no account by that name, which is a machine this server does not serve.
const NTSTATUS_NO_SUCH_USER: u32 = 0xC000_0064;
/// MS-ERREF: a call made in an order the protocol does not allow.
const NTSTATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// `netr_ServerReqChallenge` (opnum 4): the first call of every secure channel.
pub(crate) const OPNUM_SERVER_REQ_CHALLENGE: u16 = 4;
/// `netr_ServerAuthenticate3` (opnum 26): where the machine password is proved.
pub(crate) const OPNUM_SERVER_AUTHENTICATE3: u16 = 26;
/// `netr_LogonGetDomainInfo` (opnum 29): the domain's description of itself.
pub(crate) const OPNUM_LOGON_GET_DOMAIN_INFO: u16 = 29;

/// What one netlogon pipe remembers.
///
/// One entry, not a table: `ServerReqChallenge` stores the pair and `ServerAuthenticate3` consumes
/// it, in that order, on one pipe (MS-NRPC 3.1.4.1). A second challenge before an authenticate
/// replaces the first, which is what a client retrying does.
#[derive(Debug, Default)]
pub(crate) struct Session {
    challenge: Option<Challenge>,
}

/// The pair of eight-octet values a secure channel is built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub(crate) client: [u8; 8],
    pub(crate) server: [u8; 8],
}

impl Session {
    /// The pair the last `ServerReqChallenge` established, for the call that proves it.
    pub(crate) fn challenge(&self) -> Option<Challenge> {
        self.challenge
    }
}

/// Answers one call.
pub(crate) async fn serve(
    server: &ServerState,
    _caller: &Caller,
    session: &mut Session,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    match opnum {
        OPNUM_SERVER_REQ_CHALLENGE => request_challenge(session, stub),
        OPNUM_SERVER_AUTHENTICATE3 => authenticate3(server, session, stub),
        OPNUM_LOGON_GET_DOMAIN_INFO => {
            // Said out loud because the client's own report names the step and not the cause: it
            // says the domain could not be reached, which is what a failed call looks like from the
            // outside.
            tracing::warn!(
                opnum,
                "netlogon: netr_LogonGetDomainInfo is not implemented; a member's join reads the \
                 domain's description of itself here"
            );
            Ok(not_supported(opnum))
        }
        _ => Err(Fault {
            status: NCA_OP_RNG_ERROR,
            did_not_execute: true,
        }),
    }
}

/// `netr_ServerReqChallenge`: remember the client's half, answer with this server's.
///
/// The request is `server_name` (a unique pointer, so a referent id and then a deferred string),
/// `computer_name` (an inline conformant string), and `credentials` (`[in,ref]`, so its eight octets
/// travel in the deferred section without a referent id of their own). Reading the fields in that
/// order is what puts the reader on the eight octets; a version that read them inline would take the
/// first four of the challenge for a pointer.
fn request_challenge(session: &mut Session, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    // `server_name` is a unique pointer, so its string is **deferred**: it travels after everything
    // that sits inline, and reading it here would consume the computer name and then the challenge
    // itself. Only the pointer's presence is inline, and it says nothing this call needs.
    let server_name_present = reader.pointer().unwrap_or(false);
    // `server_name` travels **inline**, in front of everything else: measured from a live client's
    // stub, where the first conformant string after the pointer is the UNC `\\samba.ad.…`. A parser
    // that expected the string in the deferred section read the computer name as the server name
    // and then took the challenge for a length.
    if server_name_present && reader.string().is_none() {
        return Err(malformed_hex("server_name", stub));
    }
    // `computer_name` is inline too, and this call does not need it - a name that disagreed with the
    // account is caught by the authenticate call.
    let _computer = reader.string();
    let Some(client) = reader.bytes(8) else {
        return Err(malformed());
    };

    let mut server = [0u8; 8];
    crate::utils::fill_random(&mut server).map_err(|_| Fault {
        status: crate::rpc::pdu::NCA_SERVER_TOO_BUSY,
        did_not_execute: true,
    })?;

    session.challenge = Some(Challenge {
        client: client.try_into().unwrap_or_default(),
        server,
    });

    // Out parameters first, the return value last: that is the order NDR marshals a stub in
    // (MS-RPCE 2.2.6), and a reply that puts `NTSTATUS` first is read as a challenge of four bytes
    // and a status taken from the middle of the server's own random value. Measured: the client
    // answered `NT code 0x16128db8` - not a status anybody defined, which is what a status read
    // from the wrong offset looks like.
    let mut writer = NdrWriter::new();
    writer.raw(&server);
    writer.u32(NTSTATUS_SUCCESS_STATUS);
    Ok(writer.finish())
}

/// `NTSTATUS` success, which every reply in this interface begins with.
const NTSTATUS_SUCCESS_STATUS: u32 = 0x0000_0000;

/// A refusal for the two calls this server does not make.
///
/// The out parameters are still written, zeroed, because a client decodes the stub by the shape of
/// the call it made and not by the status it finds: `ServerAuthenticate3` answers with a server
/// credential, the negotiated flags and a RID before the status, and a reply that omitted them
/// would be read as a shorter structure with a status made of their first octets.
fn not_supported(opnum: u16) -> Vec<u8> {
    let mut writer = NdrWriter::new();
    match opnum {
        OPNUM_SERVER_AUTHENTICATE3 => {
            writer.raw(&[0u8; 8]);
            writer.u32(0); // negotiate_flags, which no channel agreed on
            writer.u32(0); // rid
        }
        _ => {
            // `netr_LogonGetDomainInfo` answers with an authenticator and a `netr_DomainInfo`
            // union; zeros are the only honest content for a call that did nothing.
            writer.raw(&[0u8; 8]);
            writer.u32(0);
            writer.u32(0);
        }
    }
    writer.u32(NTSTATUS_NOT_SUPPORTED);
    writer.finish()
}

/// `netr_ServerAuthenticate3`: prove the machine holds the password its account was made with.
///
/// MS-NRPC 3.1.4.1.1 and 3.1.4.4.1, cross-read against `libcli/auth/credentials.c`
/// (`netlogon_creds_init_128bit`, `netlogon_creds_first_step`) and impacket's `ComputeSessionKeyStrongKey`
/// and `ComputeNetlogonCredential`:
///
/// ```text
/// session_key      = HMAC_MD5(nt_hash, MD5(Z(4) || client_challenge || server_challenge))
/// client_credential = DES(session_key[7..14], DES(session_key[0..7], client_challenge))
/// server_credential = the same over server_challenge
/// ```
///
/// The client sends the credential it derived from its half; this server derives the same value and
/// answers with the other half, so each side proves it knows the session key without either sending
/// it. A mismatch is `STATUS_ACCESS_DENIED` - the only answer that says the password was wrong
/// without saying what it was.
fn authenticate3(
    server: &ServerState,
    session: &mut Session,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    // Deferred, as in `ServerReqChallenge`: the pointer is inline, the string is not.
    let _server_name = reader.pointer();
    let Some(account_units) = reader.string() else {
        return Err(malformed_at("account_name"));
    };
    // `secure_channel_type` is a **half** word: the enum carries no `v1_enum`, and reading it as a
    // full one puts every field after it two octets out. Measured: the client sends `0200`, the
    // machine-account channel type.
    let _secure_channel_type = reader
        .u16()
        .ok_or_else(|| malformed_at("secure_channel_type"))?;
    let Some(computer_units) = reader.string() else {
        return Err(malformed_hex("computer_name", stub));
    };
    let Some(client_credential) = reader.bytes(8) else {
        return Err(malformed_at("client_credential"));
    };
    let client_credential: [u8; 8] = client_credential
        .try_into()
        .map_err(|_| malformed_at("client_credential"))?;
    let client_flags = reader
        .u32()
        .ok_or_else(|| malformed_at("negotiate_flags"))?;

    let account = String::from_utf16_lossy(&account_units);
    let computer = String::from_utf16_lossy(&computer_units);

    // The challenge is the pipe's, not the process's: a channel built on one pipe may not be
    // authenticated on another.
    let Some(challenge) = session.challenge() else {
        tracing::warn!(
            account = %account,
            "netlogon: authenticate before any challenge was requested"
        );
        return Ok(refusal(
            server_flags(client_flags),
            0,
            NTSTATUS_INVALID_PARAMETER,
        ));
    };

    let Some(secrets) = server.config.machine_secrets.as_ref() else {
        tracing::warn!(
            account = %account,
            "netlogon: this server has no machine accounts to check a secure channel against"
        );
        return Ok(refusal(
            server_flags(client_flags),
            0,
            NTSTATUS_NOT_SUPPORTED,
        ));
    };
    let Some(machine) = secrets.machine(&account) else {
        tracing::warn!(account = %account, "netlogon: no such machine account");
        return Ok(refusal(
            server_flags(client_flags),
            0,
            NTSTATUS_NO_SUCH_USER,
        ));
    };

    let key = session_key(&machine.nt_hash, &challenge.client, &challenge.server);
    let expected = credential(&challenge.client, &key);
    if !constant_time_eq(&expected, &client_credential) {
        tracing::warn!(
            account = %account,
            computer = %computer,
            "netlogon: the machine's credential does not match its password"
        );
        return Ok(refusal(
            server_flags(client_flags),
            0,
            NTSTATUS_ACCESS_DENIED,
        ));
    }

    let answer = credential(&challenge.server, &key);
    let flags = server_flags(client_flags);
    tracing::info!(
        account = %account,
        computer = %computer,
        rid = machine.rid,
        negotiate_flags = format!("{flags:#010x}"),
        "netlogon: secure channel established"
    );
    Ok(reply(&answer, flags, machine.rid, NTSTATUS_SUCCESS))
}

/// The flags this server agrees to, from what the client offered.
///
/// An intersection and not an echo: a flag this server does not implement yet, claimed here, is a
/// client that takes a path nobody wrote. AES is the one that matters - claiming it makes the
/// credential AES-CFB8 instead of DES, and nothing in this crate computes that.
fn server_flags(client: u32) -> u32 {
    /// `NETLOGON_NEG_STRONG_KEYS` (0x00004000): a 128-bit session key, which is what
    /// [`session_key`] produces.
    const STRONG_KEYS: u32 = 0x0000_4000;
    /// `NETLOGON_NEG_AUTHENTICATED_RPC` (0x40000000): the channel is checked, not anonymous.
    const AUTHENTICATED_RPC: u32 = 0x4000_0000;

    client & (STRONG_KEYS | AUTHENTICATED_RPC)
}

/// `HMAC_MD5(nt_hash, MD5(Z(4) || client_challenge || server_challenge))`.
fn session_key(nt_hash: &[u8; 16], client: &[u8; 8], server: &[u8; 8]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use md5::Md5;
    use sha2::Digest as _;

    let mut inner = Md5::new();
    inner.update([0u8; 4]);
    inner.update(client);
    inner.update(server);
    let digest = inner.finalize();

    let mut mac =
        <Hmac<Md5> as Mac>::new_from_slice(nt_hash).expect("HMAC takes a key of any length");
    mac.update(&digest);
    let out = mac.finalize().into_bytes();
    out.into()
}

/// `ComputeNetlogonCredential`: two DES passes over one block.
///
/// The order matters and the keys are seven bytes each: `session_key[0..7]` for the inner pass and
/// `session_key[7..14]` for the outer. Each seven-byte key becomes an eight-byte DES key by the bit
/// packing in MS-NRPC 3.1.4.4.1 - copying the seven bytes and padding would encrypt with a
/// different key, and the client would answer `STATUS_ACCESS_DENIED` for a password that was right.
fn credential(input: &[u8; 8], session_key: &[u8; 16]) -> [u8; 8] {
    use des::cipher::{BlockCipherEncrypt, KeyInit};

    let mut block = des::cipher::Block::<des::Des>::from(*input);
    for key in [&session_key[..7], &session_key[7..14]] {
        let cipher = des::Des::new_from_slice(&des_key(key)).expect("an eight-octet DES key");
        cipher.encrypt_block(&mut block);
    }
    block.into()
}

/// Seven octets as the eight-octet DES key they spell (MS-NRPC 3.1.4.4.1, `transformKey`).
///
/// The seven octets are packed one bit at a time into the top seven bits of each output octet; the
/// low bit of every DES key octet is parity and DES ignores it.
fn des_key(seven: &[u8]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = seven[0] >> 1;
    key[1] = ((seven[0] & 0x01) << 6) | (seven[1] >> 2);
    key[2] = ((seven[1] & 0x03) << 5) | (seven[2] >> 3);
    key[3] = ((seven[2] & 0x07) << 4) | (seven[3] >> 4);
    key[4] = ((seven[3] & 0x0F) << 3) | (seven[4] >> 5);
    key[5] = ((seven[4] & 0x1F) << 2) | (seven[5] >> 6);
    key[6] = ((seven[5] & 0x3F) << 1) | (seven[6] >> 7);
    key[7] = seven[6] & 0x7F;
    // Odd parity, as DES wants it: the low bit is set when the other seven hold an even number of
    // ones. Set and not toggled - a byte that already ends in a one keeps it, and flipping it there
    // yields a key one bit away from the one the client used.
    for byte in &mut key {
        if byte.count_ones() % 2 == 0 {
            *byte |= 1;
        }
    }
    key
}

/// Whether two eight-octet credentials are equal, in time that does not depend on where they differ.
fn constant_time_eq(left: &[u8; 8], right: &[u8; 8]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// A `ServerAuthenticate3` reply: the out parameters in order, then the status.
fn reply(server_credential: &[u8; 8], flags: u32, rid: u32, status: u32) -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.raw(server_credential);
    writer.u32(flags);
    writer.u32(rid);
    writer.u32(status);
    writer.finish()
}

/// The same shape, for a refusal: nothing was agreed, so the fields are zero and the status says why.
fn refusal(flags: u32, rid: u32, status: u32) -> Vec<u8> {
    reply(&[0u8; 8], flags, rid, status)
}

/// The stub is not the shape this call has, and the field that stopped it is named.
fn malformed_at(field: &str) -> Fault {
    tracing::warn!(field, "netlogon: the request stub ends before this field");
    malformed()
}

/// The same, with the octets that were read: a layout mistake is visible in a hex dump and
/// invisible in a message.
fn malformed_hex(field: &str, stub: &[u8]) -> Fault {
    let head = &stub[..stub.len().min(96)];
    tracing::warn!(
        field,
        len = stub.len(),
        hex = %head.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "netlogon: the request stub ends before this field"
    );
    malformed()
}

/// The stub is not the shape this call has.
fn malformed() -> Fault {
    Fault {
        status: crate::rpc::pdu::NCA_PROTO_ERROR,
        did_not_execute: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stub padded to four, the way NDR lays one out: the next referent starts on a boundary.
    fn pad(stub: &mut Vec<u8>) {
        while stub.len() % 4 != 0 {
            stub.push(0);
        }
    }

    /// A conformant string as NDR writes one: counts, then the units, then padding.
    fn string(stub: &mut Vec<u8>, text: &str) {
        let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
        stub.extend_from_slice(&(units.len() as u32).to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for unit in &units {
            stub.extend_from_slice(&unit.to_le_bytes());
        }
        pad(stub);
    }

    /// The request as Samba builds it: `server_name` a unique pointer with its string deferred,
    /// `computer_name` an inline conformant string, and the eight challenge octets deferred after
    /// the server name.
    fn request(client: &[u8; 8]) -> Vec<u8> {
        let mut stub = Vec::new();
        // The pointer, then the computer name, then the challenge: everything inline, in the order
        // the call declares it.
        stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        // `server_name` first, and inline: a live client's stub puts the UNC string directly after
        // the pointer, before the computer name.
        string(&mut stub, "\\samba.ad.example.com");
        string(&mut stub, "SAMBA");
        stub.extend_from_slice(client);
        stub
    }

    #[test]
    fn a_challenge_is_answered_and_remembered() {
        let client = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut session = Session::default();
        let reply = request_challenge(&mut session, &request(&client)).expect("answered");

        assert_eq!(
            reply.len(),
            12,
            "the eight octets and the status, nothing else"
        );
        assert_eq!(
            u32::from_le_bytes(reply[8..].try_into().expect("status")),
            0,
            "the status is last, after the out parameters"
        );
        assert_ne!(
            &reply[..8],
            &[0u8; 8],
            "the server's own challenge is random"
        );

        let stored = session
            .challenge()
            .expect("the pair is kept for the next call");
        assert_eq!(stored.client, client, "the client's half is what it sent");
        assert_eq!(
            stored.server,
            <[u8; 8]>::try_from(&reply[..8]).expect("eight octets"),
            "the half the client was told is the half this server will check against"
        );
    }

    #[test]
    fn each_challenge_replaces_the_last() {
        let mut session = Session::default();
        request_challenge(&mut session, &request(&[1; 8])).expect("first");
        let first = session.challenge().expect("stored");
        request_challenge(&mut session, &request(&[2; 8])).expect("second");
        let second = session.challenge().expect("stored");
        assert_ne!(
            first.client, second.client,
            "the newer call is the one in force"
        );
        assert_eq!(second.client, [2; 8]);
    }

    #[test]
    fn a_stub_that_stops_before_the_challenge_is_a_protocol_error() {
        let mut session = Session::default();
        // The pointer and the computer name, and then nothing: the challenge has not arrived, and a
        // server that filled it with zeros would answer a challenge nobody sent.
        let mut stub = Vec::new();
        stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        string(&mut stub, "SAMBA");
        stub.extend_from_slice(&[0u8; 4]);

        let fault = request_challenge(&mut session, &stub).expect_err("four octets are not eight");
        assert_eq!(fault.status, crate::rpc::pdu::NCA_PROTO_ERROR);
        assert!(session.challenge().is_none(), "nothing half-stored");
    }

    #[test]
    fn the_calls_this_server_does_not_make_are_refused_after_their_own_shape() {
        // `ServerAuthenticate3` answers with a credential, the flags and a RID before the status, so
        // a refusal that omitted them would be decoded as a shorter structure.
        let reply = not_supported(OPNUM_SERVER_AUTHENTICATE3);
        assert_eq!(reply.len(), 20, "eight octets, two words, then the status");
        assert_eq!(
            u32::from_le_bytes(reply[16..].try_into().expect("status")),
            NTSTATUS_NOT_SUPPORTED
        );
        assert_eq!(&reply[..16], &[0u8; 16], "nothing was agreed");
    }

    /// A known answer for the whole chain, produced outside this crate: the hash from Python's
    /// `hashlib` and the DES passes from `openssl enc -des-ecb -provider legacy`.
    ///
    /// The end-to-end proof is the join stand - a live Samba answers `ACCESS_DENIED` for a
    /// credential it did not expect - but a vector pins *which* bytes are wrong when it does.
    #[test]
    fn the_credential_chain_matches_an_independent_computation() {
        let nt_hash: [u8; 16] = std::array::from_fn(|i| i as u8);
        let client = [0x11u8; 8];
        let server = [0x22u8; 8];

        let key = session_key(&nt_hash, &client, &server);
        assert_eq!(
            key,
            [
                0x4b, 0x08, 0x25, 0xc0, 0xde, 0xb9, 0xd3, 0x02, 0x63, 0x4b, 0xbe, 0x34, 0xcf, 0x03,
                0xb7, 0xb1
            ],
            "HMAC_MD5(nt_hash, MD5(Z(4) || client || server))"
        );

        assert_eq!(
            des_key(&key[..7]),
            [0x25, 0x43, 0x04, 0x5d, 0x07, 0x7a, 0x73, 0x53],
            "seven octets packed into a DES key"
        );
        assert_eq!(
            des_key(&key[7..14]),
            [0x01, 0x19, 0x69, 0x3b, 0x71, 0x53, 0x1f, 0x03]
        );

        assert_eq!(
            credential(&client, &key),
            [0x6a, 0x9e, 0x03, 0x2e, 0x1f, 0x48, 0x4e, 0xbb],
            "the value a client sends, derived from its own half"
        );
        assert_eq!(
            credential(&server, &key),
            [0x1f, 0xd5, 0x9e, 0xa9, 0x84, 0xa5, 0x5e, 0xf7],
            "the value this server answers with, from its half"
        );
    }

    /// The two halves must not produce the same credential, or a server could answer with what the
    /// client sent and prove nothing.
    #[test]
    fn the_two_halves_give_different_credentials() {
        let nt_hash: [u8; 16] = std::array::from_fn(|i| i as u8);
        let key = session_key(&nt_hash, &[0x11; 8], &[0x22; 8]);
        assert_ne!(credential(&[0x11; 8], &key), credential(&[0x22; 8], &key));
    }

    /// A password that differs by one bit gives a key that differs throughout: the chain has no
    /// step where a wrong hash can still produce the right credential.
    #[test]
    fn one_bit_of_the_hash_changes_the_session_key() {
        let mut changed = [0u8; 16];
        changed[0] = 1;
        let a = session_key(&[0u8; 16], &[1; 8], &[2; 8]);
        let b = session_key(&changed, &[1; 8], &[2; 8]);
        assert_ne!(a, b);
        assert_ne!(a[..8], b[..8], "no half survives a change to the key");
    }

    #[test]
    fn only_the_flags_both_sides_support_are_agreed() {
        // AES is the one that matters: claiming it makes the client switch the credential to
        // AES-CFB8, which nothing here computes.
        const CLIENT: u32 = 0x0000_4000 | 0x4000_0000 | 0x0100_0000 | 0x0000_0004;
        assert_eq!(server_flags(CLIENT), 0x0000_4000 | 0x4000_0000);
        assert_eq!(
            server_flags(0),
            0,
            "a client that offered nothing is agreed to nothing"
        );
    }

    #[test]
    fn a_refusal_has_the_shape_of_the_call() {
        let reply = refusal(0x4000_4000, 0, NTSTATUS_ACCESS_DENIED);
        assert_eq!(reply.len(), 20);
        assert_eq!(reply[..8], [0u8; 8], "no server credential was derived");
        assert_eq!(
            u32::from_le_bytes(reply[16..].try_into().expect("status")),
            NTSTATUS_ACCESS_DENIED
        );
    }
}
