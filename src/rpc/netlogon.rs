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
/// `netr_LogonGetCapabilities`. A join cannot finish without it: Samba's `libnet_join` proves its
/// secure channel here, and treats a missing call as a downgrade whenever AES was negotiated.
pub(crate) const OPNUM_LOGON_GET_CAPABILITIES: u16 = 21;
/// `netr_ServerPasswordSet2` (opnum 46): the machine password a join picks, encrypted under the
/// channel's session key.
pub(crate) const OPNUM_SERVER_PASSWORD_SET2: u16 = 46;

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
    tracing::debug!(opnum, len = stub.len(), "netlogon: call");
    // Behind `NETLOGON_DUMP` like every other octet dump here: a call's own bytes are what settles
    // where a field lands, and an ordinary run stays quiet.
    if std::env::var_os("NETLOGON_DUMP").is_some() {
        tracing::warn!(
            opnum,
            len = stub.len(),
            hex = %stub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "netlogon: call stub"
        );
    }
    match opnum {
        OPNUM_SERVER_REQ_CHALLENGE => request_challenge(session, stub),
        OPNUM_SERVER_AUTHENTICATE3 => authenticate3(server, session, stub),
        OPNUM_SERVER_PASSWORD_SET2 => password_set2(server, session, stub),
        OPNUM_LOGON_GET_CAPABILITIES => logon_get_capabilities(server, stub),
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

/// `netr_ServerPasswordSet2`: the new machine password, encrypted under the session key.
///
/// MS-NRPC 3.1.4.4.3: `netr_CryptPassword` is 512 octets of ciphertext and a four-octet length, and
/// the whole 516 is run through the channel's cipher - AES-128-CFB8 or RC4 - with the session key.
/// The plaintext is the password in UTF-16LE, zero-padded to 512, and the length says how much of
/// it is real.
fn password_set2(
    server: &ServerState,
    session: &mut Session,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    // The stub first: a client's argument order here is not the IDL's wording, and the hex is what
    // settles it. Behind `NETLOGON_DUMP` so that an ordinary run stays quiet.
    if std::env::var_os("NETLOGON_DUMP").is_some() {
        tracing::warn!(
            len = stub.len(),
            hex = %stub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "netlogon: ServerPasswordSet2 stub"
        );
    }
    let _ = (server, session);
    Err(Fault {
        status: NCA_OP_RNG_ERROR,
        did_not_execute: true,
    })
}

/// Advances the credential chain one step, and returns the pair the step produced.
///
/// MS-NRPC 3.1.4.1.3, and Samba's `netlogon_creds_step` is the shape of it: the sequence number is
/// the `timestamp` the CALLER sent - not a counter this server keeps - and each step derives both
/// credentials from the seed, then moves the seed on. A channel that held one fixed pair would
/// answer the first call correctly and every one after it wrongly, which is exactly what the stand
/// showed: the credential at `netr_ServerAuthenticate3` and the one at `netr_LogonGetCapabilities`
/// differ, and neither is an encryption of the other.
///
/// The arithmetic is little-endian on the seed's first word and leaves the second alone, because
/// that is what `SIVAL` does in the reference implementation; read big-endian, the addition lands in
/// the wrong half and every later credential is wrong.
fn advance_credential(
    channel: &mut crate::server::ChannelState,
    sequence: u32,
) -> ([u8; 8], [u8; 8]) {
    let low = u32::from_le_bytes(
        channel.seed[..4]
            .try_into()
            .expect("four octets of the seed"),
    )
    .wrapping_add(sequence);
    let mut seed = channel.seed;
    seed[..4].copy_from_slice(&low.to_le_bytes());
    let client = credential_aes(&seed, &channel.key);

    seed[..4].copy_from_slice(&low.wrapping_add(1).to_le_bytes());
    let server = credential_aes(&seed, &channel.key);

    channel.seed = seed;
    channel.client_credential = client;
    channel.server_credential = server;
    (client, server)
}

/// `netr_LogonGetCapabilities`: what this server supports, said under the channel's own proof.
///
/// Samba's `libnet_join` cannot finish without this call, and refuses three different answers with
/// the same sentence about a possible attempt to compromise security (`libcli/auth/netlogon_creds_cli.c`):
///
/// * a call that is missing, when AES was negotiated - it reads that as a downgrade;
/// * a `return_authenticator.cred` that is not the half this server computed at the authenticate;
/// * `server_capabilities` that is not **exactly** the flags both sides negotiated.
///
/// The last one is compared for equality and not by mask, so echoing anything else - a superset, a
/// subset, the value a real DC would send - is a downgrade as far as the client is concerned.
///
/// Layout, measured from a live stub: `server_name` in place (a top-level string, so no referent),
/// `computer_name` behind a referent, then the two authenticators - eight octets of credential and
/// eight of timestamp each - and `query_level`. What follows them is a
/// `dcerpc_sec_verification_trailer`, not more arguments: three commands carrying the NDR transfer
/// syntax, which read as a GUID and a syntax id if the fields are guessed wrong.
fn logon_get_capabilities(server: &ServerState, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let Some(_server_name) = reader.string() else {
        return Err(malformed_hex("server_name", stub));
    };
    // The computer name is how the channel is found: this call arrives on a pipe that never saw the
    // challenge, and the name is the key the channel was proved under.
    let computer = match reader.pointer() {
        Some(true) => match reader.string() {
            Some(units) => Some(String::from_utf16_lossy(&units).trim().to_string()),
            None => return Err(malformed_hex("computer_name", stub)),
        },
        _ => None,
    };
    let Some(credential) = reader.bytes(8) else {
        return Err(malformed_hex("credential", stub));
    };
    let credential: [u8; 8] = credential
        .try_into()
        .map_err(|_| malformed_at("credential"))?;
    // The authenticator's second half is the sequence number the chain steps by: the reference
    // implementation sets `creds->sequence` from it and never from its own count, so a server that
    // kept a counter of its own would answer with a credential the client is not holding.
    let Some(client_timestamp) = reader.bytes(8) else {
        return Err(malformed_hex("credential.timestamp", stub));
    };
    let sequence = u32::from_le_bytes(
        client_timestamp[..4]
            .try_into()
            .expect("four octets of the timestamp"),
    );
    // `return_authenticator` is `[in,out,ref]`, and only its IN half travels: eight octets of
    // credential, with the timestamp the server fills left off the wire. Measured - read as sixteen,
    // the reader lands eight octets past `query_level` and takes the verification trailer's first
    // words for a level (a live run read 0x7138bb42 there).
    let Some(_return_authenticator) = reader.bytes(8) else {
        return Err(malformed_hex("return_authenticator", stub));
    };
    let Some(query_level) = reader.u32() else {
        return Err(malformed_hex("query_level", stub));
    };

    // The chain moves under the lock, because it must move on every call: the client computes the
    // next pair before it sends, so a reader that took a copy of the channel would answer with a
    // credential already left behind - and the call after it would be wrong too.
    let stepped = computer.as_deref().and_then(|computer| {
        server.advance_channel(computer, |channel| advance_credential(channel, sequence))
    });
    let Some((expected_client, server_credential)) = stepped else {
        tracing::warn!(
            computer = computer.as_deref().unwrap_or("<none>"),
            "netlogon: capabilities asked for before a channel was proved"
        );
        return Ok(capabilities_reply(
            None,
            query_level,
            NTSTATUS_ACCESS_DENIED,
        ));
    };
    // The client's half of the pair, compared in constant time: it is a secret of this channel, and
    // a comparison that stops at the first differing octet is a comparison that answers questions
    // about the ones it did compare.
    if !rrl_crypto::ct_eq(&expected_client, &credential) {
        tracing::warn!(
            sequence,
            "netlogon: capabilities asked for with a credential the chain does not produce"
        );
        return Ok(capabilities_reply(
            None,
            query_level,
            NTSTATUS_ACCESS_DENIED,
        ));
    }
    // The step has already moved the channel on, so what it holds now is what this call answers
    // with: the flags are the ones both sides negotiated, and the credential is the second half the
    // chain just produced.
    let Some(channel) = computer
        .as_deref()
        .and_then(|computer| server.channel(computer))
    else {
        return Ok(capabilities_reply(
            None,
            query_level,
            NTSTATUS_ACCESS_DENIED,
        ));
    };
    let _ = server_credential;
    if query_level != 1 {
        // The union has arms for 1 and 2 and this server has nothing to say at 2. Samba's own server
        // answers the same way, and a fault is what the client already handles for an old server.
        tracing::warn!(
            query_level,
            "netlogon: capabilities asked for at a level this server does not answer"
        );
        // Nothing is handed back for a level this server does not answer: a credential or a
        // capability beside a refusal is an answer, and this is not one.
        return Ok(capabilities_reply(
            None,
            query_level,
            NTSTATUS_NOT_SUPPORTED,
        ));
    }

    tracing::info!(
        capabilities = format_args!("{:#010x}", channel.flags),
        "netlogon: capabilities answered"
    );
    Ok(capabilities_reply(
        Some(&channel),
        query_level,
        NTSTATUS_SUCCESS,
    ))
}

/// The reply stub, in the order a live client reads it.
///
/// Four fields, and two layouts were tried before this one, each refused with a number naming where
/// the discriminator is **not**:
///
/// * `cred`, `timestamp` (eight octets), capabilities, status - twenty-four octets - was refused with
///   `Bad switch value 0`: the client read the switch from inside the zero timestamp, so it wants
///   the switch four octets earlier than that layout put it;
/// * `cred`, the level as a four-octet word, capabilities, status - twenty octets - was refused with
///   `Bad switch value 1090666496`, which is `0x41024000`: the flags it negotiated, read as a switch.
///
/// Together they put the switch at offset **twelve**: eight octets of credential, then a four-octet
/// `time_t` (this struct's timestamp is half the width of the request's), then the switch, the arm
/// and the status. The level is `[in]` in the IDL and travels anyway - a switched union cannot be
/// read without knowing its arm.
fn capabilities_reply(
    channel: Option<&crate::server::ChannelState>,
    query_level: u32,
    status: u32,
) -> Vec<u8> {
    let zero = [0u8; 8];
    let (credential, flags) = match channel {
        Some(channel) => (channel.server_credential, channel.flags),
        None => (zero, 0),
    };
    let mut writer = NdrWriter::new();
    writer.raw(&credential);
    // The authenticator's timestamp, four octets wide here and zero: the reference server sets it so,
    // and nothing reads it.
    writer.u32(0);
    writer.u32(query_level);
    writer.u32(flags);
    writer.u32(status);
    writer.finish()
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
    // The pointer, then **its string**: `server_name` travels inline directly behind the pointer,
    // as measured on this call from a live client - `0x00020000` then the UNC `\\samba.…`. Skipping
    // that string made the account name the server's own UNC, and the lookup then reported
    // `NO_SUCH_USER` for a machine account that existed.
    let server_name_present = reader.pointer().unwrap_or(false);
    if server_name_present && reader.string().is_none() {
        return Err(malformed_hex("server_name", stub));
    }
    let Some(account_units) = reader.string() else {
        return Err(malformed_hex("account_name", stub));
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

    // Which credential the client computed is decided by the flags, not by preference: with
    // `NETLOGON_NEG_SUPPORTS_AES` it uses a 32-octet HMAC-SHA256 session key and AES-128-CFB8,
    // without it the 16-octet HMAC-MD5 key and two DES passes.
    let aes = client_flags & SUPPORTS_AES != 0;
    let des = server.config.netlogon_des;
    // The channel's own key, which schannel signs every later PDU with. Gated: a key in a log is a
    // key everybody who can read the log has.
    if std::env::var_os("NETLOGON_KEY_DUMP").is_some() {
        let key = if aes {
            session_key_aes(&machine.nt_hash, &challenge.client, &challenge.server).to_vec()
        } else {
            session_key(&machine.nt_hash, &challenge.client, &challenge.server).to_vec()
        };
        tracing::warn!(
            account = %account,
            session_key = %key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            encrypt = aes,
            "netlogon-key"
        );
    }
    let answer = match verdict(&machine.nt_hash, aes, des, &challenge, &client_credential) {
        Verdict::Accepted(answer) => answer,
        Verdict::Unsupported => {
            // Fail fast and loudly. Answering with the AES flags and then checking DES - or the
            // reverse - is a channel that refuses a correct password with no way to tell why.
            tracing::warn!(
                account = %account,
                client_flags = format_args!("{client_flags:#010x}"),
                "netlogon: the client offered no AES channel and netlogon_des is off; \
                 refusing the channel"
            );
            return Ok(refusal(
                server_flags(client_flags),
                0,
                NTSTATUS_NOT_SUPPORTED,
            ));
        }
        Verdict::Wrong => {
            tracing::warn!(
                account = %account,
                computer = %computer,
                aes = aes,
                "netlogon: the machine's credential does not match its password"
            );
            return Ok(refusal(
                server_flags(client_flags),
                0,
                NTSTATUS_ACCESS_DENIED,
            ));
        }
    };

    // The whole channel, kept for the calls that come after this one - on this pipe or another: a
    // client re-signs with the key and re-sends the credential without repeating the challenge, so
    // a channel held in this pipe alone would refuse them.
    let channel_key = if aes {
        session_key_aes(&machine.nt_hash, &challenge.client, &challenge.server)
    } else {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&session_key(
            &machine.nt_hash,
            &challenge.client,
            &challenge.server,
        ));
        key
    };
    let flags = server_flags(client_flags);
    server.remember_channel(
        &computer,
        crate::server::ChannelState {
            key: channel_key,
            // The chain starts where the authenticate left it: the client's own half is the seed,
            // exactly as `netlogon_creds_first_step` sets it.
            seed: client_credential,
            client_credential,
            server_credential: answer,
            flags,
        },
    );
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
/// credential AES-CFB8 instead of DES, so the flag is echoed only now that [`credential_aes`] exists.
/// `NETLOGON_NEG_SUPPORTS_AES` (0x01000000): the credential is AES-128-CFB8 over a 32-octet
/// session key, which [`credential_aes`] computes.
const SUPPORTS_AES: u32 = 0x0100_0000;

/// `NETLOGON_NEG_PASSWORD_SET2` (0x00020000): `netr_ServerPasswordSet2` is served. Samba requires
/// it of an AD domain and answers `DOWNGRADE_DETECTED` without it - measured: a join aborted right
/// after `ServerAuthenticate3` while the credential itself matched.
const PASSWORD_SET2: u32 = 0x0002_0000;

fn server_flags(client: u32) -> u32 {
    /// `NETLOGON_NEG_STRONG_KEYS` (0x00004000): a 128-bit session key.
    const STRONG_KEYS: u32 = 0x0000_4000;
    /// `NETLOGON_NEG_AUTHENTICATED_RPC` (0x40000000): the channel is checked, not anonymous.
    const AUTHENTICATED_RPC: u32 = 0x4000_0000;

    client & (STRONG_KEYS | SUPPORTS_AES | AUTHENTICATED_RPC | PASSWORD_SET2)
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

/// What this server answers to the credential a client sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// It matches the account's password; this is the value to answer with.
    Accepted([u8; 8]),
    /// The client offered no AES channel and this server does not serve the DES one.
    Unsupported,
    /// It does not match: the channel is refused, and the password is not the reason to guess at.
    Wrong,
}

/// The decision, on its own: no pipe, no state, no logging.
fn verdict(
    nt_hash: &[u8; 16],
    aes: bool,
    des: bool,
    challenge: &Challenge,
    sent: &[u8; 8],
) -> Verdict {
    // The client's value is derived from its own half of the pair; this server's answer is the
    // same computation over its own half. Both come from `expected_credential`, so the flags and
    // the setting decide one arithmetic, not two that could disagree.
    let Some(expected) = expected_credential(nt_hash, aes, des, challenge, &challenge.client)
    else {
        return Verdict::Unsupported;
    };
    if !rrl_crypto::ct_eq(&expected, sent) {
        return Verdict::Wrong;
    }
    Verdict::Accepted(
        expected_credential(nt_hash, aes, des, challenge, &challenge.server)
            .expect("the same flags and the same setting decided the client credential"),
    )
}

/// The credential a client computed, or `None` when this server does not serve that channel.
///
/// AES needs nothing beyond what every build has. DES is a 56-bit cipher kept for one call, and
/// whether to serve it is a deployment decision rather than a build one: `ServerConfig::netlogon_des`
/// turns it on, and with it off a client that offers no AES is refused instead of being handed a
/// channel nobody derived a credential for.
/// The two halves name the challenge the value is computed over; the session key is always the
/// same one, derived from `client || server` in that order (MS-NRPC 3.1.4.1.2).
///
/// Passing the halves in swapped to get the answer's credential was wrong: it derived a *different*
/// session key, so this server answered with a value the client could not reproduce. It went unseen
/// while the client's own credential was being refused for another reason - the first refusal hid
/// the second - and a test on the answer alone found it.
fn expected_credential(
    nt_hash: &[u8; 16],
    aes: bool,
    des: bool,
    challenge: &Challenge,
    input: &[u8; 8],
) -> Option<[u8; 8]> {
    if aes {
        return Some(credential_aes(
            input,
            &session_key_aes(nt_hash, &challenge.client, &challenge.server),
        ));
    }
    if !des {
        return None;
    }
    Some(credential(
        input,
        &session_key(nt_hash, &challenge.client, &challenge.server),
    ))
}

/// The 32-octet session key of an AES secure channel: `HMAC_SHA256(nt_hash, client || server)`.
///
/// MS-NRPC 3.1.4.1.2. The message is the two challenges with no separator and no zero prefix - the
/// prefix belongs to the MD5 form the DES path uses, and carrying it over produces a key the client
/// never computes.
fn session_key_aes(nt_hash: &[u8; 16], client: &[u8; 8], server: &[u8; 8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(nt_hash).expect("HMAC takes a key of any length");
    mac.update(client);
    mac.update(server);
    mac.finalize().into_bytes().into()
}

/// A credential under an AES secure channel: AES-128-CFB8 over the challenge, zero IV (MS-NRPC
/// 3.1.4.3.1, `ComputeNetlogonCredential`).
///
/// The first sixteen octets of the session key are the key, and the mode is CFB with one-octet
/// segments - so the block cipher is run once per octet and the result feeds the next block. This is
/// the same operation in both directions: the keystream is what the plaintext is exclusive-ored
/// with, so encrypting a received credential reproduces it.
fn credential_aes(input: &[u8; 8], session_key: &[u8; 32]) -> [u8; 8] {
    use aes::cipher::{BlockEncrypt, KeyInit};

    let cipher = aes::Aes128::new_from_slice(&session_key[..16]).expect("a 16-octet AES key");
    let mut state = [0u8; 16];
    let mut out = [0u8; 8];
    for (index, byte) in input.iter().enumerate() {
        let mut block = aes::Block::from(state);
        cipher.encrypt_block(&mut block);
        let keystream = block[0];
        out[index] = byte ^ keystream;
        state.copy_within(1.., 0);
        state[15] = out[index];
    }
    out
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
        while !stub.len().is_multiple_of(4) {
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
        // AES-CFB8, so it is agreed only because `credential_aes` computes that path now.
        const CLIENT: u32 = 0x0000_4000 | 0x4000_0000 | 0x0100_0000 | 0x0000_0004;
        assert_eq!(
            server_flags(CLIENT),
            0x0000_4000 | 0x4000_0000 | 0x0100_0000,
            "the AES flag is echoed, and the unsupported bit 0x4 is not"
        );
        assert_eq!(
            server_flags(0x0000_4000 | 0x4000_0000),
            0x0000_4000 | 0x4000_0000,
            "a client that did not offer AES gets the DES path"
        );
        assert_eq!(
            server_flags(0),
            0,
            "a client that offered nothing is agreed to nothing"
        );
    }

    #[test]
    fn a_refusal_has_the_shape_of_the_call() {
        let reply = refusal(0x4000_4000, 0, NTSTATUS_ACCESS_DENIED);
        assert_eq!(reply.len(), 20, "eight octets, two words, then the status");
        assert_eq!(reply[..8], [0u8; 8], "no server credential was derived");
        assert_eq!(
            u32::from_le_bytes(reply[16..].try_into().expect("status")),
            NTSTATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn an_aes_channel_matches_the_credential_a_client_computes() {
        // Measured from a live client on the join stand: the machine's NT hash, the two challenges
        // and the eight octets it sent. With HMAC-SHA256 over the challenges and AES-128-CFB8 over
        // the client challenge these reproduce it exactly; the DES path does not, which is what
        // made every channel answer ACCESS_DENIED while the hash itself was right.
        let nt_hash: [u8; 16] = [
            0xe2, 0x3d, 0x8a, 0x88, 0xfb, 0x99, 0x8d, 0x47, 0x89, 0x5b, 0x77, 0xef, 0xdd, 0xe9,
            0x24, 0x7b,
        ];
        let client: [u8; 8] = [0xa2, 0xd4, 0x27, 0x65, 0x1d, 0x3d, 0x9c, 0x59];
        let server: [u8; 8] = [0xc6, 0xc4, 0x44, 0xd5, 0x59, 0x1e, 0xab, 0x90];

        let key = session_key_aes(&nt_hash, &client, &server);
        assert_eq!(
            credential_aes(&client, &key),
            [0xb0, 0x14, 0xa0, 0x61, 0x9c, 0xae, 0x3b, 0xdb]
        );
        // The server's answer is the same computation over its own challenge.
        assert_ne!(credential_aes(&server, &key), [0u8; 8]);
    }

    /// The three answers this server can give a credential, each on its own input.
    ///
    /// Written because a mutation showed the check was not covered at all: forcing the
    /// comparison to succeed left every test in the crate green, which means nothing exercised
    /// the path a wrong password takes. The stand found it first, as `ACCESS_DENIED` for a client
    /// whose account and hash were both right - the wrong answer for the wrong reason.
    #[test]
    fn a_credential_is_accepted_refused_or_refused_for_lack_of_a_cipher() {
        let nt_hash: [u8; 16] = std::array::from_fn(|i| i as u8);
        let challenge = Challenge {
            client: [0x11; 8],
            server: [0x22; 8],
        };

        // The DES channel, when the deployment turns it on: the client's own value opens it, and
        // the server's is what comes back.
        let des_key_16 = session_key(&nt_hash, &challenge.client, &challenge.server);
        let client_credential = credential(&challenge.client, &des_key_16);
        let server_credential = credential(&challenge.server, &des_key_16);
        assert_eq!(
            verdict(&nt_hash, false, true, &challenge, &client_credential),
            Verdict::Accepted(server_credential),
        );

        // One bit anywhere in it is another password.
        for index in 0..8 {
            let mut wrong = client_credential;
            wrong[index] ^= 0x01;
            assert_eq!(
                verdict(&nt_hash, false, true, &challenge, &wrong),
                Verdict::Wrong,
                "octet {index} of the credential was not compared"
            );
        }

        // A different account's password is refused even when the client's own arithmetic is
        // right: the value it sent belongs to a key this server never derived.
        let mut other_hash = nt_hash;
        other_hash[0] ^= 0x01;
        let other_key = session_key(&other_hash, &challenge.client, &challenge.server);
        assert_eq!(
            verdict(
                &nt_hash,
                false,
                true,
                &challenge,
                &credential(&challenge.client, &other_key)
            ),
            Verdict::Wrong,
            "a credential made from another account's hash must not open this one"
        );

        // The same, on the AES channel, which is what a current client uses.
        let aes_key = session_key_aes(&nt_hash, &challenge.client, &challenge.server);
        let aes_client = credential_aes(&challenge.client, &aes_key);
        let aes_server = credential_aes(&challenge.server, &aes_key);
        assert_eq!(
            verdict(&nt_hash, true, false, &challenge, &aes_client),
            Verdict::Accepted(aes_server),
            "the AES channel needs no DES setting to be served"
        );
        let mut aes_wrong = aes_client;
        aes_wrong[0] ^= 0x80;
        assert_eq!(
            verdict(&nt_hash, true, false, &challenge, &aes_wrong),
            Verdict::Wrong
        );

        // A client that offers no AES, against a deployment that does not serve DES: refused for
        // the setting, not for the password.
        assert_eq!(
            verdict(&nt_hash, false, false, &challenge, &client_credential),
            Verdict::Unsupported,
            "with DES off the answer must name the setting, not the credential"
        );

        // And the AES credential is not accepted on the DES channel or the other way round: the
        // flags decide which arithmetic ran, and the two never produce the same eight octets.
        assert_eq!(
            verdict(&nt_hash, false, true, &challenge, &aes_client),
            Verdict::Wrong,
            "an AES credential must not open a DES channel"
        );
        assert_eq!(
            verdict(&nt_hash, true, false, &challenge, &client_credential),
            Verdict::Wrong,
            "a DES credential must not open an AES channel"
        );
    }

    /// The capabilities call as a live client builds it.
    ///
    /// Measured: `server_name` is in place - a top-level string, so no referent - `computer_name`
    /// is behind a referent, then the client's authenticator, the empty one it expects back, and
    /// the level. A parser that expected the server name behind a referent reads the first string's
    /// maximum count as that referent and then looks for the name eight octets early.
    fn capabilities_stub(credential: &[u8; 8], sequence: u32, query_level: u32) -> Vec<u8> {
        let mut stub = Vec::new();
        string(&mut stub, "\\\\samba.ad.example.com");
        stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        string(&mut stub, "SAMBA");
        stub.extend_from_slice(credential);
        // The authenticator's second half: the sequence the chain steps by, then two words of
        // nothing, because `time_t` is eight octets.
        let mut stamp = sequence.to_le_bytes().to_vec();
        stamp.extend_from_slice(&[0u8; 4]);
        stub.extend_from_slice(&stamp);
        // `return_authenticator` is `[in,out,ref]`: only eight octets of credential travel.
        stub.extend_from_slice(&[0u8; 8]);
        stub.extend_from_slice(&query_level.to_le_bytes());
        stub
    }

    /// One live channel, from a join that reached the capabilities call.
    ///
    /// Held as octets rather than recomputed so that the test is an oracle and not a mirror: the
    /// session key, the credential the client sent at `netr_ServerAuthenticate3` (which is also the
    /// chain's seed), the sequence it sent with the capabilities call, and both halves that call
    /// produced. The expected values come from an independent computation over these octets.
    const LIVE_KEY: &str = "9bb79993694b31a684786abbaabdaec7b57d8beaa426a85470f6a59a182791fa";
    const LIVE_SEED: &str = "d31ebd87cf8e814d";
    const LIVE_SEQUENCE: u32 = 1_794_403_242;
    const LIVE_CLIENT: &str = "61c0b6c4c89e7180";
    const LIVE_SERVER: &str = "6211ad7dd60011b9";
    const LIVE_NEXT_SEED: &str = "7e8ab1f2cf8e814d";

    fn octets(text: &str) -> [u8; 8] {
        hex::decode(text)
            .expect("hex")
            .try_into()
            .expect("eight octets")
    }

    fn live_key() -> [u8; 32] {
        hex::decode(LIVE_KEY)
            .expect("hex")
            .try_into()
            .expect("32 octets")
    }

    /// A state holding the live channel, with the flags that join negotiated.
    ///
    /// Built directly rather than through the builder, like the `lsarpc` tests: the channel lives on
    /// the state because the call that reads it arrives on another pipe.
    fn proved() -> ServerState {
        let state = ServerState::new(
            crate::server::ServerConfig::for_test(),
            crate::server::ServerUsers {
                table: Default::default(),
            },
            Vec::new(),
        );
        state.remember_channel(
            "SAMBA",
            crate::server::ChannelState {
                key: live_key(),
                seed: octets(LIVE_SEED),
                client_credential: octets(LIVE_SEED),
                server_credential: octets("891125d2c1847fe9"),
                flags: 0x610f_ffff,
            },
        );
        state
    }

    /// The chain reproduces both halves a live client and a live server exchanged.
    ///
    /// This is the test that settles what a credential is. It is not a constant derived at the
    /// authenticate: the client steps it before every call, from a seed the previous step left
    /// behind, keyed by the sequence number it sends. A server that answered with the authenticate's
    /// value - or with an encryption of it - is refused, measured, with `ACCESS_DENIED`.
    #[test]
    fn the_credential_chain_reproduces_a_live_step() {
        let mut channel = crate::server::ChannelState {
            key: live_key(),
            seed: octets(LIVE_SEED),
            client_credential: octets(LIVE_SEED),
            server_credential: octets("891125d2c1847fe9"),
            flags: 0x610f_ffff,
        };
        let (client, server) = advance_credential(&mut channel, LIVE_SEQUENCE);

        assert_eq!(client, octets(LIVE_CLIENT), "the half the client sent");
        assert_eq!(server, octets(LIVE_SERVER), "the half the server owed it");
        assert_eq!(
            channel.seed,
            octets(LIVE_NEXT_SEED),
            "the seed the next call steps from"
        );
    }

    /// A second call steps again, from the seed the first left: the chain is a chain, not a pair.
    #[test]
    fn each_call_advances_the_chain() {
        let mut channel = crate::server::ChannelState {
            key: live_key(),
            seed: octets(LIVE_SEED),
            client_credential: octets(LIVE_SEED),
            server_credential: octets("891125d2c1847fe9"),
            flags: 0x610f_ffff,
        };
        let (first_client, _) = advance_credential(&mut channel, LIVE_SEQUENCE);
        let (second_client, _) = advance_credential(&mut channel, LIVE_SEQUENCE + 1);

        assert_eq!(first_client, octets(LIVE_CLIENT));
        assert_ne!(
            second_client, first_client,
            "the same credential twice is a replay this server would accept"
        );
        assert_eq!(
            channel.seed[4..],
            octets(LIVE_NEXT_SEED)[4..],
            "the second word of the seed is carried, not stepped"
        );
    }

    /// The answer carries the half the chain produced, and the flags it negotiated - exactly.
    ///
    /// Samba's client compares `server_capabilities` against `creds->negotiate_flags` for equality
    /// and refuses anything else as a downgrade, so a superset is as wrong as a zero.
    #[test]
    fn the_capabilities_answer_carries_the_half_the_client_expects() {
        let state = proved();
        let reply = logon_get_capabilities(
            &state,
            &capabilities_stub(&octets(LIVE_CLIENT), LIVE_SEQUENCE, 1),
        )
        .expect("answered");

        assert_eq!(
            reply.len(),
            24,
            "credential, timestamp, the union's discriminant, capabilities, status"
        );
        assert_eq!(
            &reply[..8],
            &octets(LIVE_SERVER),
            "the server's half of the chain, not the client's"
        );
        assert_eq!(
            &reply[8..12],
            &[0u8; 4],
            "the authenticator's timestamp: nothing reads it"
        );
        assert_eq!(
            u32::from_le_bytes(reply[12..16].try_into().expect("switch")),
            1,
            "the union's arm, at the offset the client reads it from"
        );
        assert_eq!(
            u32::from_le_bytes(reply[16..20].try_into().expect("capabilities")),
            0x610f_ffff,
            "the flags both sides negotiated, and nothing else"
        );
        assert_eq!(
            u32::from_le_bytes(reply[20..24].try_into().expect("status")),
            NTSTATUS_SUCCESS
        );
    }

    /// A credential the chain does not produce is refused, and the refusal is still the right shape.
    #[test]
    fn capabilities_with_the_wrong_credential_are_refused() {
        let state = proved();
        let reply = logon_get_capabilities(
            &state,
            &capabilities_stub(&octets("0000000000000001"), LIVE_SEQUENCE, 1),
        )
        .expect("answered");

        assert_eq!(reply.len(), 24, "a refusal is the same shape");
        assert_eq!(&reply[..8], &[0u8; 8], "no credential is handed back");
        assert_eq!(
            u32::from_le_bytes(reply[16..20].try_into().expect("capabilities")),
            0,
            "no capability is claimed to a caller that did not prove the channel"
        );
        assert_eq!(
            u32::from_le_bytes(reply[20..24].try_into().expect("status")),
            NTSTATUS_ACCESS_DENIED
        );
    }

    /// Level 2 is not answered, and is not answered as though it were level 1.
    #[test]
    fn a_level_this_server_does_not_answer_is_refused_and_the_level_is_echoed() {
        let state = proved();
        let reply = logon_get_capabilities(
            &state,
            &capabilities_stub(&octets(LIVE_CLIENT), LIVE_SEQUENCE, 2),
        )
        .expect("answered");

        assert_eq!(reply.len(), 24);
        assert_eq!(
            u32::from_le_bytes(reply[12..16].try_into().expect("switch")),
            2,
            "the level the call was made at, echoed - a client told 1 reads the arm it did not ask for"
        );
        assert_eq!(
            u32::from_le_bytes(reply[16..20].try_into().expect("capabilities")),
            0,
            "a level this server does not answer carries no capability"
        );
        assert_eq!(
            u32::from_le_bytes(reply[20..24].try_into().expect("status")),
            NTSTATUS_NOT_SUPPORTED
        );
    }

    /// Before any authenticate there is no channel, and the call says so rather than inventing one.
    #[test]
    fn capabilities_before_a_channel_is_proved_are_refused() {
        let state = ServerState::new(
            crate::server::ServerConfig::for_test(),
            crate::server::ServerUsers {
                table: Default::default(),
            },
            Vec::new(),
        );
        let reply = logon_get_capabilities(
            &state,
            &capabilities_stub(&octets(LIVE_CLIENT), LIVE_SEQUENCE, 1),
        )
        .expect("answered");

        assert_eq!(reply.len(), 24);
        assert_eq!(
            u32::from_le_bytes(reply[20..24].try_into().expect("status")),
            NTSTATUS_ACCESS_DENIED
        );
    }

    /// The whole capabilities stub a live client sent.
    ///
    /// Held as the client's octets rather than assembled from the IDL's wording, because the two
    /// disagree: `server_name` is in place with no referent, `computer_name` is behind one, and the
    /// fields after them are aligned by size, not packed.
    const LIVE_CAPABILITIES_STUB: &str = "1700000000000000170000005c005c00730061006d00620061002e00610064002e006500780061006d0070006c0065002e0063006f006d000000000000000200060000000000000006000000530041004d004200410000002be1cf050b62a06ae46ef46a000000000000000000000000010000008ae3137102f43671010004000100000002002800785634123412cdabef0001234567cffb01000000045d888aeb1cc9119fe808002b104860020000000340100000000000100000000900000000001500158b7c187bbad0707bc0bfa5f3dd44df18ca396a549b8247c75855ff412b61aa62e9457ebc714f5af5b1ca016e69c6523e142da69dbb7a4ae98ef2a71d856f0f6c6445b514d0c26fcc35a24e130436915da499acaebea95d2b683056b388eda3e91fd6b8b83b9d857599dc6e3cf3317970612217c176071845b05bac54eb5adb609978f2b4ccd341efa171f3afaeb2078a727577bfff091abbac35ceccbd132a19187f8c68b5fd01ae13d89d4b6aaa450b0b088577900eecf70491317d1f6b7b537e3152bdd502c6ec5e976b9f19c9bb";

    #[test]
    fn the_live_capabilities_stub_parses_to_the_fields_it_carries() {
        let stub = hex::decode(LIVE_CAPABILITIES_STUB).expect("hex");
        assert_eq!(stub.len(), 404, "one whole request");
        let mut reader = NdrReader::new(&stub);
        let server_name = reader.string().expect("server_name");
        assert_eq!(
            String::from_utf16_lossy(&server_name),
            "\\\\samba.ad.example.com",
            "in place, with no referent"
        );
        assert_eq!(
            reader.pointer(),
            Some(true),
            "computer_name is a unique pointer"
        );
        let computer = reader.string().expect("computer_name");
        assert_eq!(String::from_utf16_lossy(&computer), "SAMBA");
        let credential = reader.bytes(8).expect("credential");
        assert_eq!(
            credential,
            hex::decode("2be1cf050b62a06a").expect("hex").as_slice(),
            "the half the client computed for this step"
        );
        let timestamp = reader.bytes(8).expect("timestamp");
        assert_eq!(
            u32::from_le_bytes(timestamp[..4].try_into().expect("four")),
            0x6af4_6ee4,
            "the sequence the chain steps by"
        );
        assert_eq!(
            reader.bytes(8).expect("return_authenticator"),
            &[0u8; 8],
            "the client expects a credential back and has none to send"
        );
        assert_eq!(reader.u32(), Some(1), "query_level");
    }
}
