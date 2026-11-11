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
        OPNUM_SERVER_AUTHENTICATE3 | OPNUM_LOGON_GET_DOMAIN_INFO => {
            // Said out loud because the client's own report names the step and not the cause: it
            // says the domain could not be contacted, which is what a failed secure channel looks
            // like from the outside.
            tracing::warn!(
                opnum,
                netbios = %server.config.netbios_name,
                "netlogon: a secure channel needs the machine account's NT hash, \
                 which this crate has no directory to read"
            );
            Ok(not_supported())
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
    let server_name_present = reader.pointer().unwrap_or(false);
    // The computer name is a conformant string and is not used here: the challenge belongs to the
    // pipe, and a name that disagreed with the account would be caught by the authenticate call.
    let _computer = reader.string();
    if server_name_present && reader.string().is_none() {
        return Err(malformed());
    }
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

    // A `[ref]` return has no referent id: the caller receives the eight octets and nothing else.
    let mut writer = NdrWriter::new();
    writer.u32(NTSTATUS_SUCCESS_STATUS);
    writer.raw(&server);
    Ok(writer.finish())
}

/// `NTSTATUS` success, which every reply in this interface begins with.
const NTSTATUS_SUCCESS_STATUS: u32 = 0x0000_0000;

/// A refusal with nothing after it, for the two calls this server does not make.
fn not_supported() -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.u32(NTSTATUS_NOT_SUPPORTED);
    writer.finish()
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
        stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        string(&mut stub, "SAMBA");
        string(&mut stub, "samba.ad.example.com");
        stub.extend_from_slice(client);
        stub
    }

    #[test]
    fn a_challenge_is_answered_and_remembered() {
        let client = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut session = Session::default();
        let reply = request_challenge(&mut session, &request(&client)).expect("answered");

        assert_eq!(
            u32::from_le_bytes(reply[..4].try_into().expect("status")),
            0,
            "the call succeeds"
        );
        assert_eq!(reply.len(), 12, "status and the eight octets, nothing else");
        assert_ne!(
            &reply[4..12],
            &[0u8; 8],
            "the server's own challenge is random"
        );

        let stored = session
            .challenge()
            .expect("the pair is kept for the next call");
        assert_eq!(stored.client, client, "the client's half is what it sent");
        assert_eq!(
            stored.server,
            <[u8; 8]>::try_from(&reply[4..12]).expect("eight octets"),
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
        let full = request(&[0; 8]);
        let fault = request_challenge(&mut session, &full[..full.len() - 4])
            .expect_err("four octets are not eight");
        assert_eq!(fault.status, crate::rpc::pdu::NCA_PROTO_ERROR);
        assert!(session.challenge().is_none(), "nothing half-stored");
    }

    #[test]
    fn the_calls_this_server_does_not_make_are_refused_by_name() {
        let reply = not_supported();
        assert_eq!(
            u32::from_le_bytes(reply[..4].try_into().expect("status")),
            NTSTATUS_NOT_SUPPORTED
        );
        assert_eq!(reply.len(), 4, "a refusal carries no structure");
    }
}
