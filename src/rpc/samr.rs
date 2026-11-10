//! samr: the interface a member's join creates its machine account through.
//!
//! `net ads join` does not add the computer entry over LDAP. After it has found the computers
//! container it opens this pipe (`12345778-1234-abcd-ef00-0123456789ac` v0.0) and creates the
//! account here: `samr_Connect2`, `samr_OpenDomain`, `samr_CreateUser2`, then a password and the
//! rest of the account's attributes. Measured on the join stand: without this pipe the client stops
//! at `Error connecting to SAM pipe ... NT_STATUS_OBJECT_NAME_NOT_FOUND` and the whole join reads
//! `The object name is not found` - a message about a name, for a pipe that was never opened.
//!
//! # What is implemented, and why the line is drawn here
//!
//! The calls that lead to the account - connecting, opening the domain, naming it - are answered,
//! because each one is a fact about this server's own identity that it can state honestly: its
//! domain SID (`ServerConfig::domain_sid`), its NetBIOS name, the handle a client may keep.
//!
//! `CreateUser2` is refused, with a status and a log line that name what is missing rather than
//! what was asked. Creating a machine account is a **write to the directory**, and this crate does
//! not read a directory: the daemon that owns one (`rust-rest-ldap`) would have to do it. Answering
//! `success` here and putting nothing anywhere would give the client a RID it could not use, and
//! the failure would surface later as a machine that cannot authenticate - which is a worse
//! diagnostic than an honest refusal now.
//!
//! # Handles are not tracked
//!
//! Every call that returns a handle returns the same twenty octets, and no call checks where a
//! handle came from. A join is one client on one connection doing one thing in order, and a table
//! of live handles would be state to keep correct for a protocol nothing here depends on. The
//! bytes carry a marker so a capture reads as deliberate rather than as an address.

use crate::rpc::association::Fault;
use crate::rpc::ndr::{NdrReader, NdrWriter};
use crate::rpc::pdu::NCA_OP_RNG_ERROR;
use crate::server::ServerState;

/// `samr_ConnectVersion`: what a Windows 2003 and later server states, which is what a modern
/// client expects to read (MS-SAMR 2.2.3.3).
const SAMR_CONNECT_AFTER_W2K: u32 = 3;

/// MS-ERREF: the call is understood and this server does not do it.
const NTSTATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const NTSTATUS_SUCCESS: u32 = 0x0000_0000;

/// `samr_Connect` (opnum 0): the oldest form, still asked for by some clients.
pub(crate) const OPNUM_CONNECT: u16 = 0;
/// `samr_Close` (opnum 1).
pub(crate) const OPNUM_CLOSE: u16 = 1;
/// `samr_LookupDomain` (opnum 5): the SID of a domain, by name.
pub(crate) const OPNUM_LOOKUP_DOMAIN: u16 = 5;
/// `samr_OpenDomain` (opnum 7).
pub(crate) const OPNUM_OPEN_DOMAIN: u16 = 7;
/// `samr_CreateUser2` (opnum 50): where the machine account would be created.
pub(crate) const OPNUM_CREATE_USER2: u16 = 50;
/// `samr_Connect2` (opnum 57): what a Samba member actually calls.
pub(crate) const OPNUM_CONNECT2: u16 = 57;
/// `samr_Connect5` (opnum 64).
pub(crate) const OPNUM_CONNECT5: u16 = 64;

/// Answers one call.
pub(crate) async fn serve(
    server: &ServerState,
    _caller: &crate::server::Caller,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    dispatch(&server.config, opnum, stub)
}

/// Which call an opnum reaches, and what it answers.
///
/// Separate from [`serve`] so that routing is testable without a whole [`ServerState`]: a
/// mutation that answered `Connect2` with the domain-opening handler would otherwise look like a
/// working server until a client sent a handle where a domain SID belongs.
pub(crate) fn dispatch(
    config: &crate::server::ServerConfig,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    match opnum {
        OPNUM_CONNECT | OPNUM_CONNECT2 => connect(stub),
        OPNUM_CONNECT5 => connect5(stub),
        OPNUM_CLOSE => close_handle(stub),
        OPNUM_OPEN_DOMAIN => open_domain(stub),
        OPNUM_LOOKUP_DOMAIN => lookup_domain(config, stub),
        OPNUM_CREATE_USER2 => create_user2(stub),
        other => {
            // The number goes to the log: a client reports only "the procedure number is out of
            // range", and which number is the difference between a missing feature and a typo.
            tracing::warn!(
                opnum = other,
                stub = stub.len(),
                "samr: no handler for this call"
            );
            Err(Fault {
                status: NCA_OP_RNG_ERROR,
                did_not_execute: true,
            })
        }
    }
}

/// A handle as this interface writes it: twenty octets, distinctive on purpose.
///
/// The last four spell `samr` in ASCII, so a capture shows an interface that answered rather than a
/// cookie copied from somewhere. The first sixteen are zero: nothing here looks a handle up, and a
/// value that looked like an address would invite a reader to think something did.
fn samr_handle() -> [u8; 20] {
    let mut handle = [0u8; 20];
    handle[16..].copy_from_slice(b"samr");
    handle
}

/// The handle, then the status - and **no referent id** in front of it.
///
/// `[out,ref] policy_handle *` looks like a pointer, and pidl does not marshal it as one: a
/// `policy_handle` is a context handle, and a context handle travels as its twenty octets whatever
/// the IDL says about pointers. Measured twice - `lsarpc` records the same finding, and writing a
/// referent here made the client read the status from inside the handle: it reported
/// `NT code 0x726d6173`, which is the ASCII of this handle's marker read as a status code.
fn handle_response() -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.bytes(&samr_handle());
    writer.u32(NTSTATUS_SUCCESS);
    writer.finish()
}

/// `samr_Connect`: `[in,unique] string *system_name`, `[in] uint32 access_mask`, out handle.
fn connect(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    // Read, not used: the name a client passes is the server it already reached, and the access
    // mask is a request this interface answers without a policy behind it.
    let _system_name = reader.string();
    let _access_mask = reader.u32();
    Ok(handle_response())
}

/// `samr_Connect5`: the same, plus a level and the information that goes with it.
///
/// The reply carries `[in,out] uint32 *level` and `[out,ref] samr_ConnectInfo *info`. Level 0 has no
/// information at all, which is what this server states: an unknown level would be a claim about
/// its capabilities that nothing here maintains.
fn connect5(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let _system_name = reader.string();
    let _access_mask = reader.u32();
    let level = reader.u32().unwrap_or(0);

    // `samr_ConnectInfo` has one arm, `case(1)` (MS-SAMR 2.2.3.2), so level 1 is the only level
    // this server can answer with information. The level the client asked for is not honoured
    // beyond that: a client asking for 0 gets 1 and a stated version, which is what Windows answers
    // and what a client can read without guessing.
    let _ = level;

    let mut writer = NdrWriter::new();
    // `[out,ref] uint32 *level_out`: a real pointer, referent and value.
    writer.pointer(true);
    writer.u32(1);
    // `[out,ref] samr_ConnectInfo *info_out`: a pointer to the union, then its discriminant.
    writer.pointer(true);
    writer.u16(1);
    writer.align(4);
    // `samr_ConnectInfo1`: the version this server speaks, and no optional features.
    writer.u32(SAMR_CONNECT_AFTER_W2K);
    // `samr_SupportedFeatures` is a bitmap64.
    writer.raw(&0u64.to_le_bytes());
    // The handle last, inline, as [`handle_response`] records.
    writer.bytes(&samr_handle());
    writer.u32(NTSTATUS_SUCCESS);
    Ok(writer.finish())
}

/// `samr_Close`: `[in,out] policy_handle *handle`, nulled in the reply.
fn close_handle(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    const HANDLE: usize = 20;
    if stub.len() < HANDLE {
        return Err(Fault {
            status: crate::rpc::pdu::NCA_PROTO_ERROR,
            did_not_execute: true,
        });
    }

    let mut writer = NdrWriter::new();
    // The handle nulled, as MS-SAMR 3.1.5.4.1 requires: a client that keeps the value it sent would
    // use a handle the server has forgotten.
    writer.bytes(&[0u8; HANDLE]);
    writer.u32(NTSTATUS_SUCCESS);
    Ok(writer.finish())
}

/// `samr_OpenDomain`: `[in] handle`, `[in] uint32 access`, `[in,ref] dom_sid2 *sid`, out handle.
///
/// The SID is read only far enough to know the request is well formed. A directory that holds more
/// than one domain would have to compare it; this server answers for exactly one, and refusing a
/// SID that is not its own belongs with the access rules rather than here.
fn open_domain(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let _handle = reader.bytes(20);
    let _access = reader.u32();
    // `[in,ref] dom_sid2 *`: a referent, then the conformant count and the SID's own header.
    let _present = reader.pointer();
    let _count = reader.u32();

    Ok(handle_response())
}

/// `samr_LookupDomain`: `[in] handle`, `[in,ref] lsa_String *name`, `[out,ref] dom_sid2 *sid`.
///
/// Answered from the domain's own SID, and only for the domain's own names: a server that returned
/// its SID for any name it was given would tell a client that a domain it invented exists here.
fn lookup_domain(config: &crate::server::ServerConfig, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let _handle = reader.bytes(20);
    let _present = reader.pointer();
    let name = reader
        .string()
        .map(|units| String::from_utf16_lossy(&units).trim().to_string());

    let matches = match (&name, &config.domain_netbios, &config.dns_domain) {
        (Some(name), Some(netbios), dns) => {
            name.eq_ignore_ascii_case(netbios)
                || dns
                    .as_deref()
                    .is_some_and(|dns| name.eq_ignore_ascii_case(dns))
        }
        _ => false,
    };

    let sid = config.domain_sid.as_deref().filter(|_| matches);
    let mut writer = NdrWriter::new();
    match sid {
        Some(sid) => {
            writer.pointer(true);
            write_dom_sid2(&mut writer, sid);
            writer.u32(NTSTATUS_SUCCESS);
        }
        None => {
            // The refusal names nothing a client could pass off as an answer: no pointer, and a
            // status that says the domain is not this one.
            writer.pointer(false);
            writer.u32(STATUS_NO_SUCH_DOMAIN);
        }
    }
    Ok(writer.finish())
}

/// MS-ERREF: no such domain.
const STATUS_NO_SUCH_DOMAIN: u32 = 0xC000_00DF;

/// `samr_CreateUser2`: refused, because the write belongs to the directory that owns it.
///
/// The shape of the reply is the shape a successful one would have - a handle, the granted access
/// and a RID, all empty - so that a client's unmarshalling cannot fail before it reads the status.
/// An empty stub with a non-zero status would make `ndr_pull` complain about missing `[out,ref]`
/// pointers, and the client would report a marshalling error for a refusal it could have read.
fn create_user2(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let _handle = reader.bytes(20);
    let _present = reader.pointer();
    let name = reader
        .string()
        .map(|units| String::from_utf16_lossy(&units));

    tracing::warn!(
        account = name.as_deref().unwrap_or(""),
        "samr: a machine account was asked for over RPC. Creating one is a directory write, and \
         this server does not read a directory: the daemon that owns one has to answer \
         CreateUser2, and until it does the account is not created and this join cannot finish. \
         Over LDAP the same write is implemented and tested (rust-rest-ldap, the computer-account \
         path)."
    );

    let mut writer = NdrWriter::new();
    // The layout a successful answer has, as the client reads it: the (empty) user handle and the
    // two scalars inline, then the status. Measured - written with referents, the client read the
    // second referent id as the status and reported `NT code 0x00020004`, which is this server's
    // marshalling talking to itself rather than a status at all.
    writer.bytes(&[0u8; 20]);
    writer.u32(0);
    writer.u32(0);
    writer.u32(NTSTATUS_NOT_SUPPORTED);
    Ok(writer.finish())
}

/// `dom_sid2`: a conformant array of sub-authorities behind the SID's own header.
///
/// Not the flat octets a directory stores: `[size_is(num_auths)] uint32 sub_auths[]` puts its
/// maximum before the header, and sending the flat form makes a client read the revision byte as
/// the array's length. The same rule `lsarpc` records, and the same wire bytes.
fn write_dom_sid2(writer: &mut NdrWriter, sid: &[u8]) {
    const HEADER: usize = 8;
    if sid.len() < HEADER {
        return;
    }
    let count = usize::from(sid[1]);
    writer.u32(u32::try_from(count).unwrap_or(u32::MAX));
    writer.raw(&sid[..HEADER]);
    let end = (HEADER + count * 4).min(sid.len());
    writer.raw(&sid[HEADER..end]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::ServerConfig;

    fn config() -> ServerConfig {
        let mut config = ServerConfig::for_test();
        config.domain_netbios = Some("AD".to_string());
        config.dns_domain = Some("ad.example.com".to_string());
        // 1-5-21-1-2-3: revision, count, authority, three sub-authorities.
        // S-1-5-21-1-2-3: revision, count, the six-octet authority, then four sub-authorities -
        // 8 + 4*4 = 24 octets, the shape a directory stores and `dom_sid2` carries.
        config.domain_sid = Some(vec![
            1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,
        ]);
        config
    }

    /// A `samr_LookupDomain` request: handle, string referent, the units and their NUL.
    fn lookup_stub(name: &str) -> Vec<u8> {
        let mut reader = NdrWriter::new();
        reader.bytes(&samr_handle());
        reader.pointer(true);
        reader.string(name);
        reader.finish()
    }

    #[test]
    fn a_connect_answers_a_handle_and_a_status() {
        // The layout a client reads: referent, twenty octets, status. Four octets off, and the
        // status lands inside the handle - which `lsarpc` records costing a stand run.
        let mut writer = NdrWriter::new();
        writer.string("\\\\samba");
        writer.u32(0x0000_0030);
        let stub = writer.finish();

        let body = dispatch(&config(), OPNUM_CONNECT2, &stub).expect("answered");

        // Twenty octets, then the status: no referent id, because a context handle travels inline.
        assert_eq!(body.len(), 20 + 4);
        assert_eq!(&body[..20], &samr_handle());
        assert_eq!(&body[20..], &[0, 0, 0, 0]);
    }

    #[test]
    fn connect5_echoes_the_level_it_answers_with() {
        let mut writer = NdrWriter::new();
        writer.string("\\\\samba");
        writer.u32(0x0000_0030);
        writer.u32(0);
        let stub = writer.finish();

        let body = dispatch(&config(), OPNUM_CONNECT5, &stub).expect("answered");

        // The level and its information first, then the handle inline, then the status: the order
        // the IDL lists the out parameters in (MS-SAMR 3.1.5.2.5).
        assert_eq!(&body[..4], &[0, 0, 2, 0], "level_out referent");
        assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), 1);
        assert_eq!(
            &body[8..12],
            &[4, 0, 2, 0],
            "info_out referent, the next id"
        );
        assert_eq!(u16::from_le_bytes(body[12..14].try_into().unwrap()), 1);
        // The arm: the version (u32) and the 64-bit feature bitmap.
        assert_eq!(
            u32::from_le_bytes(body[16..20].try_into().unwrap()),
            SAMR_CONNECT_AFTER_W2K
        );
        assert_eq!(&body[20..28], &[0u8; 8], "no optional features claimed");
        assert_eq!(&body[28..48], &samr_handle(), "the handle, inline");
        assert_eq!(&body[48..], &[0, 0, 0, 0]);
    }

    #[test]
    fn closing_a_handle_nulls_it_and_puts_the_status_last() {
        let body = dispatch(&config(), OPNUM_CLOSE, &samr_handle()).expect("answered");

        assert_eq!(body, [0u8; 24].to_vec());
    }

    #[test]
    fn the_domain_is_named_by_either_of_its_names() {
        // A client may ask with the NetBIOS name or with the DNS one; both are this domain, and a
        // server that knew only one of them would answer "no such domain" to a correct question.
        for name in ["AD", "ad", "ad.example.com", "AD.EXAMPLE.COM"] {
            let body =
                dispatch(&config(), OPNUM_LOOKUP_DOMAIN, &lookup_stub(name)).expect("answered");
            assert_eq!(
                u32::from_le_bytes(body[body.len() - 4..].try_into().unwrap()),
                NTSTATUS_SUCCESS,
                "{name}"
            );
        }
    }

    #[test]
    fn another_domain_is_refused_rather_than_answered_with_this_sid() {
        let body =
            dispatch(&config(), OPNUM_LOOKUP_DOMAIN, &lookup_stub("OTHER")).expect("answered");

        assert_eq!(
            u32::from_le_bytes(body[body.len() - 4..].try_into().unwrap()),
            STATUS_NO_SUCH_DOMAIN
        );
        assert_eq!(&body[..4], &[0, 0, 0, 0], "no pointer, so nothing to read");
    }

    #[test]
    fn the_sid_travels_as_a_conformant_array_not_as_stored_octets() {
        // The count first, then the header. Sending the flat form makes a client read the revision
        // byte as the length of the array.
        let body = dispatch(&config(), OPNUM_LOOKUP_DOMAIN, &lookup_stub("AD")).expect("answered");

        // Referent ids start at 0x00020000 (C706 14.3.10.5, and what Samba's marshaller writes).
        assert_eq!(&body[..4], &[0, 0, 2, 0], "the referent id");
        assert_eq!(
            u32::from_le_bytes(body[4..8].try_into().unwrap()),
            4,
            "four sub-authorities, written before the header"
        );
        assert_eq!(body[8], 1, "revision");
        assert_eq!(body[9], 4, "count");
    }

    #[test]
    fn a_domain_with_no_sid_answers_null_rather_than_an_invented_one() {
        let mut config = config();
        config.domain_sid = None;

        let body = dispatch(&config, OPNUM_LOOKUP_DOMAIN, &lookup_stub("AD")).expect("answered");

        assert_eq!(&body[..4], &[0, 0, 0, 0]);
        assert_eq!(
            u32::from_le_bytes(body[4..8].try_into().unwrap()),
            STATUS_NO_SUCH_DOMAIN
        );
    }

    #[test]
    fn creating_a_machine_account_is_refused_and_the_reply_still_has_its_shape() {
        // `[out,ref]` pointers are non-null, so a client's unmarshalling needs them present before
        // it reads the status: an empty stub with a non-zero status reports a marshalling error
        // instead of the refusal it carried.
        let mut writer = NdrWriter::new();
        writer.bytes(&samr_handle());
        writer.pointer(true);
        writer.string("samba$");
        writer.u32(0x0080);
        writer.u32(0x0000_0002);
        let stub = writer.finish();

        let body = dispatch(&config(), OPNUM_CREATE_USER2, &stub).expect("refused, not failed");

        assert_eq!(
            u32::from_le_bytes(body[body.len() - 4..].try_into().unwrap()),
            NTSTATUS_NOT_SUPPORTED
        );
        assert_eq!(body.len(), 20 + 4 + 4 + 4);
        assert_eq!(&body[..20], &[0u8; 20], "no handle was created");
    }

    #[test]
    fn a_call_this_interface_does_not_answer_is_a_fault_with_its_number() {
        let fault = dispatch(&config(), 40, &[]).expect_err("no handler");

        assert_eq!(fault.status, NCA_OP_RNG_ERROR);
    }
}
