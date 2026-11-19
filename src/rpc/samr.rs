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
const NTSTATUS_WRONG_PASSWORD: u32 = 0xC000_006A;
const NTSTATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_NO_SUCH_USER`: a RID this directory does not hold.
const NTSTATUS_NO_SUCH_USER: u32 = 0xC000_0063;
/// `STATUS_NONE_MAPPED`: none of the names resolved. An error, not a warning: a client that read
/// RID 0 with success would treat account zero as the account it asked for.
const STATUS_NONE_MAPPED: u32 = 0xC000_0073;
/// `STATUS_SOME_NOT_MAPPED`: a warning, not an error - some names resolved and some did not.
const STATUS_SOME_NOT_MAPPED: u32 = 0x0000_0107;

/// `samr_Connect` (opnum 0): the oldest form, still asked for by some clients.
pub(crate) const OPNUM_CONNECT: u16 = 0;
/// `samr_Close` (opnum 1).
pub(crate) const OPNUM_CLOSE: u16 = 1;
/// `samr_EnumerateDomainsInSamServer` (opnum 0x06): the domains this server holds.
///
/// A member asks this before it looks one up by name, and a server that faults sends it to the next
/// controller. There is exactly one domain here, so the enumeration is one entry and the second call
/// - the one that asks for more - is an empty page, which is how a client learns it has them all.
///
/// `SAMPR_ENUMERATION_BUFFER` is `{ EntriesRead ULONG, Buffer PSAMPR_RID_ENUMERATION_ARRAY }`; the
/// array's element is `{ RelativeId ULONG, Name RPC_UNICODE_STRING }`. A domain has no RID of its
/// own, so `RelativeId` is zero and the name is the NetBIOS name a client matches its configuration
/// against.
fn enumerate_domains(config: &crate::server::ServerConfig) -> Result<Vec<u8>, Fault> {
    let name = config
        .domain_netbios
        .clone()
        .or_else(|| config.dns_domain.clone())
        .unwrap_or_else(|| config.netbios_name.clone());

    let mut writer = NdrWriter::new();
    writer.u32(0); // EnumerationContext: this enumeration has one page
    // `[out,ref] SAMPR_ENUMERATION_BUFFER *Buffer`: a real pointer, referent and value.
    writer.pointer(true);
    writer.u32(1); // EntriesRead
    // The array behind the pointer: the maximum it could hold, the offset, and how many are there.
    writer.pointer(true);
    writer.u32(1);
    writer.u32(0);
    writer.u32(1);
    writer.u32(0); // RelativeId: a domain is not an account and has none
    // The name as an `RPC_UNICODE_STRING`: length and size in octets, then the pointer, then the
    // characters in the deferred section - the shape `lookup_names` reads back off a live stub.
    let octets = u16::try_from(name.encode_utf16().count() * 2).expect("a short domain name");
    writer.u16(octets);
    writer.u16(octets);
    writer.pointer(true);
    // No terminator: this is a counted string, and a client reads exactly `length` octets.
    let units: Vec<u16> = name.encode_utf16().collect();
    let count = u32::try_from(units.len()).expect("a short domain name");
    writer.u32(count);
    writer.u32(0);
    writer.u32(count);
    for unit in units {
        writer.raw(&unit.to_le_bytes());
    }
    writer.u32(1); // CountReturned
    writer.u32(NTSTATUS_SUCCESS);
    Ok(writer.finish())
}

/// `samr_LookupDomain` (opnum 5): the SID of a domain, by name.
pub(crate) const OPNUM_ENUMERATE_DOMAINS: u16 = 6;
pub(crate) const OPNUM_LOOKUP_DOMAIN: u16 = 5;
/// `samr_LookupNames` (0x11): a name to a RID and a name type. What a join calls on the machine
/// account it has just created, before it can set that account's password.
pub(crate) const OPNUM_LOOKUP_NAMES: u16 = 17;
/// `SamrDeleteUser` (MS-SAMR 3.1.5.5.7): a client undoing an account it created.
pub(crate) const OPNUM_DELETE_USER: u16 = 35;
/// `samr_OpenUser` (opnum 0x22): a user handle, from a domain handle and a RID.
///
/// The call that makes every later user operation possible: the client names the user by RID and
/// nothing else, and a handle this server did not hand out is one it cannot resolve back to an
/// account. Measured against a Windows member running `netdom resetpwd`: it opens the machine's own
/// user twice, with two read access masks, before it changes the password.
pub(crate) const OPNUM_OPEN_USER: u16 = 34;
/// `SamrQueryInformationUser` (MS-SAMR 3.1.5.6.37): the same as the `2` call with a class.
pub(crate) const OPNUM_QUERY_INFO_USER: u16 = 36;
/// `SamrGetUserDomainPasswordInformation` (MS-SAMR 3.1.5.9.5): the domain's password policy.
pub(crate) const OPNUM_USER_DOMAIN_PASSWORD: u16 = 44;
/// `samr_OpenDomain` (opnum 7).
pub(crate) const OPNUM_OPEN_DOMAIN: u16 = 7;
/// `samr_CreateUser2` (opnum 50): where a join creates the account it cannot create over LDAP,
/// because the domain it is joining has not issued it a ticket yet.
pub(crate) const OPNUM_CREATE_USER2: u16 = 50;
/// `samr_SetInformationUser2` (opnum 58): what a join calls last, to set the flags and the name.
pub(crate) const OPNUM_SET_INFO_USER2: u16 = 58;
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
    // Every call and its answer, behind `RRL_SAMR_DUMP`: a client that reports a status this server
    // never produced is a client reading an answer shaped differently from what it expected, and the
    // only way to see which field is to look at both halves.
    let dump = std::env::var_os("RRL_SAMR_DUMP").is_some();
    if dump {
        tracing::warn!(
            opnum,
            stub = %stub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "samr: call"
        );
    }
    let answer = match opnum {
        // The two calls that write: they ask whoever owns the accounts and need the server state
        // that remembers the handles those writes hand out.
        OPNUM_CREATE_USER2 => create_user2(server, stub).await,
        OPNUM_SET_INFO_USER2 => set_information_user2(server, _caller, stub).await,
        OPNUM_QUERY_INFO_USER => query_information_user(server, stub).await,
        OPNUM_OPEN_USER => open_user(server, stub).await,
        OPNUM_DELETE_USER => delete_user(server, stub).await,
        OPNUM_USER_DOMAIN_PASSWORD => user_domain_password_information(stub),
        other => dispatch(&server.config, other, stub),
    };
    if dump {
        match &answer {
            Ok(body) => tracing::warn!(
                opnum,
                answer = %body.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "samr: answer"
            ),
            Err(fault) => tracing::warn!(
                opnum,
                status = format_args!("{:#x}", fault.status),
                "samr: fault"
            ),
        }
    }
    answer
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
        OPNUM_ENUMERATE_DOMAINS => enumerate_domains(config),
        OPNUM_LOOKUP_DOMAIN => lookup_domain(config, stub),
        OPNUM_LOOKUP_NAMES => lookup_names(config, stub),
        other => {
            // The number goes to the log: a client reports only "the procedure number is out of
            // range", and which number is the difference between a missing feature and a typo.
            tracing::warn!(
                opnum = other,
                stub = stub.len(),
                hex = %stub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "samr: no handler for this call"
            );
            Err(Fault {
                status: NCA_OP_RNG_ERROR,
                did_not_execute: true,
            })
        }
    }
}

/// `samr_LookupNames` (opnum 0x11): `[in] policy_handle domain`, `[in] uint32 num_names`,
/// `[in,size_is(1000),length_is(num_names)] lsa_String names[]`, out `samr_Ids rids`,
/// out `samr_Ids types`.
///
/// The caller is a join: it has just created the account and needs its RID before it can set that
/// account's password. The type reported is **`SID_NAME_USER`** for a machine account, not
/// `SID_NAME_COMPUTER`: Samba's `libnet_join.c` refuses anything else at this exact call, with the
/// comment "We *must* do this.... don't ask...", and answers `INVALID_WORKSTATION` even when the RID
/// is right.
fn lookup_names(config: &crate::server::ServerConfig, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    /// `SID_NAME_USER`. A machine account is a user account to SAMR, whatever the directory thinks.
    const SID_NAME_USER: u32 = 1;
    /// `SID_NAME_UNKNOWN`: a name this server could not resolve.
    const SID_NAME_UNKNOWN: u32 = 0;

    let mut reader = NdrReader::new(stub);
    let Some(_handle) = reader.bytes(20) else {
        return Err(malformed_at("domain_handle", stub));
    };
    let Some(count) = reader.u32() else {
        return Err(malformed_at("num_names", stub));
    };
    // The conformant-varying array's own header. `size_is(1000)` is the maximum the interface
    // allows; the offset is zero for an array that was not sliced; the third word is what is
    // actually there.
    let Some(max) = reader.u32() else {
        return Err(malformed_at("names.max_count", stub));
    };
    let Some(_offset) = reader.u32() else {
        return Err(malformed_at("names.offset", stub));
    };
    let Some(present) = reader.u32() else {
        return Err(malformed_at("names.actual_count", stub));
    };
    // The count and the array must agree, and a count beyond the array's maximum is a client that
    // disagrees with the interface about the shape of the call.
    if present != count || count > max {
        return Err(malformed_at("names.actual_count", stub));
    }

    // An `lsa_String` is not a bare pointer, whatever the IDL's wording suggests: it is a
    // two-octet length in **octets**, a two-octet size, and the pointer, then the characters in
    // the deferred section. Measured from a live stub of 68 octets holding one name:
    //
    //   0c00 0c00 00000200   "samba$" is twelve octets, behind a referent
    //   06000000 00000000 06000000  then six UTF-16 units - length counts octets, the array counts
    //                              units, and both are right
    //
    // Reading it as a bare pointer consumed the length and the size as that pointer and then
    // looked for a string header eight octets early.
    for _ in 0..count {
        let Some(_length) = reader.u16() else {
            return Err(malformed_at("names[].length", stub));
        };
        let Some(_size) = reader.u16() else {
            return Err(malformed_at("names[].size", stub));
        };
        match reader.pointer() {
            Some(true) => {}
            _ => return Err(malformed_at("names[].name", stub)),
        }
    }

    let mut names = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Some(units) = reader.string() else {
            return Err(malformed_at("names[].name", stub));
        };
        names.push(String::from_utf16_lossy(&units).trim().to_string());
    }

    // The RID and the type, per name. A name the directory does not serve keeps RID 0 and
    // `SID_NAME_UNKNOWN`, and the status says so - zero with success would read as an account.
    let mut rids = Vec::with_capacity(names.len());
    let mut types = Vec::with_capacity(names.len());
    let mut mapped = 0usize;
    for name in &names {
        match config
            .machine_secrets
            .as_ref()
            .and_then(|secrets| secrets.machine(name))
        {
            Some(account) => {
                rids.push(account.rid);
                types.push(SID_NAME_USER);
                mapped += 1;
            }
            None => {
                rids.push(0);
                types.push(SID_NAME_UNKNOWN);
            }
        }
    }

    let status = if mapped == names.len() && mapped > 0 {
        NTSTATUS_SUCCESS
    } else if mapped == 0 {
        STATUS_NONE_MAPPED
    } else {
        // Some of the names resolved: a warning, and the client reads the array.
        STATUS_SOME_NOT_MAPPED
    };

    let mut writer = NdrWriter::new();
    write_samr_ids(&mut writer, &rids);
    write_samr_ids(&mut writer, &types);
    writer.u32(status);
    Ok(writer.finish())
}

/// The stub ended before a field this call reads, with the octets that were there.
///
/// The hex is what turned `names[].name` from a guess into a measurement: a client's array of
/// `lsa_String` does not put each name where the IDL's wording suggests, and the offsets in a dump
/// say where they are.
fn malformed_at(field: &str, stub: &[u8]) -> Fault {
    let head = &stub[..stub.len().min(96)];
    tracing::warn!(
        field,
        len = stub.len(),
        hex = %head.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "samr: the request stub ends before this field"
    );
    Fault {
        status: 0x0002_0004, // NT_STATUS_INFO_LENGTH_MISMATCH
        did_not_execute: true,
    }
}

/// One `samr_Ids`: a count, and a conformant array of that many words behind a pointer.
///
/// The struct itself gets **no referent**, even though the IDL declares it `[out,ref] samr_Ids *`:
/// NDR marshals a `[ref]` pointer's pointee in place, and a referent here shifts every field by one
/// word. Measured against a live client, which reads the referent as part of `count`, finds
/// `0x00020000` where a count belongs, and refuses the reply with
/// `ndr_pull_samr_Ids: Range Error: value out of range` - `count` is ranged 0..1024. The same
/// finding as `policy_handle` below, and the same cause.
fn write_samr_ids(writer: &mut NdrWriter, ids: &[u32]) {
    writer.u32(u32::try_from(ids.len()).unwrap_or(u32::MAX));
    // The array is a plain pointer inside the struct, so this one *does* carry a referent.
    writer.pointer(true);
    // A conformant array carries its maximum before the values; no offset, because
    // `[size_is(count)]` without `length_is` is not varying.
    writer.u32(u32::try_from(ids.len()).unwrap_or(u32::MAX));
    for id in ids {
        writer.u32(*id);
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

    // MS-SAMR 3.1.5.6.5 lists the out parameters as `OutVersion`, `OutRevisionInfo`,
    // `ServerHandle`, `ErrorCode` - in that order, and none of the first two is a pointer:
    // `SAMPR_REVISION_INFO` is a union whose switch is a **ULONG** (4.2.3.16), and the only arm is
    // V1 { Revision ULONG, SupportedFeatures ULONG }.
    //
    // A response that sends them as pointers - which is what this did - is a stub the client cannot
    // unmarshal: `NetpProvisionComputerAccount` reports `0x6f7 RPC_X_BAD_STUB_DATA`, and the join
    // stops at the first RPC call it makes after LDAP.
    let mut writer = NdrWriter::new();
    writer.u32(1); // OutVersion
    writer.u32(1); // SAMPR_REVISION_INFO tag: case 1
    writer.u32(SAMR_CONNECT_AFTER_W2K); // Revision
    writer.u32(0); // SupportedFeatures: nothing claimed
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
    // The order is the pointer *first* and the struct after it, because the parameter is a
    // `[in,string] RPC_UNICODE_STRING *`: NDR writes the referent id, then the constructed type -
    // `{ Length <H, MaximumLength <H, Data LPWSTR }` - and only then the characters behind their own
    // pointer. Reading the lengths first consumed the referent as `Length = 1, MaximumLength = 0`,
    // the name came out as `None`, and the client was told `STATUS_NO_SUCH_DOMAIN` for the domain it
    // had just enumerated: `NetpProvisionComputerAccount: 0x54b`.
    //
    // The bytes, from a Windows Server 2022 join - twenty-eight of them, with no pointer to the
    // characters at all:
    //     <handle 20>  01 00 00 00  00 00  00 00
    //                  referent    Length  Max
    let _present = reader.pointer();
    let _length = reader.u16();
    let _maximum = reader.u16();
    // Both lengths zero *is* the empty name, and a Windows join sends exactly that - 28 octets in
    // all: the handle, the referent, and two zero half-words. The client does not even write the
    // pointer to the characters when there are none, so reading one here consumed nothing and
    // everything after it failed.
    let empty = _length == Some(0) && _maximum == Some(0);
    let _buffer = reader.pointer();
    let name = if empty {
        Some(String::new())
    } else {
        reader
            .string_or_empty()
            .map(|units| String::from_utf16_lossy(&units).trim().to_string())
    };

    // An **empty** name is the question "which domain is this?", and it is the one a Windows join
    // actually asks: the capture above carries `Length = 0`. Answering it with this server's SID is
    // not the leniency the next paragraph refuses - nothing was claimed to exist - and refusing it
    // leaves the client with `0x54b` for the domain it just enumerated.
    let matches = match (&name, &config.domain_netbios, &config.dns_domain) {
        (Some(name), _netbios, _dns) if name.is_empty() => true,
        (Some(name), Some(netbios), dns) => {
            name.eq_ignore_ascii_case(netbios)
                || dns
                    .as_deref()
                    .is_some_and(|dns| name.eq_ignore_ascii_case(dns))
        }
        _ => false,
    };

    tracing::debug!(
        stub = %stub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        name = ?name,
        netbios = ?config.domain_netbios,
        dns = ?config.dns_domain,
        matches,
        sid = config.domain_sid.is_some(),
        "samr: LookupDomain"
    );
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

/// MS-ERREF: the handle was not one this server issued.
const NTSTATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// MS-ERREF: no such domain.
const STATUS_NO_SUCH_DOMAIN: u32 = 0xC000_00DF;

/// `samr_QueryInformationUser` (36): `[in] handle`, `[in] USER_INFORMATION_CLASS`, out a union.
///
/// The class is the union's discriminant and it is **not** repeated on the wire - the method
/// correlates it with the parameter - so the reply is the `[out,ref]` referent and then the arm.
///
/// The class a join asks for is `UserControlInformation` (**16**), immediately after `CreateUser2`
/// and before any password call: it is reading back the flags it has just asked for. Its arm is one
/// word, and answering it wrongly is not something a client can describe - it unmarshals the arm as
/// the shape its class names and reports `0x6c5`, `RPC_S_INVALID_BOUND`.
/// `samr_OpenUser` (opnum 0x22): a user handle, from a domain handle and a RID.
///
/// Every call after this one goes through the handle, and this server resolves a handle back to an
/// account name - so the RID has to be resolved *here*, or a password change would be applied to
/// nobody. `None` is `STATUS_NO_SUCH_USER` and not a handle: answering one would let a client
/// believe it opened an account this directory does not have, and the write that followed would go
/// nowhere while the client reported success.
///
/// The access mask is read and not enforced. What a client may do with the account is decided by
/// who it proved to be, and this interface has no policy of its own to compare against.
async fn open_user(server: &ServerState, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let Some(_domain_handle) = reader.bytes(20) else {
        return Err(malformed_at("domain_handle", stub));
    };
    let Some(_access) = reader.u32() else {
        return Err(malformed_at("access_mask", stub));
    };
    let Some(rid) = reader.u32() else {
        return Err(malformed_at("rid", stub));
    };

    let mut writer = NdrWriter::new();
    let Some(accounts) = server.config.machine_accounts.as_ref() else {
        tracing::warn!(
            rid,
            "samr: OpenUser on a server with no directory to resolve the RID against"
        );
        writer.bytes(&[0u8; 20]);
        writer.u32(NTSTATUS_NO_SUCH_USER);
        return Ok(writer.finish());
    };
    let Some(account) = accounts.account_of_rid(rid).await else {
        tracing::warn!(
            rid,
            "samr: OpenUser named a RID this directory does not hold"
        );
        writer.bytes(&[0u8; 20]);
        writer.u32(NTSTATUS_NO_SUCH_USER);
        return Ok(writer.finish());
    };

    let handle = server.remember_samr_user(&account);
    tracing::debug!(rid, account = %account, "samr: OpenUser");
    writer.bytes(&handle);
    writer.u32(NTSTATUS_SUCCESS);
    Ok(writer.finish())
}

async fn query_information_user(server: &ServerState, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let Some(handle) = reader.bytes(20) else {
        return Err(malformed_at("user_handle", stub));
    };
    let account = server.samr_user(handle).unwrap_or_default();
    // Both widths are read, as in `set_information_user2`: a producer that declares the enum
    // `v1_enum` sends four octets.
    let narrow = reader.u16();
    let wide = {
        let mut again = NdrReader::new(stub);
        let _ = again.bytes(20);
        again.u32()
    };
    let class = narrow.map(u32::from).or(wide).unwrap_or(u32::MAX);

    let mut writer = NdrWriter::new();
    match class {
        USER_CONTROL_INFORMATION => {
            let control = match server.config.machine_accounts.as_ref() {
                Some(accounts) => accounts.machine_control(&account).await,
                None => None,
            };
            match control {
                Some(control) => {
                    tracing::debug!(account = %account, control, "samr: QueryInformationUser");
                    writer.pointer(true);
                    // The union's discriminant travels on the wire: the `[out]` shape carries its
                    // own tag, and a reply without it is read as an arm of a different number -
                    // `0x6c5`, `RPC_S_INVALID_BOUND`, from the client's unmarshalling.
                    writer.u32(USER_CONTROL_INFORMATION);
                    writer.u32(control);
                    writer.u32(NTSTATUS_SUCCESS);
                }
                None => {
                    tracing::warn!(
                        account = %account,
                        "samr: QueryInformationUser for an account this server cannot read"
                    );
                    writer.pointer(false);
                    writer.u32(NTSTATUS_OBJECT_NAME_NOT_FOUND);
                }
            }
        }
        other => {
            tracing::warn!(
                class = other,
                name = info_class_name(other),
                account = %account,
                octets = stub.len(),
                "samr: QueryInformationUser - a class this server cannot answer"
            );
            writer.pointer(false);
            writer.u32(NTSTATUS_NOT_SUPPORTED);
        }
    }
    Ok(writer.finish())
}

/// `USER_INFORMATION_CLASS` 16 (MS-SAMR 2.2.6.28): the account's own flags.
const USER_CONTROL_INFORMATION: u32 = 16;

/// MS-ERREF: the object asked about does not exist.
const NTSTATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// `samr_GetUserDomainPasswordInformation` (44): `[in] handle`, out the domain's password policy.
///
/// A join asks this before it sets the machine's password - the answer says how long one has to be -
/// and a fault here is a join that stops one call short of the write. This domain enforces no
/// minimum and no complexity: the values are the account's own business, and a machine password is
/// generated by the client anyway.
fn user_domain_password_information(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    if reader.bytes(20).is_none() {
        return Err(malformed_at("user_handle", stub));
    }
    let mut writer = NdrWriter::new();
    // `[out] PUSER_DOMAIN_PASSWORD_INFORMATION`: a referent, then the struct - two octets of
    // minimum length, two of padding, and the flags word.
    writer.pointer(true);
    writer.u16(0); // MinimumPasswordLength
    writer.u16(0); // padding
    writer.u32(0); // PasswordProperties
    writer.u32(NTSTATUS_SUCCESS);
    Ok(writer.finish())
}

/// `samr_DeleteUser` (35): `[in] handle`.
///
/// A join that fails after creating its account deletes that account, and a server that refuses the
/// delete leaves the directory holding an object nobody will use - the name the next attempt wants.
async fn delete_user(server: &ServerState, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let Some(handle) = reader.bytes(20) else {
        return Err(malformed_at("user_handle", stub));
    };

    // A join that gives up deletes the account it just created, and a server that refuses leaves
    // an object nobody will use holding the name the next attempt wants. Measured: the account
    // survived the refusal and the following run went down a different path, because a machine
    // account that exists takes the `already exists` branch on the way in.
    let Some(name) = server.samr_user(handle) else {
        tracing::warn!("samr: DeleteUser on a handle this server did not hand out");
        let mut writer = NdrWriter::new();
        writer.u32(NTSTATUS_INVALID_HANDLE);
        return Ok(writer.finish());
    };

    let deleted = match server.config.machine_accounts.as_ref() {
        Some(accounts) => accounts.delete_machine(&name).await,
        None => false,
    };
    server.forget_samr_user(handle);

    let mut writer = NdrWriter::new();
    writer.u32(if deleted {
        NTSTATUS_SUCCESS
    } else {
        // The account is gone already, or the directory refused. Either way the handle is spent,
        // and a client that retries with it must not address whatever the number names next.
        NTSTATUS_OBJECT_NAME_NOT_FOUND
    });
    tracing::info!(account = %name, deleted, "samr: DeleteUser");
    Ok(writer.finish())
}

/// `samr_CreateUser2`: `[in] handle`, `[in,string] PRPC_UNICODE_STRING *name`, `[in] uint32 access`,
/// `[in] uint32 unknown`, out a user handle, the granted access and a RID.
///
/// Asked of whoever owns the accounts, and never answered with a handle this server did not create:
/// the handle it returns is what `samr_SetInformationUser2` sends back to name the account whose
/// password it carries, so a fabricated one would be a password written nowhere.
///
/// The reply's layout is the one a real client reads - the handle inline, the two scalars, the
/// status - and not the referent-per-field shape the IDL might suggest: measured, written with
/// referents the client read the second referent id as the status and reported `NT code 0x00020004`,
/// which is this server's marshalling talking to itself rather than a status at all.
async fn create_user2(server: &ServerState, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let _handle = reader.bytes(20);
    // The name is `[in,string] PRPC_UNICODE_STRING` **by value**, so the struct starts here: the two
    // lengths, then the referent of the characters, then the conformant varying array. Not the shape
    // `samr_LookupDomain` sends - there the parameter is `[in,ref]` and the referent comes first -
    // and reading this one that way consumed `Length` as a referent and reported the machine's name
    // as the empty string, which the directory then refused as "an account with no name".
    //
    // From a Windows Server 2022 join, in full:
    //     <handle 20> | 20 00 22 00 | 00 00 02 00 | 11 00 00 00 00 00 00 00 10 00 00 00 | chars
    //                  Length Max    referent      count       offset      present
    let length = reader.u16();
    let maximum = reader.u16();
    let name = if length == Some(0) && maximum == Some(0) {
        String::new()
    } else {
        let _buffer = reader.pointer();
        reader
            .string_or_empty()
            .map(|units| String::from_utf16_lossy(&units).trim().to_string())
            .unwrap_or_default()
    };
    let access = reader.u32().unwrap_or(0);

    let rid = match server.config.machine_accounts.as_ref() {
        Some(accounts) => accounts.create_machine(&name).await,
        None => None,
    };

    let mut writer = NdrWriter::new();
    match rid {
        Some(rid) => {
            let handle = server.remember_samr_user(&name);
            tracing::info!(account = %name, rid, "samr: machine account created");
            writer.bytes(&handle);
            // The access the caller asked for, granted in full: a client that reads back less than
            // it requested treats the account as one it cannot finish setting up.
            writer.u32(access);
            writer.u32(rid);
            writer.u32(NTSTATUS_SUCCESS);
        }
        None => {
            tracing::warn!(
                account = %name,
                "samr: a machine account was asked for and refused - the directory declined it or \
                 this server has no directory to write to, and the join cannot finish without one"
            );
            writer.bytes(&[0u8; 20]);
            writer.u32(0);
            writer.u32(0);
            writer.u32(NTSTATUS_NOT_SUPPORTED);
        }
    }
    Ok(writer.finish())
}

/// `samr_SetInformationUser2`: `[in] handle`, `[in] USER_INFORMATION_CLASS`, `[in] buffer`.
///
/// The call a join makes to set its account's password, and the password arrives **encrypted under
/// the SMB session key**: a server without that key cannot read what it is being asked to store, and
/// one that answers `success` without storing leaves the directory on no password at all while the
/// member holds one - the next secure channel is then refused for an account that exists.
///
/// Class 25, `UserInternal4InformationNew`, is `SAMPR_USER_ALL_INFORMATION` followed by
/// `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` (MS-SAMR 2.2.6.25): 516 octets of RC4 ciphertext and the
/// sixteen-octet salt they were encrypted under, keyed `MD5(salt || session key)` (3.2.2.1). The
/// cleartext inside is `SAMPR_USER_PASSWORD` (2.2.6.21) - a 512-octet buffer whose *last* `Length`
/// octets, counted from its end, are the password as UTF-16LE.
///
/// The plaintext is handed to whoever owns the accounts and not hashed here: one derivation serves
/// both an LDAP write of `unicodePwd` and this, and a second one would be a second place to be wrong
/// about a key nobody can check afterwards.
/// Stores a password this server has already decrypted, and answers the status to hand back.
///
/// Shared by the classes a client uses to change a password: the decryption differs by class and the
/// store does not, and two copies of "write it, log it, report it" is two places to be wrong about
/// whether a password was written at all.
async fn store_machine_password(
    server: &ServerState,
    account: &str,
    password: &[u8],
    class: u32,
) -> u32 {
    let stored = match server.config.machine_passwords.as_ref() {
        Some(passwords) => passwords.set_password(account, password).await,
        None => false,
    };
    tracing::info!(
        account = %account,
        octets = password.len(),
        stored,
        class,
        "samr: a password was set"
    );
    if stored {
        NTSTATUS_SUCCESS
    } else {
        NTSTATUS_NOT_SUPPORTED
    }
}

async fn set_information_user2(
    server: &ServerState,
    caller: &crate::server::Caller,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let Some(handle) = reader.bytes(20) else {
        return Err(malformed_at("user_handle", stub));
    };
    let account = server.samr_user(handle);
    let narrow = reader.u16();
    let wide = {
        let mut again = NdrReader::new(stub);
        let _ = again.bytes(20);
        again.u32()
    };
    let class = narrow.map(u32::from).or(wide).unwrap_or(u32::MAX);

    // The account has to be one this server handed a handle for: a handle it did not issue names
    // nothing, and a password written to nothing is worse than a refusal.
    let Some(account) = account else {
        tracing::warn!(
            octets = stub.len(),
            "samr: SetInformationUser2 for a handle this server never issued"
        );
        let mut writer = NdrWriter::new();
        writer.u32(NTSTATUS_INVALID_HANDLE);
        return Ok(writer.finish());
    };

    let mut writer = NdrWriter::new();
    match class {
        USER_INTERNAL4_INFORMATION_NEW => {
            let Some((cipher, salt)) = encrypted_password(stub, PASSWORD_BLOCK_AT) else {
                tracing::warn!(
                    account = %account,
                    octets = stub.len(),
                    "samr: SetInformationUser2 with a password block this server could not find \
                     where the structure puts it"
                );
                writer.u32(NTSTATUS_NOT_SUPPORTED);
                return Ok(writer.finish());
            };
            if std::env::var_os("RRL_PW_DIAG").is_some() {
                let _ = std::fs::write("/stand/setinfo.bin", stub);
                let _ = std::fs::write(
                    "/stand/sessionkey.txt",
                    caller
                        .session_key
                        .0
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                );
            }
            let Some(password) = open_password(cipher, salt, caller.session_key) else {
                tracing::warn!(
                    account = %account,
                    "samr: the password a join sent does not open under this session's key"
                );
                writer.u32(NTSTATUS_NOT_SUPPORTED);
                return Ok(writer.finish());
            };
            let stored = match server.config.machine_passwords.as_ref() {
                Some(passwords) => passwords.set_password(&account, &password).await,
                None => false,
            };
            tracing::info!(
                account = %account,
                octets = password.len(),
                stored,
                "samr: the machine password a join set"
            );
            writer.u32(if stored {
                NTSTATUS_SUCCESS
            } else {
                NTSTATUS_NOT_SUPPORTED
            });
        }
        // `UserInternal4Information` (23): the same structure as 25 with the **older** password
        // block - `SAMPR_ENCRYPTED_USER_PASSWORD` (MS-SAMR 2.2.6.20), 516 octets with no salt,
        // encrypted with the session key itself. This is the class `rpcclient setuserinfo2` and
        // Samba's `net rpc password` send, and answering it is what turns a second, independent
        // client into a test of the key: its password is one the operator typed.
        USER_INTERNAL4_INFORMATION => {
            let Some(cipher) =
                stub.get(PASSWORD_BLOCK_AT..PASSWORD_BLOCK_AT + ENCRYPTED_PASSWORD_LEN)
            else {
                tracing::warn!(account = %account, octets = stub.len(), "samr: class 23 without a password block");
                writer.u32(NTSTATUS_NOT_SUPPORTED);
                return Ok(writer.finish());
            };
            if std::env::var_os("RRL_PW_DIAG").is_some() {
                let _ = std::fs::write("/stand/setinfo23.bin", stub);
                let _ = std::fs::write(
                    "/stand/sessionkey23.txt",
                    caller
                        .session_key
                        .0
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                );
            }
            let Some(password) = open_password_unsalted(cipher, caller.session_key) else {
                tracing::warn!(
                    account = %account,
                    "samr: the password in class 23 does not open under this session's key"
                );
                writer.u32(NTSTATUS_WRONG_PASSWORD);
                return Ok(writer.finish());
            };
            let stored = match server.config.machine_passwords.as_ref() {
                Some(passwords) => passwords.set_password(&account, &password).await,
                None => false,
            };
            tracing::info!(
                account = %account,
                octets = password.len(),
                stored,
                class = 23,
                "samr: a password was set"
            );
            writer.u32(if stored {
                NTSTATUS_SUCCESS
            } else {
                NTSTATUS_NOT_SUPPORTED
            });
        }
        USER_INTERNAL5_INFORMATION_NEW => {
            let Some((cipher, salt)) = encrypted_password(stub, BUFFER_AT) else {
                tracing::warn!(
                    account = %account,
                    octets = stub.len(),
                    "samr: class 26 with the password block not where the union starts"
                );
                writer.u32(NTSTATUS_NOT_SUPPORTED);
                return Ok(writer.finish());
            };
            let Some(password) = open_password(cipher, salt, caller.session_key) else {
                tracing::warn!(
                    account = %account,
                    "samr: the password in class 26 does not open under this session's key"
                );
                // `WRONG_PASSWORD` and not "not supported": the block was there and the key does
                // not open it, which is a different statement to a client than a class this server
                // does not implement - and the one that tells an operator which side is wrong.
                writer.u32(NTSTATUS_WRONG_PASSWORD);
                return Ok(writer.finish());
            };
            let status = store_machine_password(server, &account, &password, class).await;
            writer.u32(status);
        }
        other => {
            tracing::warn!(
                class = other,
                name = info_class_name(other),
                account = %account,
                octets = stub.len(),
                "samr: SetInformationUser2 - a class this server cannot answer"
            );
            writer.u32(NTSTATUS_NOT_SUPPORTED);
        }
    }
    Ok(writer.finish())
}

/// `USER_INFORMATION_CLASS` 25 (MS-SAMR 2.2.6.28): every attribute, plus an encrypted password.
const USER_INTERNAL4_INFORMATION: u32 = 23;
const USER_INTERNAL4_INFORMATION_NEW: u32 = 25;
/// `USER_INFORMATION_CLASS` 26 (MS-SAMR 2.2.6.26): the password block **alone** - no attribute
/// structure in front of it - and one octet after it saying the password is expired.
///
/// Not "25 plus an old password": Samba's `samr.idl` spells it `samr_UserInfo26 = { samr_CryptPasswordEx
/// password; uint8 password_expired; }`, so the block starts where the union starts. That is the
/// whole difference from 25, and the reason the offset below is not `PASSWORD_BLOCK_AT`.
///
/// `netdom resetpwd` sends this class when a member changes its own password, so a server that
/// answers only 25 replies "not supported" to a domain member's request to change its password.
const USER_INTERNAL5_INFORMATION_NEW: u32 = 26;
/// Where the union starts in a `SetInformationUser2` request: the twenty-octet handle and the class.
const BUFFER_AT: usize = 24;

/// `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` (MS-SAMR 2.2.6.22): the ciphertext, then its salt.
const ENCRYPTED_PASSWORD_LEN: usize = 516;
const ENCRYPTED_SALT_LEN: usize = 16;

/// Where the password block sits in a class 25 request.
///
/// After the handle, the class and the union's discriminant (two octets each, MS-SAMR 2.2.6.28 as a
/// `v1_enum` narrowed to `switch_is`), the in-line part of `SAMPR_USER_ALL_INFORMATION` follows. It
/// is 196 octets for the shape every client sends - measured on a Windows Server 2022 join, and
/// checkable in the same capture: the block is followed only by the account's name, deferred as a
/// conformant array, and 220 + 532 + 32 + 4 octets account for the whole stub.
///
/// A client that sent a different in-line shape would be refused rather than mis-read, because the
/// block is *verified* below: a wrong offset does not decrypt to a length that fits a password.
const PASSWORD_BLOCK_AT: usize = 220;

/// The encrypted password and its salt, or `None` when this stub does not carry them.
fn encrypted_password(stub: &[u8], at: usize) -> Option<(&[u8], [u8; ENCRYPTED_SALT_LEN])> {
    let block = stub.get(at..at + ENCRYPTED_PASSWORD_LEN)?;
    let salt =
        stub.get(at + ENCRYPTED_PASSWORD_LEN..at + ENCRYPTED_PASSWORD_LEN + ENCRYPTED_SALT_LEN)?;
    Some((block, <[u8; ENCRYPTED_SALT_LEN]>::try_from(salt).ok()?))
}

/// The password inside the block, as UTF-16LE octets, when it opens under `key`.
///
/// The key is `MD5(salt || session key)` (MS-SAMR 3.2.2.1) and the ciphertext is one RC4 stream.
/// What the decryption has to produce is `SAMPR_USER_PASSWORD`: 512 octets of buffer followed by a
/// length, and the password is the last `length` octets of that buffer - which is why a password is
/// read from the end and not from the start.
fn open_password(
    cipher: &[u8],
    salt: [u8; ENCRYPTED_SALT_LEN],
    key: crate::server::SessionKey,
) -> Option<Vec<u8>> {
    use md5::{Digest, Md5};
    use rc4::{KeyInit, Rc4, StreamCipher};

    // Two orders exist in the wild: MS-SAMR 3.2.2.2 hashes the salt first, and Samba's own
    // `samba_gnutls_arcfour_confounded_md5` takes (confounder, key) in that same order - so the
    // salt-first form is the one to try first. The other is tried because a buffer that will not
    // open gives no clue which side is wrong, and a wrong order fails identically to a wrong key.
    for (index, order) in [true, false].into_iter().enumerate() {
        let mut digest = Md5::new();
        if order {
            digest.update(salt);
            digest.update(key.0);
        } else {
            digest.update(key.0);
            digest.update(salt);
        }
        let rc4_key = digest.finalize();
        let mut attempt = cipher.to_vec();
        let mut stream = Rc4::new_from_slice(&rc4_key).expect("a 16-octet RC4 key");
        stream.apply_keystream(&mut attempt);
        // A password is UTF-16 text; random octets are not. This is what tells a successful
        // decryption from one that produced a plausible-looking `Length` by chance.
        let Some(password) = password_at_the_end(&attempt) else {
            continue;
        };
        tracing::debug!(
            order = if index == 0 {
                "salt-first"
            } else {
                "key-first"
            },
            "samr: the password block opened"
        );
        return Some(password);
    }
    None
}

/// The password inside a 516-octet block encrypted with the session key itself.
///
/// `SAMPR_ENCRYPTED_USER_PASSWORD` (MS-SAMR 2.2.6.20): no salt and no MD5, unlike the `_NEW` form -
/// the RC4 key *is* the session key. Class 23 is where a client that is not a Windows join puts a
/// password, and answering it is what makes a second client a usable test of the key: its password
/// is one an operator typed, so a block that opens proves the key and one that does not disproves it.
fn open_password_unsalted(cipher: &[u8], key: crate::server::SessionKey) -> Option<Vec<u8>> {
    use rc4::{KeyInit, Rc4, StreamCipher};

    let mut plain = cipher.to_vec();
    let mut stream = Rc4::new_from_slice(&key.0).expect("a 16-octet RC4 key");
    stream.apply_keystream(&mut plain);
    password_at_the_end(&plain)
}

/// The password at the end of a `SAMPR_USER_PASSWORD` buffer, if the buffer reads like one.
///
/// `WCHAR Buffer[256]` then `ULONG Length`: the value occupies the *last* `Length` octets, so a
/// buffer whose length word is nonsense is not a password at all. Checked for the shape of UTF-16
/// text as well, because a wrong key can produce a `Length` that happens to fit.
fn password_at_the_end(plain: &[u8]) -> Option<Vec<u8>> {
    let length = u32::from_le_bytes(plain.get(512..516)?.try_into().ok()?) as usize;
    if length == 0 || length > 512 || length % 2 != 0 {
        return None;
    }
    let candidate = plain.get(512 - length..512)?;
    if !candidate
        .chunks_exact(2)
        .all(|pair| pair[1] == 0 || (0x04..=0x08).contains(&pair[1]))
    {
        return None;
    }
    Some(candidate.to_vec())
}

/// The `USER_INFORMATION_CLASS` names a log line is worth reading with (MS-SAMR 2.2.6.28).
///
/// The enumeration starts at **1** and skips numbers, which is not a detail: read as if it were
/// dense from zero, the class a join asks for - 16 - names the wrong structure, and answering the
/// wrong arm is a client that reports `0x6c5` (`RPC_S_INVALID_BOUND`) when it reads an array where
/// a word should be. Measured: 16 is `UserControlInformation`, the account's own flags.
fn info_class_name(class: u32) -> &'static str {
    match class {
        1 => "UserGeneralInformation",
        2 => "UserPreferencesInformation",
        3 => "UserLogonInformation",
        4 => "UserLogonHoursInformation",
        5 => "UserAccountInformation",
        6 => "UserNameInformation",
        7 => "UserAccountNameInformation",
        8 => "UserFullNameInformation",
        9 => "UserPrimaryGroupInformation",
        10 => "UserHomeInformation",
        11 => "UserScriptInformation",
        12 => "UserProfileInformation",
        13 => "UserAdminCommentInformation",
        14 => "UserWorkStationsInformation",
        16 => "UserControlInformation",
        17 => "UserExpiresInformation",
        18 => "UserInternal1Information",
        20 => "UserParametersInformation",
        21 => "UserAllInformation",
        23 => "UserInternal4Information",
        24 => "UserInternal5Information",
        25 => "UserInternal4InformationNew",
        26 => "UserInternal5InformationNew",
        31 => "UserInternal7Information",
        32 => "UserInternal8Information",
        _ => "unknown",
    }
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

    /// `samr_CreateUser2` as a client writes it: the domain handle, the name behind its referent and
    /// its two lengths, then the access and the unknown word.
    /// The 80 octets a Windows Server 2022 sends for `DOCKERW-K5E4442$`, taken from the stand.
    const CREATE_USER2: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x73, 0x61, 0x6d, 0x72, 0x20, 0x00, 0x22, 0x00, 0x00, 0x00, 0x02, 0x00, 0x11, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x44, 0x00, 0x4f, 0x00, 0x43,
        0x00, 0x4b, 0x00, 0x45, 0x00, 0x52, 0x00, 0x57, 0x00, 0x2d, 0x00, 0x4b, 0x00, 0x35, 0x00,
        0x45, 0x00, 0x34, 0x00, 0x34, 0x00, 0x34, 0x00, 0x32, 0x00, 0x24, 0x00, 0x80, 0x00, 0x00,
        0x00, 0xb0, 0x00, 0x05, 0xe0,
    ];

    /// `samr_CreateUser2` as a client writes it, for a name of the caller's choosing.
    fn create_stub(name: &str) -> Vec<u8> {
        let mut writer = NdrWriter::new();
        writer.bytes(&samr_handle());
        let octets = u16::try_from(name.encode_utf16().count() * 2).expect("a short name");
        writer.u16(octets); // Length
        writer.u16(octets + 2); // MaximumLength, with the terminating NUL
        writer.pointer(true); // the referent of the characters
        writer.string(name);
        writer.u32(0x0080);
        writer.u32(0x0000_0002);
        writer.finish()
    }

    /// The RID a Windows member opens its own account with, and the one it does not have.
    ///
    /// The bytes are a `netdom resetpwd` capture - `[handle 20][access 0xb0][rid]` - which is what
    /// settles that the access mask comes before the RID and that the handle travels as twenty
    /// octets. The RID here is the one the double answers for, because what is under test is the
    /// resolution and the handle, not the directory.
    #[tokio::test]
    async fn open_user_resolves_the_rid_and_answers_a_handle_that_names_it() {
        let mut stub = vec![0u8; 20];
        stub[16..].copy_from_slice(b"samr");
        stub.extend_from_slice(&0xb0_u32.to_le_bytes()); // access_mask
        stub.extend_from_slice(&1234_u32.to_le_bytes()); // rid

        let mut config = config();
        config.machine_accounts = Some(std::sync::Arc::new(CreatesAccounts));
        let server = state(config);
        let body = open_user(&server, &stub).await.expect("answered");
        assert_eq!(body.len(), 24, "the handle, then the status");
        let handle = &body[..20];
        assert_eq!(server.samr_user(handle).as_deref(), Some("SAMBA$"));
        assert_eq!(
            u32::from_le_bytes(body[20..24].try_into().expect("four octets")),
            0
        );
    }

    /// A RID this directory does not hold is refused, and answered with no handle at all: a handle
    /// here would name an account that does not exist, and the password change that follows would
    /// be applied to nobody while the client reported success.
    #[tokio::test]
    async fn open_user_refuses_a_rid_the_directory_does_not_hold() {
        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&0xb0_u32.to_le_bytes());
        stub.extend_from_slice(&999_u32.to_le_bytes());

        let server = state(config());
        let body = open_user(&server, &stub).await.expect("answered");
        assert_eq!(&body[..20], &[0u8; 20], "no handle is handed out");
        assert_eq!(
            u32::from_le_bytes(body[20..24].try_into().expect("four octets")),
            NTSTATUS_NO_SUCH_USER
        );
    }

    /// A whole server state, because the two writing calls read it: the handle table lives there.
    fn state(config: ServerConfig) -> ServerState {
        ServerState::new(
            config,
            crate::server::ServerUsers {
                table: Default::default(),
            },
            Vec::new(),
        )
    }

    fn caller() -> crate::server::Caller {
        crate::server::Caller {
            session_key: crate::server::SessionKey([0x11; 16]),
            identity: crate::proto::auth::ntlm::Identity::Anonymous,
            can_encrypt: true,
        }
    }

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
    /// The stub a client sends `samr_LookupDomain`: a handle and an `RPC_UNICODE_STRING`.
    ///
    /// The name part is the shape the reader has to expect, and it is the shape that was wrong on
    /// both sides at once: a fixture that wrote a bare pointer and a reader that expected one agreed
    /// with each other and disagreed with every real client, which is why the stand reported
    /// `STATUS_NO_SUCH_DOMAIN` for the domain it had just enumerated.
    fn lookup_stub(name: &str) -> Vec<u8> {
        let mut reader = NdrWriter::new();
        reader.bytes(&samr_handle());
        let octets = u16::try_from(name.encode_utf16().count() * 2).expect("a short name");
        reader.pointer(true); // the referent, before the struct it points at
        reader.u16(octets); // Length
        reader.u16(octets); // MaximumLength
        reader.pointer(true); // the characters, behind a pointer of their own
        reader.string(name);
        reader.finish()
    }

    /// The exact 28 octets a Windows Server 2022 sends as `samr_LookupDomain`, with an empty name.
    #[test]
    fn the_lookup_domain_a_windows_join_sends_is_read_and_answered() {
        let stub = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x73, 0x61, 0x6d, 0x72, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let body = dispatch(&config(), OPNUM_LOOKUP_DOMAIN, &stub).expect("answered");

        // `[out,ref] dom_sid2 *`: a referent, the SID, then the status.
        assert_ne!(&body[..4], &[0, 0, 0, 0], "the SID is a real pointer");
        let status = &body[body.len() - 4..];
        assert_eq!(
            u32::from_le_bytes(status.try_into().unwrap()),
            NTSTATUS_SUCCESS,
            "an empty name is the question \"which domain is this?\", not a name to refuse"
        );
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
    fn enumerate_domains_answers_one_domain_named_as_the_configuration_says() {
        // The call a member makes before it looks a domain up by name. A fault here sends it to the
        // next controller, so the answer has to be well formed even when there is nothing to say.
        let stub = samr_handle(); // the server handle, and nothing else
        let body = dispatch(&config(), OPNUM_ENUMERATE_DOMAINS, &stub).expect("answered");

        let word = |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().unwrap());
        #[allow(clippy::cast_possible_truncation)]
        let short = |at: usize| u16::from_le_bytes(body[at..at + 2].try_into().unwrap());

        // Offsets, in the order the IDL marshals them - the whole point of the test:
        //
        //    0  EnumerationContext        24  array actual_count
        //    4  buffer pointer            28  entry RelativeId
        //    8  EntriesRead               32  name length (octets)
        //   12  array pointer             34  name size   (octets)
        //   16  array max_count           36  name pointer
        //   20  array offset              40  chars max_count
        //                                  44  chars offset
        //                                  48  chars actual_count
        //                                  52  the units
        //                                  56  CountReturned
        //                                  60  status
        assert_eq!(body.len(), 64);
        assert_eq!(word(0), 0, "EnumerationContext");
        assert_ne!(word(4), 0, "the enumeration buffer is a real pointer");
        assert_eq!(word(8), 1, "EntriesRead");
        assert_ne!(word(12), 0, "the array is behind its own pointer");
        assert_eq!(word(16), 1, "the array could hold one");
        assert_eq!(word(20), 0, "no offset: the whole array is here");
        assert_eq!(word(24), 1, "and exactly one entry is");
        assert_eq!(word(28), 0, "a domain has no RelativeId");
        assert_eq!(short(32), 4, "\"AD\" is two units, counted in octets");
        assert_eq!(short(34), 4);
        assert_ne!(word(36), 0, "the characters are deferred, behind a pointer");
        assert_eq!(word(40), 2);
        assert_eq!(word(44), 0);
        assert_eq!(word(48), 2);
        let text: String = (0..2)
            .map(|index| char::from_u32(u32::from(short(52 + index * 2))).expect("a unit"))
            .collect();
        assert_eq!(
            text, "AD",
            "the NetBIOS name a client matches its configuration against"
        );
        assert_eq!(word(56), 1, "CountReturned");
        let status = body.len() - 4;
        assert_eq!(word(status), NTSTATUS_SUCCESS);
    }

    /// A 516-octet password block: `Pässwörd-123` behind `Length`, filled with a pattern, RC4-encrypted
    /// under `MD5(salt || key)` with the key and salt below.
    ///
    /// Built **outside** this crate on purpose: a fixture produced by the same code that reads it
    /// agrees with its own mistakes. This one was made by an RC4 and an MD5 that share nothing with
    /// the ones below but the published algorithms.
    #[rustfmt::skip]
    const PASSWORD_BLOCK: &[u8] = &[
            0xff, 0xbe, 0x53, 0xf6, 0xe5, 0xb8, 0xd5, 0xf3, 0x1c, 0x70, 0x00, 0x53, 0x15, 0x65, 0x6d, 0x33,
            0xda, 0x57, 0x63, 0x4e, 0x19, 0x7a, 0xe3, 0x8a, 0x5e, 0x9b, 0x6a, 0x91, 0xc0, 0x8e, 0x8f, 0xe7,
            0x6c, 0x4b, 0xa6, 0x90, 0x77, 0x34, 0xd4, 0x56, 0x03, 0x7f, 0x60, 0xff, 0x22, 0xee, 0x8b, 0xa4,
            0xba, 0x68, 0xe1, 0x94, 0xcd, 0x0f, 0xb5, 0xcd, 0xd1, 0xd2, 0xe0, 0xbb, 0xcf, 0xfb, 0x63, 0xd9,
            0xae, 0xc8, 0xf6, 0xd1, 0xbe, 0x87, 0x59, 0xaa, 0x66, 0xf7, 0x8e, 0x36, 0x33, 0x7c, 0x52, 0x8a,
            0x7f, 0x38, 0xd8, 0x8a, 0x36, 0x46, 0x33, 0x68, 0x40, 0x88, 0x47, 0x50, 0xc7, 0xb9, 0x39, 0x19,
            0x18, 0x2f, 0x33, 0xae, 0xfe, 0x34, 0xe3, 0xbf, 0x8c, 0x9b, 0x1b, 0x48, 0x09, 0xc3, 0xd7, 0x9c,
            0x76, 0xa0, 0x72, 0xbe, 0xa4, 0xb1, 0xd2, 0x5b, 0xab, 0x06, 0x94, 0xac, 0x05, 0xd7, 0x6e, 0x6b,
            0x70, 0xbc, 0x12, 0x72, 0xf1, 0x68, 0x98, 0xae, 0x6e, 0xb9, 0xb1, 0x1a, 0xe5, 0xea, 0x4d, 0x55,
            0x56, 0xc3, 0x43, 0x7c, 0x4e, 0x62, 0xce, 0x38, 0x36, 0xa1, 0x7e, 0xd0, 0x3e, 0xfb, 0x4d, 0x0a,
            0xc6, 0x7e, 0x58, 0x6d, 0xe2, 0xa5, 0x22, 0x82, 0x47, 0x86, 0x1b, 0xd1, 0xad, 0x21, 0xad, 0x3d,
            0x0a, 0xdf, 0x94, 0xa0, 0xb5, 0x30, 0xee, 0x63, 0xc7, 0x1f, 0xfd, 0x47, 0x18, 0x57, 0x32, 0x03,
            0x2c, 0xe3, 0xe9, 0x44, 0xdb, 0xb2, 0x03, 0x1d, 0xd0, 0x7e, 0x67, 0x17, 0x12, 0xa7, 0x97, 0xf6,
            0xd4, 0x89, 0x83, 0xbc, 0x13, 0x2b, 0x9f, 0x16, 0xd5, 0x08, 0xb2, 0x7c, 0xb0, 0x8a, 0x6c, 0xf2,
            0x4a, 0x4a, 0xf3, 0xa5, 0x68, 0x38, 0x25, 0xac, 0x11, 0xdf, 0x3d, 0xda, 0x6b, 0xef, 0xed, 0x55,
            0x85, 0x84, 0x2a, 0x23, 0x58, 0x81, 0xd7, 0x78, 0x20, 0x8f, 0x3a, 0x34, 0x4b, 0x3a, 0x86, 0xd5,
            0xbc, 0x9b, 0x3e, 0x54, 0x5b, 0x95, 0x40, 0x38, 0x3a, 0x11, 0x52, 0xf5, 0x87, 0xd6, 0x68, 0x62,
            0x75, 0xad, 0xd1, 0x9c, 0xdb, 0x9d, 0xff, 0x51, 0xf5, 0x8e, 0x73, 0x93, 0x1c, 0xc2, 0xf7, 0xda,
            0xc1, 0xaa, 0x1c, 0x78, 0x84, 0x8f, 0x6b, 0x90, 0x22, 0x92, 0x80, 0x99, 0x56, 0x07, 0x65, 0xb8,
            0x20, 0x45, 0xca, 0xc1, 0x2a, 0x0d, 0x75, 0xe8, 0xac, 0xd0, 0x09, 0x5d, 0x59, 0xd7, 0x01, 0xe6,
            0xc8, 0x59, 0xf9, 0x3c, 0xaa, 0xf0, 0x8e, 0xb4, 0x97, 0x59, 0x0c, 0x21, 0x54, 0x7e, 0x69, 0x75,
            0x19, 0x91, 0xc5, 0x5e, 0x7e, 0xce, 0xfa, 0x25, 0x04, 0xf7, 0xda, 0xd1, 0x3e, 0x48, 0xb7, 0x19,
            0xee, 0x4b, 0x78, 0xd5, 0x97, 0xca, 0x27, 0xa2, 0x20, 0x0b, 0x94, 0x26, 0xc1, 0x56, 0x03, 0xf5,
            0x3f, 0xfb, 0x02, 0x02, 0x19, 0x20, 0x89, 0x87, 0xac, 0x41, 0x47, 0x4f, 0x2e, 0x28, 0xf5, 0xdb,
            0x20, 0xe8, 0x99, 0xdc, 0x4c, 0xc0, 0xf9, 0x1b, 0x42, 0x2c, 0xbc, 0xf7, 0xec, 0x20, 0xc0, 0x86,
            0xc8, 0x33, 0xf5, 0x3d, 0x7a, 0x1b, 0x68, 0xd3, 0x30, 0xb4, 0x63, 0xef, 0x9b, 0xa9, 0xd1, 0x01,
            0x45, 0xa7, 0x8b, 0x38, 0x5c, 0x90, 0x59, 0xc9, 0x67, 0x80, 0xe6, 0x68, 0x9f, 0x9d, 0xd4, 0x9f,
            0x27, 0x87, 0x92, 0x9d, 0x91, 0xe7, 0x2c, 0xc1, 0xc3, 0x3b, 0xa4, 0x9e, 0x06, 0x75, 0x5f, 0x88,
            0x94, 0x08, 0xd5, 0xc5, 0xec, 0x8f, 0xb5, 0xa9, 0xe3, 0xc9, 0x56, 0x92, 0x5e, 0x92, 0x7e, 0xad,
            0x4d, 0xd7, 0xf7, 0x2d, 0xc7, 0xbd, 0x6b, 0xe7, 0x65, 0xa2, 0xda, 0xeb, 0x17, 0xa9, 0xd7, 0x13,
            0x0f, 0x41, 0xba, 0x68, 0x46, 0xf8, 0x37, 0xb6, 0x53, 0xef, 0xb0, 0x3b, 0xa1, 0x1c, 0xcd, 0x46,
            0x0c, 0xfa, 0x3c, 0x93, 0x9c, 0xc1, 0x99, 0xf5, 0x58, 0x5e, 0x27, 0x42, 0x0d, 0x50, 0xf9, 0x0c,
            0x1d, 0xc2, 0xd9, 0x20
    ];

    #[test]
    fn a_password_a_client_encrypted_opens_under_its_session_key() {
        let password = open_password(
            PASSWORD_BLOCK,
            [0x22; 16],
            crate::server::SessionKey([0x11; 16]),
        )
        .expect("the block must open under the key it was sealed with");

        let text = String::from_utf16_lossy(
            &password
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        );
        assert_eq!(text, "Pässwörd-123", "read from the end of the buffer");
    }

    #[test]
    fn the_same_password_block_does_not_open_under_another_key() {
        // The salt is what makes this so: two sessions never share one, so a block captured from one
        // is worthless in the other, and a server that ignored the salt would auth the wrong thing.
        assert!(
            open_password(
                PASSWORD_BLOCK,
                [0x22; 16],
                crate::server::SessionKey([0x12; 16]),
            )
            .is_none(),
            "another session key must not produce a password"
        );
    }

    #[tokio::test]
    async fn set_information_user2_names_the_class_and_refuses() {
        // The class has to be read correctly even when it is not answered, because the log line is
        // the only thing that says which write is missing. Reading the enum as a word instead of a
        // half word would name the class from half a number and the first two octets of the union.
        let server = state(config());
        let handle = server.remember_samr_user("samba$");
        let mut writer = NdrWriter::new();
        writer.bytes(&handle);
        writer.u16(4); // UserAccountInformation
        writer.raw(&[0u8; 32]); // the union's arm, unread
        let stub = writer.finish();
        let body = set_information_user2(&server, &caller(), &stub)
            .await
            .expect("answered");
        assert_eq!(body.len(), 4, "only a status comes back");
        assert_eq!(
            u32::from_le_bytes(body[..4].try_into().unwrap()),
            NTSTATUS_NOT_SUPPORTED
        );
    }

    #[test]
    fn every_information_class_has_a_name() {
        // A number in a log is a chore; the name is a piece of work with a scope.
        // The enum starts at one and skips: 16 is the flags, 21 everything, 20 the TS parameters.
        // Read as if it were dense from zero, 16 would name `UserParametersInformation`.
        assert_eq!(info_class_name(5), "UserAccountInformation");
        assert_eq!(info_class_name(16), "UserControlInformation");
        assert_eq!(info_class_name(20), "UserParametersInformation");
        assert_eq!(info_class_name(21), "UserAllInformation");
        assert_eq!(info_class_name(9999), "unknown");
    }

    #[test]
    fn connect5_echoes_the_level_it_answers_with() {
        let mut writer = NdrWriter::new();
        writer.string("\\\\samba");
        writer.u32(0x0000_0030);
        writer.u32(0);
        let stub = writer.finish();

        let body = dispatch(&config(), OPNUM_CONNECT5, &stub).expect("answered");

        // OutVersion, the union's ULONG tag, the arm, the handle inline, the status. Nothing here is
        // a pointer, and a client that reads `OutVersion` as one rejects the whole stub - which is
        // how this failure was found: `0x6f7 RPC_X_BAD_STUB_DATA` on the first RPC call of a join.
        assert_eq!(body.len(), 40, "4 + 4 + 4 + 4 + 20 + 4");
        assert_eq!(u32::from_le_bytes(body[0..4].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(body[4..8].try_into().unwrap()),
            1,
            "case 1"
        );
        assert_eq!(
            u32::from_le_bytes(body[8..12].try_into().unwrap()),
            SAMR_CONNECT_AFTER_W2K
        );
        assert_eq!(u32::from_le_bytes(body[12..16].try_into().unwrap()), 0);
        assert_eq!(&body[16..36], &samr_handle(), "the handle, inline");
        assert_eq!(&body[36..], &[0, 0, 0, 0]);
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

    /// A directory that creates one account and remembers nothing else: enough to see that the
    /// handle comes back, that it names the account, and that the RID is the directory's.
    #[derive(Debug)]
    struct CreatesAccounts;

    #[async_trait::async_trait]
    impl crate::server::MachineAccounts for CreatesAccounts {
        async fn create_machine(&self, name: &str) -> Option<u32> {
            name.ends_with('$').then_some(1234)
        }

        async fn machine_control(&self, name: &str) -> Option<u32> {
            name.ends_with('$').then_some(0x1000)
        }

        async fn delete_machine(&self, name: &str) -> bool {
            name.ends_with('$')
        }

        async fn account_of_rid(&self, rid: u32) -> Option<String> {
            (rid == 1234).then(|| "SAMBA$".to_string())
        }
    }

    /// The capture itself: the name has to come out of these octets as the client wrote it, and the
    /// access as `0x80`. Measured - read with the referent first, this stub yielded no name at all
    /// and the directory refused an account called `""`.
    #[tokio::test]
    async fn the_create_user2_a_windows_join_sends_names_its_machine() {
        let mut config = config();
        config.machine_accounts = Some(std::sync::Arc::new(CreatesAccounts));
        let body = create_user2(&state(config), CREATE_USER2)
            .await
            .expect("answered");
        let word = |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().unwrap());
        assert_eq!(
            word(body.len() - 4),
            NTSTATUS_SUCCESS,
            "a name read correctly is an account the directory can create"
        );
        assert_eq!(word(20), 0x80, "the access the capture asked for");
    }

    #[tokio::test]
    async fn a_machine_account_the_directory_creates_comes_back_as_a_handle_that_names_it() {
        let mut config = config();
        config.machine_accounts = Some(std::sync::Arc::new(CreatesAccounts));
        let server = state(config);

        let stub = create_stub("DOCKERW-K5E4442$");

        let body = create_user2(&server, &stub).await.expect("answered");
        let word = |at: usize| u32::from_le_bytes(body[at..at + 4].try_into().unwrap());

        assert_eq!(word(body.len() - 4), NTSTATUS_SUCCESS);
        assert_eq!(word(20), 0x0080, "the access the caller asked for");
        assert_eq!(word(24), 1234, "the RID the directory gave the account");
        assert_ne!(
            &body[..20],
            &[0u8; 20],
            "a handle this server can resolve, not an empty one"
        );
        assert_eq!(
            server.samr_user(&body[..20]).as_deref(),
            Some("DOCKERW-K5E4442$"),
            "and the password that follows names this account through it"
        );
    }

    #[tokio::test]
    async fn creating_a_machine_account_is_refused_and_the_reply_still_has_its_shape() {
        // `[out,ref]` pointers are non-null, so a client's unmarshalling needs them present before
        // it reads the status: an empty stub with a non-zero status reports a marshalling error
        // instead of the refusal it carried.
        let stub = create_stub("samba$");

        let body = create_user2(&state(config()), &stub)
            .await
            .expect("refused, not failed");

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

    /// A directory with one machine account, and nothing else.
    #[derive(Debug)]
    struct OneMachine {
        name: String,
        rid: u32,
    }

    impl crate::server::MachineSecrets for OneMachine {
        fn machine(&self, account: &str) -> Option<crate::server::MachineAccount> {
            if account.eq_ignore_ascii_case(&self.name) {
                Some(crate::server::MachineAccount {
                    nt_hash: [0x5a; 16],
                    rid: self.rid,
                })
            } else {
                None
            }
        }
    }

    fn config_with_machine(name: &str, rid: u32) -> ServerConfig {
        let mut config = config();
        config.machine_secrets = Some(std::sync::Arc::new(OneMachine {
            name: name.to_string(),
            rid,
        }));
        config
    }

    /// The stub Samba sends: a domain handle, one or more names, and each name behind its pointer.
    fn lookup_names_stub(names: &[&str]) -> Vec<u8> {
        let count = u32::try_from(names.len()).expect("a small count");
        let mut stub = Vec::new();
        stub.extend_from_slice(&samr_handle());
        stub.extend_from_slice(&count.to_le_bytes());
        // The conformant-varying array: the maximum the interface allows, the offset, and how many
        // are actually there.
        stub.extend_from_slice(&1000u32.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&count.to_le_bytes());
        for name in names {
            // `lsa_String`: the length in octets, the size, then the referent.
            let octets = u16::try_from(name.len() * 2).expect("a short name");
            stub.extend_from_slice(&octets.to_le_bytes());
            stub.extend_from_slice(&octets.to_le_bytes());
            stub.extend_from_slice(&0x0002_0000u32.to_le_bytes());
        }
        for name in names {
            // The characters as a conformant-varying array of units, with no terminator: a live
            // client's name is six units for "samba$", not seven.
            let units: Vec<u16> = name.encode_utf16().collect();
            let length = u32::try_from(units.len()).expect("a short name");
            stub.extend_from_slice(&length.to_le_bytes());
            stub.extend_from_slice(&0u32.to_le_bytes());
            stub.extend_from_slice(&length.to_le_bytes());
            for unit in units {
                stub.extend_from_slice(&unit.to_le_bytes());
            }
        }
        stub
    }

    /// The two `samr_Ids` a reply carries, read back so a test asserts on values rather than on
    /// offsets. Returns the count, the ids, and where the struct ended.
    fn samr_ids(reply: &[u8], at: usize) -> (usize, Vec<u32>, usize) {
        let word = |offset: usize| {
            u32::from_le_bytes(
                reply[offset..offset + 4]
                    .try_into()
                    .unwrap_or_else(|_| panic!("four octets at {offset} of {}", reply.len())),
            )
        };
        // No referent for the struct: a `[ref]` pointee is marshalled in place. The array inside
        // it is a plain pointer and does carry one.
        let count = word(at) as usize;
        assert_ne!(word(at + 4), 0, "the ids array travels behind a pointer");
        let max = word(at + 8) as usize;
        let ids = (0..max).map(|i| word(at + 12 + 4 * i)).collect();
        (count, ids, at + 12 + 4 * max)
    }

    /// A machine account is found by the name a join asks for, and reported as a **user**.
    ///
    /// The name type is measured, not guessed: Samba's `libnet_join.c` refuses anything but
    /// `SID_NAME_USER` at the lookup it makes right after creating the account, with the comment
    /// "We *must* do this.... don't ask...", and answers `INVALID_WORKSTATION` even when the RID is
    /// right. Reporting `SID_NAME_COMPUTER` - what AD calls a machine - fails the join.
    #[test]
    fn a_machine_account_is_looked_up_by_name_and_reported_as_a_user() {
        let config = config_with_machine("SAMBA$", 1000);
        let body = dispatch(&config, OPNUM_LOOKUP_NAMES, &lookup_names_stub(&["SAMBA$"]))
            .expect("answered");

        let (rids_count, rids, after_rids) = samr_ids(&body, 0);
        assert_eq!(rids_count, 1, "one name asked, one RID answered");
        assert_eq!(rids, vec![1000]);

        let (types_count, types, after_types) = samr_ids(&body, after_rids);
        assert_eq!(types_count, 1);
        assert_eq!(
            types,
            vec![1],
            "SID_NAME_USER, which is what a join demands"
        );

        assert_eq!(
            u32::from_le_bytes(
                body[after_types..after_types + 4]
                    .try_into()
                    .expect("status")
            ),
            NTSTATUS_SUCCESS
        );
    }

    /// A name this server does not serve is reported as unmapped, not as somebody's RID.
    #[test]
    fn an_unknown_name_maps_to_nothing() {
        let config = config_with_machine("SAMBA$", 1000);
        let body = dispatch(&config, OPNUM_LOOKUP_NAMES, &lookup_names_stub(&["GHOST$"]))
            .expect("answered");

        let (_, rids, after_rids) = samr_ids(&body, 0);
        assert_eq!(rids, vec![0], "an unmapped name has no RID");
        let (_, types, after_types) = samr_ids(&body, after_rids);
        assert_eq!(types, vec![0], "SID_NAME_UNKNOWN");
        assert_eq!(
            u32::from_le_bytes(
                body[after_types..after_types + 4]
                    .try_into()
                    .expect("status")
            ),
            STATUS_NONE_MAPPED,
            "no name mapped is the status that says so"
        );
    }

    /// A server with no directory behind it maps nothing, and says so rather than answering zero
    /// with success - which a client reads as "the account exists with RID 0".
    #[test]
    fn without_a_directory_no_name_maps() {
        let config = config();
        assert!(config.machine_secrets.is_none(), "the fixture has none");
        let body = dispatch(&config, OPNUM_LOOKUP_NAMES, &lookup_names_stub(&["SAMBA$"]))
            .expect("answered");

        let (_, rids, after_rids) = samr_ids(&body, 0);
        assert_eq!(rids, vec![0]);
        let (_, _, after_types) = samr_ids(&body, after_rids);
        assert_eq!(
            u32::from_le_bytes(
                body[after_types..after_types + 4]
                    .try_into()
                    .expect("status")
            ),
            STATUS_NONE_MAPPED
        );
    }

    /// Two names, one served and one not: the array keeps its order, and the status is the warning
    /// that says half of it worked.
    ///
    /// A single-name fixture cannot tell "maps each name" from "maps the first and copies it", and
    /// `STATUS_SOME_NOT_MAPPED` is unreachable with one name - which is how a branch that returns
    /// it came to sit untested.
    #[test]
    fn a_partly_mapped_request_answers_both_slots() {
        let config = config_with_machine("SAMBA$", 1000);
        let body = dispatch(
            &config,
            OPNUM_LOOKUP_NAMES,
            &lookup_names_stub(&["SAMBA$", "GHOST$"]),
        )
        .expect("answered");

        let (rids_count, rids, after_rids) = samr_ids(&body, 0);
        assert_eq!(rids_count, 2);
        assert_eq!(
            rids,
            vec![1000, 0],
            "the RID stays in the position asked for"
        );
        let (_, types, after_types) = samr_ids(&body, after_rids);
        assert_eq!(types, vec![1, 0]);
        assert_eq!(
            u32::from_le_bytes(
                body[after_types..after_types + 4]
                    .try_into()
                    .expect("status")
            ),
            STATUS_SOME_NOT_MAPPED
        );
    }
}
