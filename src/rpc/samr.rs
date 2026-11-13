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
/// `samr_OpenDomain` (opnum 7).
pub(crate) const OPNUM_OPEN_DOMAIN: u16 = 7;
/// `samr_CreateUser2` (opnum 50): where the machine account would be created.
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
        OPNUM_ENUMERATE_DOMAINS => enumerate_domains(config),
        OPNUM_LOOKUP_DOMAIN => lookup_domain(config, stub),
        OPNUM_LOOKUP_NAMES => lookup_names(config, stub),
        OPNUM_CREATE_USER2 => create_user2(stub),
        OPNUM_SET_INFO_USER2 => set_information_user2(stub),
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
    // `RPC_UNICODE_STRING` is `{ Length <H, MaximumLength <H, Data LPWSTR }` - two two-octet
    // lengths and *then* the pointer to the characters. Reading it as a bare pointer consumed the
    // two lengths as that pointer and then read the pointer as a string header, so every name came
    // out as nonsense, `matches` was false, and the client was told `STATUS_NO_SUCH_DOMAIN` for the
    // domain it had just enumerated: `NetpProvisionComputerAccount: 0x54b`.
    let _length = reader.u16();
    let _maximum = reader.u16();
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

/// `samr_SetInformationUser2`: read, named, and refused - the write belongs to the directory.
///
/// MS-SAMR 3.1.5.6.34 sends a user handle, a `USER_INFORMATION_CLASS` and a union whose arm the
/// class selects. This crate holds no store, so the honest answer is `NOT_SUPPORTED`; what makes the
/// answer useful is naming the class, because "the client asked for something" and "the client asked
/// for `UserAccountInformation`" are different pieces of work for whoever implements the hook.
///
/// The enum travels as a half word, like `secure_channel_type` in the Netlogon interface (measured
/// there: `0200`); the union's discriminant on the wire is the same value.
fn set_information_user2(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let Some(_handle) = reader.bytes(20) else {
        return Err(malformed_at("user_handle", stub));
    };
    // Both widths are read: a producer that declares the enum `v1_enum` sends four octets, and
    // reading the wrong width would name the class from half a number and the first two octets of
    // the union.
    let narrow = reader.u16();
    let wide = {
        let mut again = NdrReader::new(stub);
        let _ = again.bytes(20);
        again.u32()
    };
    let class = narrow.map(u32::from).or(wide).unwrap_or(u32::MAX);

    tracing::warn!(
        class,
        name = info_class_name(class),
        stub = stub.len(),
        "samr: SetInformationUser2 is a directory write, and this server has no directory to write \
         it to. The class is named so the missing hook is a known piece of work rather than a \
         number in a log."
    );

    // The reply to this call has no out parameters beyond the status.
    let mut writer = NdrWriter::new();
    writer.u32(NTSTATUS_NOT_SUPPORTED);
    Ok(writer.finish())
}

/// The `USER_INFORMATION_CLASS` names a log line is worth reading with (MS-SAMR 2.2.5.20).
fn info_class_name(class: u32) -> &'static str {
    match class {
        0 => "UserGeneralInformation",
        1 => "UserPreferencesInformation",
        2 => "UserLogonInformation",
        3 => "UserLogonHoursInformation",
        4 => "UserAccountInformation",
        5 => "UserNameInformation",
        6 => "UserAccountNameInformation",
        7 => "UserFullNameInformation",
        8 => "UserPrimaryGroupInformation",
        9 => "UserHomeInformation",
        10 => "UserScriptInformation",
        11 => "UserProfileInformation",
        12 => "UserAdminCommentInformation",
        13 => "UserWorkStationsInformation",
        14 => "UserControlInformation",
        15 => "UserExpiresInformation",
        16 => "UserParametersInformation",
        17 => "UserAllInformation",
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
        reader.u16(octets); // Length
        reader.u16(octets); // MaximumLength
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

    #[test]
    fn set_information_user2_names_the_class_and_refuses() {
        // The call a join makes last. This crate has no store, so the answer is `NOT_SUPPORTED` - and
        // the class has to be read correctly anyway, because the log line is the only thing that says
        // which write is missing. Reading the enum as a word instead of a half word would name the
        // class from half a number and the first two octets of the union.
        let mut writer = NdrWriter::new();
        writer.bytes(&samr_handle());
        writer.u16(4); // UserAccountInformation
        writer.raw(&[0u8; 32]); // the union's arm, unread
        let stub = writer.finish();

        let body = dispatch(&config(), OPNUM_SET_INFO_USER2, &stub).expect("answered");
        assert_eq!(body.len(), 4, "only a status comes back");
        assert_eq!(
            u32::from_le_bytes(body[..4].try_into().unwrap()),
            NTSTATUS_NOT_SUPPORTED
        );
    }

    #[test]
    fn every_information_class_has_a_name() {
        // A number in a log is a chore; the name is a piece of work with a scope.
        assert_eq!(info_class_name(4), "UserAccountInformation");
        assert_eq!(info_class_name(14), "UserControlInformation");
        assert_eq!(info_class_name(17), "UserAllInformation");
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
