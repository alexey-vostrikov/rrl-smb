//! `drsuapi` (MS-DRSR): the interface a member binds to before it learns where its own account goes.
//!
//! One call is implemented, and it is the one a join makes first: `IDL_DRSBind` (opnum 0). A Windows
//! client reaches it over `ncacn_ip_tcp` after the endpoint mapper names a port for
//! `e3514235-4b06-11d1-ab04-00c04fc2dcd2` version 4.0 - the tower it sends to the mapper was measured
//! on the stand, and `NetpGetComputerObjectDn` is the step that asks.
//!
//! # Why this is not a stub that says "no"
//!
//! `DRSBind` is not a no-op to a client: the answer carries `DRS_EXTENSIONS`, the flags that say what
//! the server can do, and the client behaves differently depending on them. An answer that faults
//! leaves the client with nothing to read and a message about access; an answer that binds with a
//! truthful, empty extension set says "this server supports none of the optional DRS behaviours",
//! which is exactly true here and is something a client can act on.
//!
//! Everything past the bind is refused **by name**, because on this interface the difference between
//! "this server does not implement that call" and "this server refused it" decides whether a client
//! retries, falls back, or stops.

use super::association::Fault;
use super::ndr::{NdrReader, NdrWriter};
use super::pdu::{NCA_OP_RNG_ERROR, NCA_PROTO_ERROR};

/// `IDL_DRSBind` (opnum 0): the first call on the interface.
pub(crate) const OPNUM_BIND: u16 = 0;
/// `IDL_DRSUnbind` (opnum 1): the last one a well-behaved client sends.
pub(crate) const OPNUM_UNBIND: u16 = 1;
/// `IDL_DRSCrackNames` (opnum 12): what a join asks before it can name its own account.
pub(crate) const OPNUM_CRACK_NAMES: u16 = 12;

/// The names a `DRSCrackNames` answer is built from.
///
/// Two, and both already known to this server: a client arriving with `ad.example.com/` wants the
/// NetBIOS domain name, and one arriving with a canonical name of its own object wants the DN the
/// directory filed it under. Measured: a Windows join's first call after `DsBind` is
/// `DRSCrackNames` with `formatOffered` 7 (`DS_CANONICAL_NAME`), `formatDesired` 2
/// (`DS_NT4_ACCOUNT_NAME`) and the single name `ad.example.com/`.
#[derive(Debug, Clone)]
pub struct CrackNames {
    /// The domain's NetBIOS name, `AD`.
    pub nb_domain: String,
    /// The domain's DNS name, `ad.example.com`.
    pub dns_domain: String,
}

/// `DRS_NAME_ERROR_*` values a result item carries.
const NAME_ERROR_NONE: u32 = 0;
/// `DS_NAME_ERROR_NO_MAPPING`: this server has no name of that shape for what was asked.
const NAME_ERROR_NO_MAPPING: u32 = 2;

/// `DS_CANONICAL_NAME`: `ad.example.com/`.
const FORMAT_CANONICAL: u32 = 7;
/// `DS_FQDN_1779_NAME`: a distinguished name.
const FORMAT_FQDN_1779: u32 = 1;
/// `DS_NT4_ACCOUNT_NAME`: `AD` or `AD\HOST$`.
const FORMAT_NT4_ACCOUNT: u32 = 2;

/// `ERROR_SUCCESS`.
const STATUS_SUCCESS: u32 = 0;

/// The twenty octets a `DRS_HANDLE` is (MS-DRSR 5.34): an opaque value the client echoes back.
///
/// Not zero: a client that receives a null handle treats the bind as failed even with a success
/// status, because a null context handle is how this interface says "nothing was bound".
const DRS_HANDLE: [u8; 20] = [
    0x01, 0x00, 0x00, 0x00, // handle_type: a real, non-null context
    0x52, 0x52, 0x4c, 0x44, // "RRLD", so a trace of the wire says which server answered
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Answers one call on `drsuapi`.
pub(crate) fn serve(opnum: u16, stub: &[u8], names: Option<&CrackNames>) -> Result<Vec<u8>, Fault> {
    match opnum {
        OPNUM_BIND => dsa_bind(stub),
        OPNUM_UNBIND => Ok(unbind()),
        OPNUM_CRACK_NAMES => crack_names(stub, names),
        other => {
            // The number and the name, because a client reports only "the procedure number is out
            // of range" and which call it wanted is the whole of the work to plan.
            tracing::warn!(
                opnum = other,
                name = opnum_name(other),
                stub = stub.len(),
                hex = %if std::env::var_os("RRL_EPM_DIAG").is_some() {
                    stub.iter().map(|b| format!("{b:02x}")).collect::<String>()
                } else {
                    String::new()
                },
                "drsuapi: no handler for this call"
            );
            Err(Fault {
                status: NCA_OP_RNG_ERROR,
                did_not_execute: true,
            })
        }
    }
}

/// `IDL_DRSBind` (MS-DRSR 4.1.3).
///
/// In: `puuidClientDsa` (a `[ref]` pointer to the client's DSA GUID, which may be NULL), and
/// `pextClient` (a `[ref]` pointer to the client's `DRS_EXTENSIONS`). Out: the server's
/// `DRS_EXTENSIONS`, a `DRS_HANDLE`, and a status.
fn dsa_bind(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    // The request's own octets behind a diagnostic flag: this call's layout is the one thing here
    // that only a client can settle, and a misread `DS_EXTENSIONS` is invisible in the answer.
    if std::env::var_os("RRL_EPM_DIAG").is_some() {
        tracing::warn!(
            stub = %stub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "drsuapi: DsBind request bytes"
        );
    }
    let mut reader = NdrReader::new(stub);
    // `puuidClientDsa`: a referent, then the sixteen octets behind it. A null referent is a client
    // that has no DSA GUID yet, which is legal and happens on a first bind.
    let client_dsa_present = reader.pointer().unwrap_or(false);
    let client_dsa = client_dsa_present.then(|| reader.bytes(16)).flatten();
    // `pextClient`: a referent, then `{ cb: DWORD, rgb: BYTE[cb] }`.
    let ext_present = reader.pointer().unwrap_or(false);
    let (client_cb, client_flags) = if ext_present {
        match (reader.u32(), reader.u32()) {
            (Some(cb), Some(max)) => {
                let bytes = reader.bytes(max as usize);
                // `dwFlags` is the first field of `DRS_EXTENSIONS_INT`, so the first four octets of
                // the blob say what the client can do. Read for the log: a client that offers
                // something this server does not can be understood from one line.
                let flags = bytes
                    .filter(|bytes| bytes.len() >= 4)
                    .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                    .unwrap_or(0);
                (cb, flags)
            }
            _ => (0, 0),
        }
    } else {
        (0, 0)
    };

    tracing::info!(
        client_dsa = client_dsa.is_some(),
        client_ext_cb = client_cb,
        client_flags = format_args!("0x{client_flags:08x}"),
        "drsuapi: DsBind accepted; the server advertises no optional DRS behaviour"
    );

    let mut writer = NdrWriter::new();
    // `[out,ref] DRS_EXTENSIONS *ppextServer`: a referent, then `{cb, rgb}` with `rgb` a conformant
    // (not varying) array, so it is a maximum count and the octets.
    let extension = drs_extensions_int();
    writer.pointer(true);
    writer.u32(u32::try_from(extension.len()).expect("a short blob"));
    writer.u32(u32::try_from(extension.len()).expect("a short blob"));
    writer.raw(&extension);
    writer.align(4);
    // `[out] DRS_HANDLE phDrs`: twenty octets, aligned to four, inline.
    writer.bytes(&DRS_HANDLE);
    writer.u32(STATUS_SUCCESS);
    Ok(writer.finish())
}

/// `DRS_EXTENSIONS_INT` (MS-DRSR 5.39) with every optional flag clear.
///
/// The flags are what a client reads to decide which DRS behaviours it may use: async replication,
/// linked-value replication, `GetNCChanges` extensions, and so on. This server implements none of
/// them, so the honest value is zero - a client that sees it asks for nothing optional and gets a
/// plain answer rather than a surprise halfway through a replication attempt.
///
/// Forty-eight octets, which is what a live Samba controller sends and what a client reads:
/// `dwFlags`, `SiteObjGuid`, `Pid`, `dwReplEpoch`, `dwFlagsExt`, `ConfigObjGUID`.
///
/// `dwExtCaps` is not part of it. An extra four octets here shift `phDrs` and the status by four,
/// and a client that reads its handle from the wrong place sees a bind it cannot use - measured:
/// with fifty-two the join stopped right after `DsBind`, with forty-eight it goes on.
fn drs_extensions_int() -> Vec<u8> {
    let mut blob = Vec::with_capacity(48);
    blob.extend_from_slice(&0u32.to_le_bytes()); // dwFlags: no optional behaviour
    blob.extend_from_slice(&[0u8; 16]); // SiteObjGuid: this server has no site
    blob.extend_from_slice(&0u32.to_le_bytes()); // Pid: not a replication partner
    blob.extend_from_slice(&0u32.to_le_bytes()); // dwReplEpoch
    blob.extend_from_slice(&0u32.to_le_bytes()); // dwFlagsExt
    blob.extend_from_slice(&[0u8; 16]); // ConfigObjGUID
    blob
}

/// `IDL_DRSCrackNames` (MS-DRSR 4.1.4): from one shape of a name to another.
///
/// A join asks this before it can name its own account - `NetpGetComputerObjectDn` is the step, and
/// without an answer the join stops before it ever reaches the directory. What arrives here,
/// measured, is `ad.example.com/` as a canonical name wanting its NT4 form.
fn crack_names(stub: &[u8], names: Option<&CrackNames>) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    // `[in] policy_handle *bind_handle`: twenty octets, inline.
    let _handle = reader
        .bytes(20)
        .ok_or_else(|| malformed("bind_handle", stub))?;
    let _level = reader.u32().unwrap_or(0);
    // `[in,switch_is(level)] drsuapi_DsNameRequest`: the union tag, then `req1`.
    let _tag = reader.u32().unwrap_or(0);
    let _codepage = reader.u32().unwrap_or(0);
    let _language = reader.u32().unwrap_or(0);
    let _flags = reader.u32().unwrap_or(0);
    let offered = reader.u32().unwrap_or(0);
    let desired = reader.u32().unwrap_or(0);
    let count = reader.u32().unwrap_or(0);
    // `[size_is(count)] drsuapi_DsNameString *names`: a referent, then the conformant array's
    // maximum, then one pointer per name - and the strings themselves are deferred past those.
    //
    // Measured, and the first reading of this was wrong in a way that looked like an empty name:
    // the referent comes *before* the maximum, so a reader that takes the referent for the maximum
    // shifts every field after it by four and then fails to find a string at all.
    let _array_present = reader.pointer().unwrap_or(false);
    let _max = reader.u32().unwrap_or(0);
    let mut pointers = Vec::new();
    for _ in 0..count {
        pointers.push(reader.u32().unwrap_or(0));
    }
    let mut asked = Vec::new();
    for _ in 0..count {
        asked.push(reader.string_or_empty().unwrap_or_default());
    }
    let asked: Vec<String> = asked
        .into_iter()
        .map(|units| String::from_utf16_lossy(&units))
        .collect();
    tracing::info!(
        offered,
        desired,
        count,
        names = ?asked,
        "drsuapi: DRSCrackNames"
    );

    // One item per name, in the order they were asked.
    let mut items = Vec::with_capacity(asked.len());
    for name in &asked {
        items.push(crack_one(name, offered, desired, names));
    }

    let mut writer = NdrWriter::new();
    // Every field of this answer is `[out,ref]`, so every one of them is a pointer first: the
    // version, the union, the counter and its array. Writing the values inline - which the
    // specification's IDL reads like, once the `[ref]` is skimmed - produces a stub a client cannot
    // unmarshal, and it answers by unbinding: measured, `opnum 12` then `opnum 1` and nothing more.
    writer.pointer(true); // level_out ([out,ref] uint32)
    writer.u32(1); // the reply's version
    writer.pointer(true); // pmsgOut ([out,ref] drsuapi_DsNameCtr)
    writer.u32(1); // its union tag: ctr1
    writer.pointer(true); // ctr1 ([case(1)] drsuapi_DsNameCtr1 *)
    writer.u32(u32::try_from(items.len()).expect("a short list")); // cItems
    writer.pointer(true); // rItems
    writer.u32(u32::try_from(items.len()).expect("a short list")); // the array's maximum
    for (status, _, _) in &items {
        writer.u32(*status);
        writer.pointer(true); // pDomain
        writer.pointer(true); // pName
    }
    // The strings, deferred in the order the pointers appeared: each item's domain, then its name.
    for (_, domain, name) in &items {
        writer.string(domain.as_deref().unwrap_or(""));
        writer.string(name.as_deref().unwrap_or(""));
    }
    writer.u32(STATUS_SUCCESS);
    let stub = writer.finish();
    if std::env::var_os("RRL_EPM_DIAG").is_some() {
        tracing::warn!(
            hex = %stub.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "drsuapi: the DRSCrackNames answer"
        );
    }
    Ok(stub)
}

/// One name, cracked - or the status that says this server cannot.
fn crack_one(
    name: &str,
    offered: u32,
    desired: u32,
    names: Option<&CrackNames>,
) -> (u32, Option<String>, Option<String>) {
    let Some(names) = names else {
        return (NAME_ERROR_NO_MAPPING, None, None);
    };
    // A canonical name of the domain itself ends in a separator: `ad.example.com/`.
    let is_domain = name
        .trim_end_matches('/')
        .eq_ignore_ascii_case(&names.dns_domain);
    match (offered, desired) {
        // The domain's canonical name, wanted in NT4 form: the NetBIOS name, which is what a client
        // puts in front of a machine account.
        (FORMAT_CANONICAL, FORMAT_NT4_ACCOUNT) if is_domain => (
            NAME_ERROR_NONE,
            Some(names.nb_domain.clone()),
            Some(names.nb_domain.clone()),
        ),
        // The same name wanted back as a distinguished name: the naming context.
        (FORMAT_CANONICAL, FORMAT_FQDN_1779) if is_domain => {
            let dn = names
                .dns_domain
                .split('.')
                .map(|label| format!("dc={}", label.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(",");
            (NAME_ERROR_NONE, Some(names.nb_domain.clone()), Some(dn))
        }
        // An NT4 account name: `AD\HOST$` or the domain alone.
        (FORMAT_NT4_ACCOUNT, FORMAT_FQDN_1779) => {
            let account = name.rsplit('\\').next().unwrap_or(name);
            if account.is_empty() || account.eq_ignore_ascii_case(&names.nb_domain) {
                let dn = names
                    .dns_domain
                    .split('.')
                    .map(|label| format!("dc={}", label.to_ascii_lowercase()))
                    .collect::<Vec<_>>()
                    .join(",");
                (NAME_ERROR_NONE, Some(names.nb_domain.clone()), Some(dn))
            } else {
                (NAME_ERROR_NO_MAPPING, None, None)
            }
        }
        other => {
            tracing::warn!(
                offered = other.0,
                desired = other.1,
                name,
                "drsuapi: DRSCrackNames asked for a conversion this server does not make"
            );
            (NAME_ERROR_NO_MAPPING, None, None)
        }
    }
}

/// `IDL_DRSUnbind` (MS-DRSR 4.1.25): the client is done, and the handle it sends back is nulled.
fn unbind() -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.bytes(&[0u8; 20]);
    writer.u32(STATUS_SUCCESS);
    writer.finish()
}

/// The names a log line is worth reading with, for the calls this server does not implement.
fn opnum_name(opnum: u16) -> &'static str {
    match opnum {
        2 => "DRSReplicaSync",
        3 => "DRSGetNCChanges",
        4 => "DRSUpdateRefs",
        5 => "DRSReplicaAdd",
        6 => "DRSReplicaDel",
        7 => "DRSReplicaModify",
        8 => "DRSVerifyNames",
        9 => "DRSGetMemberships",
        10 => "DRSInterDomainMove",
        11 => "DRSGetNT4ChangeLog",
        12 => "DRSCrackNames",
        13 => "DRSWriteAccountSpn",
        14 => "DRSExecuteKCC",
        15 => "DRSGetReplInfo",
        16 => "DRSAddSidHistory",
        17 => "DRSGetMemberships2",
        18 => "DRSReplicaVerifyObjects",
        19 => "DRSGetObjectExistence",
        20 => "DRSQuerySitesByCost",
        _ => "unknown",
    }
}

/// Whether a stub ended before a field this server reads, naming what was missing.
#[allow(dead_code)]
fn malformed(field: &str, stub: &[u8]) -> Fault {
    tracing::warn!(
        field,
        len = stub.len(),
        "drsuapi: the stub ends before this field"
    );
    Fault {
        status: NCA_PROTO_ERROR,
        did_not_execute: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four octets"))
    }

    /// The stub a client sends: `puuidClientDsa` (a referent and sixteen octets) and `pextClient`
    /// (a referent and a `cb` before the blob).
    fn bind_stub(with_uuid: bool, flags: u32) -> Vec<u8> {
        let mut writer = NdrWriter::new();
        writer.pointer(with_uuid);
        if with_uuid {
            writer.raw(&[0x11; 16]);
        }
        writer.pointer(true);
        let mut blob = Vec::new();
        blob.extend_from_slice(&flags.to_le_bytes());
        blob.extend_from_slice(&[0u8; 48]);
        writer.u32(blob.len() as u32);
        writer.raw(&blob);
        writer.align(4);
        writer.finish()
    }

    #[test]
    fn a_bind_answers_a_handle_and_a_null_extension_set() {
        // The shape a client reads: the server's extensions behind a referent, the twenty-octet
        // handle inline, then the status. A null handle would read as "nothing was bound".
        let body = serve(OPNUM_BIND, &bind_stub(true, 0x0000_0009), None).expect("answered");

        assert_ne!(
            word(&body, 0),
            0,
            "the extensions are behind a real referent"
        );
        let cb = word(&body, 4) as usize;
        assert_eq!(cb, 48, "DRS_EXTENSIONS_INT is a fixed size");
        assert_eq!(
            word(&body, 8) as usize,
            cb,
            "the conformant array's maximum"
        );
        assert_eq!(word(&body, 12), 0, "dwFlags: no optional behaviour claimed");
        let handle_at = 12 + cb;
        assert_eq!(
            &body[handle_at..handle_at + 20],
            &DRS_HANDLE,
            "the handle, inline"
        );
        assert_eq!(word(&body, handle_at + 20), STATUS_SUCCESS);
        assert_eq!(body.len(), handle_at + 24);
    }

    #[test]
    fn a_bind_without_a_client_guid_is_answered() {
        // A first bind carries no DSA GUID; refusing it would refuse every client once.
        let body = serve(OPNUM_BIND, &bind_stub(false, 0), None).expect("answered");
        assert_eq!(word(&body, body.len() - 4), STATUS_SUCCESS);
    }

    #[test]
    fn unbind_nulls_the_handle() {
        let body = serve(OPNUM_UNBIND, &[0x01; 20], None).expect("answered");
        assert_eq!(body.len(), 24, "twenty octets of handle and a status");
        assert_eq!(&body[..20], &[0u8; 20]);
        assert_eq!(word(&body, 20), STATUS_SUCCESS);
    }

    #[test]
    fn a_call_this_server_does_not_implement_is_refused_by_number_and_name() {
        // `DRSGetNCChanges` is opnum 3. Refusing it as a protocol fault would tell a client nothing
        // about whether the server is broken or simply does not replicate.
        let fault = serve(3, &[], None).expect_err("refused");
        assert_eq!(fault.status, NCA_OP_RNG_ERROR);
        assert!(fault.did_not_execute);
        assert_eq!(opnum_name(3), "DRSGetNCChanges");
        assert_eq!(opnum_name(9999), "unknown");
    }
}
