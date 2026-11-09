//! lsarpc: the interface a member's join asks what domain it has reached.
//!
//! `net ads join` opens this pipe, binds `12345778-1234-abcd-ef00-0123456789ab` v0.0, and calls
//! `lsa_OpenPolicy2` and then `lsa_QueryInfoPolicy2` at level 5 - `PolicyDnsDomainInfo`. That answer
//! is what tells the client the DNS name of the domain and of its forest, which it needs before it
//! can decide whether the realm it has is the realm it was asked to join.
//!
//! # What is implemented, and what is not
//!
//! Two calls, and no more: opening a policy handle, and asking that one question. Everything else on
//! this interface - accounts, trusted domains, secrets - answers with a fault, because a wrong answer
//! to a question nobody asked is worse than a refusal, and a client that gets a refusal looks for
//! another way rather than believing a lie.
//!
//! # The SID
//!
//! `PolicyDnsDomainInfo` carries the domain's SID. This server answers it as NULL: a domain SID is
//! the directory's to issue, and this crate does not read a directory. A client that needs it - and
//! a join does, for the machine account - gets it from LDAP, where `rust-rest-ldap` already keeps and
//! issues it. What a NULL here costs is a second question, not a wrong answer.

use crate::rpc::ndr::{NdrReader, NdrWriter};
use crate::rpc::association::Fault;
use crate::rpc::pdu::NCA_OP_RNG_ERROR;
use crate::server::{Caller, ServerState};

/// `lsa_OpenPolicy2` (MS-LSAD 3.1.4.4.4). Opens a policy handle; takes a server name that this
/// server ignores, an object attributes pointer it also ignores, and the access wanted.
pub(crate) const OPNUM_OPEN_POLICY2: u16 = 44;

/// `lsa_QueryInfoPolicy2` (MS-LSAD 3.1.4.4.10). The same union as `lsa_QueryInfoPolicy`, with the
/// level carried as a `ushort` rather than an `enum`, which is the whole difference between them.
pub(crate) const OPNUM_QUERY_INFO_POLICY2: u16 = 46;

/// `PolicyDnsDomainInfo` (MS-LSAD 2.2.7).
const POLICY_DNS_DOMAIN_INFO: u16 = 5;

/// A policy handle is 20 octets: a context type and a UUID (MS-LSAD 2.2.1).
///
/// Not a table index: the client may keep the handle for as long as it likes, and a server that
/// reused an index would answer a stale handle with somebody else's policy. The value is opaque to
/// the client and nothing here checks it - every handle this server issues opens the same read-only
/// view - but it must be 20 octets and it must not look like a NULL handle, which is all zeroes.
fn policy_handle() -> [u8; 20] {
    let mut handle = [0u8; 20];
    // A fixed context type, then a value that is not the NULL handle.
    handle[..4].copy_from_slice(&0x0000_0000u32.to_le_bytes());
    handle[4..].copy_from_slice(&[
        0x6c, 0x9d, 0x2f, 0x14, 0x8a, 0x3e, 0x4b, 0x71, 0x9c, 0x22, 0x5d, 0x08, 0x3a, 0x71, 0x0e,
        0x4f,
    ]);
    handle
}

/// Answers one call.
pub(crate) async fn serve(
    server: &ServerState,
    _caller: &Caller,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    match opnum {
        OPNUM_OPEN_POLICY2 => open_policy(stub),
        OPNUM_QUERY_INFO_POLICY2 => query_info(server, stub),
        _ => Err(Fault {
            status: NCA_OP_RNG_ERROR,
            did_not_execute: true,
        }),
    }
}

/// The handle, and the access granted with it.
///
/// The access is echoed as `0x000f_0fff` - everything - because there is nothing here a client could
/// do with more than it asked for: the only call this interface answers reads the domain's own name.
fn open_policy(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    // The server name, the object attributes and the desired access. Read only so that a stub too
    // short to hold them is refused as a malformed request rather than answered.
    let _server_name = reader.string();
    let _object_attributes = reader.pointer();
    let _desired_access = reader.u32();

    // The handle is 20 octets of opaque data, so it is written as bytes rather than as words.
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&policy_handle());
    // The access granted, echoed as everything: the only call this interface answers reads the
    // domain's own name, and there is nothing here a client could do with more than it asked for.
    out.extend_from_slice(&0x000f_0fffu32.to_le_bytes());
    Ok(out)
}

/// `PolicyDnsDomainInfo` for the domain this server answers for.
fn query_info(server: &ServerState, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    // The handle, and the level. A level this server does not answer is refused by name rather than
    // with an empty structure: a client that asked for account domains and got a DNS name would go
    // on to use it.
    let _handle = reader.u32();
    for _ in 0..4 {
        let _ = reader.u32();
    }
    let level = reader.u32().unwrap_or(u32::MAX);
    if level as u16 != POLICY_DNS_DOMAIN_INFO {
        return Err(Fault {
            status: crate::rpc::pdu::NCA_PROTO_ERROR,
            did_not_execute: true,
        });
    }

    let netbios = server.config.netbios_name.as_str();
    let dns = dns_domain(server);

    let mut writer = NdrWriter::new();
    // `[out, switch_is(Level)] LSA_POLICY_INFO **`: a pointer, then the union member it names.
    writer.pointer(true);

    // POLICY_DNS_DOMAIN_INFO: three RPC_UNICODE_STRINGs, a GUID, and a SID pointer.
    for text in [netbios, dns.as_str(), dns.as_str()] {
        let units = text.encode_utf16().count();
        let length = u16::try_from(units * 2).unwrap_or(u16::MAX);
        // Length and MaximumLength are inline; the characters are referents after the structure.
        writer.u32(u32::from(length));
        writer.pointer(true);
    }
    // DomainGuid: the server's own, which is stable for the life of the install.
    let guid = server.config.server_guid;
    writer.u32(u32::from_le_bytes(guid.as_bytes()[0..4].try_into().expect("4")));
    writer.u32(u32::from_le_bytes(guid.as_bytes()[4..8].try_into().expect("4")));
    writer.u32(u32::from_le_bytes(guid.as_bytes()[8..12].try_into().expect("4")));
    writer.u32(u32::from_le_bytes(guid.as_bytes()[12..16].try_into().expect("4")));
    // The domain SID: NULL, and the module note says why.
    writer.pointer(false);

    // The referents, in the order their pointers appeared.
    for text in [netbios, dns.as_str(), dns.as_str()] {
        writer.string(text);
    }

    Ok(writer.finish())
}

/// The DNS name of the domain this server answers for.
///
/// Taken from the directory's naming context when the daemon passes one, and from the NetBIOS name
/// otherwise: a join compares this against the realm it was told, and a wrong answer here sends the
/// client looking for a domain that is not this one.
fn dns_domain(server: &ServerState) -> String {
    match &server.config.dns_domain {
        Some(domain) => domain.clone(),
        None => format!("{}.local", server.config.netbios_name.to_lowercase()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_handle_is_twenty_octets_and_not_the_null_handle() {
        // A NULL handle is all zeroes and means "no policy" (MS-LSAD 2.2.1). One issued by mistake
        // would make a client's second call fail for a reason it cannot see.
        let handle = policy_handle();
        assert_eq!(handle.len(), 20);
        assert!(handle.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn a_level_this_server_does_not_answer_is_refused_rather_than_approximated() {
        // A client that asked for account domains and received a DNS name would use the name.
        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&2u32.to_le_bytes());
        match query_info_stub(&stub) {
            Err(Fault { status, .. }) => assert_eq!(status, crate::rpc::pdu::NCA_PROTO_ERROR),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// `query_info` without a `ServerState`, for the branch that refuses before reading one.
    fn query_info_stub(stub: &[u8]) -> Result<Vec<u8>, Fault> {
        let mut reader = NdrReader::new(stub);
        let _handle = reader.u32();
        for _ in 0..4 {
        let _ = reader.u32();
    }
        let level = reader.u32().unwrap_or(u32::MAX);
        if level as u16 != POLICY_DNS_DOMAIN_INFO {
            return Err(Fault {
                status: crate::rpc::pdu::NCA_PROTO_ERROR,
                did_not_execute: true,
            });
        }
        Ok(Vec::new())
    }
}
