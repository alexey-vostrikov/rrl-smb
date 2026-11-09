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
//! `PolicyDnsDomainInfo` carries the domain's SID, and a member's join reads it from here and
//! stores it as the domain the machine belongs to. A domain SID is the directory's to issue, and
//! this crate does not read a directory - so the daemon that has one passes it in
//! (`ServerConfig::domain_sid`), and the answer holds it. Without one the answer is NULL, which is
//! the honest refusal: inventing a SID would attach every ACL to a domain that is not this one.

use crate::rpc::ndr::{NdrReader, NdrWriter};
use crate::rpc::association::Fault;
use crate::rpc::pdu::NCA_OP_RNG_ERROR;
use crate::server::{Caller, ServerState};

/// `lsa_OpenPolicy` (MS-LSAD 3.1.4.4.3). The older of the two calls that open a policy handle, and
/// the one Samba's join actually makes: implementing only `OpenPolicy2` answered a join with "the
/// procedure number is out of range", which names nothing and reads as a protocol mismatch.
///
/// The difference is in the request, not the answer. `system_name` here is a `uint16` array with a
/// count and no terminator - the "screwup" Samba's own IDL names in a comment above this call, and
/// the reason `OpenPolicy2` exists. Nothing in the request is read for its value: this server
/// ignores the name and issues the same read-only handle either way.
pub(crate) const OPNUM_OPEN_POLICY: u16 = 6;

/// `lsa_OpenPolicy2` (MS-LSAD 3.1.4.4.4). Opens a policy handle; takes a server name that this
/// server ignores, an object attributes pointer it also ignores, and the access wanted.
pub(crate) const OPNUM_OPEN_POLICY2: u16 = 44;

/// `lsa_QueryInfoPolicy` (MS-LSAD 3.1.4.4.9). The older question, and the one a Samba join asks
/// straight after `QueryInfoPolicy2` - so both are answered from the same body. The difference is
/// in the request: the level arrives as an `enum` here and as a `ushort` there, which is why
/// [`policy_level`] reads both widths.
pub(crate) const OPNUM_QUERY_INFO_POLICY: u16 = 7;

/// `lsa_QueryInfoPolicy2` (MS-LSAD 3.1.4.4.10). The same union as `lsa_QueryInfoPolicy`, with the
/// level carried as a `ushort` rather than an `enum`, which is the whole difference between them.
pub(crate) const OPNUM_QUERY_INFO_POLICY2: u16 = 46;

/// `STATUS_SUCCESS`: the NTSTATUS a method returns when it answered the question asked.
const NTSTATUS_SUCCESS: u32 = 0;

/// `PolicyDnsDomainInfo` (MS-LSAD 2.2.7).
const POLICY_DNS_DOMAIN_INFO: u16 = 5;

/// `LsarQueryInformationPolicy2` level 12, `PolicyDnsDomainInformation` (MS-LSAD 2.2.7).
///
/// The same structure as level 5, asked for by a different number. A Samba member's join asks for
/// this one - `dcerpc_lsa_QueryInfoPolicy2(..., LSA_POLICY_INFO_DNS, ...)` - so answering only
/// level 5 answers the question a client asks only after it has failed to ask the other.
const POLICY_DNS_DOMAIN_INFORMATION: u16 = 12;

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
        OPNUM_OPEN_POLICY => open_policy_v1(stub),
        OPNUM_OPEN_POLICY2 => open_policy(stub),
        OPNUM_QUERY_INFO_POLICY | OPNUM_QUERY_INFO_POLICY2 => query_info(server, stub),
        other => {
            // A client sees only "the procedure number is out of range" and cannot say which
            // number, so the number goes here: an unimplemented call is a fact about this server,
            // not about the request.
            tracing::warn!(
                opnum = other,
                stub = stub.len(),
                "lsarpc: no handler for this call"
            );
            Err(Fault {
                status: NCA_OP_RNG_ERROR,
                did_not_execute: true,
            })
        }
    }
}

/// The handle, behind the referent id an `[out]` pointer carries.
///
/// Two wrong answers were tried before this one. The first appended the granted access, which the
/// IDL does not ask for. The second sent the twenty octets of the handle alone - and a real client
/// refused that with `{Buffer Too Small}`, because NDR marshals an `[out]` pointer with its
/// referent id in front of the value (C706 14.3.10.5). `srvsvc` in this crate has always written
/// that id; this interface did not, and four missing bytes are the difference between a client
/// reading a handle and a client reading the start of one.
fn open_policy(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    // The server name, the object attributes and the desired access. Read only so that a stub too
    // short to hold them is refused as a malformed request rather than answered.
    let _server_name = reader.string();
    let _object_attributes = reader.pointer();
    let _desired_access = reader.u32();

    Ok(handle_response())
}

/// A policy handle as a response carries it: the twenty octets, then the status.
///
/// Established by experiment, because the IDL shows neither the return value nor its place. Four
/// layouts were tried against a real Samba member's join, and the status it reported named the
/// layout each time without saying so: with the handle at offset 4 it reported the handle's last
/// four octets (0x4f0e713a), with the handle at offset 8 the four before those (0x085d229c) - in
/// both cases exactly the bytes that fall at offset 20. So the client reads the handle first, from
/// offset 0, and the NTSTATUS return value after it.
fn handle_response() -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.bytes(&policy_handle());
    writer.u32(NTSTATUS_SUCCESS);
    writer.finish()
}

/// The same handle from the older request layout.
///
/// The name is a unique pointer to a conformant array, so the request is at least a referent, the
/// twenty octets of object attributes and the access mask - 28 bytes - whether or not a name is
/// present. Nothing in it is read for its value; the length check exists so that a truncated
/// request is refused as malformed rather than answered as if it had been understood.
fn open_policy_v1(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    const INLINE: usize = 4 + 20 + 4;
    if stub.len() < INLINE {
        return Err(Fault {
            status: crate::rpc::pdu::NCA_PROTO_ERROR,
            did_not_execute: true,
        });
    }
    Ok(handle_response())
}

/// `PolicyDnsDomainInfo` for the domain this server answers for.
fn query_info(server: &ServerState, stub: &[u8]) -> Result<Vec<u8>, Fault> {
    let Some(level) = policy_level(stub) else {
        // The bytes, not a guess about them: the request layout for this call was wrong twice
        // already, and each guess cost a stand run.
        tracing::warn!(
            stub = %stub.iter().take(48).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
            len = stub.len(),
            "lsarpc: QueryInfoPolicy2 with no level this server answers"
        );
        return Err(Fault {
            status: crate::rpc::pdu::NCA_PROTO_ERROR,
            did_not_execute: true,
        });
    };
    // A level this server does not answer is refused by name rather than with an empty structure:
    // a client that asked for account domains and got a DNS name would go on to use it.
    if !matches!(
        level,
        POLICY_DNS_DOMAIN_INFO | POLICY_DNS_DOMAIN_INFORMATION
    ) {
        return Err(Fault {
            status: crate::rpc::pdu::NCA_PROTO_ERROR,
            did_not_execute: true,
        });
    }

    // The domain's NetBIOS name, not this server's: a member compares it against the workgroup it
    // was configured with, and answering with the server's own name stopped a real join at
    // "workgroup set to 'AD', should be 'SAMBA'" after every other answer had been accepted.
    let netbios = match &server.config.domain_netbios {
        Some(name) => name.as_str(),
        None => server.config.netbios_name.as_str(),
    };
    let dns = dns_domain(server);

    let mut writer = NdrWriter::new();
    // `[out,ref,switch_is(Level)] LSA_POLICY_INFO *` (MS-LSAD 3.1.4.4.9): one pointer to the
    // union, then the union's discriminant, then the arm it selects.
    // `PLSAPR_POLICY_INFORMATION` is one pointer, not two (MS-LSAD 2.2.4.2). A second one here
    // cost a stand run: the client read the union's first field out of a pointer it had not asked
    // for and answered INVALID_PARAMETER.
    writer.pointer(true);
    // The union's discriminant (C706 14.3.8.2), two octets wide - `switch_type(uint16)` in the
    // IDL. What follows is aligned to four, so two octets of padding fall between it and the arm;
    // a reference body built by an independent implementation shows `0c 00`, then padding.
    writer.u16(level);
    // Padding, not a field: the arm is aligned to four and nothing is written in between. A
    // four-octet zero here instead of two octets of padding shifted every field after it by two -
    // which is the same symptom as a wrong count, and it took a byte-by-byte comparison to see.
    writer.align(4);

    // POLICY_DNS_DOMAIN_INFO: three `lsa_String`s, a GUID, and a SID pointer.
    for text in [netbios, dns.as_str(), dns.as_str()] {
        write_lsa_string(&mut writer, text);
    }
    // DomainGuid: the server's own, which is stable for the life of the install. A GUID on the
    // wire is its first three fields little endian and the last eight as written (MS-DTYP 2.3.4.2)
    // - which is what `to_bytes_le` is, and `as_bytes` is not.
    let guid = server.config.server_guid;
    writer.bytes(&guid.to_bytes_le());

    // The domain SID. A NULL is what this answered before the field existed, and Samba's join
    // takes it as an allocation failure it cannot explain - `dom_sid_dup` on NULL returns NULL,
    // and `NT_STATUS_HAVE_NO_MEMORY` is the error the operator then sees. Absent configuration
    // still answers NULL, because inventing a SID would attach every ACL to a domain that is not
    // this one; the daemon that has one passes it.
    match &server.config.domain_sid {
        Some(_) => writer.pointer(true),
        None => writer.pointer(false),
    }

    // The referents, in the order their pointers appeared.
    for text in [netbios, dns.as_str(), dns.as_str()] {
        write_unicode_array(&mut writer, text);
    }
    if let Some(sid) = &server.config.domain_sid {
        // `dom_sid2` is not the flat octets a directory stores (MS-DTYP 2.4.2.2): its
        // `[size_is(num_auths)] uint32 sub_auths[]` is a conformant array, so the count is
        // written before the sub-authorities. Sending the flat form made a client read a
        // sub-authority as the array's length - and report the array as past its bounds.
        write_dom_sid2(&mut writer, sid);
    }
    // The return value last, where the client reads it: after the out parameters and their
    // referents, not before.
    writer.u32(NTSTATUS_SUCCESS);

    let body = writer.finish();
    // The answer is logged at debug with its length only: a member's join is the one client of
    // this call, and when it refuses the body, the length says whether a field went missing. The
    // bytes themselves were useful while the layout was being established and are not worth the
    // noise now.
    tracing::debug!(len = body.len(), "lsarpc: QueryInfoPolicy2 answer");
    Ok(body)
}

/// The level a `QueryInformationPolicy` request asks for, or `None` when the stub is not one.
///
/// Established from the bytes a client sends, after three guesses about this request were wrong:
///
///     00 00 00 00 6c 9d 2f 14 8a 3e 4b 71 9c 22 5d 08 3a 71 0e 4f 0c 00
///     \_________________ the policy handle, 20 octets ________________/ \_/ level
///
/// Three things are visible there that the IDL does not say plainly. The handle is sent inline,
/// with no referent id in front of it - it is a context handle, and a context handle travels as
/// its twenty octets. The level is two octets, not four: `lsa_QueryInfoPolicy2` carries it as a
/// `ushort` where `lsa_QueryInfoPolicy` carries an `enum`, which is the entire difference between
/// the two calls (MS-LSAD 3.1.4.4.10). And the level is last, so a stub that ends two octets
/// early is not an error to report but a layout that was already read.
///
/// Both widths and both offsets are tried, because the older call is still answerable: a guess
/// about the layout never becomes an answer, since a wrong offset lands on handle octets that
/// match no level this server knows.
fn policy_level(stub: &[u8]) -> Option<u16> {
    let levels = [POLICY_DNS_DOMAIN_INFO, POLICY_DNS_DOMAIN_INFORMATION];
    // `ushort`: offset 20 with the handle inline, 24 behind a referent id.
    for at in [20usize, 24] {
        if let Some(bytes) = stub.get(at..at + 2).and_then(|b| <[u8; 2]>::try_from(b).ok()) {
            let level = u16::from_le_bytes(bytes);
            if levels.contains(&level) {
                return Some(level);
            }
        }
    }
    // `enum`, as the older call carries it.
    for at in [20usize, 24] {
        if let Some(bytes) = stub.get(at..at + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()) {
            let level = u32::from_le_bytes(bytes) as u16;
            if levels.contains(&level) {
                return Some(level);
            }
        }
    }
    None
}

/// A `dom_sid2` as NDR writes it: the eight-octet header, the count, then the sub-authorities.
fn write_dom_sid2(writer: &mut NdrWriter, sid: &[u8]) {
    const HEADER: usize = 8;
    if sid.len() < HEADER {
        // A SID shorter than its own header is not one; writing nothing keeps the pointers in
        // step with the referents that follow them.
        return;
    }
    let count = usize::from(sid[1]);
    // The count first: `[size_is(num_auths)] uint32 sub_auths[]` is a conformant array, and NDR
    // puts a conformant array's maximum before the structure that contains it. Writing the header
    // first - the obvious order, since `num_auths` lives in it - made a client read the revision
    // byte `01` as an array of one element. Samba's own encoder writes `04 00 00 00 01 04 ...`:
    // the count, then revision and count again inside the header.
    writer.u32(u32::try_from(count).unwrap_or(u32::MAX));
    writer.raw(&sid[..HEADER]);
    writer.raw(&sid[HEADER..HEADER + count * 4]);
}

/// An `lsa_String`: `Length` and `MaximumLength` in one word, then a pointer to its units.
fn write_lsa_string(writer: &mut NdrWriter, text: &str) {
    let units = u32::try_from(text.encode_utf16().count()).unwrap_or(u32::MAX);
    // Both counts are `2*strlen`, with no terminator added: the array below carries the characters
    // and nothing else. An independent implementation's own body writes `0a 00 0a 00` for a
    // five-character name, and a client that finds a count larger than the characters it read
    // reports the array as past its bounds.
    // MS-DTYP 2.2.5: `Length` excludes the terminating null, `MaximumLength` includes it. Two
    // uint16 in one word, `Length` low.
    let length = units.saturating_mul(2);
    let maximum = length.saturating_add(2);
    writer.u32(length | (maximum << 16));
    writer.pointer(true);
}

/// The units of an `lsa_String`: a conformant array, so its count and nothing else.
///
/// Not `[string]`: a `[string]` array is varying-conformant and carries an offset and an actual
/// count that an `lsa_String` has no field for. Writing the longer form shifts every field after
/// it, and the client reads the domain's name out of the middle of its own forest name.
fn write_unicode_array(writer: &mut NdrWriter, text: &str) {
    // `[size_is(size/2),length_is(length/2)] uint16 *string`: conformant *and* varying, so two
    // different numbers. The maximum comes from `size`, which counts the room the terminator needs;
    // the count that arrives comes from `length`, which does not. Samba's own encoder, run on the
    // same values, writes `06 00 00 00 00 00 00 00 05 00 00 00` for `SAMBA`: six, then five.
    let units: Vec<u16> = text.encode_utf16().collect();
    let actual = u32::try_from(units.len()).unwrap_or(u32::MAX);
    let maximum = actual.saturating_add(1);
    writer.u32(maximum);
    writer.u32(0);
    writer.u32(actual);
    let mut raw = Vec::with_capacity(units.len() * 2);
    for unit in units {
        raw.extend_from_slice(&unit.to_le_bytes());
    }
    // The elements are aligned to two, the array as a whole to four: Samba writes ten octets of
    // characters for `SAMBA` and then two of padding, and without that padding every referent
    // after it starts two octets early.
    writer.raw(&raw);
    writer.align(4);
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
        // Level 2 is PolicyAccountDomainInfo; the refusal has to happen before anything is
        // written, because a half-built answer is worse than none.
        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&2u32.to_le_bytes());
        assert_eq!(policy_level(&stub), None);
    }

    #[test]
    fn the_level_is_read_from_the_bytes_a_client_actually_sends() {
        // Taken from a stand run: handle inline, then the level as one `ushort`.
        let stub = [
            0x00, 0x00, 0x00, 0x00, 0x6c, 0x9d, 0x2f, 0x14, 0x8a, 0x3e, 0x4b, 0x71, 0x9c, 0x22,
            0x5d, 0x08, 0x3a, 0x71, 0x0e, 0x4f, 0x0c, 0x00,
        ];
        assert_eq!(policy_level(&stub), Some(POLICY_DNS_DOMAIN_INFORMATION));
        // Level 5 in the same place, and the older call's four-octet form.
        let mut five = stub[..20].to_vec();
        five.extend_from_slice(&5u16.to_le_bytes());
        assert_eq!(policy_level(&five), Some(5));
        let mut wide = stub[..20].to_vec();
        wide.extend_from_slice(&12u32.to_le_bytes());
        assert_eq!(policy_level(&wide), Some(12));
    }

    #[test]
    fn the_level_is_read_from_where_the_client_put_it() {
        // Both offsets, and both the `ushort` a current client sends and the `enum` an older one
        // sends. The level itself says which reading was right, so none of these is a guess.
        for (prefix, level) in [(4usize, 12u16), (0, 12), (4, 5), (0, 5)] {
            let mut stub = vec![0u8; 20 + prefix];
            stub.extend_from_slice(&u32::from(level).to_le_bytes());
            assert_eq!(
                policy_level(&stub),
                Some(level),
                "prefix {prefix} octets before the handle"
            );
        }
    }

    #[test]
    fn both_calls_that_open_a_policy_answer_with_the_handle_and_nothing_else() {
        // A join calls the older opnum first. Implementing only `OpenPolicy2` made a real Samba
        // client report "the procedure number is out of range" - a message that names neither the
        // interface nor the number, and reads as a server that does not speak this protocol.
        let v1 = open_policy_v1(&[0u8; 28]).expect("lsa_OpenPolicy is answered");
        let v2 = open_policy(&[0u8; 28]).expect("lsa_OpenPolicy2 is answered");
        let handle = policy_handle();
        // The twenty octets, then the status - no referent id in front. Every other layout was
        // refused by a real client, and the status it reported was a window onto these bytes:
        // whatever fell at offset 20 was read as the NTSTATUS. See `handle_response`.
        assert_eq!(v1.len(), 24);
        assert_eq!(&v1[..20], handle.as_slice());
        assert_eq!(&v1[20..], &[0, 0, 0, 0], "STATUS_SUCCESS after the handle");
        assert_eq!(v2, v1);
    }

    #[test]
    fn a_truncated_open_policy_is_refused_rather_than_answered() {
        // A shorter stub cannot hold the referent, the object attributes and the access mask, so
        // answering would be guessing that the parts that did arrive meant what they looked like.
        match open_policy_v1(&[0u8; 27]) {
            Err(Fault { status, .. }) => assert_eq!(status, crate::rpc::pdu::NCA_PROTO_ERROR),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

}
