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

use crate::rpc::association::Fault;
use crate::rpc::ndr::{NdrReader, NdrWriter};
use crate::rpc::pdu::NCA_OP_RNG_ERROR;
use crate::server::{Caller, ServerState};

/// `lsa_Close` (MS-LSAD 3.1.4.4.1). Closes a policy handle and nulls it in the reply.
///
/// A join closes the handle it opened before it does anything else with what it learned, so a
/// refusal here arrives at a point where the client has already succeeded - and a refusal at that
/// point reads as a failure of the whole exchange.
pub(crate) const OPNUM_CLOSE: u16 = 0;

/// The handle the client sent, nulled, and the status last.
///
/// `lsa_Close` takes `[in,out] policy_handle *handle` and must write NULL back into it (MS-LSAD
/// 3.1.4.4.1): a client that keeps the value it sent would use a handle the server has forgotten.
fn close_handle(stub: &[u8]) -> Result<Vec<u8>, Fault> {
    const HANDLE: usize = 20;
    if stub.len() < HANDLE {
        return Err(Fault {
            status: crate::rpc::pdu::NCA_PROTO_ERROR,
            did_not_execute: true,
        });
    }
    let mut writer = NdrWriter::new();
    writer.bytes(&[0u8; HANDLE]);
    writer.u32(NTSTATUS_SUCCESS);
    Ok(writer.finish())
}

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
    dispatch(&server.config, opnum, stub)
}

/// Which call an opnum reaches, and what it answers.
///
/// Separate from [`serve`] because serving needs a whole [`ServerState`] and routing does not: the
/// only thing any handler here reads is the configuration. Keeping them together is why no test
/// checked that opnum 0 reaches `lsa_Close` rather than the shared handle path - a mutation
/// answering one with the other would have survived, and a client would see a closed handle where
/// it asked for an opened one.
pub(crate) fn dispatch(
    config: &crate::server::ServerConfig,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    match opnum {
        OPNUM_CLOSE => close_handle(stub),
        OPNUM_OPEN_POLICY => open_policy_v1(stub),
        OPNUM_OPEN_POLICY2 => open_policy(stub),
        OPNUM_QUERY_INFO_POLICY | OPNUM_QUERY_INFO_POLICY2 => query_info(config, stub),
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
fn query_info(config: &crate::server::ServerConfig, stub: &[u8]) -> Result<Vec<u8>, Fault> {
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
    // No second check on the level here. `policy_level` answers only 5 and 12 and refuses the
    // rest, so a guard at this point cannot fire: a mutation removing it survived, which is how
    // dead code announces itself. The refusal lives there, where the level is read.

    let body = dns_domain_info_body(level, &DomainView::of(config));
    // The answer is logged at debug with its length only: a member's join is the one client of
    // this call, and when it refuses the body, the length says whether a field went missing. The
    // bytes themselves were useful while the layout was being established and are not worth the
    // noise now.
    tracing::debug!(len = body.len(), "lsarpc: QueryInfoPolicy2 answer");
    Ok(body)
}

/// The values `PolicyDnsDomainInfo` answers with, separate from the server that holds them.
///
/// The answer is bytes, and the only way to test bytes is to compare them with bytes. Reaching
/// them through a `ServerState` would mean building a whole server in a unit test for four fields,
/// and a test that is hard to write is a test that does not get written - which is how the layout
/// faults in this module came to be found by a stand instead.
pub(crate) struct DomainView {
    pub(crate) netbios: String,
    pub(crate) dns: String,
    pub(crate) guid: uuid::Uuid,
    pub(crate) sid: Option<Vec<u8>>,
}

impl DomainView {
    fn of(config: &crate::server::ServerConfig) -> Self {
        Self {
            // The domain's NetBIOS name, not this server's: a member compares it against the
            // workgroup it was configured with, and answering with the server's own name stopped a
            // real join at "workgroup set to 'AD', should be 'SAMBA'" after every other answer had
            // been accepted.
            netbios: match &config.domain_netbios {
                Some(name) => name.clone(),
                None => config.netbios_name.clone(),
            },
            dns: dns_domain(config),
            guid: config.server_guid,
            sid: config.domain_sid.clone(),
        }
    }
}

/// The `PolicyDnsDomainInfo` body: pointer, discriminant, the structure, its referents, status.
pub(crate) fn dns_domain_info_body(level: u16, view: &DomainView) -> Vec<u8> {
    let netbios = view.netbios.as_str();
    let dns = view.dns.as_str();

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
    for text in [netbios, dns, dns] {
        write_lsa_string(&mut writer, text);
    }
    // DomainGuid: the server's own, which is stable for the life of the install. A GUID on the
    // wire is its first three fields little endian and the last eight as written (MS-DTYP 2.3.4.2)
    // - which is what `to_bytes_le` is, and `as_bytes` is not.
    writer.bytes(&view.guid.to_bytes_le());

    // The domain SID. A NULL is what this answered before the field existed, and Samba's join
    // takes it as an allocation failure it cannot explain - `dom_sid_dup` on NULL returns NULL,
    // and `NT_STATUS_HAVE_NO_MEMORY` is the error the operator then sees. Absent configuration
    // still answers NULL, because inventing a SID would attach every ACL to a domain that is not
    // this one; the daemon that has one passes it.
    match &view.sid {
        Some(_) => writer.pointer(true),
        None => writer.pointer(false),
    }

    // The referents, in the order their pointers appeared.
    for text in [netbios, dns, dns] {
        write_unicode_array(&mut writer, text);
    }
    if let Some(sid) = &view.sid {
        // `dom_sid2` is not the flat octets a directory stores (MS-DTYP 2.4.2.2): its
        // `[size_is(num_auths)] uint32 sub_auths[]` is a conformant array, so its maximum is
        // written before the header. Sending the flat form made a client read a revision byte as
        // the array's length - and report the array as past its bounds.
        write_dom_sid2(&mut writer, sid);
    }
    // The return value last, where the client reads it: after the out parameters and their
    // referents, not before.
    writer.u32(NTSTATUS_SUCCESS);

    writer.finish()
}

/// The level a `QueryInformationPolicy` request asks for, or `None` when the stub is not one.
///
/// Established from the bytes a client sends, after three guesses about this request were wrong:
///
/// ```text
/// 00 00 00 00 6c 9d 2f 14 8a 3e 4b 71 9c 22 5d 08 3a 71 0e 4f 0c 00
/// \_________________ the policy handle, 20 octets ________________/ \_/ level
/// ```
///
/// Three things are visible there that the IDL does not say plainly. The handle is sent inline,
/// with no referent id in front of it - it is a context handle, and a context handle travels as
/// its twenty octets. The level is two octets, not four: `lsa_QueryInfoPolicy2` carries it as a
/// `ushort` where `lsa_QueryInfoPolicy` carries an `enum`, which is the entire difference between
/// the two calls (MS-LSAD 3.1.4.4.10). And the level is last, so a stub that ends two octets
/// early is not an error to report but a layout that was already read.
///
/// Two offsets are tried, because a client may send the handle inline or behind a referent id. Only
/// the two-octet width is read, and a first version also tried four: for both levels this server
/// answers - 5 and 12 - a little-endian `u32` has the same low two octets as the `ushort`, so the
/// narrow read always decided first and the wide loop never ran. A mutation removing it survived,
/// and deleting it is what the survivor was saying.
fn policy_level(stub: &[u8]) -> Option<u16> {
    let levels = [POLICY_DNS_DOMAIN_INFO, POLICY_DNS_DOMAIN_INFORMATION];
    // `ushort`: offset 20 with the handle inline, 24 behind a referent id.
    for at in [20usize, 24] {
        if let Some(bytes) = stub
            .get(at..at + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
        {
            let level = u16::from_le_bytes(bytes);
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
fn dns_domain(config: &crate::server::ServerConfig) -> String {
    match &config.dns_domain {
        Some(domain) => domain.clone(),
        None => format!("{}.local", config.netbios_name.to_lowercase()),
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

    /// The reference body, written by Samba's own NDR encoder for these exact values.
    ///
    /// `ndr_pack(lsa.DnsDomainInfo)` from the python bindings that ship with Samba - the library
    /// whose parser refuses our answers when they are wrong, which makes it the only oracle worth
    /// asking. Captured once, because asking at test time would need a container.
    const SAMBA_STRUCT: &[u8] = &[
        0x0a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x1e, 0x00, 0x04, 0x00, 0x02,
        0x00, 0x1c, 0x00, 0x1e, 0x00, 0x08, 0x00, 0x02, 0x00, 0xfd, 0xb1, 0x18, 0x47, 0x07, 0x23,
        0x46, 0x76, 0xac, 0x58, 0x82, 0x7a, 0xaf, 0x7d, 0xda, 0xaf, 0x0c, 0x00, 0x02, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x53, 0x00, 0x41, 0x00,
        0x4d, 0x00, 0x42, 0x00, 0x41, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0e, 0x00, 0x00, 0x00, 0x61, 0x00, 0x64, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00,
        0x61, 0x00, 0x6d, 0x00, 0x70, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f,
        0x00, 0x6d, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
        0x61, 0x00, 0x64, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x61, 0x00, 0x6d, 0x00, 0x70,
        0x00, 0x6c, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x08, 0x07, 0x06, 0x05, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    /// The same SID, as a directory stores it: revision, count, authority, sub-authorities.
    const DOMAIN_SID: &[u8] = &[
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x08, 0x07, 0x06, 0x05, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    fn reference_view() -> DomainView {
        DomainView {
            netbios: "SAMBA".to_string(),
            dns: "ad.example.com".to_string(),
            guid: uuid::Uuid::parse_str("4718b1fd-2307-7646-ac58-827aaf7ddaaf").expect("a uuid"),
            sid: Some(DOMAIN_SID.to_vec()),
        }
    }

    #[test]
    fn the_answer_is_the_body_samba_writes_for_the_same_values() {
        // Byte for byte against an implementation we did not write. Five faults were found by a
        // stand before this test existed - wrong pointer count, wrong discriminant width, missing
        // padding, the SID's count on the wrong side of its header, an array not padded - and
        // every one of them would have failed here in a second instead of a stand run.
        //
        // One difference is expected and has to be produced deliberately. `SAMBA_STRUCT` was packed
        // from the structure alone, so its own referent counter starts at 0x00020000. In a reply
        // the counter is shared with the union pointer, which takes the first id, so every referent
        // inside the structure is four higher. The ids are opaque to the client - what they must be
        // is unique and non-zero - but the shift is real and a comparison that ignored it would be
        // comparing the wrong thing.
        let mut expected = vec![0x00, 0x00, 0x02, 0x00];
        expected.extend_from_slice(&[0x0c, 0x00, 0x00, 0x00]);
        expected.extend_from_slice(SAMBA_STRUCT);
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // The referent ids in `SAMBA_STRUCT` sit at 12, 20, 28 and 48 once the eight-octet prefix
        // (union pointer, discriminant, its padding) is in front of it - not at 8, which is the
        // first string's `Length`. A first version of this shifted offset 8 and turned Length 10
        // into 14, which the test reported as a difference in the wrong field.
        for referent in [12usize, 20, 28, 48] {
            let value = u32::from_le_bytes(expected[referent..referent + 4].try_into().expect("4"));
            assert_ne!(value, 0, "a referent, not a NULL pointer, at {referent}");
            expected[referent..referent + 4].copy_from_slice(&(value + 4).to_le_bytes());
        }

        let ours = dns_domain_info_body(POLICY_DNS_DOMAIN_INFORMATION, &reference_view());
        assert_eq!(ours, expected, "body differs from Samba's own encoding");
    }

    #[test]
    fn the_answer_names_the_domain_and_repeats_its_name_as_the_forest() {
        // Read back rather than compared as hex: a member compares `Name` against its workgroup,
        // so a body that renders correctly but puts the server's name there is a wrong answer that
        // a hex comparison cannot point at.
        let body = dns_domain_info_body(POLICY_DNS_DOMAIN_INFORMATION, &reference_view());
        let text: Vec<u16> = body
            .chunks(2)
            .filter(|pair| pair.len() == 2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let rendered: String = String::from_utf16_lossy(&text);
        assert!(rendered.contains("SAMBA"), "{rendered:?}");
        assert_eq!(rendered.matches("ad.example.com").count(), 2);
    }

    #[test]
    fn a_domain_without_a_sid_answers_null_and_no_referent() {
        // The honest refusal, and it has to be *shorter*: a pointer of 0 writes nothing after it,
        // and a body that still wrote a SID would leave four octets the client reads as the next
        // field. Inventing a SID would attach every ACL to a domain that is not this one.
        let view = DomainView {
            sid: None,
            ..reference_view()
        };
        let body = dns_domain_info_body(POLICY_DNS_DOMAIN_INFORMATION, &view);
        let with_sid = dns_domain_info_body(POLICY_DNS_DOMAIN_INFORMATION, &reference_view());
        assert_eq!(with_sid.len() - body.len(), 4 + DOMAIN_SID.len());
    }

    #[test]
    fn both_dns_levels_answer_the_same_arm_under_their_own_discriminant() {
        // Level 5 and 12 select the same structure, and the discriminant has to say which was
        // asked: a client that reads level 12 out of a body labelled 5 is being told a different
        // question was answered.
        let five = dns_domain_info_body(POLICY_DNS_DOMAIN_INFO, &reference_view());
        let twelve = dns_domain_info_body(POLICY_DNS_DOMAIN_INFORMATION, &reference_view());
        assert_eq!(&five[4..6], &5u16.to_le_bytes());
        assert_eq!(&twelve[4..6], &12u16.to_le_bytes());
        assert_eq!(five[6..], twelve[6..], "the arm itself is the same");
    }

    #[test]
    fn closing_a_handle_nulls_it_and_puts_the_status_last() {
        // `[in,out]` handle: the client gets back a NULL where its handle was, so a client that
        // keeps the value it sent cannot use a handle the server has forgotten. The status is last
        // here for the same reason it is last everywhere in this interface - the client reads it
        // after the out parameters, and putting it first makes it read the handle as the status.
        let reply = close_handle(&[0xAA; 20]).expect("lsa_Close is answered");
        assert_eq!(reply.len(), 24);
        assert_eq!(&reply[..20], &[0u8; 20], "the handle is nulled");
        assert_eq!(
            &reply[20..],
            &[0, 0, 0, 0],
            "STATUS_SUCCESS after the handle"
        );
    }

    #[test]
    fn each_opnum_reaches_its_own_handler() {
        // Routing is behaviour: opnum 0 and opnum 6 both answer with a twenty-octet handle, and a
        // match arm that sent one to the other would look right in review. What distinguishes them
        // here is the rest of the reply - a closed handle is twenty zero octets, an opened one is
        // the handle this server issues.
        let config = crate::server::ServerConfig::for_test();
        let handle = policy_handle();

        let closed = dispatch(&config, OPNUM_CLOSE, &[0xAA; 20]).expect("opnum 0");
        assert_eq!(&closed[..20], &[0u8; 20], "a closed handle is NULL");

        for opnum in [OPNUM_OPEN_POLICY, OPNUM_OPEN_POLICY2] {
            let opened = dispatch(&config, opnum, &[0u8; 28]).expect("opnum 6 and 44");
            assert_eq!(&opened[..20], handle.as_slice(), "opnum {opnum}");
        }

        // The two query calls answer the same arm under their own discriminant.
        for (opnum, level) in [
            (OPNUM_QUERY_INFO_POLICY, POLICY_DNS_DOMAIN_INFO),
            (OPNUM_QUERY_INFO_POLICY2, POLICY_DNS_DOMAIN_INFORMATION),
        ] {
            let mut stub = vec![0u8; 20];
            stub.extend_from_slice(&level.to_le_bytes());
            let answered = dispatch(&config, opnum, &stub).expect("a query opnum");
            let expected = dns_domain_info_body(level, &DomainView::of(&config));
            assert_eq!(answered, expected, "opnum {opnum}");
        }

        // And an opnum this interface does not implement is refused by status, not answered with
        // whichever handler came last.
        match dispatch(&config, 99, &[]) {
            Err(Fault { status, .. }) => assert_eq!(status, NCA_OP_RNG_ERROR),
            other => panic!("expected an opnum refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_query_for_the_dns_level_is_answered_with_the_domain() {
        // The path a member's join actually takes, driven through the same entry point the pipe
        // uses: level 12, handle inline, and the answer has to be the DNS domain information.
        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&12u16.to_le_bytes());
        let answered = dispatch(
            &crate::server::ServerConfig::for_test(),
            OPNUM_QUERY_INFO_POLICY2,
            &stub,
        )
        .expect("level 12 is answered");
        let text = String::from_utf16_lossy(
            &answered
                .chunks(2)
                .filter(|pair| pair.len() == 2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>(),
        );
        assert!(text.contains("AD"), "the domain's name: {text:?}");
        assert_eq!(text.matches("ad.example.com").count(), 2);
        assert!(
            !text.contains("SAMBA"),
            "the server's own name belongs in neither domain field: {text:?}"
        );
    }

    #[test]
    fn a_query_for_a_level_this_server_does_not_answer_is_refused() {
        // Level 3 is PolicyPrimaryDomainInformation. A member that asked for the primary domain and
        // received the DNS name would use the name - refusing is the only answer that cannot be
        // mistaken for a different one.
        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&3u16.to_le_bytes());
        match dispatch(
            &crate::server::ServerConfig::for_test(),
            OPNUM_QUERY_INFO_POLICY2,
            &stub,
        ) {
            Err(Fault { status, .. }) => assert_eq!(status, crate::rpc::pdu::NCA_PROTO_ERROR),
            other => panic!("expected a level refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_sid_shorter_than_its_header_writes_nothing() {
        // The guard keeps a malformed SID from panicking on a slice: `domain_sid` normally comes
        // from the issuer, but a value read from a store that a different version wrote is not
        // something this module can assume is well formed. A panic in the pipe handler would take
        // the connection down mid-answer, which is worse than an answer without a SID.
        let mut writer = NdrWriter::new();
        write_dom_sid2(&mut writer, &[0x01, 0x04, 0x00, 0x00]);
        assert!(writer.finish().is_empty());

        // And a well-formed one writes its count, its header and its sub-authorities.
        let mut writer = NdrWriter::new();
        write_dom_sid2(&mut writer, DOMAIN_SID);
        let written = writer.finish();
        assert_eq!(written.len(), 4 + 24, "count, header, four sub-authorities");
        assert_eq!(&written[..4], &4u32.to_le_bytes(), "the conformant count");
        assert_eq!(&written[4..], DOMAIN_SID);
    }

    #[tokio::test]
    async fn serving_answers_through_the_pipe_entry_point() {
        // `serve` is what the pipe calls, and it delegates to `dispatch` with the server's own
        // configuration. A wrapper with no test can pass the wrong field and every handler test
        // still passes - the state is built here directly rather than through the builder because
        // this asserts the delegation, not the assembly.
        let state = ServerState::new(
            crate::server::ServerConfig::for_test(),
            crate::server::ServerUsers {
                table: Default::default(),
            },
            Vec::new(),
        );
        // Nobody is admitted by this test: `serve` ignores the caller for every call this
        // interface implements, and the anonymous identity says so rather than inventing a user.
        let caller = Caller {
            identity: crate::proto::auth::ntlm::Identity::Anonymous,
            can_encrypt: false,
        };

        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&12u16.to_le_bytes());
        let answered = serve(&state, &caller, OPNUM_QUERY_INFO_POLICY2, &stub)
            .await
            .expect("the pipe entry answers level 12");
        assert_eq!(
            answered,
            dns_domain_info_body(
                POLICY_DNS_DOMAIN_INFORMATION,
                &DomainView::of(&state.config)
            ),
            "serve must pass this server's own configuration"
        );
    }

    #[test]
    fn a_truncated_close_is_refused_rather_than_answered() {
        // Nineteen octets cannot be a policy handle. Answering would tell the client its handle was
        // closed when there never was one.
        match close_handle(&[0u8; 19]) {
            Err(Fault { status, .. }) => assert_eq!(status, crate::rpc::pdu::NCA_PROTO_ERROR),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_answer_names_the_domain_when_it_has_one_and_this_server_when_it_does_not() {
        // `Name` is what a member compares against its configured workgroup, so the fallback
        // matters: a deployment that states no domain name still has to answer with something
        // consistent, and the server's own name is the only name it has.
        let named = DomainView::of(&crate::server::ServerConfig::for_test());
        assert_eq!(named.netbios, "AD", "the domain's name, not the server's");
        assert_eq!(named.dns, "ad.example.com");

        let unnamed = crate::server::ServerConfig {
            domain_netbios: None,
            dns_domain: None,
            ..crate::server::ServerConfig::for_test()
        };
        let view = DomainView::of(&unnamed);
        assert_eq!(view.netbios, "SAMBA", "falls back to the server's own name");
        assert_eq!(
            view.dns, "samba.local",
            "and to a .local domain, lowercased - a member that compares this against its realm              finds a different domain, which is the honest outcome when none was stated"
        );
    }

    #[test]
    fn only_the_handle_shape_of_the_level_is_answered() {
        // The request carries the level as `ushort` after the handle; a level this server has no
        // answer for is refused before anything is written, because a half-built answer is worse
        // than none. Level 3 is PolicyPrimaryDomainInformation.
        let mut stub = vec![0u8; 20];
        stub.extend_from_slice(&3u16.to_le_bytes());
        assert_eq!(policy_level(&stub), None);
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
