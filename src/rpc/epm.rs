//! The endpoint mapper (MS-RPCE 2.2.2.1): the call a client makes before it can reach `drsuapi`.
//!
//! # Why this exists at all
//!
//! `DsBind` lives on `ncacn_ip_tcp`, and a client learns **which port** from this service at TCP 135.
//! Without it the client asks, gets nothing, and reports `RPC_S_SERVER_UNAVAILABLE` (`0x6ba`) for a
//! `DsBind` that would otherwise have worked - measured on a Windows Server 2022 join, where
//! `NetpGetComputerObjectDn` failed with exactly that and the whole join stopped at `0x57`.
//!
//! Serving the interface over a named pipe instead was already measured and does not help: a Windows
//! client refuses that binding with `RPC_S_INVALID_BINDING` (`0x6a7`). The endpoint has to be named
//! by a tower this service hands out.
//!
//! # The tower, octet for octet
//!
//! A tower is a floor count and then floors, with **no alignment anywhere** (pidl marks it
//! `NDR_NOALIGN`). Each floor is `u16 lhs_length`, the left-hand side, `u16 rhs_length`, the
//! right-hand side; the first octet of the left-hand side is the protocol id. The shapes below were
//! taken from a live Samba domain controller's own answer, not from reading the specification:
//!
//! ```text
//! 05 00                                      five floors
//! 13 00 0d <uuid 16> 04 00   02 00 00 00      drsuapi 4.0
//! 13 00 0d <uuid 16> 02 00   02 00 00 00      NDR 2.0
//! 01 00 0b                   02 00 00 00      ncacn
//! 01 00 07                   02 00 <port>     tcp, the port little-endian
//! 01 00 09                   04 00 00000000   ip, 0.0.0.0
//! ```
//!
//! # The answer
//!
//! `ept_lookup` answers the client's handle, a count, a **conformant and varying** array of entries,
//! then the towers (deferred, because each entry refers to one), then the status. An entry is the
//! object GUID, a pointer to its tower, and an annotation that this server writes as zero offset and
//! a length that counts its terminating NUL. Each deferred tower is written as the same length
//! twice: once for `epm_twr_t.tower_length` and once because the tower is a `[subcontext(4)]`, which
//! writes its own length. Samba's answer parses to exactly its own length under these rules, which
//! is how the last three details were confirmed.

use super::association::Fault;
use super::ndr::{NdrReader, NdrWriter};
use super::pdu::{DRSUAPI, LSARPC, NCA_OP_RNG_ERROR, NCA_PROTO_ERROR, NDR, NETLOGON, SyntaxId};

/// `ept_lookup` (opnum 2): the call a client makes to learn where an interface lives.
pub(crate) const OPNUM_LOOKUP: u16 = 2;
/// `ept_map` (opnum 3): the same question asked with a whole tower instead of an interface id.
pub(crate) const OPNUM_MAP: u16 = 3;
/// `ept_lookup_handle_free` (opnum 4): the client is done with an enumeration.
pub(crate) const OPNUM_LOOKUP_HANDLE_FREE: u16 = 4;

/// `EPMAPPER_STATUS_OK`.
const STATUS_OK: u32 = 0;
/// `EPMAPPER_STATUS_NO_MORE_ENTRIES`: a legal answer that says "nothing (more) here".
const STATUS_NO_MORE_ENTRIES: u32 = 0x16c9_a0d6;

/// Floor 1 and 2 are both interface floors, and both carry this protocol id.
const PROTOCOL_UUID: u8 = 0x0d;
/// The connection-oriented protocol floor.
const PROTOCOL_NCACN: u8 = 0x0b;
/// The TCP transport floor: its right-hand side is the port.
const PROTOCOL_TCP: u8 = 0x07;
/// The IP address floor, which this server fills with `0.0.0.0` the way Samba does.
const PROTOCOL_IP: u8 = 0x09;

/// `RPC_C_EP_MATCH_BY_IF`: the client asked for one interface rather than everything.
const INQUIRY_MATCH_BY_IF: u32 = 0x0000_0001;
/// `RPC_C_EP_MATCH_BY_BOTH`.
const INQUIRY_MATCH_BY_BOTH: u32 = 0x0000_0003;

/// What this server publishes: one interface over TCP at one port.
#[derive(Debug, Clone, Copy)]
pub struct Published {
    /// The port `drsuapi` answers on.
    pub drsuapi_port: u16,
}

/// Answers one call on the endpoint mapper.
pub(crate) fn serve(opnum: u16, stub: &[u8], published: Published) -> Result<Vec<u8>, Fault> {
    match opnum {
        OPNUM_LOOKUP => lookup(stub, published),
        OPNUM_MAP => map(stub, published),
        OPNUM_LOOKUP_HANDLE_FREE => Ok(free_handle()),
        other => {
            tracing::warn!(
                opnum = other,
                stub = stub.len(),
                "epm: no handler for this call"
            );
            Err(Fault {
                status: NCA_OP_RNG_ERROR,
                did_not_execute: true,
            })
        }
    }
}

/// Every interface this server is willing to name, on one port.
///
/// Measured: a Windows join asks the mapper about `netlogon` and `lsarpc` as well as `drsuapi`, and
/// a mapper that answers "nothing here" for the first two makes the client give up on the whole
/// controller - it never gets as far as the interface it actually needed. All three are named on the
/// port this server answers RPC on; a client reads the number from the tower and does not care which
/// interface it came with.
fn published_towers(port: u16) -> Vec<(SyntaxId, &'static str, Vec<u8>)> {
    vec![
        (DRSUAPI, "drsuapi", interface_tower(DRSUAPI, port)),
        (NETLOGON, "netlogon", interface_tower(NETLOGON, port)),
        (LSARPC, "lsarpc", interface_tower(LSARPC, port)),
    ]
}

/// The tower that names any interface on `port`.
fn interface_tower(syntax: SyntaxId, port: u16) -> Vec<u8> {
    let mut tower = Vec::new();
    tower.extend_from_slice(&5_u16.to_le_bytes());
    interface_floor(&mut tower, &syntax.uuid, syntax.version, 0);
    interface_floor(&mut tower, &NDR.uuid, NDR.version, 0);
    transport_floor(&mut tower, PROTOCOL_NCACN, &0_u16.to_le_bytes());
    transport_floor(&mut tower, PROTOCOL_TCP, &port.to_le_bytes());
    transport_floor(&mut tower, PROTOCOL_IP, &[0, 0, 0, 0]);
    tower
}

/// One interface floor: `u16 lhs`, the UUID and its version, `u16 rhs` and the minor version.
///
/// The version is narrowed to sixteen octets here because that is what the floor holds; a syntax id
/// with a version that does not fit is not one this tower could name.
fn interface_floor(tower: &mut Vec<u8>, uuid: &[u8; 16], major: u32, minor: u16) {
    let major = u16::try_from(major).expect("a version a tower can hold");
    let mut lhs = Vec::with_capacity(19);
    lhs.push(PROTOCOL_UUID);
    lhs.extend_from_slice(uuid);
    lhs.extend_from_slice(&major.to_le_bytes());
    let _ = u16::try_from(lhs.len()).map(|size| tower.extend_from_slice(&size.to_le_bytes()));
    tower.extend_from_slice(&lhs);
    let rhs = minor.to_le_bytes();
    let _ = u16::try_from(rhs.len()).map(|size| tower.extend_from_slice(&size.to_le_bytes()));
    tower.extend_from_slice(&rhs);
}

/// One transport floor: a single protocol octet and its right-hand side.
fn transport_floor(tower: &mut Vec<u8>, protocol: u8, rhs: &[u8]) {
    let _ = u16::try_from(1).map(|size| tower.extend_from_slice(&size.to_le_bytes()));
    tower.push(protocol);
    let _ = u16::try_from(rhs.len()).map(|size| tower.extend_from_slice(&size.to_le_bytes()));
    tower.extend_from_slice(rhs);
}

/// What a client reads on `ept_lookup`: the handle, the count, the entries and their towers.
fn lookup(stub: &[u8], published: Published) -> Result<Vec<u8>, Fault> {
    let mut reader = NdrReader::new(stub);
    let inquiry = reader
        .u32()
        .ok_or_else(|| malformed("inquiry_type", stub))?;
    let object_present = reader.pointer().unwrap_or(false);
    let ifid_present = reader.pointer().unwrap_or(false);
    let _vers_option = reader.u32().unwrap_or(0);
    // The handle is inline: twenty octets, not a pointer. Measured against a live Samba controller,
    // whose `ept_lookup` takes a request of forty octets with all fields empty.
    let handle = reader
        .bytes(20)
        .ok_or_else(|| malformed("entry_handle", stub))?;
    let max_ents = reader.u32().unwrap_or(0);
    // The referents, in the order their pointers appeared.
    let object = object_present.then(|| reader.bytes(16)).flatten();
    let ifid = ifid_present
        .then(|| {
            let uuid = reader.bytes(16)?;
            let major = reader.u16()?;
            let minor = reader.u16()?;
            Some((uuid, major, minor))
        })
        .flatten();
    tracing::info!(
        inquiry,
        object = object.is_some(),
        ifid = ifid.is_some(),
        max_ents,
        handle = %hex(handle),
        "epm: ept_lookup"
    );

    // An enumeration already answered is a finished one: this server publishes a fixed set, so
    // handing out the handle and stopping is the whole conversation.
    let already = handle
        .get(4..20)
        .is_some_and(|uuid| uuid.iter().any(|octet| *octet != 0));
    // What this request is entitled to see: the one interface its filter names, or everything this
    // server publishes. A filter that names an interface without an id is malformed, and answering
    // nothing is the honest reading of it.
    let filtered = matches!(inquiry, INQUIRY_MATCH_BY_IF | INQUIRY_MATCH_BY_BOTH);
    let chosen: Vec<(SyntaxId, &'static str, Vec<u8>)> = if already {
        Vec::new()
    } else {
        published_towers(published.drsuapi_port)
            .into_iter()
            .filter(|(syntax, _, _)| match (filtered, ifid) {
                // The version is not compared: a client asks with the one it will bind, and this
                // server publishes exactly one per interface. Refusing on a version that differs in
                // a way the client did not intend is how a mapper answers "nothing here" to a
                // question it could have answered.
                (true, Some((uuid, _major, _minor))) => uuid == syntax.uuid,
                (true, None) => false,
                (false, _) => true,
            })
            .take(usize::try_from(max_ents).unwrap_or(0))
            .collect()
    };
    tracing::info!(
        answers = chosen.len(),
        interfaces = ?chosen
            .iter()
            .map(|(syntax, name, _)| format!("{name} {}.{}", hex(&syntax.uuid), syntax.version))
            .collect::<Vec<_>>(),
        "epm: ept_lookup chooses"
    );

    let mut writer = NdrWriter::new();
    // The handle the client may come back with, and must come back with to end the enumeration.
    writer.bytes(&lookup_handle());
    if chosen.is_empty() {
        writer.u32(0); // num_ents
        writer.u32(max_ents);
        writer.u32(0); // offset
        writer.u32(0); // actual
        writer.u32(STATUS_NO_MORE_ENTRIES);
        return Ok(writer.finish());
    }

    let count = u32::try_from(chosen.len()).expect("a short list");
    writer.u32(count); // num_ents
    writer.u32(max_ents);
    writer.u32(0); // offset into the array
    writer.u32(count); // actual count
    for (_, name, _) in &chosen {
        // One entry: the object GUID (unset), a referent to its tower, then the annotation - which
        // names the interface, as a real controller's does.
        writer.bytes(&[0_u8; 16]);
        writer.pointer(true);
        writer.u32(0); // annotation offset
        let mut annotation = name.as_bytes().to_vec();
        annotation.push(0);
        writer.u32(u32::try_from(annotation.len()).expect("a short annotation"));
        writer.raw(&annotation);
        writer.align(4);
    }
    // The towers, deferred and in the order their referents appeared: `tower_length`, then the
    // subcontext's own length, then the octets.
    for (_, _, tower) in &chosen {
        let size = u32::try_from(tower.len()).expect("a short tower");
        writer.u32(size);
        writer.u32(size);
        writer.raw(tower);
        writer.align(4);
    }
    writer.u32(STATUS_OK);
    Ok(writer.finish())
}

/// `ept_map`: a client that sends a whole tower and asks for a complete one back.
///
/// This is the call a Windows join actually makes - measured, and not the `ept_lookup` the
/// specification suggests: the request arrives with `object` set, a `map_tower` holding the
/// interface and transport it wants, a handle and `max_towers`. The tower is found by its own
/// self-describing length rather than at a fixed offset, because the fields around it differ
/// between clients and a tower's floors chain to exactly the length written before them.
///
/// The request is answered only when the tower asks for an interface this server publishes over a
/// transport it serves: a client asking for something else is told there is nothing here, which is
/// a different answer from a tower naming a service that would not answer.
fn map(stub: &[u8], published: Published) -> Result<Vec<u8>, Fault> {
    // The request bytes behind a diagnostic flag: this call's layout is the one thing here that
    // could not be taken from the specification, and a client that sends it is the only source.
    if std::env::var_os("RRL_EPM_DIAG").is_some() {
        tracing::warn!(stub = %hex(stub), "epm: ept_map request bytes");
    }
    let asked = tower_in(stub);
    // Which interface the request's tower names, and the tower this server has for it. A request
    // for something this server does not publish is answered "nothing here", which is a different
    // statement from a tower naming a service that would refuse the client.
    let wanted = asked
        .as_deref()
        .and_then(|tower| published_interface(tower, published.drsuapi_port));
    let serves = wanted.is_some();
    tracing::info!(
        asked = %asked
            .as_deref()
            .map(|tower| hex(&tower[..tower.len().min(40)]))
            .unwrap_or_default(),
        interface = wanted.as_ref().map(|(_, name, _)| *name).unwrap_or("-"),
        serves,
        "epm: ept_map asked about this interface"
    );
    // `max_towers` is a size parameter, and the answer's conformant array has to be sized by the
    // value the client named - not by what this server happens to return. Answering one tower in an
    // array declared with room for one, when the client asked for more, is what a client reports as
    // `RPC_X_BAD_STUB_DATA` (0x6f7): its unmarshaller checks the bound before reading an element.
    //
    // Measured: a Windows Server 2022 request carries it at octet 20, and zeroing that word makes a
    // real Samba answer "no more entries" instead of a tower.
    // `max_towers` is the last word of the request: the arguments are `object`, `map_tower` (both
    // deferred to the end), the handle inline and this bound after it. Measured against a live
    // Samba controller: the same 132-octet request carries `04 00 00 00` there, and its answer
    // declares exactly that bound.
    let max_towers = u32::from_le_bytes(
        stub.get(stub.len().saturating_sub(4)..)
            .and_then(|word| word.try_into().ok())
            .unwrap_or([1, 0, 0, 0]),
    )
    .clamp(1, 500);
    tracing::info!(
        stub = stub.len(),
        tower = asked.as_ref().map(Vec::len),
        serves,
        max_towers,
        "epm: ept_map"
    );

    let mut writer = NdrWriter::new();
    writer.bytes(&[0_u8; 20]); // a null entry handle: this answer is complete
    if !serves {
        writer.u32(0); // num_towers
        writer.u32(max_towers); // the conformant bound the client named
        writer.u32(0); // offset
        writer.u32(0); // actual
        writer.u32(STATUS_NO_MORE_ENTRIES);
        return Ok(writer.finish());
    }
    let (_, _, tower) = wanted.expect("checked above");
    writer.u32(1); // num_towers
    writer.u32(max_towers); // the maximum
    writer.u32(0); // offset
    writer.u32(1); // actual
    // The referent id is measured, not chosen: a live Samba controller answers `03 00 00 00` here,
    // and a Windows client refuses an answer whose id is `0x00020000` with `RPC_X_BAD_STUB_DATA`
    // (0x6f7) after accepting the rest of the stub. The value means nothing in NDR - only being
    // non-zero and unique does - so the one a client is known to accept is the one to send.
    writer.u32(TOWER_REFERENT);
    let size = u32::try_from(tower.len()).expect("a short tower");
    writer.u32(size);
    writer.u32(size);
    writer.raw(&tower);
    writer.align(4);
    writer.u32(STATUS_OK);
    Ok(writer.finish())
}

/// The referent id a client is known to accept in an `ept_map` answer.
const TOWER_REFERENT: u32 = 3;

/// The tower in a request, found by its self-describing length.
///
/// `epm_twr_t` writes the tower's size and then, because the tower is a `[subcontext(4)]`, the same
/// size again before the octets. A candidate is taken only if the floors inside it chain to exactly
/// that length, so a coincidence in the surrounding fields cannot be mistaken for a tower.
fn tower_in(stub: &[u8]) -> Option<Vec<u8>> {
    let mut at = 0;
    while at + 8 <= stub.len() {
        let outer = u32::from_le_bytes(stub[at..at + 4].try_into().expect("four octets")) as usize;
        let inner =
            u32::from_le_bytes(stub[at + 4..at + 8].try_into().expect("four octets")) as usize;
        let start = at + 8;
        if outer == inner
            && outer >= 4
            && start + outer <= stub.len()
            && tower_size(&stub[start..start + outer]) == Some(outer)
        {
            return Some(stub[start..start + outer].to_vec());
        }
        at += 4;
    }
    None
}

/// How many octets a tower's floors take, or `None` if they do not describe one.
fn tower_size(tower: &[u8]) -> Option<usize> {
    let count = usize::from(u16::from_le_bytes(tower.get(..2)?.try_into().ok()?));
    if count == 0 {
        return None;
    }
    let mut at = 2;
    for _ in 0..count {
        let lhs = usize::from(u16::from_le_bytes(tower.get(at..at + 2)?.try_into().ok()?));
        at += 2 + lhs;
        let rhs = usize::from(u16::from_le_bytes(tower.get(at..at + 2)?.try_into().ok()?));
        at += 2 + rhs;
        if at > tower.len() {
            return None;
        }
    }
    Some(at)
}

/// The tower this server would answer with, for the interface a request's tower names.
///
/// Read from the floors rather than searched for: the first floor carries the interface, and one of
/// the later ones names the transport. A tower for an interface this server does not publish over a
/// transport it does not serve is `None`.
fn published_interface(tower: &[u8], port: u16) -> Option<(SyntaxId, &'static str, Vec<u8>)> {
    let floors = floors_of(tower)?;
    let (protocol, uuid, _version) = floors.first().and_then(interface_of)?;
    if protocol != PROTOCOL_UUID || !floors.iter().any(|floor| floor.protocol == PROTOCOL_TCP) {
        return None;
    }
    published_towers(port)
        .into_iter()
        .find(|(syntax, _, _)| syntax.uuid == uuid)
}

/// One floor as the tower holds it.
struct Floor<'a> {
    protocol: u8,
    left: &'a [u8],
}

/// The floors of a tower, or `None` when its lengths do not chain.
fn floors_of(tower: &[u8]) -> Option<Vec<Floor<'_>>> {
    let count = usize::from(u16::from_le_bytes(tower.get(..2)?.try_into().ok()?));
    let mut at = 2;
    let mut floors = Vec::with_capacity(count);
    for _ in 0..count {
        let lhs = usize::from(u16::from_le_bytes(tower.get(at..at + 2)?.try_into().ok()?));
        at += 2;
        let left = tower.get(at..at + lhs)?;
        at += lhs;
        let rhs = usize::from(u16::from_le_bytes(tower.get(at..at + 2)?.try_into().ok()?));
        at += 2;
        at = at.checked_add(rhs)?;
        if at > tower.len() {
            return None;
        }
        floors.push(Floor {
            protocol: *left.first()?,
            left,
        });
    }
    (at == tower.len()).then_some(floors)
}

/// An interface floor's UUID and major version, when the floor is one.
fn interface_of(floor: &Floor<'_>) -> Option<(u8, [u8; 16], u16)> {
    // The protocol octet, sixteen of UUID, two of major version.
    if floor.left.len() != 19 {
        return None;
    }
    let uuid: [u8; 16] = floor.left.get(1..17)?.try_into().ok()?;
    let major = u16::from_le_bytes(floor.left.get(17..19)?.try_into().ok()?);
    Some((floor.protocol, uuid, major))
}

/// `ept_lookup_handle_free`: the handle comes back nulled, which is the whole answer.
fn free_handle() -> Vec<u8> {
    let mut writer = NdrWriter::new();
    writer.bytes(&[0_u8; 20]);
    writer.u32(STATUS_OK);
    writer.finish()
}

/// The handle this server hands out, and the one it recognises as its own.
///
/// A client only echoes it, but a null handle is what it reads as "the enumeration is over", so the
/// value has to be non-zero somewhere in its UUID.
fn lookup_handle() -> [u8; 20] {
    let mut handle = [0_u8; 20];
    handle[4..12].copy_from_slice(b"RRL-EPM!");
    handle
}

/// A stub that ended before a field this server reads, named for the log.
fn malformed(field: &str, stub: &[u8]) -> Fault {
    tracing::warn!(
        field,
        len = stub.len(),
        "epm: the stub ends before this field"
    );
    Fault {
        status: NCA_PROTO_ERROR,
        did_not_execute: true,
    }
}

/// Hex for a log line, in the form a trace of the wire reads.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|octet| format!("{octet:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published() -> Published {
        Published {
            drsuapi_port: 49152,
        }
    }

    /// The request a client sends when it wants everything: forty octets of nothing but a count.
    fn lookup_stub(max_ents: u32, handle: &[u8; 20]) -> Vec<u8> {
        let mut stub = Vec::new();
        stub.extend_from_slice(&0_u32.to_le_bytes()); // inquiry_type: all elements
        stub.extend_from_slice(&0_u32.to_le_bytes()); // object: NULL
        stub.extend_from_slice(&0_u32.to_le_bytes()); // interface_id: NULL
        stub.extend_from_slice(&0_u32.to_le_bytes()); // vers_option
        stub.extend_from_slice(handle);
        stub.extend_from_slice(&max_ents.to_le_bytes());
        stub
    }

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four octets"))
    }

    /// The tower, in the shape a live Samba controller answers with.
    #[test]
    fn the_tower_names_drsuapi_over_tcp_and_pads_nothing() {
        let tower = interface_tower(DRSUAPI, 49152);
        assert_eq!(&tower[..2], &[0x05, 0x00], "five floors");
        // Floor one: the interface floor, nineteen octets of left-hand side.
        assert_eq!(&tower[2..4], &[0x13, 0x00]);
        assert_eq!(tower[4], PROTOCOL_UUID);
        assert_eq!(&tower[5..21], &DRSUAPI.uuid);
        assert_eq!(&tower[21..23], &4_u16.to_le_bytes(), "drsuapi version 4.0");
        // Every floor's right-hand side is written with its own length.
        assert_eq!(&tower[23..25], &[0x02, 0x00]);
        assert_eq!(&tower[25..27], &[0x00, 0x00], "minor version");
        // The transport floor carries the port little-endian.
        let port_at = tower
            .windows(4)
            .position(|window| window == [0x01, 0x00, PROTOCOL_TCP, 0x02])
            .expect("a tcp floor");
        // `01 00` the left-hand side, `07` the protocol, `02 00` the right-hand side's length, then
        // the port: two octets of length come before it, not one.
        assert_eq!(
            u16::from_le_bytes([tower[port_at + 5], tower[port_at + 6]]),
            49152
        );
        assert_eq!(tower.len(), 75, "the size a live controller sends");
    }

    /// The acceptance of the whole interface: a client that asks for everything is told where
    /// `drsuapi` lives, and the answer is one entry with one tower behind a referent.
    #[test]
    fn a_lookup_answers_every_interface_this_server_publishes() {
        let stub = lookup_stub(500, &[0_u8; 20]);
        let body = serve(OPNUM_LOOKUP, &stub, published()).expect("answered");

        assert_eq!(word(&body, 0), 0, "the handle type the client sent");
        assert_eq!(&body[4..12], b"RRL-EPM!", "a handle that is not null");
        // Three interfaces, because a client asks about more than the one it needs: measured, a
        // join asks for `netlogon` and `lsarpc` as well, and a mapper that answers "nothing here"
        // for those makes it give up on the controller.
        assert_eq!(word(&body, 20), 3, "three endpoints");
        assert_eq!(word(&body, 24), 500, "the maximum the client offered");
        assert_eq!(word(&body, 28), 0, "offset into the array");
        assert_eq!(word(&body, 32), 3, "actual count");

        // Walk the entries: sixteen octets of GUID, a referent, then the annotation and its NUL.
        let mut at = 36;
        let mut names = Vec::new();
        for _ in 0..3 {
            assert_eq!(&body[at..at + 16], &[0_u8; 16], "no object");
            assert_ne!(word(&body, at + 16), 0, "the tower is behind a referent");
            assert_eq!(word(&body, at + 20), 0, "the annotation offset");
            let len = word(&body, at + 24) as usize;
            let name = &body[at + 28..at + 28 + len - 1];
            names.push(String::from_utf8(name.to_vec()).expect("ascii"));
            at = (at + 28 + len).next_multiple_of(4);
        }
        assert_eq!(names, ["drsuapi", "netlogon", "lsarpc"]);

        // Then the towers, in the same order, each length written twice.
        for syntax in [DRSUAPI, NETLOGON, LSARPC] {
            let len = word(&body, at) as usize;
            assert_eq!(
                word(&body, at + 4) as usize,
                len,
                "the subcontext repeats it"
            );
            assert_eq!(
                &body[at + 8..at + 8 + len],
                &interface_tower(syntax, 49152)[..]
            );
            at = (at + 8 + len).next_multiple_of(4);
        }
        assert_eq!(word(&body, at), STATUS_OK);
        assert_eq!(body.len(), at + 4, "nothing trails the status");
    }

    /// A filter naming `netlogon` is answered with `netlogon`, not with whatever is published first.
    #[test]
    fn a_lookup_by_interface_answers_that_interface() {
        let mut stub = Vec::new();
        stub.extend_from_slice(&INQUIRY_MATCH_BY_IF.to_le_bytes());
        stub.extend_from_slice(&0_u32.to_le_bytes()); // object: NULL
        stub.extend_from_slice(&1_u32.to_le_bytes()); // interface_id: a referent
        stub.extend_from_slice(&0_u32.to_le_bytes()); // vers_option
        stub.extend_from_slice(&[0_u8; 20]); // handle
        stub.extend_from_slice(&500_u32.to_le_bytes());
        stub.extend_from_slice(&NETLOGON.uuid);
        stub.extend_from_slice(&NETLOGON.version.to_le_bytes());
        stub.extend_from_slice(&0_u16.to_le_bytes());

        let body = serve(OPNUM_LOOKUP, &stub, published()).expect("answered");
        assert_eq!(word(&body, 20), 1, "one endpoint");
        let len = word(&body, 60) as usize;
        assert_eq!(
            &body[64..64 + len - 1],
            b"netlogon",
            "the one that was asked for"
        );
        let tower_at = (64 + len).next_multiple_of(4);
        let tower_len = word(&body, tower_at) as usize;
        assert_eq!(
            &body[tower_at + 8..tower_at + 8 + tower_len],
            &interface_tower(NETLOGON, 49152)[..]
        );
    }

    /// A client that comes back with the handle it was given has seen everything.
    #[test]
    fn a_second_lookup_with_the_handle_says_there_is_no_more() {
        let mut handle = lookup_handle();
        handle[0..4].copy_from_slice(&0_u32.to_le_bytes());
        let stub = lookup_stub(500, &handle);
        let body = serve(OPNUM_LOOKUP, &stub, published()).expect("answered");
        assert_eq!(word(&body, 20), 0, "no entries");
        assert_eq!(word(&body, body.len() - 4), STATUS_NO_MORE_ENTRIES);
    }

    /// An interface this server does not publish is not named, and the client is told so rather
    /// than being given a tower for something else.
    #[test]
    fn a_lookup_for_another_interface_answers_nothing() {
        let mut stub = Vec::new();
        stub.extend_from_slice(&INQUIRY_MATCH_BY_IF.to_le_bytes());
        stub.extend_from_slice(&0_u32.to_le_bytes()); // object: NULL
        stub.extend_from_slice(&1_u32.to_le_bytes()); // interface_id: a referent
        stub.extend_from_slice(&0_u32.to_le_bytes()); // vers_option
        stub.extend_from_slice(&[0_u8; 20]); // handle
        stub.extend_from_slice(&500_u32.to_le_bytes());
        // The referent: an interface this server does not serve, at any version.
        stub.extend_from_slice(&[0x11_u8; 16]);
        stub.extend_from_slice(&1_u16.to_le_bytes());
        stub.extend_from_slice(&0_u16.to_le_bytes());

        let body = serve(OPNUM_LOOKUP, &stub, published()).expect("answered");
        assert_eq!(word(&body, 20), 0, "nothing is published for it");
        assert_eq!(word(&body, body.len() - 4), STATUS_NO_MORE_ENTRIES);
    }

    /// The interface the client did ask for is answered: the filter must not refuse everything.
    #[test]
    fn a_lookup_for_drsuapi_by_interface_is_answered() {
        let mut stub = Vec::new();
        stub.extend_from_slice(&INQUIRY_MATCH_BY_IF.to_le_bytes());
        stub.extend_from_slice(&0_u32.to_le_bytes());
        stub.extend_from_slice(&1_u32.to_le_bytes());
        stub.extend_from_slice(&0_u32.to_le_bytes());
        stub.extend_from_slice(&[0_u8; 20]);
        stub.extend_from_slice(&500_u32.to_le_bytes());
        stub.extend_from_slice(&DRSUAPI.uuid);
        stub.extend_from_slice(&DRSUAPI.version.to_le_bytes());
        stub.extend_from_slice(&0_u16.to_le_bytes());

        let body = serve(OPNUM_LOOKUP, &stub, published()).expect("answered");
        assert_eq!(word(&body, 20), 1, "the endpoint it asked for");
        assert_eq!(word(&body, body.len() - 4), STATUS_OK);
    }

    /// The request a Windows Server 2022 join actually sends, captured from a live one.
    ///
    /// It is `ept_map`, not the `ept_lookup` the specification suggests, and its layout is not the
    /// one this crate would have written: `object` is not a pointer, the handle is inline, and
    /// `max_towers` sits before the tower rather than after it. What matters is that the tower is
    /// found and answered - without this, `DsBind` is unreachable and a join stops at `0x57`.
    fn windows_map_stub() -> Vec<u8> {
        let hex = concat!(
            "0100000000000000000000000000000000000000020000004b0000004b000000",
            "050013000d354251e3064bd111ab0400c04fc2dcd204000200000013000d045d",
            "888aeb1cc9119fe808002b10486002000200000001000b020000000100070200",
            "0087010009040000000000000000000000000000000000000000000000000000",
            "04000000",
        );
        (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn the_tower_a_windows_join_sends_is_found_and_answered() {
        let stub = windows_map_stub();
        assert_eq!(stub.len(), 132, "the capture is this long");
        let asked = tower_in(&stub).expect("the tower is found by its own length");
        assert_eq!(asked.len(), 75);
        assert!(
            published_interface(&asked, 49152).is_some(),
            "it asks for drsuapi over tcp"
        );

        let body = serve(OPNUM_MAP, &stub, published()).expect("answered");
        assert_eq!(word(&body, 20), 1, "one tower is offered");
        // The conformant bound the client named is what the answer declares, not a number of this
        // server's choosing. In this capture it is the last word of the request, `04 00 00 00`.
        assert_eq!(word(&body, 24), 4, "the client's own max_towers");
        assert_eq!(word(&body, body.len() - 4), STATUS_OK);
        // The port this server publishes is inside the tower it answers with.
        assert!(
            body.windows(2).any(|pair| pair == [0x00, 0xc0]),
            "49152 as little-endian octets"
        );
    }

    #[test]
    fn a_tower_for_another_interface_is_not_answered() {
        // The same request with drsuapi's UUID replaced by one nobody serves: the client must be
        // told there is nothing here rather than sent to a port that will refuse it.
        let mut stub = windows_map_stub();
        let asked = tower_in(&stub).expect("a tower");
        let at = stub
            .windows(asked.len())
            .position(|window| window == asked.as_slice())
            .expect("where the tower sits");
        stub[at + 5] ^= 0xFF;
        let body = serve(OPNUM_MAP, &stub, published()).expect("answered");
        assert_eq!(word(&body, 20), 0, "nothing is offered");
        assert_eq!(word(&body, body.len() - 4), STATUS_NO_MORE_ENTRIES);
    }

    #[test]
    fn freeing_the_handle_nulls_it() {
        let body =
            serve(OPNUM_LOOKUP_HANDLE_FREE, &lookup_handle(), published()).expect("answered");
        assert_eq!(body.len(), 24);
        assert_eq!(&body[..20], &[0_u8; 20]);
        assert_eq!(word(&body, 20), STATUS_OK);
    }

    #[test]
    fn a_call_this_server_does_not_implement_is_refused() {
        let fault = serve(0, &[], published()).expect_err("refused");
        assert_eq!(fault.status, NCA_OP_RNG_ERROR);
    }
}
