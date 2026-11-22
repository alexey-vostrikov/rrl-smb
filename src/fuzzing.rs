//! Parsers the crate exposes to `cargo fuzz`, reached through `--cfg fuzzing`.
//!
//! Each function takes the octets a fuzz target hands it and asserts only that the parser answers
//! rather than panics: the assertion is the point, since a panic is what libFuzzer reports. Nothing
//! here is compiled into a normal build — the module is behind `#[cfg(fuzzing)]`, which `cargo fuzz`
//! sets — so a coverage figure for these functions is always zero, and a CRAP score built from it
//! says nothing about the code they exercise.
//!
//! Kept out of `lib.rs` rather than inside it: a harness that no build contains is not part of the
//! crate's surface, and a reader of the crate's root should not have to scroll past it.

use std::sync::Arc;

use crate::conn::state::Connection;
use crate::proto::auth::{ntlm, spnego};
use crate::proto::framing;
use crate::proto::header::Smb2Header;

/// Decodes the start of `data` as a transport frame header.
pub fn frame(data: &[u8]) {
    if let Some(hdr) = data.first_chunk::<{ framing::FRAME_HEADER_LEN }>() {
        let _ = framing::decode_frame_header(hdr);
    }
}

/// Parses `data` as an SMB2 header.
pub fn header(data: &[u8]) {
    let _ = Smb2Header::parse(data);
}

/// Decodes `data` as a SPNEGO NegTokenInit and as a NegTokenResp.
pub fn spnego(data: &[u8]) {
    let _ = spnego::decode_init_token(data);
    let _ = spnego::decode_resp_token(data);
}

/// Parses `data` as each NTLM message the server receives.
pub fn ntlm(data: &[u8]) {
    let _ = ntlm::NtlmNegotiate::parse(data);
    let _ = ntlm::NtlmAuthenticate::parse(data);
}

/// Parses `data` as the data of a lease create context.
pub fn lease_context(data: &[u8]) {
    let _ = crate::proto::messages::LeaseContext::parse(data);
}

/// Parses `data` as a UTF-16LE CREATE name and checks the result. A
/// name without `:` parses as `SmbPath::from_utf16` does. In a name
/// with one, the text before the first `:` parses as the path, a suffix
/// that selects no named stream is `::$DATA`, `::$INDEX_ALLOCATION` or
/// `:$I30:$INDEX_ALLOCATION`, and the path and stream put back together
/// parse to the same result. A data stream that a stream rename target
/// names is the one CREATE opens for `f` followed by the target.
pub fn create_name(data: &[u8]) {
    use crate::stream::{StreamPart, StreamType, parse_create_name, parse_stream_target};
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    if let Ok(target) = parse_stream_target(&units) {
        let part = match (target.stream, target.kind) {
            (Some(stream), None | Some(StreamType::Data)) => Some(StreamPart::Named(stream)),
            (None, Some(StreamType::Data)) => Some(StreamPart::Data),
            _ => None,
        };
        if let Some(part) = part {
            let mut file: Vec<u16> = "f".encode_utf16().collect();
            file.extend_from_slice(&units);
            let expected = ("f".parse().expect("a valid path"), part);
            assert_eq!(parse_create_name(&file).ok(), Some(expected));
        }
    }
    let parsed = parse_create_name(&units);
    let Ok(name) = String::from_utf16(&units) else {
        assert!(parsed.is_err());
        return;
    };
    let Some((file, suffix)) = name.split_once(':') else {
        let path = parsed.ok().map(|(path, stream)| {
            assert_eq!(stream, StreamPart::None);
            path
        });
        assert_eq!(path, crate::SmbPath::from_utf16(&units).ok());
        return;
    };
    let Ok((path, stream)) = parsed else {
        return;
    };
    assert_eq!(file.parse::<crate::SmbPath>().ok(), Some(path.clone()));
    let suffix = suffix.to_ascii_uppercase();
    let rebuilt = match &stream {
        StreamPart::None => panic!("a name with `:` parsed without a stream part"),
        StreamPart::Data => {
            assert_eq!(suffix, ":$DATA");
            format!("{}::$DATA", path.display_backslash())
        }
        StreamPart::Directory => {
            assert!(matches!(
                suffix.as_str(),
                ":$INDEX_ALLOCATION" | "$I30:$INDEX_ALLOCATION"
            ));
            format!("{}::$INDEX_ALLOCATION", path.display_backslash())
        }
        StreamPart::Named(stream) => {
            format!("{}:{}", path.display_backslash(), stream.as_str())
        }
        StreamPart::NamedDirectory(stream) => format!(
            "{}:{}:$INDEX_ALLOCATION",
            path.display_backslash(),
            stream.as_str()
        ),
    };
    let units: Vec<u16> = rebuilt.encode_utf16().collect();
    assert_eq!(parse_create_name(&units).ok(), Some((path, stream)));
}

/// Parses `data` as the data of an `AAPL` create context. It parses
/// exactly when it is 24 bytes with CommandCode 1, into the bitmap and
/// client caps at offsets 8 and 16. The reply to it holds the parts its
/// bitmap asks for, each at the offset the bits before it leave.
pub fn aapl_context(data: &[u8]) {
    use crate::proto::messages::aapl::{AAPL_MODEL_INFO, AAPL_SERVER_CAPS, AAPL_VOLUME_CAPS};
    use crate::proto::messages::{AaplQuery, AaplReply};
    let parsed = AaplQuery::parse(data);
    assert_eq!(
        parsed.is_ok(),
        data.len() == 24 && data[..4] == [1, 0, 0, 0]
    );
    let Ok(query) = parsed else {
        return;
    };
    assert_eq!(query.bitmap.to_le_bytes(), data[8..16]);
    assert_eq!(query.client_caps.to_le_bytes(), data[16..24]);
    let (server_caps, volume_caps) = (query.client_caps, !query.client_caps);
    let model = "smb-server";
    let reply = AaplReply {
        bitmap: query.bitmap,
        server_caps,
        volume_caps,
        model,
    }
    .encode();
    let bitmap = query.bitmap & (AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO);
    assert_eq!(reply[..8], [1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(reply[8..16], bitmap.to_le_bytes());
    let mut at = 16;
    for (bit, caps) in [
        (AAPL_SERVER_CAPS, server_caps),
        (AAPL_VOLUME_CAPS, volume_caps),
    ] {
        if bitmap & bit != 0 {
            assert_eq!(reply[at..at + 8], caps.to_le_bytes());
            at += 8;
        }
    }
    if bitmap & AAPL_MODEL_INFO != 0 {
        let units = crate::utils::utf16le(model);
        assert_eq!(reply[at..at + 4], [0, 0, 0, 0]);
        assert_eq!(reply[at + 4..at + 8], (units.len() as u32).to_le_bytes());
        assert_eq!(reply[at + 8..], units);
        at += 8 + units.len();
    }
    assert_eq!(reply.len(), at);
}

/// Parses `data` as a FILE_FULL_EA_INFORMATION list and as a
/// FILE_GET_EA_INFORMATION list. Every attribute read has a valid name
/// and reads back the same from the list it encodes to; every name read
/// is valid and listed once.
pub fn ea_list(data: &[u8]) {
    use crate::ea::{encode_full_list, parse_full_list, parse_get_list, valid_name};
    if let Ok(eas) = parse_full_list(data) {
        assert!(!eas.is_empty());
        assert!(eas.iter().all(|ea| valid_name(ea.name.as_bytes())));
        assert_eq!(parse_full_list(&encode_full_list(&eas)), Ok(eas));
    }
    if let Ok(names) = parse_get_list(data) {
        for (at, name) in names.iter().enumerate() {
            assert!(valid_name(name.as_bytes()));
            assert!(
                !names[..at]
                    .iter()
                    .any(|before| before.eq_ignore_ascii_case(name))
            );
        }
    }
}

/// Parses `data` as a lease break acknowledgment.
pub fn lease_ack(data: &[u8]) {
    let _ = crate::proto::messages::LeaseBreakAck::parse(data);
}

/// Parses `data` as the data of each durable handle create context.
pub fn durable_context(data: &[u8]) {
    use crate::proto::messages::{
        DurableReconnect, DurableReconnectV2, DurableRequest, DurableRequestV2,
    };
    let _ = DurableRequest::parse(data);
    let _ = DurableReconnect::parse(data);
    let _ = DurableRequestV2::parse(data);
    let _ = DurableReconnectV2::parse(data);
}

/// Parses `data` as a create context chain and reads its durable handle
/// contexts on each dialect.
pub fn durable_ask(data: &[u8]) {
    use crate::proto::messages::{CreateContext, Dialect};
    let Ok(contexts) = CreateContext::parse_chain(data) else {
        return;
    };
    for dialect in [
        None,
        Some(Dialect::Smb202),
        Some(Dialect::Smb210),
        Some(Dialect::Smb300),
        Some(Dialect::Smb302),
        Some(Dialect::Smb311),
        Some(Dialect::Smb2Wildcard),
    ] {
        let _ = crate::handlers::create::durable_ask(&contexts, dialect);
    }
}

/// Parses `data` as a DCE/RPC PDU a client sends.
pub fn rpc_pdu(data: &[u8]) {
    let _ = crate::rpc::pdu::parse(data);
}

/// Writes `data` to an association in chunks whose size the first
/// byte picks, answering every call with a fault and with its stub as
/// a response. Every PDU sent back parses, a response fits in the size
/// the bind negotiated, and what the association holds stays bounded.
pub fn rpc_association(data: &[u8]) {
    use crate::rpc::association::{Association, Fault, Step};
    use crate::rpc::pdu::{
        self, MAX_FRAG, NCA_OP_RNG_ERROR, PTYPE_ALTER_CONTEXT_RESP, PTYPE_BIND_ACK, PTYPE_RESPONSE,
    };

    let Some((&chunk, data)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(chunk).max(1);
    let mut assoc = Association::default();
    let mut max_frag = MAX_FRAG;
    for mut piece in data.chunks(chunk) {
        while let Some(step) = assoc.next_step(&mut piece, &|_| None) {
            let sent = match step {
                Step::Send(pdu) => vec![pdu],
                Step::Call(call) => {
                    let fault = Fault {
                        status: NCA_OP_RNG_ERROR,
                        did_not_execute: true,
                    };
                    let mut replies = assoc.reply(&call, Err(fault));
                    replies.extend(assoc.reply(&call, Ok(call.stub.clone())));
                    replies
                }
            };
            for pdu in sent {
                assert!(pdu::parse(&pdu).is_some());
                match pdu[2] {
                    PTYPE_BIND_ACK => max_frag = u16::from_le_bytes([pdu[16], pdu[17]]),
                    PTYPE_RESPONSE => assert!(pdu.len() <= usize::from(max_frag)),
                    PTYPE_ALTER_CONTEXT_RESP => {}
                    _ => assert!(pdu.len() <= usize::from(MAX_FRAG)),
                }
            }
            assert!(assoc.held() <= (64 << 10) + usize::from(u16::MAX));
        }
    }
}

/// Runs `data` as a srvsvc request stub. The first byte picks the
/// operation: NetrShareEnum, NetrShareGetInfo, NetrServerGetInfo or,
/// with the second byte, any opnum. The caller sees three shares.
pub fn srvsvc_request(data: &[u8]) {
    use crate::rpc::srvsvc::{self, ListedShare, ShareView};

    let Some((&pick, stub)) = data.split_first() else {
        return;
    };
    let (opnum, stub) = match pick % 4 {
        0 => (srvsvc::OPNUM_SHARE_ENUM, stub),
        1 => (srvsvc::OPNUM_SHARE_GET_INFO, stub),
        2 => (srvsvc::OPNUM_SERVER_GET_INFO, stub),
        _ => match stub.split_first() {
            Some((&opnum, stub)) => (u16::from(opnum), stub),
            None => return,
        },
    };
    let share = |name: &str, kind, remark: &str| ListedShare {
        name: name.to_string(),
        kind,
        remark: remark.to_string(),
    };
    let view = ShareView {
        server_name: "FUZZ".to_string(),
        shares: vec![
            share("public", 0, ""),
            share("d\u{f6}cs$", 0, "\u{1F9A4} remark"),
            share("IPC$", 0x8000_0003, "Remote IPC"),
        ],
    };
    let _ = srvsvc::call(opnum, stub, &view);
}

/// Runs `data` through the WS-Discovery target service: the first byte
/// picks the family of the sender, the next 4 or 16 bytes its address
/// and 2 its port, and the rest is the datagram. A reply goes only to a
/// sender on the link, and is a well-formed envelope that fits a
/// datagram.
#[cfg(all(feature = "discovery", unix))]
pub fn wsd_datagram(data: &[u8]) {
    crate::discovery::wsd::fuzz_datagram(data);
}

/// Answers `data` as a whole request to the WS-Discovery metadata
/// endpoint.
#[cfg(all(feature = "discovery", unix))]
pub fn wsd_http(data: &[u8]) {
    crate::discovery::wsd::fuzz_http(data);
}

/// Dispatches one frame payload on a fresh connection to `server`.
pub async fn dispatch(server: &crate::SmbServer, frame: &[u8]) -> Option<Vec<u8>> {
    let state = server.state();
    let conn = Arc::new(Connection::new(
        state.config.server_guid,
        state.config.max_read_size,
        state.config.max_write_size,
    ));
    crate::dispatch::dispatch_frame(&state, &conn, frame)
        .await
        .map(|out| out.bytes)
}
