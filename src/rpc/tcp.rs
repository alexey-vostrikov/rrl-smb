//! `drsuapi` over `ncacn_ip_tcp`: the endpoint a Windows join reaches after asking the mapper.
//!
//! # Why this exists at all
//!
//! A join asks the endpoint mapper (port 135) where `drsuapi` lives, and a real domain controller
//! answers with a **TCP port**, not with the named pipe this server already serves. The client then
//! opens that port and binds `e3514235-4b06-11d1-ab04-00c04fc2dcd2` there - so a server that only
//! serves the pipe is invisible to it, and `NetpGetComputerObjectDn` fails with
//! `RPC_S_SERVER_UNAVAILABLE` however well the pipe works.
//!
//! Publishing a pipe floor (`0x08`) in the mapper's tower was measured and does **not** work: a
//! Windows client refuses such a binding with `RPC_S_INVALID_BINDING` (`0x6a7`), with the pipe name
//! as `drsuapi` and as `\drsuapi` alike. The endpoint has to be TCP.
//!
//! # What is served here
//!
//! Bind, alter_context and calls on `drsuapi`, over NDR32. The association is per TCP connection and
//! holds nothing else: a connection is one client, and closing it forgets everything, which is what
//! lets this be a plain loop rather than a state machine with a lifetime.
//!
//! # What is not here yet
//!
//! Authentication. A Windows client's `alter_context` for this endpoint carries `auth_type` 9
//! (`RPC_C_AUTHN_GSS_NEGOTIATE`) at level 6 (`Packet Privacy`), which is measured, not assumed; the
//! answer today names the contexts and leaves the verifier out, so the client reports
//! `RPC_S_PROTOCOL_ERROR` (`0x6c0`). The fields it sent are logged, because the next step is to
//! answer them and the values are the specification of what to answer.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use super::pdu::{self, AuthReply, Body, ContextResult, Pdu, SyntaxId};

/// The largest fragment this server will send, in octets.
///
/// 5840 is what a Samba domain controller advertises in its own `bind_ack`, measured on the stand;
/// matching it keeps a client's buffer assumptions unchanged between the two servers.
const MAX_FRAG: u16 = 5840;

/// `acceptance`: the context was taken.
const RESULT_ACCEPTANCE: u16 = 0;
/// `provider_rejection`: this server knows the interface but not the transfer syntax asked for.
const RESULT_PROVIDER_REJECTION: u16 = 2;
/// `reason_not_specified`, for an interface this server does not serve at all.
const REASON_NOT_SPECIFIED: u16 = 1;
/// `abstract_syntax_not_supported`, for a known interface with an unusable transfer syntax.
const REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED: u16 = 3;

/// Binds `addr` and serves every connection until the process ends.
///
/// Binding is not retried and not softened: a port this process cannot have is a configuration
/// fault, and a server that starts anyway is one that a client cannot reach while the log says it is
/// running.
pub async fn serve(addr: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    info!(%local, "rpc: serving drsuapi over ncacn_ip_tcp");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                // A failed accept is one connection, not the end of the listener: the next client
                // may well succeed, and stopping here would take the endpoint away for good.
                warn!(%err, "rpc: accept failed");
                continue;
            }
        };
        let port = local.port();
        tokio::spawn(async move {
            debug!(%peer, "rpc: connection opened");
            if let Err(err) = connection(stream, port).await {
                debug!(%peer, %err, "rpc: connection ended");
            }
        });
    }
}

/// Serves one connection until the client closes it.
async fn connection(mut stream: TcpStream, port: u16) -> std::io::Result<()> {
    let mut inbox: Vec<u8> = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut contexts: Vec<(u16, SyntaxId)> = Vec::new();

    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        inbox.extend_from_slice(&buffer[..read]);

        // A PDU is cut by its `frag_length`, which sits at octets 8 and 9: one PDU may span reads,
        // and one read may hold several.
        loop {
            if inbox.len() < pdu::HEADER_LEN {
                break;
            }
            let frag = usize::from(u16::from_le_bytes([inbox[8], inbox[9]]));
            if frag < pdu::HEADER_LEN || inbox.len() < frag {
                break;
            }
            let raw: Vec<u8> = inbox.drain(..frag).collect();
            let Some(parsed) = pdu::parse(&raw) else {
                debug!(len = raw.len(), "rpc: unparseable PDU dropped");
                continue;
            };
            for reply in answer(&parsed, &mut contexts, port) {
                stream.write_all(&reply).await?;
            }
        }
    }
}

/// Every PDU this server owes an answer to, in order.
///
/// Split out from [`connection`] so it can be tested without a socket: the interesting decisions are
/// which contexts are taken and what a call is answered with, and neither needs a peer.
fn answer(parsed: &Pdu<'_>, contexts: &mut Vec<(u16, SyntaxId)>, port: u16) -> Vec<Vec<u8>> {
    match &parsed.body {
        Body::Bind(bind) => {
            // Bound to a local before the call: an `AuthReply` borrowed from a temporary would have
            // to outlive the statement the answer is built in.
            let verifier = parsed.auth.as_ref().map(|auth| AuthReply {
                auth_type: auth.auth_type,
                auth_level: auth.auth_level,
                auth_pad_length: auth.auth_pad_length,
                auth_context_id: auth.auth_context_id,
                // No token: this is the step that has to become a SPNEGO answer.
                token: &[],
            });
            vec![pdu::bind_ack(
                pdu::PTYPE_BIND_ACK,
                parsed.header.call_id,
                MAX_FRAG,
                0,
                &port.to_string(),
                &results(bind, contexts),
                verifier.as_ref(),
            )]
        }

        Body::AlterContext(bind) => {
            // Measured on the stand: a Windows join asks for `RPC_C_AUTHN_GSS_NEGOTIATE` at level 6
            // on this endpoint. Named in the log because the answer to it is the next step, and the
            // values are what the answer has to satisfy.
            if let Some(auth) = &parsed.auth {
                info!(
                    auth_type = auth.auth_type,
                    auth_level = auth.auth_level,
                    auth_context_id = auth.auth_context_id,
                    token = auth.token.len(),
                    "rpc: alter_context with authentication"
                );
            }
            let verifier = parsed.auth.as_ref().map(|auth| AuthReply {
                auth_type: auth.auth_type,
                auth_level: auth.auth_level,
                auth_pad_length: 0,
                auth_context_id: auth.auth_context_id,
                token: &[],
            });
            vec![pdu::bind_ack(
                pdu::PTYPE_ALTER_CONTEXT_RESP,
                parsed.header.call_id,
                MAX_FRAG,
                0,
                "",
                &results(bind, contexts),
                verifier.as_ref(),
            )]
        }

        Body::Request(request) => {
            // The interface comes from the context the call named: a call on a context that was
            // never accepted has none, and guessing an interface would answer the wrong service.
            let interface = contexts
                .iter()
                .find(|(id, _)| *id == request.context_id)
                .map(|(_, syntax)| *syntax);
            let result = match interface {
                Some(syntax) if syntax.uuid == pdu::DRSUAPI.uuid => {
                    super::drsuapi::serve(request.opnum, request.stub)
                }
                other => {
                    warn!(
                        interface = ?other,
                        context_id = request.context_id,
                        opnum = request.opnum,
                        "rpc: no handler for this interface over tcp"
                    );
                    Err(super::association::Fault {
                        status: pdu::NCA_UNK_IF,
                        did_not_execute: true,
                    })
                }
            };
            match result {
                Ok(stub) => vec![pdu::response(
                    parsed.header.call_id,
                    pdu::PFC_FIRST_FRAG | pdu::PFC_LAST_FRAG,
                    u32::try_from(stub.len()).unwrap_or(u32::MAX),
                    request.context_id,
                    &stub,
                    None,
                )],
                Err(fault) => vec![pdu::fault(
                    parsed.header.call_id,
                    pdu::PFC_FIRST_FRAG | pdu::PFC_LAST_FRAG | pdu::PFC_DID_NOT_EXECUTE,
                    request.context_id,
                    fault.status,
                )],
            }
        }

        // auth3 carries the last step of an NTLM handshake and expects no answer of its own; the
        // client's next PDU is the call it was authenticating for. Answering it, or closing the
        // connection on it, is what a client reports as a bad tag (`RPC_S_INVALID_TAG`, 0x6be).
        Body::Unexpected(ptype) => {
            debug!(ptype, "rpc: unexpected PDU type, no answer");
            Vec::new()
        }

        Body::CoCancel | Body::Orphaned => Vec::new(),
    }
}

/// One result per context element, and the accepted ones recorded for later calls.
fn results(bind: &pdu::Bind, contexts: &mut Vec<(u16, SyntaxId)>) -> Vec<ContextResult> {
    let mut results = Vec::with_capacity(bind.contexts.len());
    for element in &bind.contexts {
        let serves_interface = element.abstract_syntax.uuid == pdu::DRSUAPI.uuid;
        let speaks_ndr32 = element
            .transfer_syntaxes
            .iter()
            .any(|syntax| syntax.uuid == pdu::NDR.uuid);
        if serves_interface && speaks_ndr32 {
            results.push(ContextResult {
                result: RESULT_ACCEPTANCE,
                reason: 0,
                transfer_syntax: pdu::NDR,
            });
            if !contexts.iter().any(|(id, _)| *id == element.id) {
                contexts.push((element.id, pdu::DRSUAPI));
            }
        } else {
            // Two refusals that read the same to a client and differently to whoever reads the log:
            // an interface this server does not serve, and a transfer syntax it cannot speak.
            let reason = if serves_interface {
                REASON_ABSTRACT_SYNTAX_NOT_SUPPORTED
            } else {
                REASON_NOT_SPECIFIED
            };
            results.push(ContextResult {
                result: RESULT_PROVIDER_REJECTION,
                reason,
                transfer_syntax: SyntaxId {
                    uuid: [0; 16],
                    version: 0,
                },
            });
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header, so a test speaks the same framing a client does.
    fn header(ptype: u8, call_id: u32, frag: u16) -> Vec<u8> {
        let mut out = vec![5, 0, ptype, 0x03];
        out.extend_from_slice(&[0x10, 0, 0, 0]); // drep: little-endian NDR
        out.extend_from_slice(&frag.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&call_id.to_le_bytes());
        out
    }

    fn context(id: u16, abstract_syntax: SyntaxId, transfer: SyntaxId) -> Vec<u8> {
        // `p_cont_id` then `n_transfer_syn`, and nothing between them: an element of a bind is
        // 24 octets of header (two for the id, two for the count, twenty for the abstract syntax)
        // followed by twenty per transfer syntax. A stray reserved octet shifts every later field
        // by one, and the abstract syntax then reads as an interface nobody serves.
        let mut out = id.to_le_bytes().to_vec();
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&abstract_syntax.uuid);
        out.extend_from_slice(&abstract_syntax.version.to_le_bytes());
        out.extend_from_slice(&transfer.uuid);
        out.extend_from_slice(&transfer.version.to_le_bytes());
        out
    }

    fn bind_pdu(contexts: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&5840u16.to_le_bytes());
        body.extend_from_slice(&5840u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.push(u8::try_from(contexts.len()).expect("few contexts"));
        body.extend_from_slice(&[0, 0, 0]);
        for element in contexts {
            body.extend_from_slice(element);
        }
        let frag = u16::try_from(16 + body.len()).expect("a small bind");
        let mut out = header(pdu::PTYPE_BIND, 1, frag);
        out.extend_from_slice(&body);
        out
    }

    fn request_pdu(opnum: u16, stub: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(
            &u32::try_from(stub.len())
                .expect("a short stub")
                .to_le_bytes(),
        );
        body.extend_from_slice(&0u16.to_le_bytes()); // context 0
        body.extend_from_slice(&opnum.to_le_bytes());
        body.extend_from_slice(stub);
        let frag = u16::try_from(16 + body.len()).expect("a small request");
        let mut out = header(pdu::PTYPE_REQUEST, 2, frag);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn a_bind_for_drsuapi_over_ndr_is_accepted() {
        let raw = bind_pdu(&[context(0, pdu::DRSUAPI, pdu::NDR)]);
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        let replies = answer(&parsed, &mut contexts, 49152);
        assert_eq!(replies.len(), 1);
        assert_eq!(contexts, vec![(0, pdu::DRSUAPI)]);

        let ack = &replies[0];
        // A `bind_ack` is ptype 12, and its result for the single context is `acceptance`.
        assert_eq!(ack[2], pdu::PTYPE_BIND_ACK);
        let results_at = ack.len() - 24;
        assert_eq!(
            u16::from_le_bytes([ack[results_at], ack[results_at + 1]]),
            0
        );
        // The secondary address names the port the client should have reached.
        let text = String::from_utf8_lossy(ack);
        assert!(
            text.contains("49152"),
            "the address names the port: {text:?}"
        );
    }

    #[test]
    fn a_bind_for_another_interface_is_refused() {
        let raw = bind_pdu(&[context(0, pdu::SRVSVC, pdu::NDR)]);
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        let replies = answer(&parsed, &mut contexts, 49152);
        assert!(contexts.is_empty(), "nothing was taken");
        let ack = &replies[0];
        let results_at = ack.len() - 24;
        assert_eq!(
            u16::from_le_bytes([ack[results_at], ack[results_at + 1]]),
            2
        );
    }

    #[test]
    fn a_call_on_drsuapi_reaches_the_handler() {
        let raw = bind_pdu(&[context(0, pdu::DRSUAPI, pdu::NDR)]);
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        answer(&parsed, &mut contexts, 49152);

        // `IDL_DRSBind` takes two pointers, both absent: a client with no DSA GUID yet.
        let stub = [0_u8; 8];
        let call = request_pdu(0, &stub);
        let parsed = pdu::parse(&call).expect("a request");
        let replies = answer(&parsed, &mut contexts, 49152);
        assert_eq!(replies.len(), 1);
        let reply = &replies[0];
        assert_eq!(reply[2], pdu::PTYPE_RESPONSE, "a handler answered");
        // A non-null handle and a zero status mean the bind was taken, not faulted.
        assert!(
            reply.len() > 40,
            "the answer carries extensions and a handle: {} octets",
            reply.len()
        );
    }

    #[test]
    fn a_call_on_an_unaccepted_context_is_a_fault() {
        let mut contexts = Vec::new();
        let call = request_pdu(0, &[0_u8; 8]);
        let parsed = pdu::parse(&call).expect("a request");
        let replies = answer(&parsed, &mut contexts, 49152);
        assert_eq!(replies[0][2], pdu::PTYPE_FAULT);
    }
}
