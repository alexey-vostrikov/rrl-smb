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
use crate::proto::auth::ntlm::{NtlmServer, NtlmTargetInfo};
use crate::proto::auth::spnego::{self, NegState, OID_NTLMSSP};

/// What this endpoint needs in order to answer a client's SPNEGO exchange.
///
/// The names are the ones a client compares against its own configuration: `nb_domain` is what it
/// calls the domain, and `dns_domain` is what it was told to join. Answering with this server's own
/// name instead is how a join stops at "workgroup set to X, should be Y" with everything else right.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// Where to listen.
    pub addr: SocketAddr,
    /// The domain's NetBIOS name.
    pub nb_domain: String,
    /// The domain's DNS name.
    pub dns_domain: String,
    /// This computer's NetBIOS name.
    pub nb_computer: String,
    /// This computer's DNS name.
    pub dns_computer: String,
}

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

/// The SPNEGO exchange over this endpoint, as far as NTLM inside it goes.
///
/// A join's `alter_context` carries `auth_type` 9 (`RPC_C_AUTHN_GSS_NEGOTIATE`) with a SPNEGO
/// `NegTokenInit` at level 6, measured on the stand. RFC 4178 §4.2 puts the mechanism's own tokens
/// inside the negotiation: the init's `mechToken` is an NTLMSSP NEGOTIATE, the answer is an NTLMSSP
/// CHALLENGE inside a `NegTokenResp` with `negState` `accept-incomplete`, and the client's third leg
/// arrives in an `auth3` PDU with no answer expected.
///
/// NTLM rather than Kerberos on purpose: the sealing that level 6 requires is already implemented for
/// NTLM in `proto::auth::ntlm`, and a client accepts whichever mechanism the `NegTokenResp` names.
fn spnego_answer(
    parsed: &Pdu<'_>,
    endpoint: &Endpoint,
    acceptor: &mut Option<NtlmServer>,
) -> Option<Vec<u8>> {
    let auth = parsed.auth.as_ref()?;
    if auth.auth_type != pdu::AuthVerifier::TYPE_GSS_NEGOTIATE {
        debug!(
            auth_type = auth.auth_type,
            "rpc: authentication this endpoint cannot answer"
        );
        return None;
    }
    let token = auth.token;
    // `[APPLICATION 0]` opens a `NegTokenInit`; `[1]` opens a `NegTokenResp`, which is how the
    // client brings the AUTHENTICATE back.
    match token.first() {
        Some(0x60) => {
            let init = match spnego::decode_init_token(token) {
                Ok(init) => init,
                Err(err) => {
                    warn!(%err, "rpc: SPNEGO init did not parse");
                    return None;
                }
            };
            if !init.mech_types.iter().any(|mech| mech == OID_NTLMSSP) {
                warn!(
                    mechs = init.mech_types.len(),
                    "rpc: SPNEGO init offers no NTLMSSP, and Kerberos is not implemented here"
                );
                return None;
            }
            let inner = match init.mech_token {
                Some(inner) => inner,
                None => {
                    warn!("rpc: SPNEGO init offered NTLMSSP without a token");
                    return None;
                }
            };
            let mut challenge = [0_u8; 8];
            if let Err(err) = crate::utils::fill_random(&mut challenge) {
                // An NTLM challenge that is not random is an NTLM challenge that repeats: the
                // exchange must not continue with one.
                warn!(%err, "rpc: the OS random source failed; no challenge");
                return None;
            }
            let mut server = NtlmServer::new(
                challenge,
                NtlmTargetInfo::new(
                    endpoint.nb_domain.clone(),
                    endpoint.nb_domain.clone(),
                    endpoint.nb_computer.clone(),
                    endpoint.dns_domain.clone(),
                    endpoint.dns_computer.clone(),
                ),
                crate::utils::now_filetime(),
            );
            if let Err(err) = server.step1_negotiate(&inner) {
                warn!(%err, "rpc: the client's NEGOTIATE did not parse");
                return None;
            }
            let blob = server.challenge();
            *acceptor = Some(server);
            info!(
                challenge = blob.len(),
                "rpc: answering SPNEGO with an NTLMSSP challenge"
            );
            Some(spnego::encode_resp_token(
                NegState::AcceptIncomplete,
                Some(OID_NTLMSSP),
                Some(&blob),
                None,
            ))
        }
        Some(0xa1) => {
            let resp = match spnego::decode_resp_token(token) {
                Ok(resp) => resp,
                Err(err) => {
                    warn!(%err, "rpc: SPNEGO response did not parse");
                    return None;
                }
            };
            // The third leg: the AUTHENTICATE the client signs its calls with. Verifying it needs
            // the account's hash, which is the next step; until then the fact that it arrived is
            // what the log can honestly say, and no answer is due for it.
            info!(
                token = resp.response_token.as_ref().map_or(0, Vec::len),
                "rpc: client sent its AUTHENTICATE; verification is not implemented yet"
            );
            None
        }
        other => {
            debug!(first = ?other, "rpc: authentication token of an unknown shape");
            None
        }
    }
}

/// Binds `addr` and serves every connection until the process ends.
///
/// Binding is not retried and not softened: a port this process cannot have is a configuration
/// fault, and a server that starts anyway is one that a client cannot reach while the log says it is
/// running.
pub async fn serve(endpoint: Endpoint) -> std::io::Result<()> {
    let listener = TcpListener::bind(endpoint.addr).await?;
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
        let endpoint = endpoint.clone();
        tokio::spawn(async move {
            debug!(%peer, "rpc: connection opened");
            if let Err(err) = connection(stream, port, &endpoint).await {
                debug!(%peer, %err, "rpc: connection ended");
            }
        });
    }
}

/// Serves one connection until the client closes it.
async fn connection(mut stream: TcpStream, port: u16, endpoint: &Endpoint) -> std::io::Result<()> {
    let mut inbox: Vec<u8> = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut contexts: Vec<(u16, SyntaxId)> = Vec::new();
    // One exchange per connection: the client authenticates the association it is about to call on.
    let mut acceptor: Option<NtlmServer> = None;

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
            for reply in answer(&parsed, &mut contexts, port, endpoint, &mut acceptor) {
                stream.write_all(&reply).await?;
            }
        }
    }
}

/// Every PDU this server owes an answer to, in order.
///
/// Split out from [`connection`] so it can be tested without a socket: the interesting decisions are
/// which contexts are taken and what a call is answered with, and neither needs a peer.
fn answer(
    parsed: &Pdu<'_>,
    contexts: &mut Vec<(u16, SyntaxId)>,
    port: u16,
    endpoint: &Endpoint,
    acceptor: &mut Option<NtlmServer>,
) -> Vec<Vec<u8>> {
    // Computed once here, because both bind-shaped answers carry it and a call does not.
    let token = spnego_answer(parsed, endpoint, acceptor);
    match &parsed.body {
        Body::Bind(bind) => {
            // C706 chap. 12, `rpcconn_bind_ack_hdr_t`: the verifier is present **iff
            // `auth_length != 0`**. Attaching a `sec_trailer` with an empty token therefore leaves
            // eight octets a client cannot account for - it locates the trailer by counting back
            // `auth_length`, and that is zero. This server has no token to send yet, so it sends no
            // verifier at all, which is a different (and legal) statement from "an empty one".
            vec![pdu::bind_ack(
                pdu::PTYPE_BIND_ACK,
                parsed.header.call_id,
                MAX_FRAG,
                // "may also contain a new association group identifier if one was requested by the
                // client": echoing a requested zero is what "no group" means, and inventing an
                // identifier would claim a grouping this server does not keep.
                bind.assoc_group_id,
                &port.to_string(),
                &results(bind, contexts),
                token
                    .as_deref()
                    .map(|token| AuthReply {
                        auth_type: pdu::AuthVerifier::TYPE_GSS_NEGOTIATE,
                        auth_level: parsed.auth.as_ref().map_or(6, |auth| auth.auth_level),
                        // This PDU adds no padding: the token follows the result list directly, and a
                        // non-zero count here would tell the client to skip octets that are not there.
                        auth_pad_length: 0,
                        auth_context_id: parsed
                            .auth
                            .as_ref()
                            .map_or(0, |auth| auth.auth_context_id),
                        token,
                    })
                    .as_ref(),
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
            // C706 chap. 12, `rpcconn_alter_context_response_hdr_t`: same fields as `bind_ack`, and
            // `sec_addr` is present but ignored - so an empty `port_any_t` (length 0) is the correct
            // value, not a missing field. The verifier follows the same rule as in `bind_ack`: it is
            // present only when `auth_length != 0`, and this server has no SPNEGO token to send yet.
            vec![pdu::bind_ack(
                pdu::PTYPE_ALTER_CONTEXT_RESP,
                parsed.header.call_id,
                MAX_FRAG,
                0,
                "",
                &results(bind, contexts),
                token
                    .as_deref()
                    .map(|token| AuthReply {
                        auth_type: pdu::AuthVerifier::TYPE_GSS_NEGOTIATE,
                        auth_level: parsed.auth.as_ref().map_or(6, |auth| auth.auth_level),
                        auth_pad_length: 0,
                        auth_context_id: parsed
                            .auth
                            .as_ref()
                            .map_or(0, |auth| auth.auth_context_id),
                        token,
                    })
                    .as_ref(),
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

    /// An endpoint, so the tests do not depend on the stand's names.
    fn endpoint() -> Endpoint {
        Endpoint {
            addr: "127.0.0.1:0".parse().expect("a literal address"),
            nb_domain: "AD".to_string(),
            dns_domain: "ad.example.com".to_string(),
            nb_computer: "SAMBA".to_string(),
            dns_computer: "samba.ad.example.com".to_string(),
        }
    }

    /// DER helpers, so a test builds the token a client builds rather than a byte soup.
    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(u8::try_from(body.len()).expect("short"));
        } else {
            out.push(0x81);
            out.push(u8::try_from(body.len()).expect("under 256"));
        }
        out.extend_from_slice(body);
        out
    }

    /// A `NegTokenInit` offering NTLMSSP, with a NEGOTIATE inside - what a Windows join sends in its
    /// `alter_context` (measured: `auth_type` 9, level 6, token opening `60 82 ...`).
    fn spnego_init() -> Vec<u8> {
        let mut negotiate = b"NTLMSSP\x00".to_vec();
        negotiate.extend_from_slice(&1u32.to_le_bytes());
        negotiate.extend_from_slice(&0xe2_08_82_15_u32.to_le_bytes());
        negotiate.extend_from_slice(&[0; 16]); // the two empty name fields
        let mech_types = der(0x30, &der(0x06, OID_NTLMSSP));
        let mut body = der(0xa0, &mech_types);
        body.extend_from_slice(&der(0xa2, &der(0x04, &negotiate)));
        let init = der(0x30, &body);
        let mut gss = der(0x06, spnego::OID_SPNEGO);
        gss.extend_from_slice(&der(0xa0, &init));
        der(0x60, &gss)
    }

    /// An `alter_context` carrying `token` as an SPNEGO verifier at level 6.
    fn alter_context_with(token: &[u8]) -> Vec<u8> {
        let mut raw = bind_pdu(&[context(2, pdu::DRSUAPI, pdu::NDR)]);
        raw[2] = pdu::PTYPE_ALTER_CONTEXT;
        let mut body = raw[16..].to_vec();
        // The verifier: `sec_trailer` (auth_type 9, level 6, no padding, context 2) then the token.
        body.extend_from_slice(&[9, 6, 0, 0]);
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(token);
        let frag = u16::try_from(16 + body.len()).expect("a small PDU");
        let mut out = header(pdu::PTYPE_ALTER_CONTEXT, 3, frag);
        out[10..12].copy_from_slice(
            &u16::try_from(token.len())
                .expect("a short token")
                .to_le_bytes(),
        );
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn a_spnego_init_gets_an_ntlmssp_challenge_inside_a_response_token() {
        let raw = alter_context_with(&spnego_init());
        let parsed = pdu::parse(&raw).expect("an alter_context with a verifier");
        let mut contexts = Vec::new();
        let mut acceptor = None;
        let answer = &answer(&parsed, &mut contexts, 49152, &endpoint(), &mut acceptor)[0];

        assert!(acceptor.is_some(), "an NTLM exchange was started");
        // `auth_length` counts the token only, not the eight-octet `sec_trailer` before it.
        let auth_len = usize::from(u16::from_le_bytes([answer[10], answer[11]]));
        assert!(auth_len > 0, "the answer carries a token");
        let token = &answer[answer.len() - auth_len..];
        assert_eq!(token[0], 0xa1, "a `NegTokenResp` context tag");
        let text = String::from_utf8_lossy(token);
        assert!(
            token.windows(8).any(|w| w == b"NTLMSSP\x00"),
            "the challenge is inside: {text:?}"
        );
    }

    #[test]
    fn a_bind_for_drsuapi_over_ndr_is_accepted() {
        let raw = bind_pdu(&[context(0, pdu::DRSUAPI, pdu::NDR)]);
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        let replies = answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        );
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
        let replies = answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        );
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
        answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        );

        // `IDL_DRSBind` takes two pointers, both absent: a client with no DSA GUID yet.
        let stub = [0_u8; 8];
        let call = request_pdu(0, &stub);
        let parsed = pdu::parse(&call).expect("a request");
        let replies = answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        );
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
    fn a_bind_ack_carries_no_verifier_when_it_has_no_token() {
        // C706 chap. 12: the verifier is present iff `auth_length != 0`. Eight octets of
        // `sec_trailer` with a zero `auth_length` are octets a client cannot place, so their
        // absence is part of the format, not an omission.
        let raw = bind_pdu(&[context(0, pdu::DRSUAPI, pdu::NDR)]);
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        let ack = &answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        )[0];
        assert_eq!(u16::from_le_bytes([ack[10], ack[11]]), 0, "no auth_length");
        // frag_length is the whole PDU, so nothing trails the result list.
        let frag = usize::from(u16::from_le_bytes([ack[8], ack[9]]));
        assert_eq!(frag, ack.len(), "the fragment is exactly what was sent");
        // 16 header; `max_xmit_frag` 2, `max_recv_frag` 2, `assoc_group_id` 4; `sec_addr` 2 + 6
        // ("49152" and its NUL), already four-aligned so no pad; `p_result_list` 1 + 3; and 24 per
        // result. Only the fields the IDL names, and each once.
        assert_eq!(
            ack.len(),
            16 + 2 + 2 + 4 + 2 + 6 + 1 + 3 + 24,
            "body laid out per the IDL"
        );
    }

    #[test]
    fn a_bind_ack_echoes_the_association_group_the_client_asked_for() {
        let mut raw = bind_pdu(&[context(0, pdu::DRSUAPI, pdu::NDR)]);
        // `assoc_group_id` at octets 20..24 of the PDU: a non-zero request must come back as is.
        raw[20..24].copy_from_slice(&7u32.to_le_bytes());
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        let ack = &answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        )[0];
        let echoed = u32::from_le_bytes([ack[20], ack[21], ack[22], ack[23]]);
        assert_eq!(echoed, 7);
    }

    #[test]
    fn an_alter_context_response_keeps_the_secondary_address_field_empty() {
        // The field is in the IDL and its value is ignored; dropping it would shift every result.
        let mut raw = bind_pdu(&[context(2, pdu::DRSUAPI, pdu::NDR)]);
        raw[2] = pdu::PTYPE_ALTER_CONTEXT;
        let parsed = pdu::parse(&raw).expect("an alter_context");
        let mut contexts = Vec::new();
        let ack = &answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        )[0];
        assert_eq!(ack[2], pdu::PTYPE_ALTER_CONTEXT_RESP);
        assert_eq!(
            u16::from_le_bytes([ack[24], ack[25]]),
            0,
            "an empty sec_addr"
        );
        assert_eq!(u16::from_le_bytes([ack[10], ack[11]]), 0, "no verifier");
        assert_eq!(contexts, vec![(2, pdu::DRSUAPI)]);
    }

    #[test]
    fn a_call_on_an_unaccepted_context_is_a_fault() {
        let mut contexts = Vec::new();
        let call = request_pdu(0, &[0_u8; 8]);
        let parsed = pdu::parse(&call).expect("a request");
        let replies = answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            &mut Option::<NtlmServer>::None,
        );
        assert_eq!(replies[0][2], pdu::PTYPE_FAULT);
    }
}
