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
//! # Authentication
//!
//! A Windows client's `alter_context` for this endpoint carries `auth_type` 9
//! (`RPC_C_AUTHN_GSS_NEGOTIATE`) at level 6 (`Packet Privacy`), measured rather than assumed, and the
//! mechanism token inside the SPNEGO offer is a **Kerberos AP-REQ** - also measured, and the ticket
//! in it names `ldap/<host>` because that is the service ticket the client already holds for this
//! domain controller. A ticket for a service this server holds a key for is a ticket it can accept,
//! whatever port it arrived on, so Kerberos is answered first, from the keytab.
//!
//! NTLM stays as the fallback for a client that offers no usable ticket: the sealing it needs is
//! already implemented and proven against a live client.
//!
//! # What is not here yet
//!
//! The path is implemented and **not yet measured end to end**: sealing was written from RFC 4121
//! §4.2 and the crate's own per-message tokens, and no Windows client has accepted a sealed answer
//! from this endpoint yet. An NTLM AUTHENTICATE is still unverified - that needs the account source.

use std::net::SocketAddr;
use std::sync::Arc;

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
    /// The keytab whose keys accept a client's service ticket, when Kerberos is offered.
    ///
    /// Absent means this endpoint accepts NTLM only - a different statement from "the keytab is
    /// broken", which is a startup error.
    pub keytab: Option<std::path::PathBuf>,
}

/// What one association has proved so far.
///
/// No `Debug`: it holds an NTLM acceptor, whose state is the password material this server compares
/// against, and a derive here would put that into a log line the first time somebody traced a
/// binding.
struct Exchange {
    /// The NTLM acceptor, once a NEGOTIATE arrived.
    ntlm: Option<NtlmServer>,
    /// The SPNEGO negotiation, while it is still going.
    ///
    /// Kept because SPNEGO can need more than one round: when the mechanism the initiator's token
    /// names is not the first it offered, RFC 4178 section 5 requires a `mechListMIC`, and that
    /// exchange has state. Accepting the ticket with the bare Kerberos acceptor works - the ticket
    /// verifies - but the answer then carries no MIC, and Windows ends the binding with
    /// `RPC_S_PROTOCOL_ERROR` (0x6c0) however good the ticket was.
    /// The session key from an accepted ticket.
    kerberos: Option<[u8; 16]>,
    /// Who the client proved to be.
    principal: Option<String>,
    /// The RFC 4121 per-message machinery of an accepted ticket: what seals a call at level 6.
    ///
    /// Keyed on the ticket's base key, which is the initiator's subkey when one was offered - the
    /// same choice SMB signing makes, and taking the plain session key here would seal with a key the
    /// client never uses.
    seal: Option<krb5::token::PerMessageTokens<krb5::token::ContextKey>>,
    /// Sequence numbers, one per direction.
    ///
    /// GSS wrap does not carry them in a DCE/RPC PDU - only in the token header, which this server
    /// writes itself - so both sides count from zero: the client's first sealed call is 0 and the
    /// answer to it is 0 too.
    recv_seq: u64,
    send_seq: u64,
}

impl Default for Exchange {
    fn default() -> Self {
        Exchange {
            ntlm: None,
            kerberos: None,
            principal: None,
            seal: None,
            recv_seq: 0,
            send_seq: 0,
        }
    }
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

/// The association group id this server returns.
///
/// Non-zero, chosen here rather than echoed: C706 lets a server name a group, and a real controller
/// does - Samba answers 3181 to a request carrying 0, measured. The value never has to match
/// anything, because a group only means something to a server that shares one association across
/// several connections, and this one keeps everything per connection.
fn assoc_group() -> u32 {
    let mut bytes = [0_u8; 4];
    match crate::utils::fill_random(&mut bytes) {
        // Any non-zero value: zero is the one that reads as "no group", so it is mapped to 1 rather
        // than sent.
        Ok(()) => u32::from_le_bytes(bytes) | 1,
        Err(_) => 1,
    }
}

/// Answers the client's authentication offer, if there is one to answer.
///
/// Kerberos first, from the keytab: the mechanism token a Windows join sends is an AP-REQ, measured,
/// and it names a service this server holds a key for - so it can be accepted here without a password
/// and without a second round. NTLM is the fallback for a client whose ticket cannot be used, because
/// the sealing it needs is already implemented and proven against a live client.
fn spnego_answer(
    parsed: &Pdu<'_>,
    endpoint: &Endpoint,
    kerberos: Option<&Arc<krb5::Keytab>>,
    exchange: &mut Exchange,
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
    // client brings its next message back.
    match token.first() {
        Some(0x60) => {
            let init = match spnego::decode_init_token(token) {
                Ok(init) => init,
                Err(err) => {
                    warn!(%err, "rpc: SPNEGO init did not parse");
                    return None;
                }
            };
            let offers_ntlm = init.mech_types.iter().any(|mech| mech == OID_NTLMSSP);
            info!(
                mechs = init.mech_types.len(),
                offers_ntlm,
                token = init.mech_token.as_ref().map_or(0, Vec::len),
                "rpc: SPNEGO offer"
            );

            // Kerberos, from the keytab. Two details here are not choices and are the whole of a
            // `RPC_S_PROTOCOL_ERROR` (0x6c0): the answer must name **the mechanism the client listed
            // first** - it builds its token for that one, and answering with the other Kerberos OID
            // leaves it no field to say what it disliked - and the AP-REP must be sent as the
            // mechanism's own token, not as the GSS-API envelope the acceptor produced.
            if let (Some(keytab), Some(inner)) = (kerberos, init.mech_token.as_deref())
                && matches!(inner.first(), Some(&0x60) | Some(&0x6e))
            {
                // The context, not an identity: the per-message tokens that seal a call at level 6
                // are derived from its base key, and an acceptor that returns only a session key
                // cannot seal anything the client would accept.
                let accepted = match inner.first() {
                    Some(&0x60) => krb5::KerberosContext::accept_token(keytab, inner),
                    _ => krb5::KerberosContext::accept_ap_req(
                        keytab,
                        inner,
                        &krb5::acceptor::AcceptOptions::default(),
                    ),
                };
                match accepted {
                    Ok((context, ap_rep)) => {
                        let principal = context.client_principal.clone();
                        let mechanism = spnego::offered_kerberos(&init.mech_types);
                        // The base key is the initiator's subkey when one was offered (RFC 4121 §2),
                        // and SMB signing takes the same one; sealing with the ticket's session key
                        // instead would produce tokens the client refuses without saying why.
                        match context.per_message_tokens() {
                            Ok(tokens) => exchange.seal = Some(tokens),
                            Err(err) => {
                                warn!(%err, "rpc: no per-message tokens; calls cannot be sealed");
                            }
                        }
                        exchange.kerberos = Some(truncate_key(&context.base_key));
                        exchange.principal = Some(principal.clone());
                        let ap_rep = (!ap_rep.is_empty()).then_some(ap_rep);
                        info!(
                            %principal,
                            ap_rep = ap_rep.as_ref().map_or(0, Vec::len),
                            "rpc: a service ticket was accepted"
                        );
                        // One round or two. Measured with ETW: answering `accept-completed` made the
                        // client's own security package fail internally (`RPC_S_SEC_PKG_ERROR` 0x721
                        // and `SEC_E_INTERNAL_ERROR` 0x80090304, reported as "an internal error"),
                        // which is the package saying it was still waiting for a round the server had
                        // already closed. The switch exists because the SMB path needed it too and the
                        // right answer differs per client.
                        let state = if std::env::var_os("RRL_RPC_KRB_TWOROUND").is_some() {
                            NegState::AcceptIncomplete
                        } else {
                            NegState::AcceptCompleted
                        };
                        return Some(spnego::encode_resp_token(
                            state,
                            mechanism,
                            ap_rep.as_deref().map(mechanism_token),
                            None,
                        ));
                    }
                    Err(err) => {
                        // Named, not swallowed: a ticket this server cannot use and a client that
                        // offers no ticket are different faults with the same remedy in the log.
                        debug!(%err, "rpc: the offered ticket was refused; falling back to SPNEGO");
                    }
                }
            }

            if !offers_ntlm {
                warn!("rpc: SPNEGO offers nothing this endpoint can accept");
                return Some(spnego::encode_resp_token(
                    NegState::Reject,
                    Some(OID_NTLMSSP),
                    None,
                    None,
                ));
            }
            match init.mech_token.as_deref() {
                // Already an NTLMSSP NEGOTIATE: answer it here.
                Some(inner) if inner.starts_with(b"NTLMSSP\x00") => {
                    challenge_for(inner, endpoint, exchange)
                }
                // A token for another mechanism: RFC 4178 §4.2.2 turns this into `accept-incomplete`
                // with `supportedMech`, which is the server saying "this exchange continues, with that
                // mechanism". Answering `reject` here would end it.
                other => {
                    info!(
                        token = other.map_or(0, <[u8]>::len),
                        "rpc: asking the client for NTLMSSP"
                    );
                    Some(spnego::encode_resp_token(
                        NegState::AcceptIncomplete,
                        Some(OID_NTLMSSP),
                        None,
                        None,
                    ))
                }
            }
        }
        Some(0xa1) => {
            let resp = match spnego::decode_resp_token(token) {
                Ok(resp) => resp,
                Err(err) => {
                    warn!(%err, "rpc: SPNEGO response did not parse");
                    return None;
                }
            };
            let inner = resp.response_token.clone().unwrap_or_default();
            match inner
                .get(8..12)
                .map(|kind| u32::from_le_bytes(kind.try_into().expect("four")))
            {
                // The NEGOTIATE, after this server asked for NTLMSSP.
                Some(1) if inner.starts_with(b"NTLMSSP\x00") => {
                    challenge_for(&inner, endpoint, exchange)
                }
                // The AUTHENTICATE. Verifying it needs the account source, which is the next step;
                // what the log can say honestly is that it arrived and with which flags.
                Some(3) => {
                    let flags = inner
                        .get(60..64)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four")));
                    info!(
                        token = inner.len(),
                        flags = flags.map(|flags| format!("0x{flags:08x}")),
                        "rpc: client sent its AUTHENTICATE; verification is not implemented yet"
                    );
                    None
                }
                _ => {
                    info!(
                        token = inner.len(),
                        "rpc: SPNEGO response carries no NTLMSSP message"
                    );
                    None
                }
            }
        }
        other => {
            debug!(first = ?other, "rpc: authentication token of an unknown shape");
            None
        }
    }
}

/// Opens a call sealed at level 6, or says why it cannot be.
///
/// The token is in two pieces: the sixteen-octet RFC 4121 header travels in the verifier and the
/// ciphertext travels where the arguments would be, so they are joined here before the token layer
/// sees them. `Ok(None)` means this association never accepted a ticket, which is a client talking
/// NTLM or nothing: its stub is arguments in clear text, not a token that failed.
///
/// The pad is stripped **after** the seal opens. MS-RPCE 2.2.2.11 has `auth_pad_length` count octets
/// at the end of the stub, and at this level those octets are inside the ciphertext - subtracting
/// them from the ciphertext instead would hand the handler a stub that is short and still parses.
fn open_sealed_call(
    header: &[u8],
    stub: &[u8],
    pad: usize,
    exchange: &mut Exchange,
) -> Result<Option<Vec<u8>>, &'static str> {
    // Taken out of the exchange and put back: the sequence counter lives beside the tokens, and
    // `unwrap` needs the tokens while the counter needs to change.
    let Some(tokens) = exchange.seal.take() else {
        return Ok(None);
    };
    let mut token = header.to_vec();
    token.extend_from_slice(stub);
    let opened = tokens.unwrap(&token);
    exchange.seal = Some(tokens);
    let verified = opened.map_err(|_| "the token did not verify")?;
    exchange.recv_seq = verified.seq.saturating_add(1);
    let kept = verified
        .message
        .len()
        .checked_sub(pad)
        .ok_or("the pad is longer than the sealed stub")?;
    let mut message = verified.message;
    message.truncate(kept);
    debug!(
        seq = verified.seq,
        plaintext = message.len(),
        pad,
        "rpc: a sealed call was opened"
    );
    Ok(Some(message))
}

/// The first sixteen octets of a key, for the paths that take a fixed-size session key.
///
/// Every KDF this crate implements for a *session* consumes 128 bits, and a shorter key is a
/// configuration the caller has to see rather than a key padded with zeros.
fn truncate_key(base_key: &[u8]) -> [u8; 16] {
    let mut key = [0_u8; 16];
    let take = base_key.len().min(16);
    key[..take].copy_from_slice(&base_key[..take]);
    key
}

/// The body and verifier of an answer at one authentication level.
///
/// At level 6 the answer is sealed the way the call was: an RFC 4121 Wrap token whose sixteen-octet
/// header becomes the verifier and whose ciphertext becomes the body. `emit_wrap` builds the token
/// whole, so the split is exactly at `HEADER_LEN` — that is only true because this crate emits with
/// RRC = 0, which is always legal for AES (RFC 4121 §4.2.4).
///
/// The plaintext is padded to four octets before it is sealed, and the padding goes **inside** the
/// seal: MS-RPCE 2.2.2.11.1 puts it in the encrypted data, so the PDU reports none.
fn seal_answer(stub: &[u8], level: u8, exchange: &mut Exchange) -> (Vec<u8>, Option<Vec<u8>>) {
    if level != 6 {
        return (stub.to_vec(), None);
    }
    let Some(tokens) = exchange.seal.take() else {
        // No ticket was accepted on this association: the client is talking NTLM or nothing, and a
        // plain answer is the honest one.
        return (stub.to_vec(), None);
    };
    let mut plaintext = stub.to_vec();
    plaintext.resize(plaintext.len().next_multiple_of(4), 0);
    let seq = exchange.send_seq;
    let sealed = tokens.emit_wrap(seq, &plaintext);
    exchange.seal = Some(tokens);
    match sealed {
        Ok(token) => {
            exchange.send_seq = seq.saturating_add(1);
            let (header, body) = token.split_at(krb5::token::HEADER_LEN);
            debug!(
                seq,
                plaintext = stub.len(),
                sealed = body.len(),
                "rpc: the answer was sealed"
            );
            (body.to_vec(), Some(header.to_vec()))
        }
        Err(err) => {
            // An answer that cannot be sealed must not travel in the clear: a client at level 6
            // discards an unsealed answer, and sending one would look like a protocol error on its
            // side rather than a fault on this one.
            warn!(%err, "rpc: the answer could not be sealed; sending an empty body");
            (Vec::new(), None)
        }
    }
}

/// The mechanism's own token inside a GSS-API envelope.
///
/// `0x6e` opens an AP-REQ and `0x6f` an AP-REP; a client that receives the envelope where it expects
/// the token has no field to say so. Taken from the SMB path, which learned it against a live client.
fn mechanism_token(token: &[u8]) -> &[u8] {
    if token.first() == Some(&0x60)
        && let Some(position) = token.iter().position(|byte| *byte == 0x6f || *byte == 0x6e)
    {
        return &token[position..];
    }
    token
}

/// A CHALLENGE for an NTLMSSP NEGOTIATE, inside a `NegTokenResp`.
fn challenge_for(
    negotiate: &[u8],
    endpoint: &Endpoint,
    exchange: &mut Exchange,
) -> Option<Vec<u8>> {
    let mut challenge = [0_u8; 8];
    if let Err(err) = crate::utils::fill_random(&mut challenge) {
        // An NTLM challenge that is not random is one that repeats: the exchange must not go on.
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
    if let Err(err) = server.step1_negotiate(negotiate) {
        warn!(%err, "rpc: the client's NEGOTIATE did not parse");
        return None;
    }
    let blob = server.challenge();
    exchange.ntlm = Some(server);
    info!(
        challenge = blob.len(),
        "rpc: answering with an NTLMSSP challenge"
    );
    Some(spnego::encode_resp_token(
        NegState::AcceptIncomplete,
        Some(OID_NTLMSSP),
        Some(&blob),
        None,
    ))
}

/// Binds `addr` and serves every connection until the process ends.
///
/// Binding is not retried and not softened: a port this process cannot have is a configuration
/// fault, and a server that starts anyway is one that a client cannot reach while the log says it is
/// running.
pub async fn serve(endpoint: Endpoint) -> std::io::Result<()> {
    let listener = TcpListener::bind(endpoint.addr).await?;
    let local = listener.local_addr()?;
    // Read once and shared: a keytab that changes under a running endpoint is one an operator meant
    // to restart for. A keytab that will not load is a startup error naming the file, because an
    // endpoint that silently accepts NTLM only is one whose Kerberos failures look like client bugs.
    //
    // The raw `Keytab`, not a ready-made acceptor: accepting a ticket has to yield the *context*,
    // because the per-message tokens that seal a call at level 6 are derived from its base key, and
    // an acceptor that returns only an identity and a session key throws that away.
    let kerberos = match &endpoint.keytab {
        None => None,
        Some(path) => {
            let keytab = krb5::Keytab::load(path).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("drsuapi keytab '{}': {err:?}", path.display()),
                )
            })?;
            info!(
                path = %path.display(),
                "rpc: Kerberos accepted on this endpoint"
            );
            Some(Arc::new(keytab))
        }
    };
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
        let kerberos = kerberos.clone();
        tokio::spawn(async move {
            debug!(%peer, "rpc: connection opened");
            if let Err(err) = connection(stream, port, &endpoint, kerberos.as_ref()).await {
                debug!(%peer, %err, "rpc: connection ended");
            }
        });
    }
}

/// Serves one connection until the client closes it.
async fn connection(
    mut stream: TcpStream,
    port: u16,
    endpoint: &Endpoint,
    kerberos: Option<&Arc<krb5::Keytab>>,
) -> std::io::Result<()> {
    let mut inbox: Vec<u8> = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut contexts: Vec<(u16, SyntaxId)> = Vec::new();
    // One exchange per connection: the client authenticates the association it is about to call on.
    let mut exchange = Exchange::default();

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
            for reply in answer(
                &parsed,
                &mut contexts,
                port,
                endpoint,
                kerberos,
                &mut exchange,
            ) {
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
    kerberos: Option<&Arc<krb5::Keytab>>,
    exchange: &mut Exchange,
) -> Vec<Vec<u8>> {
    // Computed once here, because both bind-shaped answers carry it and a call does not.
    let token = spnego_answer(parsed, endpoint, kerberos, exchange);
    // One line per PDU: which packet type arrived and, for a call, which interface and opnum. A
    // client that connects and then stops speaking is otherwise indistinguishable from one that
    // never connected, and that difference was the whole of a day's work on this endpoint.
    debug!(
        ptype = parsed.header.ptype,
        call_id = parsed.header.call_id,
        auth_length = parsed.header.auth_length,
        body = ?parsed.body,
        "rpc: pdu"
    );
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
                // C706 says this "may contain a new association group identifier if one was requested
                // by the client", and a real controller answers with a fresh non-zero id even when the
                // client asked for zero - measured: Samba returns 3181 for a request carrying 0. A
                // server that echoes the zero is one a client can read as "no association".
                assoc_group(),
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

            // At level 6 the stub is not the arguments: it is a sealed RFC 4121 Wrap token whose
            // sixteen-octet header travels in the verifier and whose ciphertext travels where the
            // arguments would be. Handing the ciphertext to a handler parses nonsense - which is
            // what a join reports as `RPC_X_BAD_STUB_DATA`.
            let level = parsed.auth.as_ref().map_or(0, |auth| auth.auth_level);
            let verifier_token = parsed.auth.as_ref().map(|auth| auth.token);
            let pad = usize::from(parsed.auth.as_ref().map_or(0, |auth| auth.auth_pad_length));
            let unsealed = match (level, verifier_token) {
                (6, Some(header)) => match open_sealed_call(header, request.stub, pad, exchange) {
                    Ok(opened) => opened,
                    // A call that cannot be opened is not answered: the alternative is a handler
                    // reading ciphertext as arguments, which is what a client reports as a bad stub.
                    Err(detail) => {
                        warn!(detail, "rpc: a sealed call could not be opened");
                        return Vec::new();
                    }
                },
                // Below level 6 the stub is the arguments, and padding it needs is the PDU's own.
                _ => None,
            };
            let stub = unsealed.as_deref().unwrap_or(request.stub);

            let result = match interface {
                Some(syntax) if syntax.uuid == pdu::DRSUAPI.uuid => {
                    super::drsuapi::serve(request.opnum, stub)
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
                Ok(stub) => {
                    let (body, header) = seal_answer(&stub, level, exchange);
                    // Built here, not inside the helper: a verifier borrows its token, and the token
                    // is the helper's return value, so it has to outlive the call.
                    let verifier = header.as_deref().map(|token| AuthReply {
                        auth_type: pdu::AuthVerifier::TYPE_GSS_NEGOTIATE,
                        auth_level: 6,
                        // The padding travels **inside** the seal (MS-RPCE 2.2.2.11.1), so the PDU
                        // itself adds none and this count is what the client must not skip.
                        auth_pad_length: 0,
                        auth_context_id: parsed
                            .auth
                            .as_ref()
                            .map_or(0, |auth| auth.auth_context_id),
                        token,
                    });
                    vec![pdu::response(
                        parsed.header.call_id,
                        pdu::PFC_FIRST_FRAG | pdu::PFC_LAST_FRAG,
                        u32::try_from(stub.len()).unwrap_or(u32::MAX),
                        request.context_id,
                        &body,
                        verifier.as_ref(),
                    )]
                }
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
            keytab: None,
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
        let mut exchange = Exchange::default();
        let answer = &answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            None,
            &mut exchange,
        )[0];

        assert!(exchange.ntlm.is_some(), "an NTLM exchange was started");
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
    fn a_ticket_offer_without_a_keytab_keeps_the_exchange_alive() {
        // The offer's token is not NTLMSSP but a Kerberos AP-REQ (`6e`), and there is no keytab to
        // accept it with. The answer must name NTLMSSP and leave the negotiation running: a
        // `reject` would end it, and no answer at all is what the client reports as
        // `RPC_S_PROTOCOL_ERROR` (0x6c0).
        let mut mech_types = der(0x06, spnego::OID_KRB5);
        mech_types.extend_from_slice(&der(0x06, OID_NTLMSSP));
        let mut body = der(0xa0, &der(0x30, &mech_types));
        body.extend_from_slice(&der(
            0xa2,
            &der(0x04, b"\x6e\x82\x00\x10a kerberos ap-req "),
        ));
        let init = der(0x30, &body);
        let mut gss = der(0x06, spnego::OID_SPNEGO);
        gss.extend_from_slice(&der(0xa0, &init));

        let raw = alter_context_with(&der(0x60, &gss));
        let parsed = pdu::parse(&raw).expect("an alter_context with a verifier");
        let mut contexts = Vec::new();
        let mut exchange = Exchange::default();
        let answer = &answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            None,
            &mut exchange,
        )[0];

        let auth_len = usize::from(u16::from_le_bytes([answer[10], answer[11]]));
        assert!(auth_len > 0, "the answer carries a token");
        let token = &answer[answer.len() - auth_len..];
        assert_eq!(token[0], 0xa1, "a `NegTokenResp`");
        // `accept-incomplete (1)` inside `negState [0]`: `a0 03 0a 01 01`.
        assert!(
            token.windows(4).any(|w| w == [0xa0, 0x03, 0x0a, 0x01]),
            "the negotiation continues: {token:02x?}"
        );
        assert!(!exchange.ntlm.is_some(), "no NTLM exchange was started");
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
            None,
            &mut Exchange::default(),
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
            None,
            &mut Exchange::default(),
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
            None,
            &mut Exchange::default(),
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
            None,
            &mut Exchange::default(),
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
            None,
            &mut Exchange::default(),
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
    fn a_bind_ack_names_an_association_group_of_its_own() {
        // Measured: Samba answers 3181 to a request carrying 0. A zero in the answer is the one
        // value that reads as "no group", so the answer must carry a number.
        let raw = bind_pdu(&[context(0, pdu::DRSUAPI, pdu::NDR)]);
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        let ack = &answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            None,
            &mut Exchange::default(),
        )[0];
        let group = u32::from_le_bytes([ack[20], ack[21], ack[22], ack[23]]);
        assert_ne!(group, 0, "a zero group is what a client reads as none");
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
            None,
            &mut Exchange::default(),
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
            None,
            &mut Exchange::default(),
        );
        assert_eq!(replies[0][2], pdu::PTYPE_FAULT);
    }

    /// The two ends of one context, over a key they were both given.
    ///
    /// `krb5::token` is used directly rather than a ticket: what these tests check is the RFC 4121
    /// wiring in this file - that a sealed call is opened, that the answer is sealed back with the
    /// verifier carrying the token header, and that the sequence numbers advance - and all of that
    /// is the same arithmetic whoever agreed on the key. Accepting the ticket that produces the key
    /// is tested by the SMB path (`proto::auth::kerberos`) and, live, by the stand.
    fn endpoints_of_one_context() -> (
        krb5::token::PerMessageTokens<krb5::token::ContextKey>,
        krb5::token::PerMessageTokens<krb5::token::ContextKey>,
    ) {
        // aes256-cts-hmac-sha1-96: the etype a modern client negotiates with this server.
        let key = [0x5a_u8; 32];
        let server = krb5::token::ContextKey::new(18, &key).expect("a key of the right length");
        let client = krb5::token::ContextKey::new(18, &key).expect("a key of the right length");
        (
            krb5::token::PerMessageTokens::new(server, krb5::token::Role::Acceptor, false),
            krb5::token::PerMessageTokens::new(client, krb5::token::Role::Initiator, false),
        )
    }

    /// A request whose stub is a sealed token: the RFC 4121 header travels in the verifier and the
    /// ciphertext where the arguments would be, which is what MS-RPCE 2.2.2.11.1 asks for at level 6.
    fn sealed_request_pdu(call_id: u32, opnum: u16, token: &[u8], pad: u8) -> Vec<u8> {
        let (header_part, body) = token.split_at(krb5::token::HEADER_LEN);
        let mut out = header(pdu::PTYPE_REQUEST, call_id, 0);
        out[10..12].copy_from_slice(
            &u16::try_from(header_part.len())
                .expect("a short header")
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &u32::try_from(body.len())
                .expect("a short body")
                .to_le_bytes(),
        );
        out.extend_from_slice(&0u16.to_le_bytes()); // context 0
        out.extend_from_slice(&opnum.to_le_bytes());
        out.extend_from_slice(body);
        // `sec_trailer`: auth_type GSS negotiate, level 6, the pad, a reserved octet, the id.
        out.extend_from_slice(&[pdu::AuthVerifier::TYPE_GSS_NEGOTIATE, 6, pad, 0]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(header_part);
        let frag = u16::try_from(out.len()).expect("a small request");
        out[8..10].copy_from_slice(&frag.to_le_bytes());
        out
    }

    /// A context accepted on this association, the way a bind leaves it.
    fn accepted_context() -> Vec<(u16, SyntaxId)> {
        let raw = bind_pdu(&[context(0, pdu::DRSUAPI, pdu::NDR)]);
        let parsed = pdu::parse(&raw).expect("a bind");
        let mut contexts = Vec::new();
        answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            None,
            &mut Exchange::default(),
        );
        contexts
    }

    /// The acceptance of the level-6 path: a sealed call is opened, and the answer comes back
    /// sealed, with the token's header in the verifier and its ciphertext in the body.
    #[test]
    fn a_sealed_call_is_opened_and_the_answer_is_sealed_back() {
        let (server, client) = endpoints_of_one_context();
        let mut contexts = accepted_context();
        let mut exchange = Exchange {
            seal: Some(server),
            ..Exchange::default()
        };

        // `IDL_DRSBind` with both pointers absent, sealed by the client at sequence 0.
        let stub = [0_u8; 8];
        let token = client.emit_wrap(0, &stub).expect("the client seals");
        let call = sealed_request_pdu(2, 0, &token, 0);
        let parsed = pdu::parse(&call).expect("a request");
        let replies = answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            None,
            &mut exchange,
        );

        assert_eq!(replies.len(), 1, "a sealed call is answered");
        let reply = &replies[0];
        assert_eq!(reply[2], pdu::PTYPE_RESPONSE);
        let parsed = pdu::parse(reply).expect("a response");
        let verifier = parsed
            .auth
            .as_ref()
            .expect("an answer at level 6 carries a verifier");
        assert_eq!(verifier.auth_level, 6);
        assert_eq!(
            verifier.token.len(),
            krb5::token::HEADER_LEN,
            "the verifier is the token header, and the body is the ciphertext"
        );

        // The body is what follows the eight-octet response header at offset 24; `pdu::parse` reads
        // a response's stub as `Unexpected`, because nothing in this crate parses an answer.
        // Eight octets of `sec_trailer`, which is where the verifier's token begins.
        const TRAILER: usize = 8;
        let body = &reply[24..reply.len() - verifier.token.len() - TRAILER];
        let mut whole = verifier.token.to_vec();
        whole.extend_from_slice(body);
        let opened = client
            .unwrap(&whole)
            .expect("the client opens what the server sealed");
        assert_eq!(opened.seq, 0, "the first answer is sequence 0");
        // `IDL_DRSBind` answers the server's `DRS_EXTENSIONS`, a handle and then the status, so the
        // status is the last word: zero is a bind that was taken rather than a fault or a refusal.
        assert_eq!(
            &opened.message[opened.message.len() - 4..],
            &[0, 0, 0, 0],
            "a DRSBind that was taken answers ERROR_SUCCESS, not a fault"
        );
        assert!(
            opened.message.len() >= 8,
            "and carries a handle: {} octets",
            opened.message.len()
        );
        assert!(
            body.len() != opened.message.len(),
            "the body on the wire is the ciphertext, not the plaintext"
        );
        assert_eq!(exchange.recv_seq, 1, "the next call is expected at 1");
        assert_eq!(exchange.send_seq, 1, "and the next answer is 1");
    }

    /// The pad MS-RPCE counts in `auth_pad_length` travels inside the seal, so it is stripped after
    /// the token opens. Stripping it from the ciphertext instead would shorten a stub that still
    /// parses - the failure would be a handler reading somebody else's octets.
    #[test]
    fn the_pad_reported_by_the_trailer_is_removed_after_the_seal_opens() {
        let (server, client) = endpoints_of_one_context();
        let mut contexts = accepted_context();
        let mut exchange = Exchange {
            seal: Some(server),
            ..Exchange::default()
        };

        // Eight octets of arguments and three of pad, sealed together, with the pad reported.
        let mut plaintext = vec![0_u8; 8];
        plaintext.extend_from_slice(&[0xAA; 3]);
        let token = client.emit_wrap(0, &plaintext).expect("the client seals");
        let call = sealed_request_pdu(3, 0, &token, 3);
        let parsed = pdu::parse(&call).expect("a request");
        let replies = answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            None,
            &mut exchange,
        );

        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies[0][2],
            pdu::PTYPE_RESPONSE,
            "the handler saw exactly the eight argument octets, so it answered instead of faulting"
        );
    }

    /// A token sealed under a key this context does not hold is refused, and nothing is sent: an
    /// answer built from ciphertext nobody can read would be a protocol error invented here.
    #[test]
    fn a_call_sealed_under_another_key_is_refused_without_an_answer() {
        let (server, _client) = endpoints_of_one_context();
        let mut contexts = accepted_context();
        let mut exchange = Exchange {
            seal: Some(server),
            ..Exchange::default()
        };

        let other = krb5::token::ContextKey::new(18, &[0x11_u8; 32]).expect("a key");
        let stranger =
            krb5::token::PerMessageTokens::new(other, krb5::token::Role::Initiator, false);
        let token = stranger.emit_wrap(0, &[0_u8; 8]).expect("sealed");
        let call = sealed_request_pdu(4, 0, &token, 0);
        let parsed = pdu::parse(&call).expect("a request");
        let replies = answer(
            &parsed,
            &mut contexts,
            49152,
            &endpoint(),
            None,
            &mut exchange,
        );

        assert!(
            replies.is_empty(),
            "a call that cannot be opened is not answered"
        );
        assert_eq!(
            exchange.recv_seq, 0,
            "and the sequence does not advance for it"
        );
    }
}
