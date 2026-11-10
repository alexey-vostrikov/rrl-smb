//! NEGOTIATE handler.

use std::sync::Arc;

use crate::proto::auth::spnego::encode_init_response;
use crate::proto::crypto::{Cipher, SigningAlgo};
use crate::proto::header::{SMB2_HEADER_LEN, Smb2Header};
use crate::proto::messages::{
    Dialect, EncryptionCapabilities, NegotiateContext, NegotiateRequest, NegotiateResponse,
    PreauthIntegrityCapabilities, SigningCapabilities,
};
use binrw::BinRead;
use tracing::info;
use uuid::Uuid;

use crate::conn::state::Connection;
use crate::dispatch::HandlerResponse;
use crate::ntstatus;
use crate::server::ServerState;
use crate::utils::{fill_random, now_filetime};

// MS-SMB2 2.2.4 SecurityMode bits.
const SIGNING_ENABLED: u16 = 0x0001;
const SIGNING_REQUIRED: u16 = 0x0002;

const CAP_LEASING: u32 = 0x0000_0002;
const CAP_LARGE_MTU: u32 = 0x0000_0004;
const CAP_ENCRYPTION: u32 = 0x0000_0040;

/// Size of the fixed part of a NEGOTIATE request, before Dialects.
const NEGOTIATE_FIXED_LEN: usize = 36;

/// Values from the client's NEGOTIATE request (MS-SMB2 3.3.5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientNegotiate {
    pub capabilities: u32,
    pub security_mode: u16,
    pub guid: [u8; 16],
    pub dialects: Vec<u16>,
}

impl ClientNegotiate {
    /// Connection.ShouldSign: the client set SMB2_NEGOTIATE_SIGNING_REQUIRED.
    pub fn should_sign(&self) -> bool {
        self.security_mode & SIGNING_REQUIRED != 0
    }
}

/// SecurityMode the server sends (Connection.ServerSecurityMode).
pub(crate) fn server_security_mode(server: &ServerState) -> u16 {
    if server.auth.settings.require_signing {
        SIGNING_ENABLED | SIGNING_REQUIRED
    } else {
        SIGNING_ENABLED
    }
}

/// Capabilities the server sends for `dialect` to a client that sent
/// `client_capabilities` (Connection.ServerCapabilities). LEASING is not
/// defined for SMB 2.0.2, and LARGE_MTU needs multi-credit support, which
/// SMB 2.0.2 lacks. ENCRYPTION goes to SMB 3.0 and 3.0.2 clients that have
/// it; 3.1.1 negotiates a cipher instead.
pub(crate) fn server_capabilities(dialect: Dialect, client_capabilities: u32) -> u32 {
    let mut caps = match dialect {
        Dialect::Smb202 => 0,
        _ => CAP_LEASING | CAP_LARGE_MTU,
    };
    if matches!(dialect, Dialect::Smb300 | Dialect::Smb302)
        && client_capabilities & CAP_ENCRYPTION != 0
    {
        caps |= CAP_ENCRYPTION;
    }
    caps
}

/// Connection.CipherId for an SMB 3.0 or 3.0.2 connection: AES-128-CCM
/// when the client has the ENCRYPTION capability.
fn cipher_30(client_capabilities: u32) -> Option<Cipher> {
    (client_capabilities & CAP_ENCRYPTION != 0).then_some(Cipher::Aes128Ccm)
}

/// The first cipher in the client's list that the server implements.
fn select_cipher(ciphers: &[u16]) -> Option<Cipher> {
    ciphers.iter().find_map(|&id| Cipher::from_id(id))
}

/// What the client's 3.1.1 NegotiateContextList asks of the response.
struct ClientContexts {
    /// The signing algorithm picked from the client's
    /// SMB2_SIGNING_CAPABILITIES, when it sent one.
    signing_algorithm: Option<u16>,
    /// The cipher picked from the client's SMB2_ENCRYPTION_CAPABILITIES,
    /// when it sent one: `Some(None)` when no cipher is in common.
    cipher: Option<Option<Cipher>>,
}

/// Checks the 3.1.1 NegotiateContextList of `req` (MS-SMB2 3.3.5.4).
/// `body` is the request after the SMB2 header.
fn read_contexts(body: &[u8], req: &NegotiateRequest) -> Result<ClientContexts, u32> {
    let invalid = ntstatus::STATUS_INVALID_PARAMETER;
    let field = req.negotiate_context_offset_or_client_start_time;
    let offset = (field & 0xFFFF_FFFF) as usize;
    let count = ((field >> 32) & 0xFFFF) as u16;
    let dialects_end = NEGOTIATE_FIXED_LEN + 2 * req.dialects.len();
    let start = offset.checked_sub(SMB2_HEADER_LEN).ok_or(invalid)?;
    if start < dialects_end || start > body.len() {
        return Err(invalid);
    }
    let list = NegotiateContext::parse_list(&body[start..], count).map_err(|_| invalid)?;

    let of_type = |t: u16| list.iter().filter(move |c| c.context_type == t);
    let mut preauth = of_type(NegotiateContext::TYPE_PREAUTH_INTEGRITY);
    let (Some(preauth), None) = (preauth.next(), preauth.next()) else {
        return Err(invalid);
    };
    for t in [
        NegotiateContext::TYPE_ENCRYPTION,
        NegotiateContext::TYPE_COMPRESSION,
        NegotiateContext::TYPE_RDMA_TRANSFORM,
        NegotiateContext::TYPE_SIGNING,
    ] {
        if of_type(t).count() > 1 {
            return Err(invalid);
        }
    }

    let caps = PreauthIntegrityCapabilities::read(&mut std::io::Cursor::new(&preauth.data))
        .map_err(|_| invalid)?;
    if !caps
        .hash_algorithms
        .contains(&PreauthIntegrityCapabilities::HASH_SHA512)
    {
        return Err(ntstatus::STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
    }

    let signing_algorithm = match of_type(NegotiateContext::TYPE_SIGNING).next() {
        Some(ctx) => {
            let caps = SigningCapabilities::read(&mut std::io::Cursor::new(&ctx.data))
                .map_err(|_| invalid)?;
            if caps.signing_algorithm_count == 0 {
                return Err(invalid);
            }
            let chosen = select_signing(&caps.signing_algorithms)?;
            // Both halves of the choice in one line: a client that offers only GMAC and a server
            // that answers CMAC is a bug that shows up as a failed signature several messages later,
            // far from this decision.
            tracing::debug!(
                offered = ?caps
                    .signing_algorithms
                    .iter()
                    .map(|id| format!("{id:04x}"))
                    .collect::<Vec<_>>(),
                chosen = format!("{chosen:04x}"),
                "negotiate: signing algorithm"
            );
            Some(chosen)
        }
        None => None,
    };
    let cipher = match of_type(NegotiateContext::TYPE_ENCRYPTION).next() {
        Some(ctx) => {
            let caps = EncryptionCapabilities::read(&mut std::io::Cursor::new(&ctx.data))
                .map_err(|_| invalid)?;
            if caps.cipher_count == 0 {
                return Err(invalid);
            }
            Some(select_cipher(&caps.ciphers))
        }
        None => None,
    };
    Ok(ClientContexts {
        signing_algorithm,
        cipher,
    })
}

/// The signing algorithm to answer with, from the client's list (MS-SMB2 §3.2.5.3.1).
///
/// The client's order decides: the first algorithm in its list that this crate implements. A
/// server that answered a fixed algorithm - which is what this did while CMAC was the only one
/// implemented - names an algorithm a client may never have offered, and the signatures that
/// follow are the first thing to disagree.
///
/// No overlap is a refusal, not a fallback: a signature the other end cannot verify fails later,
/// on a message whose failure looks like corruption rather than like a negotiation that went wrong.
fn select_signing(algorithms: &[u16]) -> Result<u16, u32> {
    algorithms
        .iter()
        .find_map(|id| SigningAlgo::from_id(*id))
        .map(|algo| algo.id())
        .ok_or(ntstatus::STATUS_NOT_SUPPORTED)
}

pub async fn handle(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    _hdr: &Smb2Header,
    body: &[u8],
) -> HandlerResponse {
    let req = match NegotiateRequest::parse(body) {
        Ok(r) => r,
        Err(_) => return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER),
    };
    *conn
        .client_negotiate
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ClientNegotiate {
        capabilities: req.capabilities,
        security_mode: req.security_mode,
        guid: req.client_guid,
        dialects: req.dialects.clone(),
    });
    if req.dialects.is_empty() {
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }

    let Some(dialect) = select_dialect(&req.dialects) else {
        return HandlerResponse::err(ntstatus::STATUS_NOT_SUPPORTED);
    };
    let chosen = dialect.as_u16();
    let contexts = if dialect == Dialect::Smb311 {
        match read_contexts(body, &req) {
            Ok(c) => Some(c),
            Err(status) => return HandlerResponse::err(status),
        }
    } else {
        None
    };

    *conn.dialect.write().await = Some(dialect);
    *conn.client_guid.write().await = Uuid::from_bytes(req.client_guid);
    *conn.signing_algo.write().await = match dialect {
        Dialect::Smb202 | Dialect::Smb210 => SigningAlgo::HmacSha256,
        // 3.1.1 signs with whichever algorithm the negotiation settled on; every earlier 3.x dialect
        // has only CMAC, and so does a 3.1.1 client that sent no SIGNING_CAPABILITIES context.
        Dialect::Smb311 => contexts
            .as_ref()
            .and_then(|c| c.signing_algorithm)
            .and_then(SigningAlgo::from_id)
            .unwrap_or(SigningAlgo::AesCmac),
        _ => SigningAlgo::AesCmac,
    };
    *conn.cipher.write().await = match (dialect, &contexts) {
        (Dialect::Smb300 | Dialect::Smb302, _) => cipher_30(req.capabilities),
        (Dialect::Smb311, Some(c)) => c.cipher.flatten(),
        _ => None,
    };

    // Build SPNEGO security blob (mech-list-only, advertising NTLMSSP).
    let security_blob = encode_init_response();
    let security_buffer_offset: u16 = 64 + 64; // SMB2 header + fixed NEG response (64 bytes)
    let security_buffer_length: u16 = security_blob.len() as u16;

    // For 3.1.1 build negotiate contexts.
    let mut contexts_bytes: Vec<u8> = Vec::new();
    let mut context_count: u16 = 0;
    let mut negotiate_context_offset: u32 = 0;

    if let Some(client_contexts) = contexts {
        // PREAUTH_INTEGRITY_CAPABILITIES
        let mut salt = [0u8; 32];
        if let Err(e) = fill_random(&mut salt) {
            tracing::error!(error = %e, "OS RNG failed; cannot generate preauth salt");
            return HandlerResponse::err(ntstatus::STATUS_INTERNAL_ERROR);
        }
        let preauth_caps = PreauthIntegrityCapabilities {
            hash_algorithm_count: 1,
            salt_length: 32,
            hash_algorithms: vec![PreauthIntegrityCapabilities::HASH_SHA512],
            salt: salt.to_vec(),
        };
        let preauth_data = {
            use binrw::BinWrite;
            let mut c = std::io::Cursor::new(Vec::new());
            BinWrite::write(&preauth_caps, &mut c).expect("preauth negotiate context encodes");
            c.into_inner()
        };
        let preauth_ctx = NegotiateContext {
            context_type: NegotiateContext::TYPE_PREAUTH_INTEGRITY,
            data_length: preauth_data.len() as u16,
            reserved: 0,
            data: preauth_data,
        };

        let mut ctxs = vec![preauth_ctx];
        // SIGNING_CAPABILITIES goes back only to a client that sent one.
        if let Some(algorithm) = client_contexts.signing_algorithm {
            let signing_caps = SigningCapabilities {
                signing_algorithm_count: 1,
                signing_algorithms: vec![algorithm],
            };
            let signing_data = {
                use binrw::BinWrite;
                let mut c = std::io::Cursor::new(Vec::new());
                BinWrite::write(&signing_caps, &mut c).expect("signing negotiate context encodes");
                c.into_inner()
            };
            ctxs.push(NegotiateContext {
                context_type: NegotiateContext::TYPE_SIGNING,
                data_length: signing_data.len() as u16,
                reserved: 0,
                data: signing_data,
            });
        }
        // ENCRYPTION_CAPABILITIES too, with cipher 0 when none is in common.
        if let Some(cipher) = client_contexts.cipher {
            let encryption_caps = EncryptionCapabilities {
                cipher_count: 1,
                ciphers: vec![cipher.map_or(0, Cipher::id)],
            };
            let encryption_data = {
                use binrw::BinWrite;
                let mut c = std::io::Cursor::new(Vec::new());
                BinWrite::write(&encryption_caps, &mut c)
                    .expect("encryption negotiate context encodes");
                c.into_inner()
            };
            ctxs.push(NegotiateContext {
                context_type: NegotiateContext::TYPE_ENCRYPTION,
                data_length: encryption_data.len() as u16,
                reserved: 0,
                data: encryption_data,
            });
        }
        if let Err(e) = NegotiateContext::encode_list(&ctxs, &mut contexts_bytes) {
            tracing::error!(error = %e, "encode_list failed");
            return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
        }
        context_count = ctxs.len() as u16;

        // The contexts go after security buffer, 8-byte aligned.
        let post_security = security_buffer_offset as u32 + security_buffer_length as u32;
        // Round up to next multiple of 8 from the start of the SMB2 header.
        negotiate_context_offset = (post_security + 7) & !7;
    }

    let max_read_size = *conn.max_read_size.read().await;
    let max_write_size = *conn.max_write_size.read().await;
    let max_transact_size = max_read_size;

    let resp = NegotiateResponse {
        structure_size: 65,
        security_mode: server_security_mode(server),
        dialect_revision: chosen,
        negotiate_context_count_or_reserved: context_count,
        server_guid: *server.config.server_guid.as_bytes(),
        capabilities: server_capabilities(dialect, req.capabilities),
        max_transact_size,
        max_read_size,
        max_write_size,
        system_time: now_filetime(),
        server_start_time: 0,
        security_buffer_offset,
        security_buffer_length,
        negotiate_context_offset_or_reserved2: negotiate_context_offset,
        security_buffer: security_blob,
    };

    let mut body_out = Vec::new();
    if let Err(e) = resp.write_to(&mut body_out) {
        tracing::error!(error = %e, "encode NEGOTIATE response");
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    // Append padding to align contexts at `negotiate_context_offset`.
    if dialect == Dialect::Smb311 && context_count > 0 {
        let cur = 64 + body_out.len() as u32; // header + body so far
        if cur < negotiate_context_offset {
            let pad = (negotiate_context_offset - cur) as usize;
            body_out.extend(std::iter::repeat_n(0u8, pad));
        }
        body_out.extend_from_slice(&contexts_bytes);
    }
    info!(?dialect, "NEGOTIATE complete");
    let mut hr = HandlerResponse::ok(body_out);
    hr.skip_signing = true;
    hr
}

/// The greatest dialect in `offered` that the server implements.
pub(crate) fn select_dialect(offered: &[u16]) -> Option<Dialect> {
    const SUPPORTED: &[u16] = &[0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    offered
        .iter()
        .copied()
        .filter(|d| SUPPORTED.contains(d))
        .max()
        .and_then(Dialect::from_u16)
}

/// Build the SMB2 NEGOTIATE response sent in reply to an SMB1 multi-protocol
/// NEGOTIATE_REQUEST that listed an SMB2 dialect (MS-SMB2 §3.3.5.3.1).
///
/// Leaves the connection dialect unset. The client follows up with an SMB2
/// NEGOTIATE, which goes through [`handle`].
pub async fn multi_protocol_response(
    server: &Arc<ServerState>,
    conn: &Arc<Connection>,
    chosen: u16,
) -> HandlerResponse {
    let security_blob = encode_init_response();
    let security_buffer_offset: u16 = 64 + 64;
    let security_buffer_length: u16 = security_blob.len() as u16;
    let max_read_size = *conn.max_read_size.read().await;
    let max_write_size = *conn.max_write_size.read().await;
    let max_transact_size = max_read_size;

    let resp = NegotiateResponse {
        structure_size: 65,
        security_mode: server_security_mode(server),
        dialect_revision: chosen,
        negotiate_context_count_or_reserved: 0,
        server_guid: *server.config.server_guid.as_bytes(),
        // MS-SMB2 3.3.5.3.1: the "SMB 2.???" reply advertises leasing.
        capabilities: if chosen == Dialect::Smb2Wildcard.as_u16() {
            CAP_LEASING
        } else {
            0
        },
        max_transact_size,
        max_read_size,
        max_write_size,
        system_time: now_filetime(),
        server_start_time: 0,
        security_buffer_offset,
        security_buffer_length,
        negotiate_context_offset_or_reserved2: 0,
        security_buffer: security_blob,
    };

    let mut body_out = Vec::new();
    if let Err(e) = resp.write_to(&mut body_out) {
        tracing::error!(error = %e, "encode multi-protocol NEGOTIATE response");
        return HandlerResponse::err(ntstatus::STATUS_INVALID_PARAMETER);
    }
    info!(
        chosen = %format_args!("0x{chosen:04X}"),
        "SMB1 multi-protocol -> SMB2"
    );
    let mut hr = HandlerResponse::ok(body_out);
    hr.skip_signing = true;
    hr
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Samba 4.17 lists CMAC alone; Windows 2022 lists GMAC first. Both must get an answer they
    /// can sign with, and the answer must be one they listed.
    #[test]
    fn select_signing_follows_the_client_order() {
        assert_eq!(
            select_signing(&[SigningAlgo::AesCmac.id()]),
            Ok(SigningAlgo::AesCmac.id())
        );
        assert_eq!(
            select_signing(&[SigningAlgo::AesGmac.id()]),
            Ok(SigningAlgo::AesGmac.id())
        );
        assert_eq!(
            select_signing(&[SigningAlgo::AesGmac.id(), SigningAlgo::AesCmac.id()]),
            Ok(SigningAlgo::AesGmac.id()),
            "the client's order wins, not this crate's preference"
        );
        // An algorithm nobody implements is skipped, not chosen: a list that mentions HMAC-SHA-256
        // alongside CMAC still negotiates CMAC, because 3.1.1 does not offer SHA-256 there.
        assert_eq!(
            select_signing(&[0x0000, SigningAlgo::AesCmac.id()]),
            Ok(SigningAlgo::AesCmac.id())
        );
    }

    /// Nothing in common is a refusal at negotiation, with a status that names the cause.
    #[test]
    fn select_signing_refuses_a_list_it_cannot_sign_with() {
        assert_eq!(select_signing(&[]), Err(ntstatus::STATUS_NOT_SUPPORTED));
        assert_eq!(
            select_signing(&[0x0000, 0x7FFF]),
            Err(ntstatus::STATUS_NOT_SUPPORTED)
        );
    }
}
