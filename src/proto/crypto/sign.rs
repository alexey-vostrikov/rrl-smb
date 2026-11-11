//! SMB2/3 message signing per MS-SMB2 §3.1.4.1.
//!
//! Three algorithms are supported:
//! 1. **HMAC-SHA-256** for SMB 2.0.2 / 2.1.
//! 2. **AES-CMAC** for SMB 3.0+, and the default for 3.1.1.
//! 3. **AES-128-GMAC** for SMB 3.1.1, when the client's SIGNING_CAPABILITIES
//!    context lists it and no earlier algorithm.
//!
//! All three produce a 16-byte signature that lives at bytes 48..64 of the SMB2
//! header (the `Signature` field, MS-SMB2 §2.2.1.2), and all three authenticate
//! the message with that field zeroed. They differ in what else they take:
//!
//! * HMAC-SHA-256 and AES-CMAC take the message and nothing else.
//! * AES-128-GMAC takes a nonce built from the MessageId and two flag bits, and
//!   the message as associated data. The nonce is why `gmac_nonce` exists and
//!   why it converts endianness: the header stores those fields little-endian
//!   and the nonce takes them big-endian.

use aes::Aes128;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::proto::error::{ProtoError, ProtoResult};
use crate::proto::header::{SMB2_FLAGS_ASYNC_COMMAND, SMB2_FLAGS_SERVER_TO_REDIR};

type HmacSha256 = Hmac<Sha256>;
type CmacAes128 = Cmac<Aes128>;

/// SMB2 header is 64 bytes; the 16-byte signature field starts at offset 48.
const SIG_OFF: usize = 48;
const SIG_LEN: usize = 16;
const SMB2_HEADER_LEN: usize = 64;

/// `SMB2_OP_CANCEL` (MS-SMB2 §2.2.1.2): the one opcode whose header fields the
/// GMAC nonce reads as something other than a command's.
const OP_CANCEL: u16 = 0x000C;

/// Field offsets inside the fixed 64-byte header (MS-SMB2 §2.2.1.2).
const OFF_FLAGS: usize = 16;
const OFF_MESSAGE_ID: usize = 24;

/// Which signing algorithm to use for a given session/dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgo {
    /// HMAC-SHA-256, used by SMB 2.x.
    HmacSha256,
    /// AES-CMAC over AES-128, used by SMB 3.0+.
    AesCmac,
    /// AES-128-GMAC, offered by SMB 3.1.1 (MS-SMB2 §3.1.4.1).
    AesGmac,
}

impl SigningAlgo {
    /// The id this algorithm has in a SIGNING_CAPABILITIES negotiate context.
    pub fn id(self) -> u16 {
        match self {
            Self::HmacSha256 => 0x0000,
            Self::AesCmac => 0x0001,
            Self::AesGmac => 0x0002,
        }
    }

    /// The algorithm an id names, for the two this crate implements.
    ///
    /// `None` for anything else: a client may list algorithms nobody implements (Samba lists one
    /// that nobody does), and a list that mentions a name is not a request for it.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(Self::AesCmac),
            0x0002 => Some(Self::AesGmac),
            _ => None,
        }
    }
}

/// Compute the 16-byte MAC over `msg` as if the SMB2 signature field were
/// zeroed, without copying the whole message.
fn compute_mac_zeroed_signature(msg: &[u8], key: &[u8; 16], algo: SigningAlgo) -> [u8; SIG_LEN] {
    let mut out = [0u8; SIG_LEN];
    let zero_signature = [0u8; SIG_LEN];
    let prefix = &msg[..SIG_OFF];
    let suffix = &msg[SIG_OFF + SIG_LEN..];

    match algo {
        SigningAlgo::HmacSha256 => {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
                .expect("HMAC-SHA-256 accepts keys of any length");
            mac.update(prefix);
            mac.update(&zero_signature);
            mac.update(suffix);
            let full = mac.finalize().into_bytes();
            out.copy_from_slice(&full[..SIG_LEN]);
        }
        SigningAlgo::AesCmac => {
            let mut mac = <CmacAes128 as Mac>::new_from_slice(key)
                .expect("AES-128-CMAC requires a 16-byte key, which we have");
            mac.update(prefix);
            mac.update(&zero_signature);
            mac.update(suffix);
            let full = mac.finalize().into_bytes();
            out.copy_from_slice(&full[..SIG_LEN]);
        }
        SigningAlgo::AesGmac => {
            // GMAC and CMAC differ in more than the primitive: GMAC is an AEAD tag taken over the
            // message as associated data, under a nonce that carries the MessageId and the flags.
            // The message is authenticated with its signature field zeroed, exactly as the two MACs
            // above are - but an AEAD takes one contiguous slice of associated data, so the zeroing
            // happens in a copy rather than by feeding three pieces.
            let nonce = gmac_nonce(msg);
            let mut aad = msg.to_vec();
            aad[SIG_OFF..SIG_OFF + SIG_LEN].fill(0);

            let mut plaintext: [u8; 0] = [];
            let tag = <Aes128Gcm as AeadInPlace>::encrypt_in_place_detached(
                &Aes128Gcm::new_from_slice(key).expect("AES-128-GMAC requires a 16-byte key"),
                (&nonce).into(),
                &aad,
                &mut plaintext,
            );
            match tag {
                Ok(tag) => out.copy_from_slice(&tag),
                // Reachable only for a message this crate built itself, and the honest answer to a
                // tag that could not be produced is a refusal, not a zero signature: a zero
                // signature over a message the client is told to trust is worse than no answer.
                Err(_) => {
                    debug_assert!(false, "GMAC over a well-formed header cannot fail");
                    out = [0xFF; SIG_LEN];
                }
            }
        }
    }
    out
}

/// The nonce GMAC signs under (MS-SMB2 §3.1.4.1, and Samba's `smb2_signing_sign_pdu`).
///
/// Twelve octets: the MessageId, then the two flag bits that make a message unique without being
/// part of its id - `SERVER_TO_REDIR`, so a response and a request with the same MessageId sign
/// differently, and `ASYNC_COMMAND` for a CANCEL, whose status and id fields carry something else.
///
/// Both fields are stored **little-endian**, matching the header they are read from: Samba's
/// `SBVAL(iv, 0, msg_id)` is `PUSH_LE_U64`, and the flags land at octet 8 as a little-endian
/// value. Writing them big-endian produces signatures that verify against themselves and against
/// nothing else, which is how this was first written and how the stand caught it - Samba answered
/// `Bad SMB2 (sign_algo_id=2) signature for message`.
fn gmac_nonce(msg: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let message_id = u64::from_le_bytes(
        msg[OFF_MESSAGE_ID..OFF_MESSAGE_ID + 8]
            .try_into()
            .expect("a 64-byte header"),
    );
    let flags = u32::from_le_bytes(
        msg[OFF_FLAGS..OFF_FLAGS + 4]
            .try_into()
            .expect("a 64-byte header"),
    );
    let command = u16::from_le_bytes(msg[12..14].try_into().expect("a 64-byte header"));

    let mut high_bits = flags & SMB2_FLAGS_SERVER_TO_REDIR;
    if command == OP_CANCEL {
        high_bits |= SMB2_FLAGS_ASYNC_COMMAND;
    }

    nonce[..8].copy_from_slice(&message_id.to_le_bytes());
    nonce[8..].copy_from_slice(&high_bits.to_le_bytes());
    nonce
}

/// Compute and embed a signature in `msg`. Mutates `msg` in place.
///
/// The caller is responsible for setting the SMB2 SIGNED flag (`0x00000008`)
/// on the header *before* calling - it is part of the bytes that get MAC'd.
///
/// Errors if `msg` is too short to contain an SMB2 header (< 64 bytes).
pub fn sign(msg: &mut [u8], key: &[u8; 16], algo: SigningAlgo) -> ProtoResult<()> {
    if msg.len() < SMB2_HEADER_LEN {
        return Err(ProtoError::Crypto("message too short to sign"));
    }

    // Compute MAC over the whole message with the signature field treated as
    // zero, then place the MAC into the signature field.
    let mac = compute_mac_zeroed_signature(msg, key, algo);
    msg[SIG_OFF..SIG_OFF + SIG_LEN].copy_from_slice(&mac);

    Ok(())
}

/// Verify the signature in `msg`. Does **not** modify `msg`.
///
/// Uses constant-time comparison. Returns `Ok(())` if the embedded signature
/// matches the freshly computed MAC.
pub fn verify(msg: &[u8], key: &[u8; 16], algo: SigningAlgo) -> ProtoResult<()> {
    if msg.len() < SMB2_HEADER_LEN {
        return Err(ProtoError::Crypto("message too short to verify"));
    }

    // Capture the embedded signature.
    let mut embedded = [0u8; SIG_LEN];
    embedded.copy_from_slice(&msg[SIG_OFF..SIG_OFF + SIG_LEN]);

    let computed = compute_mac_zeroed_signature(msg, key, algo);

    if constant_time_eq(&embedded, &computed) {
        Ok(())
    } else {
        Err(ProtoError::Crypto("signature mismatch"))
    }
}

/// Constant-time comparison of two 16-byte arrays.
#[inline]
/// Constant-time comparison, from the crypto layer (RRL-7.2).
fn constant_time_eq(a: &[u8; SIG_LEN], b: &[u8; SIG_LEN]) -> bool {
    rrl_crypto::ct_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 100-byte message: a plausible 64-byte SMB2 header followed by
    /// 36 bytes of body. The signature region (bytes 48..64) is left zero;
    /// `sign` will overwrite it.
    fn fixture_message() -> Vec<u8> {
        let mut msg = vec![0u8; 100];
        // Magic: 0xFE 'S' 'M' 'B'
        msg[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // StructureSize = 64
        msg[4..6].copy_from_slice(&64u16.to_le_bytes());
        // Pretend ChannelSequence = 0
        msg[6..8].copy_from_slice(&0u16.to_le_bytes());
        // Command = NEGOTIATE (0)
        msg[12..14].copy_from_slice(&0u16.to_le_bytes());
        // Flags: SIGNED (0x00000008)
        msg[16..20].copy_from_slice(&0x0000_0008u32.to_le_bytes());
        // Body filler
        for (i, b) in msg[64..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        msg
    }

    #[test]
    fn sign_and_verify_hmac_sha256() {
        let key = [0xAAu8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::HmacSha256).expect("sign ok");

        // Signature should now be non-zero (overwhelmingly likely).
        assert_ne!(&msg[SIG_OFF..SIG_OFF + SIG_LEN], &[0u8; 16]);

        verify(&msg, &key, SigningAlgo::HmacSha256).expect("verify ok");
    }

    #[test]
    fn sign_and_verify_aes_cmac() {
        let key = [0x55u8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::AesCmac).expect("sign ok");
        assert_ne!(&msg[SIG_OFF..SIG_OFF + SIG_LEN], &[0u8; 16]);
        verify(&msg, &key, SigningAlgo::AesCmac).expect("verify ok");
    }

    #[test]
    fn sign_and_verify_aes_gmac() {
        let key = [0x55u8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::AesGmac).expect("sign ok");
        assert_ne!(&msg[SIG_OFF..SIG_OFF + SIG_LEN], &[0u8; 16]);
        verify(&msg, &key, SigningAlgo::AesGmac).expect("verify ok");
    }

    /// The nonce rule, pinned byte for byte: both fields leave the header as they arrived.
    ///
    /// A version that converts endianness round-trips against itself and fails against every other
    /// implementation, so the bytes are asserted rather than round-tripped.
    #[test]
    fn gmac_nonce_is_message_id_then_high_bits_little_endian() {
        let mut msg = fixture_message();
        // MessageId 0x0102_0304_0506_0708, stored little-endian as the header does.
        msg[24..32].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        // SERVER_TO_REDIR set, ASYNC clear, command NEGOTIATE.
        msg[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&SMB2_FLAGS_SERVER_TO_REDIR.to_le_bytes());

        assert_eq!(
            gmac_nonce(&msg),
            [
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00
            ],
            "message id little-endian, then the redir bit little-endian"
        );

        // A request (no SERVER_TO_REDIR) and the response to it share a MessageId and must not
        // share a nonce, or the two GMACs are over the same nonce and different data.
        msg[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(&gmac_nonce(&msg)[8..], &[0, 0, 0, 0]);
    }

    /// A CANCEL carries ASYNC in the nonce whatever its Flags say (MS-SMB2 §3.1.4.1).
    #[test]
    fn gmac_nonce_sets_async_for_cancel() {
        let mut msg = fixture_message();
        msg[12..14].copy_from_slice(&OP_CANCEL.to_le_bytes());
        msg[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            &gmac_nonce(&msg)[8..12],
            &SMB2_FLAGS_ASYNC_COMMAND.to_le_bytes(),
            "a cancel signs under the async bit"
        );
    }

    /// The same message under the same key signs differently in CMAC and in GMAC: the algorithms
    /// are not interchangeable, so a connection that picked one must not verify with the other.
    #[test]
    fn gmac_and_cmac_disagree() {
        let key = [0x33u8; 16];
        let mut cmac = fixture_message();
        let mut gmac = fixture_message();
        sign(&mut cmac, &key, SigningAlgo::AesCmac).expect("sign ok");
        sign(&mut gmac, &key, SigningAlgo::AesGmac).expect("sign ok");
        assert_ne!(
            &cmac[SIG_OFF..SIG_OFF + SIG_LEN],
            &gmac[SIG_OFF..SIG_OFF + SIG_LEN]
        );
        assert!(matches!(
            verify(&cmac, &key, SigningAlgo::AesGmac),
            Err(ProtoError::Crypto(_))
        ));
    }

    #[test]
    fn tamper_outside_sig_fails_verify_gmac() {
        let key = [0xAAu8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::AesGmac).expect("sign ok");
        msg[80] ^= 0x01;
        assert!(matches!(
            verify(&msg, &key, SigningAlgo::AesGmac),
            Err(ProtoError::Crypto(_))
        ));
    }

    #[test]
    fn tamper_outside_sig_fails_verify_hmac() {
        let key = [0xAAu8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::HmacSha256).expect("sign ok");

        // Flip one body byte.
        msg[80] ^= 0x01;
        let res = verify(&msg, &key, SigningAlgo::HmacSha256);
        assert!(matches!(res, Err(ProtoError::Crypto(_))));
    }

    #[test]
    fn tamper_outside_sig_fails_verify_cmac() {
        let key = [0x55u8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::AesCmac).expect("sign ok");

        // Flip a header byte (not in the sig region).
        msg[10] ^= 0xFF;
        let res = verify(&msg, &key, SigningAlgo::AesCmac);
        assert!(matches!(res, Err(ProtoError::Crypto(_))));
    }

    #[test]
    fn tamper_signature_fails_verify() {
        let key = [0xAAu8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::HmacSha256).expect("sign ok");
        msg[SIG_OFF] ^= 0x01;
        let res = verify(&msg, &key, SigningAlgo::HmacSha256);
        assert!(matches!(res, Err(ProtoError::Crypto(_))));
    }

    #[test]
    fn wrong_key_fails_verify() {
        let key = [0xAAu8; 16];
        let bad_key = [0xBBu8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::HmacSha256).expect("sign ok");
        let res = verify(&msg, &bad_key, SigningAlgo::HmacSha256);
        assert!(matches!(res, Err(ProtoError::Crypto(_))));
    }

    #[test]
    fn too_short_message_errors() {
        let mut tiny = [0u8; 10];
        let key = [0u8; 16];
        let res = sign(&mut tiny, &key, SigningAlgo::HmacSha256);
        assert!(matches!(res, Err(ProtoError::Crypto(_))));
        let res = verify(&tiny, &key, SigningAlgo::HmacSha256);
        assert!(matches!(res, Err(ProtoError::Crypto(_))));
    }

    #[test]
    fn verify_does_not_mutate_message_hmac_sha256() {
        let key = [0xAAu8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::HmacSha256).expect("sign ok");
        let snapshot = msg.clone();
        verify(&msg, &key, SigningAlgo::HmacSha256).expect("verify ok");
        assert_eq!(msg, snapshot);
    }

    #[test]
    fn verify_does_not_mutate_message_aes_cmac() {
        let key = [0x55u8; 16];
        let mut msg = fixture_message();
        sign(&mut msg, &key, SigningAlgo::AesCmac).expect("sign ok");
        let snapshot = msg.clone();
        verify(&msg, &key, SigningAlgo::AesCmac).expect("verify ok");
        assert_eq!(msg, snapshot);
    }

    #[test]
    fn sign_ignores_existing_signature_bytes() {
        let key = [0xAAu8; 16];
        let mut clean = fixture_message();
        let mut dirty = fixture_message();
        dirty[SIG_OFF..SIG_OFF + SIG_LEN].fill(0xCC);

        sign(&mut clean, &key, SigningAlgo::HmacSha256).expect("sign clean");
        sign(&mut dirty, &key, SigningAlgo::HmacSha256).expect("sign dirty");

        assert_eq!(
            &clean[SIG_OFF..SIG_OFF + SIG_LEN],
            &dirty[SIG_OFF..SIG_OFF + SIG_LEN]
        );
        verify(&dirty, &key, SigningAlgo::HmacSha256).expect("verify dirty");
    }
}
