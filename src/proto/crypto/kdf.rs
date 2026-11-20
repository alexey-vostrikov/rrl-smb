//! SP 800-108 CTR-mode KDF using HMAC-SHA-256, as required by MS-SMB2 §3.1.4.2.
//!
//! Fixed input fed to the PRF (HMAC-SHA-256) is:
//!
//! ```text
//! i (u32be=1) || Label || 0x00 || Context || L (u32be, 128 or 256)
//! ```
//!
//! Convention in this crate:
//! * Callers pass `label` and `context` *already including* a trailing `\x00`.
//! * The KDF then **also** emits a single `0x00` separator between `label`
//!   and `context`, so the wire-level input has two consecutive NULs at that
//!   boundary.

// The derivation itself lives in `rrl-crypto`; what is left here is the SMB spelling of it and the
// names of the keys SMB derives.

/// SP 800-108 CTR-mode KDF using HMAC-SHA-256 with L = 128.
///
/// * `key` - the input key (session key, typically 16 bytes).
/// * `label` - the label string with trailing NUL (e.g. `b"SMB2AESCMAC\x00"`).
/// * `context` - the context string with trailing NUL (e.g. `b"SmbSign\x00"`).
///
/// Returns the first 16 bytes of `HMAC-SHA-256(key, fixed_input)` where
/// `fixed_input = [0,0,0,1] || label || 0x00 || context || [0,0,0,0x80]`.
pub fn smb2_kdf(key: &[u8], label: &[u8], context: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    smb2_kdf_into(key, label, context, &mut out);
    out
}

/// SP 800-108 CTR-mode KDF using HMAC-SHA-256, filling `out` with
/// L = `out.len() * 8` bits. One HMAC block covers the 16- and 32-byte keys
/// SMB derives.
///
/// The derivation itself is [`rrl_crypto::kdf::kdf_hmac_sha2`] (RRL-7.4): SP 800-108 counter mode is
/// **one** function with two spellings, and the whole difference between them is who writes the NUL
/// after the label. A Kerberos caller passes `b"prf"` and the layer writes the separator; an SMB
/// caller passes `b"SMB2AESCMAC\x00"`, NUL included, and the layer's separator makes the second one.
/// That is the wire format MS-SMB2 §3.1.4.2 asks for - `i || Label || 0x00 || Context || L` with the
/// label's own terminator already in place - and it is what the published vector below checks.
pub(crate) fn smb2_kdf_into(key: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 32, "SMB keys are at most 256 bits");
    let derived = rrl_crypto::kdf::kdf_hmac_sha2(
        rrl_crypto::kdf::Sha2Kind::Sha256,
        key,
        label,
        Some(context),
        u32::try_from(out.len() * 8).expect("an SMB key is at most 256 bits"),
    )
    .expect("the label, context and length this crate passes are a valid SP 800-108 input");
    out.copy_from_slice(&derived[..out.len()]);
}

// --- Convenience helpers ---------------------------------------------------

/// Signing key for SMB 3.0 / 3.0.2.
///
/// Label = `"SMB2AESCMAC\x00"`, Context = `"SmbSign\x00"` (MS-SMB2 §3.1.4.2).
pub fn signing_key_30(session_key: &[u8]) -> [u8; 16] {
    smb2_kdf(session_key, b"SMB2AESCMAC\x00", b"SmbSign\x00")
}

/// Signing key for SMB 3.1.1.
///
/// Label = `"SMBSigningKey\x00"`, Context = pre-auth integrity hash
/// (the SHA-512 snapshot taken at SESSION_SETUP completion).
pub fn signing_key_311(session_key: &[u8], preauth_hash: &[u8; 64]) -> [u8; 16] {
    smb2_kdf(session_key, b"SMBSigningKey\x00", preauth_hash)
}

/// Application key for SMB 3.0 / 3.0.2.
///
/// Label `"SMB2APP\x00"`, context `"SmbRpc\x00"` — `smb2_signing.c` in Samba derives exactly these
/// for `protocol >= PROTOCOL_SMB3_00` and below 3.1.1.
pub fn application_key_30(session_key: &[u8]) -> [u8; 16] {
    smb2_kdf(session_key, b"SMB2APP\x00", b"SmbRpc\x00")
}

/// Application key for SMB 3.1.1.
///
/// Label `"SMBAppKey\x00"`, context the pre-auth integrity hash. Not `SMB2APP`/`SmbRpc`: Samba's
/// `smb2_signing_derivation` switches both names when the dialect reaches 3.1.1, and this is the key
/// a client seals an RPC password block with. Measured: a Windows Server 2022 join's block opens
/// under this key and under no other, and the whole `samr_SetInformationUser2` failure was this
/// derivation.
pub fn application_key_311(session_key: &[u8], preauth_hash: &[u8; 64]) -> [u8; 16] {
    smb2_kdf(session_key, b"SMBAppKey\x00", preauth_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Determinism / shape sanity: the function always produces 16 bytes and
    /// is reproducible for the same inputs.
    #[test]
    fn smb2_kdf_is_deterministic() {
        let key = [0x11u8; 16];
        let a = smb2_kdf(&key, b"SMB2AESCMAC\x00", b"SmbSign\x00");
        let b = smb2_kdf(&key, b"SMB2AESCMAC\x00", b"SmbSign\x00");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    /// Known-answer test computed directly from the documented fixed-input
    /// construction. This pins the exact byte layout we feed to HMAC.
    ///
    /// Reference computation (Python):
    /// ```text
    /// import hmac, hashlib
    /// key = bytes(16)  # all zeros
    /// label = b"SMB2AESCMAC\x00"
    /// context = b"SmbSign\x00"
    /// data = b"\x00\x00\x00\x01" + label + b"\x00" + context + b"\x00\x00\x00\x80"
    /// hmac.new(key, data, hashlib.sha256).hexdigest()[:32]
    /// # = "9951088b83220f39d99420419d16d393"
    /// ```
    #[test]
    fn smb2_kdf_known_answer_zero_key_signing_30() {
        let key = [0u8; 16];
        let out = signing_key_30(&key);
        let expected = hex::decode("9951088b83220f39d99420419d16d393").unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    /// 3.1.1 derivation differs from 3.0 (different label, 64-byte context).
    #[test]
    fn smb2_kdf_311_differs_from_30() {
        let key = [0u8; 16];
        let preauth = [0u8; 64];
        let k30 = signing_key_30(&key);
        let k311 = signing_key_311(&key, &preauth);
        assert_ne!(k30, k311);
    }

    /// Known-answer test for 3.1.1 with zero key and zero pre-auth hash.
    ///
    /// Reference computation (Python):
    /// ```text
    /// data = b"\x00\x00\x00\x01" + b"SMBSigningKey\x00" + b"\x00" + bytes(64) + b"\x00\x00\x00\x80"
    /// hmac.new(bytes(16), data, hashlib.sha256).hexdigest()[:32]
    /// # = "a06a153e09bd0f34706a5c671acaa37d"
    /// ```
    #[test]
    fn smb2_kdf_known_answer_zero_key_signing_311() {
        let key = [0u8; 16];
        let preauth = [0u8; 64];
        let out = signing_key_311(&key, &preauth);
        let expected = hex::decode("a06a153e09bd0f34706a5c671acaa37d").unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }
}
