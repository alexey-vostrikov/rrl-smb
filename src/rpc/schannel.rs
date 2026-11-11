//! `NL_AUTH_MESSAGE`: what an authenticated DCE/RPC bind carries on the netlogon pipe.
//!
//! MS-RPCE asks for a `sec_trailer` and a token, and leaves the token to the authentication service.
//! On this pipe the service is `RPC_C_AUTHN_NETLOGON` (68) — Samba's schannel — and the token is
//! MS-NRPC 2.2.1.3.1's `NL_AUTH_MESSAGE`:
//!
//! ```text
//! MessageType   uint32   0 = Negotiate, 1 = Challenge, 2 = Response
//! Flags         uint32   what the sender supports; meaningful on Negotiate
//! ```
//!
//! Measured from a live join: the bind carried `00000000 03000000` — Negotiate, flags 3 — followed
//! by the domain and computer names as **one-byte** strings, `AD\0` then `SAMBA\0`, nine octets in
//! all: 8 + 3 + 6 = 17, which is `auth_length` exactly.
//!
//! Not UTF-16, whatever the rest of this protocol prefers: read as units the same octets spell
//! `䑁匀䵁䅂`, and a parser that assumed UTF-16 would name a domain nobody has. The message is not
//! NTLMSSP either, and an implementation that expected one would refuse a client whose machine
//! password was right.
//!
//! The names are the interesting part of a Negotiate: they say *which* account the client means,
//! and this server keeps no directory to look one up in — the daemon that owns the accounts does.
//! So the message is parsed and kept, and the decision is made by whoever holds the key.

/// The message a client sends first, and the one a server answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Negotiate {
    /// What the sender says it supports. Kept verbatim: the bits are the protocol's, not ours.
    pub flags: u32,
    /// The domain the client names, when it named one.
    pub domain: String,
    /// The computer the client names.
    pub computer: String,
}

/// Why a token is not an `NL_AUTH_MESSAGE` this server can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    /// Shorter than `MessageType` and `Flags`.
    Truncated,
    /// A message type this server does not answer.
    UnexpectedType(u32),
    /// The signature names an algorithm this server does not speak.
    SignatureAlgorithm,
    /// The signature's sequence number is not the one expected next.
    Sequence,
    /// The checksum does not cover the message it arrived with.
    Checksum,
}

/// `MessageType` values (MS-NRPC 2.2.1.3.1).
const TYPE_NEGOTIATE: u32 = 0;
/// The client's answer to the server's challenge.
const TYPE_RESPONSE: u32 = 2;

/// Reads the message a client sent on its bind.
///
/// A `Negotiate` carries the two names after the header. Their length is not written anywhere in
/// the message, so the rest of the token is decoded as far as it goes: a name this protocol writes
/// as UTF-16LE and terminates with a zero unit.
pub(crate) fn parse_negotiate(token: &[u8]) -> Result<Negotiate, Error> {
    if token.len() < 8 {
        return Err(Error::Truncated);
    }
    let message_type = u32::from_le_bytes([token[0], token[1], token[2], token[3]]);
    let flags = u32::from_le_bytes([token[4], token[5], token[6], token[7]]);
    if message_type != TYPE_NEGOTIATE {
        return Err(Error::UnexpectedType(message_type));
    }
    let names = &token[8..];
    let (domain, rest) = take_name(names);
    let (computer, _) = take_name(rest);
    Ok(Negotiate {
        flags,
        domain,
        computer,
    })
}

/// The message a server answers a bind with: the same type, and its own flags.
///
/// No nonce here. MS-NRPC puts the server's challenge in the AUTH3 exchange that follows, and
/// sending one in the bind answer would be a value the client never compares.
pub(crate) fn negotiate(flags: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&TYPE_NEGOTIATE.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out
}

/// One zero-terminated one-byte name, and what follows it.
///
/// One byte per character, measured: the names in a live negotiate are `41 44 00` and
/// `53 41 4d 42 41 00`. Decoding them as UTF-16 units spells `䑁匀䵁䅂` and produces a domain no
/// directory has, which is the kind of error that looks like a client problem.
fn take_name(bytes: &[u8]) -> (String, &[u8]) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let rest = if end < bytes.len() {
        &bytes[end + 1..]
    } else {
        &bytes[bytes.len()..]
    };
    (String::from_utf8_lossy(&bytes[..end]).into_owned(), rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The token from a live join, verbatim.
    ///
    /// `00000000 03000000` then the names one byte at a time: the domain and the computer, which is
    /// what the client says before anything is proved.
    const CAPTURED: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x41, 0x44, 0x00, 0x53, 0x41, 0x4d, 0x42,
        0x41, 0x00,
    ];

    #[test]
    fn a_live_negotiate_names_the_domain_and_the_computer() {
        let message = parse_negotiate(CAPTURED).expect("a negotiate");
        assert_eq!(message.flags, 3, "what the client said it supports");
        assert_eq!(message.domain, "AD");
        assert_eq!(message.computer, "SAMBA");
    }

    /// A message that is not a Negotiate is refused by its type, not read as one.
    #[test]
    fn a_response_is_not_a_negotiate() {
        let mut token = CAPTURED.to_vec();
        token[0] = 2;
        assert_eq!(parse_negotiate(&token), Err(Error::UnexpectedType(2)));
    }

    #[test]
    fn a_token_shorter_than_the_header_is_refused() {
        assert_eq!(parse_negotiate(&[0; 7]), Err(Error::Truncated));
        // Eight octets are a whole header and no names, which is legal.
        let message = parse_negotiate(&[0; 8]).expect("a header and nothing else");
        assert_eq!((message.flags, message.domain.as_str()), (0, ""));
    }

    /// The answer is the same type with this server's flags, and nothing else.
    #[test]
    fn the_answer_is_a_negotiate_with_our_flags() {
        let answer = negotiate(7);
        assert_eq!(answer, vec![0, 0, 0, 0, 7, 0, 0, 0]);
        let back = parse_negotiate(&answer).expect("our own answer parses");
        assert_eq!(back.flags, 7);
        assert_eq!(back.domain, "");
    }
}

/// The signature a sealed PDU carries, as this server writes and checks it.
///
/// MS-NRPC 3.1.4.4.5, measured from a live client rather than read off the IDL - which does not
/// carry it. With AES the blob is 56 octets, and the fields sit at fixed offsets:
///
/// ```text
///   0..8    header: u16 SignatureAlgorithm, u16 SealAlgorithm, u16 0xFFFF, u16 0
///   8..16   SequenceNumber, itself encrypted once the checksum is known
///  16..24   Checksum: the first 8 octets of HMAC-SHA256 over header || confounder || data
///  24..32   Confounder: the 8 octets the sealed body was prefixed with
///  32..56   zero padding - the blob is allocated at 56 and only 32 are filled
/// ```
///
/// `NL_SIGN_HMAC_SHA256` is 19 and `NL_SEAL_AES128` is 26; both appear verbatim in a capture as
/// `1300 1a00`.
pub(crate) const SIG_LEN_AES: usize = 56;
/// `NL_SIGN_HMAC_SHA256`.
const SIGN_SHA256: u16 = 19;
/// `NL_SEAL_AES128`.
const SEAL_AES: u16 = 26;
/// `NL_SEAL_NONE`: signed, not sealed.
const SEAL_NONE: u16 = 1;

/// The header of a signature blob, before the checksum can be computed.
fn signature_header(sealed: bool) -> [u8; 8] {
    let mut header = [0u8; 8];
    header[0..2].copy_from_slice(&SIGN_SHA256.to_le_bytes());
    let seal = if sealed { SEAL_AES } else { SEAL_NONE };
    header[2..4].copy_from_slice(&seal.to_le_bytes());
    header[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes());
    header[6..8].copy_from_slice(&0u16.to_le_bytes());
    header
}

/// AES-128-CFB8, which is the mode both the sealing and the sequence step use.
///
/// Eight-bit segments: one block-cipher call per octet, and the feedback is the **ciphertext**
/// octet - in both directions. That is the whole difference between the two functions below, and
/// getting it wrong is invisible in one direction: a single function that feeds back its output
/// encrypts correctly and decrypts to garbage, which reads as a wrong key.
/// AES-128-CFB8 in place, for the callers outside this file that need the mode without the
/// sealing rules around it - a password blob is encrypted with the session key and a zero IV, which
/// is the same cipher and none of the same framing.
pub(crate) fn cfb8(key: &[u8], iv: &[u8; 16], data: &mut [u8], decrypt: bool) {
    if decrypt {
        cfb8_decrypt(key, iv, data);
    } else {
        cfb8_encrypt(key, iv, data);
    }
}

fn cfb8_encrypt(key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};

    let cipher = aes::Aes128::new_from_slice(key).expect("a 16-octet AES key");
    let mut state = *iv;
    for byte in data.iter_mut() {
        let mut block = aes::Block::from(state);
        cipher.encrypt_block(&mut block);
        let ciphertext = *byte ^ block[0];
        *byte = ciphertext;
        state.copy_with_below(ciphertext);
    }
}

/// The inverse: the keystream comes from the same block cipher, and the state advances on the
/// octet that arrived, not on the one recovered.
fn cfb8_decrypt(key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};

    let cipher = aes::Aes128::new_from_slice(key).expect("a 16-octet AES key");
    let mut state = *iv;
    for byte in data.iter_mut() {
        let mut block = aes::Block::from(state);
        cipher.encrypt_block(&mut block);
        let ciphertext = *byte;
        *byte ^= block[0];
        state.copy_with_below(ciphertext);
    }
}

/// Shifts `state` left by one octet and appends `byte` (CFB8's feedback).
trait ShiftIn {
    fn copy_with_below(&mut self, byte: u8);
}

impl ShiftIn for [u8; 16] {
    fn copy_with_below(&mut self, byte: u8) {
        self.copy_within(1.., 0);
        self[15] = byte;
    }
}

/// The signature for `data`, and the body sealed under it.
///
/// The order is the protocol's and each step depends on the one before: the checksum covers the
/// **plaintext**, the sequence blob is encrypted under that checksum, and the body is sealed under
/// the *plaintext* sequence blob - the two use the same state, and swapping them produces a blob
/// the client rejects without saying why.
///
/// `counter` is this side's own counter, zero for the first PDU and one more for each after. The
/// sequence number is **not** carried in a form anyone can read back: the receiver builds it from
/// its own counter and compares. `initiator` sets the top bit of the high word - true for the side
/// that opened the channel, false for the responder.
pub(crate) fn seal(
    session_key: &[u8; 32],
    counter: u64,
    initiator: bool,
    data: &mut [u8],
) -> [u8; SIG_LEN_AES] {
    let header = signature_header(true);
    let mut confounder = [0u8; 8];
    getrandom::fill(&mut confounder).expect("the OS has randomness");

    let seq_plain = sequence_blob(counter, initiator);

    // 1. The checksum, over the plaintext. The HMAC key is the session key's FIRST HALF: the
    //    protocol grew a 32-octet key for AES and then hashed with sixteen of them, which is
    //    measured - a 32-octet key gives a digest the client never produces.
    let checksum = hmac_sha256_prefix(session_key, &[&header, &confounder, data]);

    // 2. The body, sealed under the plaintext sequence blob. The confounder is the stream's first
    //    eight octets and what the signature carries is its SEALED form.
    let sealed_confounder = transform_body(true, session_key, &seq_plain, &confounder, data);

    // 3. The sequence blob, encrypted under the checksum.
    let seq_wire = crypt_sequence(session_key, &checksum, &seq_plain);

    let mut sig = [0u8; SIG_LEN_AES];
    sig[0..8].copy_from_slice(&header);
    sig[8..16].copy_from_slice(&seq_wire);
    sig[16..24].copy_from_slice(&checksum);
    sig[24..32].copy_from_slice(&sealed_confounder);
    sig
}

/// Checks a signature and opens the body in place.
///
/// `counter` and `initiator` are what this server expects for this PDU - its own bookkeeping, not
/// anything read out of the signature. A sequence number that does not match means the PDU is not
/// the one expected next, which is how a replayed or reordered message is refused.
pub(crate) fn unseal(
    session_key: &[u8; 32],
    counter: u64,
    initiator: bool,
    sig: &[u8],
    data: &mut [u8],
) -> Result<(), Error> {
    if sig.len() < 32 {
        return Err(Error::Truncated);
    }
    let mut header = [0u8; 8];
    header.copy_from_slice(&sig[0..8]);
    if u16::from_le_bytes([header[0], header[1]]) != SIGN_SHA256 {
        return Err(Error::SignatureAlgorithm);
    }
    let sealed = u16::from_le_bytes([header[2], header[3]]) == SEAL_AES;
    let checksum: [u8; 8] = sig[16..24].try_into().map_err(|_| Error::Truncated)?;
    let seq_wire: [u8; 8] = sig[8..16].try_into().map_err(|_| Error::Truncated)?;
    let seq_plain = sequence_blob(counter, initiator);

    // The sequence is checked before the body is opened: it needs only the checksum, which travels
    // in the clear, and a PDU from another position in the stream should not be unwrapped at all.
    if crypt_sequence(session_key, &checksum, &seq_plain) != seq_wire {
        return Err(Error::Sequence);
    }

    let mut confounder: [u8; 8] = sig[24..32].try_into().map_err(|_| Error::Truncated)?;
    if sealed {
        confounder = transform_body(false, session_key, &seq_plain, &confounder, data);
    }

    // A signature that is only signed carries no confounder at all: Samba hashes the header and the
    // data with nothing between them.
    let expected = if sealed {
        hmac_sha256_prefix(session_key, &[&header, &confounder, data])
    } else {
        hmac_sha256_prefix(session_key, &[&header, data])
    };
    if !rrl_crypto::ct_eq(&expected, &checksum) {
        return Err(Error::Checksum);
    }
    Ok(())
}

/// `low32` then `high32`, both **big-endian**, with the initiator bit on the high word.
///
/// Samba writes this with `RSIVAL`, and the R-prefixed macros there are the reverse-order ones - the
/// opposite of the little-endian `SIVAL`. Measured: the plaintext of a live client's first PDU is
/// `00000000 80000000`, which is be32(0) then be32(0x80000000). Read little-endian the same octets
/// are a counter of 549755813888, which is nobody's first packet.
fn sequence_blob(counter: u64, initiator: bool) -> [u8; 8] {
    let low = (counter & 0xFFFF_FFFF) as u32;
    let mut high = (counter >> 32) as u32;
    if initiator {
        high |= 0x8000_0000;
    }
    let mut blob = [0u8; 8];
    blob[0..4].copy_from_slice(&low.to_be_bytes());
    blob[4..8].copy_from_slice(&high.to_be_bytes());
    blob
}

/// HMAC-SHA256 over the concatenation of `parts`, truncated to the 8 octets the blob carries.
///
/// The key is the session key's first sixteen octets, not all thirty-two: the protocol went to a
/// 32-octet key for AES and then hashed with half of it, and a 32-octet HMAC key gives a digest the
/// client never sends. Measured against a live signature.
fn hmac_sha256_prefix(session_key: &[u8; 32], parts: &[&[u8]]) -> [u8; 8] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&session_key[..16]).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    let full = mac.finalize().into_bytes();
    full[..8].try_into().expect("eight octets")
}

/// The sequence blob through AES-128-CFB8 with the checksum twice as the IV.
///
/// One function for both directions because the plaintext here is always the same blob and the mode
/// is its own inverse for a keystream XOR - the caller decides which side it is on.
fn crypt_sequence(session_key: &[u8; 32], checksum: &[u8; 8], blob: &[u8; 8]) -> [u8; 8] {
    let mut iv = [0u8; 16];
    iv[0..8].copy_from_slice(checksum);
    iv[8..16].copy_from_slice(checksum);
    let mut out = *blob;
    cfb8_encrypt(&session_key[..16], &iv, &mut out);
    out
}

fn transform_body(
    encrypt: bool,
    session_key: &[u8; 32],
    seq_num: &[u8; 8],
    confounder: &[u8; 8],
    data: &mut [u8],
) -> [u8; 8] {
    let mut key = [0u8; 16];
    for (i, octet) in key.iter_mut().enumerate() {
        *octet = session_key[i] ^ 0xF0;
    }
    let mut iv = [0u8; 16];
    iv[0..8].copy_from_slice(seq_num);
    iv[8..16].copy_from_slice(seq_num);

    // One stream over the confounder and then the body, in that order: the confounder is the
    // stream's first eight octets and the body continues it, so the two cannot be transformed
    // apart - the second depends on the cipher state the first leaves behind.
    let mut both = Vec::with_capacity(8 + data.len());
    both.extend_from_slice(confounder);
    both.extend_from_slice(data);
    if encrypt {
        cfb8_encrypt(&key, &iv, &mut both);
    } else {
        cfb8_decrypt(&key, &iv, &mut both);
    }
    data.copy_from_slice(&both[8..]);
    both[..8].try_into().expect("eight octets")
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    fn key() -> [u8; 32] {
        std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
    }

    /// What this server seals, this server opens - and the body comes back unchanged.
    ///
    /// A round trip is the least a symmetric implementation can be asked, and it does catch the
    /// faults that matter here: the `^ 0xF0` on the sealing key, the sequence used as the IV, and
    /// the checksum covering the plaintext rather than the ciphertext. Get any of them wrong on
    /// both sides alike and the round trip still passes - which is why the stand, not this, decides
    /// whether the client agrees.
    /// What this server seals, this server opens - and the body comes back unchanged.
    ///
    /// A round trip is the least a symmetric implementation can be asked. What it caught here: the
    /// feedback in CFB8 is the ciphertext octet in both directions, so one function cannot serve
    /// both, and the confounder is the stream's FIRST eight octets, so what the signature carries
    /// has to be its sealed form - with the plaintext there, the reader's cipher diverges from the
    /// writer's at octet one and the body opens to garbage under a signature that verifies.
    ///
    /// It cannot say the client agrees; only the stand can. What it does say is that the two sides
    /// of this file are the same protocol.
    #[test]
    fn a_sealed_pdu_opens_again() {
        let key = key();
        for sequence in [0u64, 1, 7, 0xFFFF_FFFF] {
            for len in [0usize, 1, 8, 33, 216] {
                let plaintext: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x5a).collect();
                let mut body = plaintext.clone();
                let sig = seal(&key, sequence, true, &mut body);
                // A one-octet body can coincide with its own keystream octet - one chance in 256,
                // and it happened - so the claim is made where it is a claim: at eight octets the
                // odds against a whole match are past coincidence.
                if len >= 8 {
                    assert_ne!(body, plaintext, "the body must not travel in the clear");
                }

                unseal(&key, sequence, true, &sig, &mut body)
                    .unwrap_or_else(|err| panic!("seq {sequence} len {len}: {err:?}"));
                assert_eq!(body, plaintext, "seq {sequence} len {len}");
            }
        }
    }

    /// Every octet of the signature is checked, and the sequence must be the one expected.
    #[test]
    fn a_damaged_or_misplaced_signature_is_refused() {
        let key = key();
        let plaintext = b"the stub a client signed".to_vec();

        let mut body = plaintext.clone();
        let sig = seal(&key, 5, true, &mut body);

        // One bit anywhere in the signature: the checksum, the sequence or the header.
        for index in 0..32 {
            let mut damaged = sig;
            damaged[index] ^= 0x01;
            let mut copy = body.clone();
            assert!(
                unseal(&key, 5, true, &damaged, &mut copy).is_err(),
                "octet {index} of the signature was not checked"
            );
        }

        // The same signature on the next message in the stream: the sequence number decodes to 5,
        // not 6, so this is a replay and not a fresh PDU.
        let mut copy = body.clone();
        assert_eq!(
            unseal(&key, 6, true, &sig, &mut copy),
            Err(Error::Sequence),
            "a signature must not move onto another message"
        );

        // And the body itself cannot be altered under a valid signature. Which refusal comes back
        // is not part of the contract: a damaged body fails whichever check reads it first, and
        // the point is that it does not pass.
        let mut copy = body.clone();
        copy[0] ^= 0x01;
        assert!(
            unseal(&key, 5, true, &sig, &mut copy).is_err(),
            "a body altered under a valid signature must be refused"
        );
    }

    /// A signature one octet short is refused before anything is read past its end.
    #[test]
    fn a_truncated_signature_is_refused() {
        let mut body = b"x".to_vec();
        let sig = seal(&key(), 1, true, &mut body);
        let mut copy = body.clone();
        assert_eq!(
            unseal(&key(), 1, true, &sig[..31], &mut copy),
            Err(Error::Truncated)
        );
    }

    /// A request Samba signed on a live join, and the channel key it signed with.
    ///
    /// This is the test that says the implementation is the protocol rather than merely consistent
    /// with itself. The round trip below would pass with the sequence blob read little-endian, with
    /// the HMAC keyed by all 32 octets, and with a plaintext confounder in the signature - all
    /// three were wrong, and each of them passes a self-consistent test. Only these octets, made by
    /// another implementation, tell them apart.
    ///
    /// Contents: opnum 21 (`netr_LogonGetCapabilities`), counter 0 from the initiator, twelve
    /// octets of authentication padding.
    const LIVE_PDU: &str = "05000003100000002801380009000000c400000000001500ba09310f57de40c2b715f2ebe00031e360fa62e6e8dfbc219e5c1a5ea85ac7f9f19afa0d98e001b061cfb9c13a6915bb3d7bde124faabe4f5c0645e7ebb888fde3952c7cea57ab499c06356fe382b454a95b1c0e80d95ab1df176f8d07b251dffa00eb041af91b83ce9e6dd4b63d4674d1556f91f76a9b4ad2cd36f76873b53d9454c2b78f744f1ca6ee1d9a2c082ce4f31f780c853ef8e24df73a51196a36f8564afdc5c6ab78814b4bc10a41713fce47b10961a2d75fc3493efaecdd2ce304f3c69d7be623f99fb3c76f917a3bbdc344060c000100000013001a00ffff00001f830473f4d604d8282f52c2ef6da1301daa27ca945343aa000000000000000000000000000000000000000000000000";
    const LIVE_KEY: &str = "d351cce0cd557a90bbaa07c5d2e2216136e1b83b1e20b669b586777fa25bcdeb";

    #[test]
    fn a_signature_a_live_client_made_verifies() {
        let key: [u8; 32] = hex::decode(LIVE_KEY)
            .expect("hex")
            .try_into()
            .expect("32 octets");
        let pdu = hex::decode(LIVE_PDU).expect("hex");
        assert_eq!(pdu.len(), 296, "one whole PDU");

        let frag = usize::from(u16::from_le_bytes([pdu[8], pdu[9]]));
        let auth_len = usize::from(u16::from_le_bytes([pdu[10], pdu[11]]));
        assert_eq!(frag, pdu.len());
        assert_eq!(auth_len, SIG_LEN_AES);

        let trailer_at = frag - auth_len - 8;
        assert_eq!(
            pdu[trailer_at], 68,
            "auth_type NETLOGON, the service this pipe uses"
        );
        let sig = &pdu[trailer_at + 8..];

        // The payload is the stub INCLUDING its authentication padding: the padding sits between
        // the stub and the sec_trailer, and the client's checksum covers it.
        let mut payload = pdu[24..trailer_at].to_vec();

        unseal(&key, 0, true, sig, &mut payload)
            .expect("a signature a live client made must verify");

        // What it opens to: a netr_LogonGetCapabilities stub, whose first field is the handle the
        // caller already holds and whose second is a small query level.
        assert_eq!(&payload[..4], &[0x17, 0x00, 0x00, 0x00], "query level 23");
        assert!(
            payload
                .windows(12)
                .any(|w| w == b"\\\x00s\x00a\x00m\x00b\x00a\x00"),
            "the stub names the server it is asking about"
        );
    }

    /// The sequence blob's byte order is the whole difference between a counter of zero and one of
    /// 549755813888, so it is asserted rather than described.
    #[test]
    fn the_sequence_blob_is_big_endian_with_the_initiator_bit() {
        assert_eq!(sequence_blob(0, true), [0, 0, 0, 0, 0x80, 0, 0, 0]);
        assert_eq!(sequence_blob(0, false), [0; 8]);
        assert_eq!(sequence_blob(1, false), [0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(
            sequence_blob(0x0000_0001_0000_0002, true),
            [0, 0, 0, 2, 0x80, 0, 0, 1],
            "low word first, then the high word with the bit"
        );
    }
}
