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
