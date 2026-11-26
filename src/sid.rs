//! Security identifiers, as a directory stores them and a client is named by.
//!
//! A share ACL in AD is not a list of names: it is a discretionary ACL of access-control entries,
//! and every entry names a SID. `Authenticated Users` is `S-1-5-11`, `Everyone` is `S-1-1-0`, and a
//! domain group is `S-1-5-21-<domain>-<rid>`. Without a SID a server can say *who* logged on
//! (a name) and not *what it is a member of* - which is the only thing a policy like "every
//! authenticated user may read" needs to answer.
//!
//! # Two spellings, one value
//!
//! A directory carries the value as octets in `objectSid` (MS-DTYP 2.4.2.1), and every tool that
//! displays it - `whoami /groups`, `GPMC`, an audit log - uses `S-1-5-21-...`. Both are here, and
//! they round-trip: an access check compares values, not spellings, but a log an operator reads has
//! to be the second one.
//!
//! # Why the octets are kept, not the text
//!
//! Parsing `S-1-5-21-...` and reformatting it back is a place to lose a digit; comparisons happen
//! on the bytes AD itself stores. The text is produced on demand for messages and Debug.

use std::fmt;

/// A security identifier: revision, authority, and its sub-authorities.
///
/// Held as the octets `objectSid` carries, so that a value from a directory and a value from a token
/// compare without a conversion in between.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sid(Vec<u8>);

/// `S-1-1-0`: every principal, including an anonymous one. Share permission on `SYSVOL` names it.
pub const EVERYONE: &str = "S-1-1-0";

/// `S-1-5-11`: every principal that logged on. The right a file ACL on `SYSVOL` grants.
pub const AUTHENTICATED_USERS: &str = "S-1-5-11";

impl Sid {
    /// A SID from the octets of an `objectSid`, or `None` when they are not one.
    ///
    /// The layout is MS-DTYP 2.4.2.1: a revision, a count of sub-authorities, a six-octet authority
    /// and that many four-octet sub-authorities. A truncated value, or a count that does not match
    /// the length, is not a SID - and a SID that is not one must not compare equal to anything.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let count = bytes[1] as usize;
        if bytes.len() != 8 + count * 4 {
            return None;
        }
        Some(Self(bytes.to_vec()))
    }

    /// A SID from the `S-1-5-21-...` spelling every tool displays.
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.trim().split('-');
        if !parts.next()?.eq_ignore_ascii_case("S") {
            return None;
        }
        let revision: u8 = parts.next()?.parse().ok()?;
        let authority: u64 = parts.next()?.parse().ok()?;
        // Six octets: an authority wider than 48 bits cannot be written, and silently truncating it
        // would produce a SID that names a different principal.
        if authority >> 48 != 0 {
            return None;
        }

        let mut bytes = Vec::with_capacity(8);
        bytes.push(revision);
        // The count is filled in below, once the sub-authorities are known.
        bytes.push(0);
        bytes.extend_from_slice(&authority.to_be_bytes()[2..]);

        let mut count: u8 = 0;
        for part in parts {
            let value: u32 = part.parse().ok()?;
            bytes.extend_from_slice(&value.to_le_bytes());
            count = count.checked_add(1)?;
        }
        bytes[1] = count;
        Self::from_bytes(&bytes)
    }

    /// The octets, as `objectSid` carries them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether this is the SID `text` names.
    pub fn is(&self, text: &str) -> bool {
        Sid::parse(text).is_some_and(|other| other == *self)
    }

    /// `S-1-5-11`: the right a file ACL grants to anybody who logged on.
    pub fn is_authenticated_users(&self) -> bool {
        self.is(AUTHENTICATED_USERS)
    }

    /// `S-1-1-0`: every principal, anonymous included.
    pub fn is_everyone(&self) -> bool {
        self.is(EVERYONE)
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("S")?;
        write!(formatter, "-{}", self.0[0])?;
        let mut authority: u64 = 0;
        for octet in &self.0[2..8] {
            authority = (authority << 8) | u64::from(*octet);
        }
        write!(formatter, "-{authority}")?;
        for chunk in self.0[8..].as_chunks::<4>().0 {
            write!(formatter, "-{}", u32::from_le_bytes(*chunk))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    /// The readable spelling, because a SID in a log that says `[1, 1, 0, 0, ...]` is a SID an
    /// operator has to decode by hand.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Sid({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_spellings_round_trip() {
        for text in [
            "S-1-1-0",
            "S-1-5-11",
            "S-1-5-18",
            "S-1-5-21-1004336348-1177238915-682003330-512",
            "S-1-5-32-544",
        ] {
            let sid = Sid::parse(text).unwrap_or_else(|| panic!("{text} parses"));
            assert_eq!(sid.to_string(), text, "the spelling survives a round trip");
            let from_bytes = Sid::from_bytes(sid.as_bytes()).expect("its own octets are a SID");
            assert_eq!(from_bytes, sid, "and the octets are one value, not two");
        }
    }

    /// The octets AD stores, byte for byte: a comparison that is off by one here is an access check
    /// that answers for the wrong principal.
    #[test]
    fn the_octets_are_the_ones_a_directory_stores() {
        // `S-1-5-32-544` is BUILTIN\Administrators, the group every controller has.
        assert_eq!(
            Sid::parse("S-1-5-32-544").expect("a SID").as_bytes(),
            &[
                0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02,
                0x00, 0x00
            ],
            "revision 1, two sub-authorities, authority 5, then 32 and 544 little-endian"
        );
        // `S-1-1-0` is Everyone: authority 1 and one sub-authority, zero - which is the SID a share
        // permission names on SYSVOL. Twelve octets, not eight: a SID with no sub-authorities is a
        // different value, and the count byte is what says which of the two this is.
        assert_eq!(
            Sid::parse(EVERYONE).expect("a SID").as_bytes(),
            &[
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn the_well_known_ones_are_recognised_by_value() {
        assert!(
            Sid::parse("S-1-5-11")
                .expect("a SID")
                .is_authenticated_users()
        );
        assert!(Sid::parse("S-1-1-0").expect("a SID").is_everyone());
        assert!(!Sid::parse("S-1-5-11").expect("a SID").is_everyone());
        // Written by another tool in another case, and the same principal.
        assert!(
            Sid::parse("s-1-5-11")
                .expect("a SID")
                .is_authenticated_users()
        );
    }

    /// A malformed value names nobody, and must not compare equal to a principal that does exist.
    #[test]
    fn what_is_not_a_sid_is_not_one() {
        assert!(Sid::parse("").is_none());
        assert!(Sid::parse("S-1").is_none(), "no authority");
        assert!(Sid::parse("X-1-5-11").is_none(), "not the S prefix");
        assert!(
            Sid::parse("S-x-5-11").is_none(),
            "a revision that is not a number"
        );
        assert!(
            Sid::parse("S-1-281474976710656-1").is_none(),
            "an authority wider than six octets"
        );
        // A count that disagrees with the length: the shape every truncated buffer has.
        assert!(Sid::from_bytes(&[1, 2, 0, 0, 0, 0, 0, 5]).is_none());
        assert!(Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 32]).is_none());
        assert!(
            Sid::from_bytes(&[1, 0, 0, 0]).is_none(),
            "shorter than a header"
        );
    }
}
