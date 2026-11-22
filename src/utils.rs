//! Small helpers shared across modules.

use std::time::{SystemTime, UNIX_EPOCH};

/// Number of 100-nanosecond intervals between 1601-01-01 (Windows FILETIME
/// epoch) and 1970-01-01 (UNIX epoch). 369 years.
pub(crate) const FILETIME_OFFSET: u64 = 116_444_736_000_000_000;

/// Convert a `SystemTime` to a Windows FILETIME (100ns ticks since 1601),
/// rounded down to a tick. Times before 1601 become 0, and times past the
/// last FILETIME the last one.
pub fn system_time_to_filetime(t: SystemTime) -> u64 {
    let ticks = match t.duration_since(UNIX_EPOCH) {
        Ok(after) => i128::from(FILETIME_OFFSET) + (after.as_nanos() / 100) as i128,
        Err(e) => i128::from(FILETIME_OFFSET) - e.duration().as_nanos().div_ceil(100) as i128,
    };
    ticks.clamp(0, i128::from(u64::MAX)) as u64
}

/// Convert "now" to FILETIME.
pub fn now_filetime() -> u64 {
    system_time_to_filetime(SystemTime::now())
}

/// Encode a `&str` to little-endian UTF-16 bytes.
pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// Decode a UTF-16LE byte slice into a `Vec<u16>`, returning `None` on a
/// non-aligned buffer.
pub fn utf16le_to_units(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    Some(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect(),
    )
}

/// Fill `out` from the OS RNG.
pub fn fill_random(out: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(out)
}

/// The name a table gives `key`, or `"unknown"` when it has none.
///
/// A `match` over a protocol's numbering is a table written as control flow: twenty-five arms are
/// twenty-five branches to count, and the cyclomatic number they produce says nothing about how hard
/// the function is — it says how many constants the protocol happens to have. A slice with the same
/// numbers can be read, diffed and checked against the specification's own list.
///
/// The lookup is linear, which is right for tables of this size: a binary search over twenty entries
/// costs more branch prediction than the scan saves.
pub(crate) fn name_in(table: NameTable, key: u32) -> &'static str {
    match table.iter().find(|(n, _)| *n == key) {
        Some((_, name)) => name,
        None => "unknown",
    }
}

/// A table of numbers and the names a specification gives them.
///
/// The `'static` is written once, here, rather than at every table: a name in a table is a string
/// literal, and spelling the lifetime at each of them is the noise `redundant_static_lifetimes`
/// exists to point at.
pub(crate) type NameTable = &'static [(u32, &'static str)];

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn times_before_1970_and_1601_convert() {
        let ft = system_time_to_filetime;
        assert_eq!(ft(UNIX_EPOCH), FILETIME_OFFSET);
        assert_eq!(
            ft(UNIX_EPOCH - Duration::from_secs(2_082_844_800)),
            95_616_288_000_000_000,
            "1904-01-01"
        );
        assert_eq!(
            ft(UNIX_EPOCH + Duration::from_nanos(150)),
            FILETIME_OFFSET + 1
        );
        // Windows clocks count whole ticks from 1601.
        if cfg!(unix) {
            assert_eq!(
                ft(UNIX_EPOCH - Duration::from_nanos(50)),
                FILETIME_OFFSET - 1
            );
            assert_eq!(
                ft(UNIX_EPOCH - Duration::from_secs(11_644_473_600 + 1)),
                0,
                "before 1601"
            );
        }
    }
}
