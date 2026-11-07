//! Versioned required-capability note for user programs (ABI 1.1).
//! 用户程序版本化所需能力章（ABI 1.1）。

use crate::profile::{is_capability, MAX_CAPABILITIES};

/// ELF section carrying required capability names.
pub const CAPS_SECTION: &str = ".note.jasper.caps";
/// ELF note type for program required capabilities.
pub const CAPS_NOTE_TYPE: u32 = 2;
/// Note owner name, shared with the ABI stamp.
pub const CAPS_NAME: [u8; 8] = *b"JASPER\0\0";
/// Maximum encoded note size: 20-byte note header/name + 8-byte descriptor
/// header + 24 names of at most 65 bytes each.
pub const CAPS_NOTE_MAX_BYTES: usize = 20 + 8 + MAX_CAPABILITIES * 65;

/// Parsed required capabilities borrowing the ELF image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredCapabilities<'a> {
    entries: [Option<&'a str>; MAX_CAPABILITIES],
    count: usize,
}

impl<'a> RequiredCapabilities<'a> {
    /// Legacy ABI 1.0 program with no capability note.
    pub const fn empty() -> Self {
        Self { entries: [None; MAX_CAPABILITIES], count: 0 }
    }

    /// Iterate in serialized order.
    pub fn iter(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.entries[..self.count].iter().flatten().copied()
    }

    /// Number of required capabilities.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// First required capability rejected by the supplied availability predicate.
    pub fn first_unavailable(
        &self,
        mut available: impl FnMut(&str) -> bool,
    ) -> Option<&'a str> {
        self.iter().find(|capability| !available(capability))
    }
}

/// Stable malformed-note reasons. All map to the metadata error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsError {
    Truncated,
    BadHeader,
    BadName,
    BadFlags,
    BadCount,
    BadNameEntry,
    Duplicate,
    TrailingBytes,
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, CapsError> {
    let s = bytes.get(offset..offset + 2).ok_or(CapsError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, CapsError> {
    let s = bytes.get(offset..offset + 4).ok_or(CapsError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse one capability note. Variable-length names are NUL terminated and
/// encoded exactly once in order; duplicates and trailing data are rejected.
pub fn parse_caps_note<'a>(note: &'a [u8]) -> Result<RequiredCapabilities<'a>, CapsError> {
    if note.len() < 20 {
        return Err(CapsError::Truncated);
    }
    let namesz = u32_at(note, 0)?;
    let descsz = u32_at(note, 4)? as usize;
    let ty = u32_at(note, 8)?;
    if namesz != CAPS_NAME.len() as u32 || ty != CAPS_NOTE_TYPE || 20usize.checked_add(descsz) != Some(note.len()) {
        return Err(CapsError::BadHeader);
    }
    if note[12..20] != CAPS_NAME {
        return Err(CapsError::BadName);
    }
    if u16_at(note, 20)? != 1 || u16_at(note, 22)? != 0 {
        return Err(CapsError::BadFlags);
    }
    let count = u16_at(note, 24)? as usize;
    if count == 0 || count > MAX_CAPABILITIES || u16_at(note, 26)? != 0 {
        return Err(CapsError::BadCount);
    }
    let mut entries = [None; MAX_CAPABILITIES];
    let mut at = 28usize;
    for index in 0..count {
        let rest = note.get(at..).ok_or(CapsError::Truncated)?;
        let end = rest.iter().position(|&b| b == 0).ok_or(CapsError::BadNameEntry)?;
        if end == 0 || end > 64 {
            return Err(CapsError::BadNameEntry);
        }
        let name = core::str::from_utf8(&rest[..end]).map_err(|_| CapsError::BadNameEntry)?;
        if !is_capability(name) || entries[..index].iter().flatten().any(|old| *old == name) {
            return Err(if entries[..index].iter().flatten().any(|old| *old == name) {
                CapsError::Duplicate
            } else {
                CapsError::BadNameEntry
            });
        }
        entries[index] = Some(name);
        at = at.checked_add(end + 1).ok_or(CapsError::Truncated)?;
    }
    if at != note.len() {
        return Err(CapsError::TrailingBytes);
    }
    Ok(RequiredCapabilities { entries, count })
}

/// Encode a capability note into caller storage. Used by tests and ELF fixtures.
pub fn encode_caps_note<'a>(names: &[&str], out: &'a mut [u8]) -> Result<&'a [u8], CapsError> {
    if names.is_empty() || names.len() > MAX_CAPABILITIES {
        return Err(CapsError::BadCount);
    }
    let mut body_len = 0usize;
    for (index, name) in names.iter().enumerate() {
        if !is_capability(name) || names[..index].contains(name) {
            return Err(CapsError::BadNameEntry);
        }
        body_len = body_len.checked_add(name.len() + 1).ok_or(CapsError::Truncated)?;
    }
    let len = 28usize.checked_add(body_len).ok_or(CapsError::Truncated)?;
    if out.len() < len {
        return Err(CapsError::Truncated);
    }
    out[..len].fill(0);
    out[0..4].copy_from_slice(&(CAPS_NAME.len() as u32).to_le_bytes());
    out[4..8].copy_from_slice(&((8 + body_len) as u32).to_le_bytes());
    out[8..12].copy_from_slice(&CAPS_NOTE_TYPE.to_le_bytes());
    out[12..20].copy_from_slice(&CAPS_NAME);
    out[20..22].copy_from_slice(&1u16.to_le_bytes());
    out[24..26].copy_from_slice(&(names.len() as u16).to_le_bytes());
    let mut at = 28;
    for name in names {
        out[at..at + name.len()].copy_from_slice(name.as_bytes());
        at += name.len() + 1;
    }
    Ok(&out[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_reject_malformed_entries() {
        let mut storage = [0u8; CAPS_NOTE_MAX_BYTES];
        let note = encode_caps_note(&["kernel.core", "memory.virtual"], &mut storage).unwrap();
        let note_len = note.len();
        let parsed = parse_caps_note(note).unwrap();
        let mut names = parsed.iter();
        assert_eq!(names.next(), Some("kernel.core"));
        assert_eq!(names.next(), Some("memory.virtual"));
        assert_eq!(names.next(), None);
        drop(names);

        let mut duplicate = [0u8; CAPS_NOTE_MAX_BYTES];
        assert_eq!(
            encode_caps_note(&["kernel.core", "kernel.core"], &mut duplicate),
            Err(CapsError::BadNameEntry)
        );
        let mut bad = storage;
        bad[28] = b'X';
        assert_eq!(parse_caps_note(&bad[..note_len]), Err(CapsError::BadNameEntry));
        let mut trailing = storage;
        trailing[note_len] = 1;
        assert_eq!(parse_caps_note(&trailing[..=note_len]), Err(CapsError::BadHeader));
    }

    #[test]
    fn fixed_seed_mutations_never_panic() {
        let mut seed = 0x4341_5053_4e4f_5445u64;
        let mut bytes = [0u8; 256];
        for _ in 0..20_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed as usize) % (bytes.len() + 1);
            for b in &mut bytes[..len] {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            let _ = parse_caps_note(&bytes[..len]);
        }
    }

    #[test]
    fn full_and_minimal_profiles_expose_different_capability_sets() {
        let full = crate::profile::resolve(&crate::profile::HEADLESS).unwrap();
        let minimal = crate::profile::resolve(&crate::profile::HEADLESS_MIN).unwrap();
        let mut storage = [0u8; CAPS_NOTE_MAX_BYTES];
        let note = encode_caps_note(&["ipc.channel"], &mut storage).unwrap();
        let required = parse_caps_note(note).unwrap();
        assert_eq!(required.first_unavailable(|cap| full.has_capability(cap)), None);
        assert_eq!(required.first_unavailable(|cap| minimal.has_capability(cap)), Some("ipc.channel"));
    }
}
