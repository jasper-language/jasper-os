//! Bounded SMBIOS entry-point and structure parsing.

use alloc::string::String;
use alloc::vec::Vec;

use crate::acpi::PhysRead;

const SMBIOS2_ENTRY_LEN: u8 = 0x1f;
const SMBIOS3_ENTRY_LEN: u8 = 0x18;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SmbiosInfo {
    pub major: u8,
    pub minor: u8,
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub bios_release_date: Option<String>,
    pub system_vendor: Option<String>,
    pub system_product: Option<String>,
    pub system_version: Option<String>,
    pub board_vendor: Option<String>,
    pub board_product: Option<String>,
    pub board_version: Option<String>,
}

#[derive(Clone, Copy)]
struct EntryPoint {
    major: u8,
    minor: u8,
    table: u64,
    table_len: usize,
}

fn read_u8(m: &dyn PhysRead, at: u64) -> Option<u8> {
    let mut value = [0u8; 1];
    m.read(at, &mut value).then_some(value[0])
}

fn read_u16(m: &dyn PhysRead, at: u64) -> Option<u16> {
    let mut value = [0u8; 2];
    m.read(at, &mut value).then_some(u16::from_le_bytes(value))
}

fn read_u32(m: &dyn PhysRead, at: u64) -> Option<u32> {
    let mut value = [0u8; 4];
    m.read(at, &mut value).then_some(u32::from_le_bytes(value))
}

fn read_u64(m: &dyn PhysRead, at: u64) -> Option<u64> {
    let mut value = [0u8; 8];
    m.read(at, &mut value).then_some(u64::from_le_bytes(value))
}

fn checksum_ok(m: &dyn PhysRead, at: u64, len: usize) -> bool {
    if len < 4 || len > 0x100 {
        return false;
    }
    let mut bytes = [0u8; 0x100];
    m.read(at, &mut bytes[..len])
        && bytes[..len]
            .iter()
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte))
            == 0
}

fn scan_range(m: &dyn PhysRead, start: u64, len: usize) -> Option<EntryPoint> {
    let mut best = None;
    let end = start.checked_add(len as u64)?;
    let mut at = start;
    while at.checked_add(0x20)? <= end {
        let mut signature = [0u8; 5];
        if m.read(at, &mut signature) {
            if &signature == b"_SM3_" {
                let entry_len = read_u8(m, at + 6)? as usize;
                if entry_len >= SMBIOS3_ENTRY_LEN as usize
                    && checksum_ok(m, at, entry_len)
                    && read_u8(m, at + 9).is_some_and(|major| major >= 3)
                {
                    let table = read_u64(m, at + 0x10)?;
                    let table_len = read_u32(m, at + 0x0c)? as usize;
                    if table != 0 && table_len >= 4 {
                        best = Some(EntryPoint {
                            major: read_u8(m, at + 9)?,
                            minor: read_u8(m, at + 10)?,
                            table,
                            table_len,
                        });
                    }
                }
            } else if signature[..4] == *b"_SM_" {
                let entry_len = read_u8(m, at + 5)? as usize;
                if entry_len >= SMBIOS2_ENTRY_LEN as usize && checksum_ok(m, at, entry_len) {
                    let major = read_u8(m, at + 6)?;
                    let minor = read_u8(m, at + 7)?;
                    let table = read_u32(m, at + 0x18)? as u64;
                    let count = read_u16(m, at + 0x1c)? as usize;
                    if table != 0 && count != 0 && best.is_none() {
                        best = Some(EntryPoint {
                            major,
                            minor,
                            table,
                            table_len: count.saturating_mul(4).max(4),
                        });
                    }
                }
            }
        }
        at += 0x10;
    }
    best
}

fn entry_point(m: &dyn PhysRead) -> Option<EntryPoint> {
    // Legacy BIOS normally publishes in the F000 segment. UEFI systems often
    // retain the same compatibility anchor; EBDA is checked as firmware can
    // relocate it there.
    let ebda = read_u16(m, 0x40e).map(|segment| u64::from(segment) << 4);
    let ebda_entry = ebda.and_then(|base| scan_range(m, base, 0x400));
    let high_entry = scan_range(m, 0xf_0000, 0x1_0000);
    high_entry.or(ebda_entry)
}

pub fn scan_legacy(m: &dyn PhysRead) -> Option<SmbiosInfo> {
    let entry = entry_point(m)?;
    let mut table = Vec::new();
    table.try_reserve_exact(entry.table_len).ok()?;
    table.resize(entry.table_len, 0);
    if !m.read(entry.table, &mut table) {
        return None;
    }
    let mut info = SmbiosInfo {
        major: entry.major,
        minor: entry.minor,
        ..SmbiosInfo::default()
    };
    let mut offset = 0usize;
    while offset.checked_add(4).is_some_and(|end| end <= table.len()) {
        let kind = table[offset];
        let length = table[offset + 1] as usize;
        if kind == 127 || length < 4 || offset.checked_add(length).is_none_or(|end| end > table.len())
        {
            break;
        }
        let strings = offset + length;
        match kind {
            0 if length > 6 => {
                info.bios_vendor = indexed_string(&table, strings, table[offset + 4]);
                info.bios_version = indexed_string(&table, strings, table[offset + 5]);
                info.bios_release_date = indexed_string(&table, strings, table[offset + 6]);
            }
            1 if length > 4 => {
                info.system_vendor = indexed_string(&table, strings, table[offset + 4]);
                info.system_product = indexed_string(&table, strings, table[offset + 5]);
                info.system_version = indexed_string(&table, strings, table[offset + 6]);
            }
            2 if length > 4 => {
                info.board_vendor = indexed_string(&table, strings, table[offset + 4]);
                info.board_product = indexed_string(&table, strings, table[offset + 5]);
                info.board_version = indexed_string(&table, strings, table[offset + 6]);
            }
            _ => {}
        }
        offset = match next_structure(&table, strings) {
            Some(next) => next,
            None => break,
        };
    }
    Some(info)
}

fn next_structure(table: &[u8], mut at: usize) -> Option<usize> {
    while at < table.len() {
        if table[at] == 0 {
            if table.get(at + 1) == Some(&0) {
                return Some(at + 2);
            }
        }
        at += 1;
    }
    None
}

fn indexed_string(table: &[u8], mut at: usize, index: u8) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut current = 1u8;
    while at < table.len() {
        let start = at;
        while at < table.len() && table[at] != 0 {
            at += 1;
        }
        if current == index {
            if start == at {
                return None;
            }
            return Some(String::from_utf8_lossy(&table[start..at]).into_owned());
        }
        if at >= table.len() {
            return None;
        }
        at += 1;
        if at < table.len() && table[at] == 0 {
            return None;
        }
        current = current.saturating_add(1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem(Vec<u8>);

    impl PhysRead for Mem {
        fn read(&self, phys: u64, buf: &mut [u8]) -> bool {
            let Some(start) = usize::try_from(phys).ok() else {
                return false;
            };
            let Some(source) = self.0.get(start..start.saturating_add(buf.len())) else {
                return false;
            };
            buf.copy_from_slice(source);
            true
        }
    }

    fn structure(kind: u8, fields: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut out = vec![kind, (4 + fields.len()) as u8, 0, 0];
        out.extend_from_slice(fields);
        for string in strings {
            out.extend_from_slice(string.as_bytes());
            out.push(0);
        }
        out.push(0);
        out
    }

    fn fixture(valid_checksum: bool) -> Mem {
        let mut mem = vec![0u8; 0x10_0000];
        let bios = structure(0, &[1, 2, 3, 0, 0], &["Coreboot", "R1", "2026-01-01"]);
        let system = structure(1, &[1, 2, 3, 0], &["Jasper Labs", "Workstation", "v1"]);
        let board = structure(2, &[1, 2, 3, 0], &["ASUS", "ROG BOARD", "rev"]);
        let mut table = bios;
        table.extend_from_slice(&system);
        table.extend_from_slice(&board);
        table.push(127);
        table.extend_from_slice(&[4, 0, 0, 0, 0]);
        mem[0x20_000..0x20_000 + table.len()].copy_from_slice(&table);

        let at = 0xf_0000;
        mem[at..at + 5].copy_from_slice(b"_SM3_");
        mem[at + 6] = SMBIOS3_ENTRY_LEN;
        mem[at + 7] = 0;
        mem[at + 9] = 3;
        mem[at + 10] = 5;
        mem[at + 0x0c..at + 0x10].copy_from_slice(&(table.len() as u32).to_le_bytes());
        mem[at + 0x10..at + 0x18].copy_from_slice(&0x20_000u64.to_le_bytes());
        let sum = mem[at..at + SMBIOS3_ENTRY_LEN as usize]
            .iter()
            .fold(0u8, |value, byte| value.wrapping_add(*byte));
        mem[at + 7] = if valid_checksum { 0u8.wrapping_sub(sum) } else { sum };
        Mem(mem)
    }

    #[test]
    fn smbios3_bios_board_and_system_strings_are_parsed() {
        let info = scan_legacy(&fixture(true)).unwrap();
        assert_eq!((info.major, info.minor), (3, 5));
        assert_eq!(info.bios_vendor.as_deref(), Some("Coreboot"));
        assert_eq!(info.bios_version.as_deref(), Some("R1"));
        assert_eq!(info.system_vendor.as_deref(), Some("Jasper Labs"));
        assert_eq!(info.system_product.as_deref(), Some("Workstation"));
        assert_eq!(info.board_vendor.as_deref(), Some("ASUS"));
        assert_eq!(info.board_product.as_deref(), Some("ROG BOARD"));
    }

    #[test]
    fn bad_entry_checksum_is_rejected() {
        assert!(scan_legacy(&fixture(false)).is_none());
    }
}
