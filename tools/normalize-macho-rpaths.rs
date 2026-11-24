use std::convert::TryInto;
use std::env;
use std::fs;
use std::io;
use std::path::Path;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const LC_RPATH: u32 = 0x8000_001c;
const BUILD_PREFIX: &[u8] = b"/home/runner/work/darling/";
const REPLACEMENT: &[u8] = b"/usr/lib";

fn normalize_thin(data: &mut [u8], base: usize, limit: usize) -> io::Result<bool> {
    if base
        .checked_add(32)
        .is_none_or(|end| end > limit || end > data.len())
        || u32::from_le_bytes(data[base..base + 4].try_into().unwrap()) != MH_MAGIC_64
    {
        return Ok(false);
    }
    let command_count =
        u32::from_le_bytes(data[base + 16..base + 20].try_into().unwrap()) as usize;
    let command_bytes =
        u32::from_le_bytes(data[base + 20..base + 24].try_into().unwrap()) as usize;
    let commands_end = base
        .checked_add(32)
        .and_then(|start| start.checked_add(command_bytes))
        .filter(|end| *end <= data.len() && *end <= limit)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid load command region"))?;
    let mut cursor = base + 32;
    let mut changed = false;
    for _ in 0..command_count {
        if cursor.checked_add(8).is_none_or(|end| end > commands_end) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated load command",
            ));
        }
        let command = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
        let size = u32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        if size < 8 || cursor.checked_add(size).is_none_or(|end| end > commands_end) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid load command size",
            ));
        }
        if command == LC_RPATH && size >= 12 {
            let path_offset =
                u32::from_le_bytes(data[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
            let start = cursor
                .checked_add(path_offset)
                .filter(|start| *start >= cursor + 12 && *start < cursor + size)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid rpath offset"))?;
            let end = data[start..cursor + size]
                .iter()
                .position(|byte| *byte == 0)
                .map(|length| start + length)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unterminated rpath"))?;
            if data[start..end]
                .windows(BUILD_PREFIX.len())
                .any(|window| window == BUILD_PREFIX)
            {
                data[start..end].fill(0);
                data[start..start + REPLACEMENT.len()].copy_from_slice(REPLACEMENT);
                changed = true;
            }
        }
        cursor += size;
    }
    Ok(changed)
}

fn normalize(path: &Path) -> io::Result<bool> {
    let mut data = fs::read(path)?;
    let mut changed = false;
    let mut cursor = 0usize;
    while let Some(relative) = data[cursor..]
        .windows(BUILD_PREFIX.len())
        .position(|window| window == BUILD_PREFIX)
    {
        let start = cursor + relative;
        let Some(length) = data[start..].iter().position(|byte| *byte == 0) else {
            break;
        };
        if length >= REPLACEMENT.len() {
            data[start..start + length].fill(0);
            data[start..start + REPLACEMENT.len()].copy_from_slice(REPLACEMENT);
            changed = true;
        }
        cursor = start + length.max(1);
    }
    if changed {
        fs::write(path, data)?;
    }
    Ok(changed)
}

fn main() -> io::Result<()> {
    let mut changed = 0usize;
    for argument in env::args_os().skip(1) {
        if normalize(Path::new(&argument))? {
            changed += 1;
        }
    }
    println!("normalized-rpaths={changed}");
    Ok(())
}
