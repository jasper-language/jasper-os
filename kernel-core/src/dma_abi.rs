//! Versioned DMA mapping descriptor and admission rules.
//!
//! The descriptor names a Memory object and a Device handle. It never accepts a
//! host physical address. On success the kernel fills `iova`; the returned DMA
//! handle owns the mapping until it is closed.

use crate::memory_object::PAGE_BYTES;
use crate::object::Rights;

pub const VERSION: u32 = 1;
pub const ARGS_BYTES: usize = 56;
pub const WRITE: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Rights,
    Range,
}

/// Wire layout:
/// version:u32, bytes:u32, device_handle:u64, offset_pages:u64, pages:u64,
/// flags:u32, reserved:u32, iova:u64, reserved_tail:u64.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapArgs {
    pub version: u32,
    pub bytes: u32,
    pub device: u64,
    pub offset_pages: u64,
    pub pages: u64,
    pub flags: u32,
    pub reserved: u32,
    /// Input must be zero; output is the device-visible IOVA.
    pub iova: u64,
    pub reserved_tail: u64,
}

const _: [(); ARGS_BYTES] = [(); core::mem::size_of::<MapArgs>()];

impl MapArgs {
    pub fn new(device: u64, offset_pages: u64, pages: u64, writable: bool) -> Self {
        Self {
            version: VERSION,
            bytes: ARGS_BYTES as u32,
            device,
            offset_pages,
            pages,
            flags: if writable { WRITE } else { 0 },
            reserved: 0,
            iova: 0,
            reserved_tail: 0,
        }
    }

    pub fn encode(self) -> [u8; ARGS_BYTES] {
        let mut out = [0u8; ARGS_BYTES];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..8].copy_from_slice(&self.bytes.to_le_bytes());
        out[8..16].copy_from_slice(&self.device.to_le_bytes());
        out[16..24].copy_from_slice(&self.offset_pages.to_le_bytes());
        out[24..32].copy_from_slice(&self.pages.to_le_bytes());
        out[32..36].copy_from_slice(&self.flags.to_le_bytes());
        out[36..40].copy_from_slice(&self.reserved.to_le_bytes());
        out[40..48].copy_from_slice(&self.iova.to_le_bytes());
        out[48..56].copy_from_slice(&self.reserved_tail.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; ARGS_BYTES]) -> Option<Self> {
        let args = Self {
            version: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            bytes: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            device: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            offset_pages: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
            pages: u64::from_le_bytes(bytes[24..32].try_into().ok()?),
            flags: u32::from_le_bytes(bytes[32..36].try_into().ok()?),
            reserved: u32::from_le_bytes(bytes[36..40].try_into().ok()?),
            iova: u64::from_le_bytes(bytes[40..48].try_into().ok()?),
            reserved_tail: u64::from_le_bytes(bytes[48..56].try_into().ok()?),
        };
        (args.version == VERSION
            && args.bytes == ARGS_BYTES as u32
            && args.flags & !WRITE == 0
            && args.reserved == 0
            && args.iova == 0
            && args.reserved_tail == 0)
            .then_some(args)
    }

    pub fn writable(self) -> bool {
        self.flags & WRITE != 0
    }

    pub fn validate(self, have: Rights) -> Result<Range, Error> {
        let need = Rights::READ
            .union(Rights::MAP)
            .union(if self.writable() {
                Rights::WRITE
            } else {
                Rights::NONE
            });
        if !have.contains(need) {
            return Err(Error::Rights);
        }
        if self.device == 0
            || self.pages == 0
            || self.offset_pages.checked_add(self.pages).is_none()
        {
            return Err(Error::Invalid);
        }
        let bytes = self.pages.checked_mul(PAGE_BYTES).ok_or(Error::Range)?;
        Ok(Range {
            offset_pages: self.offset_pages,
            pages: self.pages,
            bytes,
            writable: self.writable(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub offset_pages: u64,
    pub pages: u64,
    pub bytes: u64,
    pub writable: bool,
}

impl Range {
    pub fn within(self, object_pages: u64) -> bool {
        self.offset_pages
            .checked_add(self.pages)
            .is_some_and(|end| end <= object_pages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_roundtrip_and_output_slot_must_start_zero() {
        let args = MapArgs::new(0x1234, 2, 3, true);
        assert_eq!(MapArgs::decode(&args.encode()), Some(args));
        let mut bytes = args.encode();
        bytes[40] = 1;
        assert_eq!(MapArgs::decode(&bytes), None);
    }

    #[test]
    fn decode_rejects_unknown_version_flags_and_reserved_words() {
        let args = MapArgs::new(1, 0, 1, false);
        let mut version = args.encode();
        version[0] = 2;
        assert_eq!(MapArgs::decode(&version), None);
        let mut flags = args.encode();
        flags[32] = 2;
        assert_eq!(MapArgs::decode(&flags), None);
        let mut reserved = args.encode();
        reserved[36] = 1;
        assert_eq!(MapArgs::decode(&reserved), None);
    }

    #[test]
    fn admission_checks_rights_bounds_and_overflow_atomically() {
        let read = MapArgs::new(1, 0, 1, false);
        assert!(read.validate(Rights::READ.union(Rights::MAP)).is_ok());
        assert_eq!(read.validate(Rights::READ), Err(Error::Rights));
        assert_eq!(
            MapArgs::new(1, 0, 1, true).validate(Rights::READ.union(Rights::MAP)),
            Err(Error::Rights)
        );
        assert_eq!(
            MapArgs::new(1, u64::MAX, 2, false).validate(Rights::READ.union(Rights::MAP)),
            Err(Error::Invalid)
        );
        assert!(
            MapArgs::new(1, 0, 65, false)
                .validate(Rights::READ.union(Rights::MAP))
                .is_ok()
        );
        let range = read.validate(Rights::READ.union(Rights::MAP)).unwrap();
        assert!(range.within(1));
        assert!(!range.within(0));
    }
}
