//! SHM-1 versioned object-mapping descriptor. Author: chatgpt.
//! Explicit little endian layout; no pointers or reused anonymous-memory reserved fields.
pub const MAP_ARGS_BYTES: usize = 40;
pub const VERSION: u32 = 1;
pub const WRITE: u32 = 1;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapArgs {
    pub version: u32,
    pub bytes: u32,
    pub address: u64,
    pub offset_pages: u64,
    pub pages: u64,
    /// 0 = read-only; WRITE = readable/writable. Executable mappings are not supported.
    pub flags: u32,
    pub reserved: u32,
}
const _: [(); MAP_ARGS_BYTES] = [(); core::mem::size_of::<MapArgs>()];
impl MapArgs {
    pub fn new(address:u64, offset_pages:u64, pages:u64, writable:bool) -> Self {
        Self { version:VERSION,bytes:MAP_ARGS_BYTES as u32,address,offset_pages,pages,
            flags:if writable { WRITE } else { 0 },reserved:0 }
    }
    pub fn encode(self) -> [u8; MAP_ARGS_BYTES] {
        let mut b=[0u8;MAP_ARGS_BYTES];
        b[0..4].copy_from_slice(&self.version.to_le_bytes()); b[4..8].copy_from_slice(&self.bytes.to_le_bytes());
        b[8..16].copy_from_slice(&self.address.to_le_bytes()); b[16..24].copy_from_slice(&self.offset_pages.to_le_bytes());
        b[24..32].copy_from_slice(&self.pages.to_le_bytes()); b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.reserved.to_le_bytes()); b
    }
    pub fn decode(b:&[u8;MAP_ARGS_BYTES]) -> Option<Self> {
        let m=Self { version:u32::from_le_bytes(b[0..4].try_into().ok()?), bytes:u32::from_le_bytes(b[4..8].try_into().ok()?),
            address:u64::from_le_bytes(b[8..16].try_into().ok()?), offset_pages:u64::from_le_bytes(b[16..24].try_into().ok()?),
            pages:u64::from_le_bytes(b[24..32].try_into().ok()?), flags:u32::from_le_bytes(b[32..36].try_into().ok()?),
            reserved:u32::from_le_bytes(b[36..40].try_into().ok()?) };
        (m.version==VERSION && m.bytes==MAP_ARGS_BYTES as u32 && m.flags & !WRITE == 0 && m.reserved==0).then_some(m)
    }
}
