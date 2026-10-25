//! ABI-R reserved extension shapes. No operation is enabled by these definitions.
//! Author: chatgpt. Existing version-first descriptors remain unchanged.
pub const VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 8;
pub const SEGMENT_BYTES: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header { pub version: u32, pub bytes: u32 }
impl Header {
    pub fn decode(input: &[u8], expected_bytes: u32) -> Option<Self> {
        let h = Self { version: u32::from_le_bytes(input.get(0..4)?.try_into().ok()?),
            bytes: u32::from_le_bytes(input.get(4..8)?.try_into().ok()?) };
        (h.version == VERSION && h.bytes == expected_bytes && expected_bytes >= HEADER_BYTES as u32
            && input.len() == expected_bytes as usize).then_some(h)
    }
}
/// Discriminant avoids interpreting an object handle as an address. No physical-address variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source { Memory(u64), UserPointer(u64) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment { pub source: Source, pub offset: u64, pub length: u64 }
impl Segment {
    /// Wire: kind:u32 (0 Memory/1 virtual pointer), flags:u32=0, source:u64, offset:u64, length:u64.
    /// Shape only; object authority, pinning, user window and operation limits require admission.
    pub fn decode(input: &[u8; SEGMENT_BYTES]) -> Option<Self> {
        let kind = u32::from_le_bytes(input[0..4].try_into().ok()?);
        if input[4..8] != [0;4] { return None; }
        let raw = u64::from_le_bytes(input[8..16].try_into().ok()?);
        let offset = u64::from_le_bytes(input[16..24].try_into().ok()?);
        let length = u64::from_le_bytes(input[24..32].try_into().ok()?);
        offset.checked_add(length)?;
        let source = match kind { 0 => Source::Memory(raw), 1 => { raw.checked_add(offset)?.checked_add(length)?; Source::UserPointer(raw) }, _ => return None };
        Some(Self { source, offset, length })
    }
}

/// Reserved SQE bit. Submission remains unsupported until registered-buffer lifetimes are implemented.
pub const SQE_REGISTERED_BUFFER: u32 = 1 << 31;
pub const SERVICE_HEADER_BYTES: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceHeader { pub protocol: u32, pub version: u16, pub bytes: u16 }
impl ServiceHeader {
    pub fn decode(b: &[u8; SERVICE_HEADER_BYTES]) -> Option<Self> {
        let h = Self { protocol:u32::from_le_bytes(b[..4].try_into().ok()?),
            version:u16::from_le_bytes(b[4..6].try_into().ok()?), bytes:u16::from_le_bytes(b[6..8].try_into().ok()?) };
        (h.protocol != 0 && h.version != 0 && h.bytes as usize >= SERVICE_HEADER_BYTES).then_some(h)
    }
}
/// Reserved v2 capability set: version=2, bytes=40, four u64 words, bit index is operation ID.
/// This wire shape does not authorize any live thread or alter v1's 64-bit entry.
pub const SYSCALL_SET_V2_BYTES: usize = 40;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallSetV2 { pub words: [u64;4] }
impl SyscallSetV2 {
    pub fn decode(b: &[u8;SYSCALL_SET_V2_BYTES]) -> Option<Self> {
        if u32::from_le_bytes(b[..4].try_into().ok()?) != 2 || u32::from_le_bytes(b[4..8].try_into().ok()?) != 40 { return None; }
        let mut words=[0;4];
        for (i, word) in words.iter_mut().enumerate() { *word=u64::from_le_bytes(b[8+i*8..16+i*8].try_into().ok()?); }
        // Operation zero is not registered and cannot be granted.
        (words[0] & 1 == 0).then_some(Self { words })
    }
    pub fn contains(self, id: u64) -> bool { id < 256 && self.words[id as usize /64] & (1u64 << (id%64)) != 0 }
}

/// Request-duration memory borrow. It names an object, never a physical frame.
/// Admission must retain/pin pages before publication; release only at a unique terminal
/// completion/cancel/close state, not when cancellation is merely requested.
pub const BORROW_BYTES: usize = 48;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BorrowDesc { pub memory: u64, pub offset: u64, pub length: u64, pub request: u64 }
impl BorrowDesc {
    pub fn decode(b: &[u8;BORROW_BYTES]) -> Option<Self> {
        Header::decode(b,BORROW_BYTES as u32)?;
        let word=|at:usize| u64::from_le_bytes(b[at..at+8].try_into().unwrap());
        let v=Self { memory:word(8),offset:word(16),length:word(24),request:word(32) };
        if word(40)!=0 || v.request==0 || v.length==0 { return None; }
        v.offset.checked_add(v.length)?; Some(v)
    }
}
/// Reserved authority-bearing control envelope for restricted execution and asynchronous
/// thread interrupt delivery. Subject is a handle, payload operation-specific; flags zero.
/// arg0 points at this descriptor. Unsupported entries do not inspect its contents.
pub const CONTROL_BYTES: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlDesc { pub subject: u64, pub payload: u64 }
impl ControlDesc {
    pub fn decode(b: &[u8;CONTROL_BYTES]) -> Option<Self> {
        Header::decode(b,CONTROL_BYTES as u32)?;
        let word=|at:usize| u64::from_le_bytes(b[at..at+8].try_into().unwrap());
        (word(24)==0).then_some(Self { subject:word(8),payload:word(16) })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagError { Invalid, Unsupported }
pub fn check_sqe_flags(flags: u32) -> Result<(), FlagError> {
    if flags & !SQE_REGISTERED_BUFFER != 0 { Err(FlagError::Invalid) }
    else if flags != 0 { Err(FlagError::Unsupported) }
    else { Ok(()) }
}
