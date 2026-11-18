//! Versioned UI service frames carried by the existing native Channel/Ring.
//!
//! The payload is opaque to the kernel. Handle/Rights and MemoryObject transfer
//! remain out-of-band operations of the existing object and IPC mechanisms; raw
//! pointers, Vulkan handles and device addresses are never encoded as authority.
//! This module registers no syscall and creates no second UI or security service.
//!
//! 本模块只定义既有原生 Channel/Ring 承载的版本化 UI 帧。载荷对内核不透明；
//! Handle/Rights 与 MemoryObject 仍经既有对象/IPC 机制带外转移，编码中没有裸
//! 指针、Vulkan 句柄或设备地址，也没有新 syscall 或第二套 UI/安全服务。

use crate::ui_service::{UiClientKey, UI_SERVICE_PROTOCOL_VERSION};

/// Little-endian bytes `JSUI`.
pub const UI_FRAME_MAGIC: u32 = 0x4955_534a;
pub const UI_FRAME_HEADER_BYTES: usize = 40;
/// One scene/patch frame payload ceiling. Larger content is split explicitly.
/// 单个场景/补丁帧载荷上限；更大内容必须显式分片，不能静默截断。
pub const MAX_UI_FRAME_PAYLOAD: usize = 64 * 1024; // JASPER-HARDCODE-REVIEW: issue=36 source=ui-ipc-protocol-v1 reason=bounded-ui-frame-payload

pub const UI_FLAG_MORE: u16 = 1 << 0;
const KNOWN_FLAGS: u16 = UI_FLAG_MORE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum UiFrameKind {
    Scene = 1,
    Patch = 2,
    Input = 3,
    Present = 4,
    Cancel = 5,
    Close = 6,
    Error = 7,
}

impl UiFrameKind {
    pub const fn from_raw(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Scene),
            2 => Some(Self::Patch),
            3 => Some(Self::Input),
            4 => Some(Self::Present),
            5 => Some(Self::Cancel),
            6 => Some(Self::Close),
            7 => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiFrameHeader {
    pub kind: UiFrameKind,
    pub flags: u16,
    pub client: UiClientKey,
    pub request_id: u64,
    pub sequence: u32,
    pub payload_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiFrame<'a> {
    pub header: UiFrameHeader,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiProtocolError {
    OutputTooSmall,
    Truncated,
    TrailingBytes,
    BadMagic,
    BadVersion,
    BadHeaderLength,
    BadKind,
    BadFlags,
    BadClient,
    ZeroRequest,
    PayloadTooLarge,
    ReservedNonZero,
}

impl UiProtocolError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::OutputTooSmall => "service.ui.protocol.error.output",
            Self::Truncated => "service.ui.protocol.error.truncated",
            Self::TrailingBytes => "service.ui.protocol.error.trailing",
            Self::BadMagic => "service.ui.protocol.error.magic",
            Self::BadVersion => "service.ui.protocol.error.version",
            Self::BadHeaderLength => "service.ui.protocol.error.header",
            Self::BadKind => "service.ui.protocol.error.kind",
            Self::BadFlags => "service.ui.protocol.error.flags",
            Self::BadClient => "service.ui.protocol.error.client",
            Self::ZeroRequest => "service.ui.protocol.error.request",
            Self::PayloadTooLarge => "service.ui.protocol.error.payload",
            Self::ReservedNonZero => "service.ui.protocol.error.reserved",
        }
    }
}

impl UiFrameHeader {
    pub fn encode_into(self, output: &mut [u8]) -> Result<usize, UiProtocolError> {
        let payload_bytes = self.payload_bytes as usize;
        if self.request_id == 0 {
            return Err(UiProtocolError::ZeroRequest);
        }
        if self.flags & !KNOWN_FLAGS != 0 {
            return Err(UiProtocolError::BadFlags);
        }
        if payload_bytes > MAX_UI_FRAME_PAYLOAD {
            return Err(UiProtocolError::PayloadTooLarge);
        }
        let total = UI_FRAME_HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or(UiProtocolError::PayloadTooLarge)?;
        let destination = output
            .get_mut(..total)
            .ok_or(UiProtocolError::OutputTooSmall)?;
        put_u32(destination, 0, UI_FRAME_MAGIC);
        put_u16(destination, 4, UI_SERVICE_PROTOCOL_VERSION);
        put_u16(destination, 6, self.kind as u16);
        put_u16(destination, 8, self.flags);
        put_u16(destination, 10, UI_FRAME_HEADER_BYTES as u16);
        put_u32(destination, 12, 0);
        put_u64(destination, 16, self.client.to_raw());
        put_u64(destination, 24, self.request_id);
        put_u32(destination, 32, self.sequence);
        put_u32(destination, 36, self.payload_bytes);
        Ok(total)
    }
}

pub fn encode_ui_frame(
    header: UiFrameHeader,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, UiProtocolError> {
    if payload.len() > u32::MAX as usize {
        return Err(UiProtocolError::PayloadTooLarge);
    }
    let header = UiFrameHeader {
        payload_bytes: payload.len() as u32,
        ..header
    };
    let len = header.encode_into(output)?;
    output[UI_FRAME_HEADER_BYTES..len].copy_from_slice(payload);
    Ok(len)
}

pub fn decode_ui_frame(input: &[u8]) -> Result<UiFrame<'_>, UiProtocolError> {
    if input.len() < UI_FRAME_HEADER_BYTES {
        return Err(UiProtocolError::Truncated);
    }
    if get_u32(input, 0) != UI_FRAME_MAGIC {
        return Err(UiProtocolError::BadMagic);
    }
    if get_u16(input, 4) != UI_SERVICE_PROTOCOL_VERSION {
        return Err(UiProtocolError::BadVersion);
    }
    if get_u16(input, 10) as usize != UI_FRAME_HEADER_BYTES {
        return Err(UiProtocolError::BadHeaderLength);
    }
    if get_u32(input, 12) != 0 {
        return Err(UiProtocolError::ReservedNonZero);
    }
    let kind = UiFrameKind::from_raw(get_u16(input, 6)).ok_or(UiProtocolError::BadKind)?;
    let flags = get_u16(input, 8);
    if flags & !KNOWN_FLAGS != 0 {
        return Err(UiProtocolError::BadFlags);
    }
    let client = UiClientKey::from_raw(get_u64(input, 16)).ok_or(UiProtocolError::BadClient)?;
    let request_id = get_u64(input, 24);
    if request_id == 0 {
        return Err(UiProtocolError::ZeroRequest);
    }
    let payload_bytes = get_u32(input, 36) as usize;
    if payload_bytes > MAX_UI_FRAME_PAYLOAD {
        return Err(UiProtocolError::PayloadTooLarge);
    }
    let total = UI_FRAME_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(UiProtocolError::PayloadTooLarge)?;
    if input.len() < total {
        return Err(UiProtocolError::Truncated);
    }
    if input.len() > total {
        return Err(UiProtocolError::TrailingBytes);
    }
    Ok(UiFrame {
        header: UiFrameHeader {
            kind,
            flags,
            client,
            request_id,
            sequence: get_u32(input, 32),
            payload_bytes: payload_bytes as u32,
        },
        payload: &input[UI_FRAME_HEADER_BYTES..],
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UiInputRecord {
    pub code: u32,
    pub pressed: bool,
    pub modifiers: u8,
}

impl UiInputRecord {
    pub fn encode_into(self, output: &mut [u8]) -> Result<usize, UiProtocolError> {
        let output = output.get_mut(..8).ok_or(UiProtocolError::OutputTooSmall)?;
        put_u32(output, 0, self.code);
        output[4] = u8::from(self.pressed);
        output[5] = self.modifiers;
        output[6..].fill(0);
        Ok(8)
    }

    pub fn decode(input: &[u8]) -> Result<Self, UiProtocolError> {
        if input.len() < 8 {
            return Err(UiProtocolError::Truncated);
        }
        if input.len() > 8 {
            return Err(UiProtocolError::TrailingBytes);
        }
        if input[4] > 1 || input[6..].iter().any(|byte| *byte != 0) {
            return Err(UiProtocolError::ReservedNonZero);
        }
        Ok(Self {
            code: get_u32(input, 0),
            pressed: input[4] == 1,
            modifiers: input[5],
        })
    }
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> UiClientKey {
        UiClientKey::from_raw((3u64 << 16) | 2).unwrap()
    }

    fn header(kind: UiFrameKind, payload_bytes: u32) -> UiFrameHeader {
        UiFrameHeader {
            kind,
            flags: UI_FLAG_MORE,
            client: client(),
            request_id: 9,
            sequence: 7,
            payload_bytes,
        }
    }

    #[test]
    fn all_frame_kinds_round_trip_with_bound_payload() {
        for kind in [
            UiFrameKind::Scene,
            UiFrameKind::Patch,
            UiFrameKind::Input,
            UiFrameKind::Present,
            UiFrameKind::Cancel,
            UiFrameKind::Close,
            UiFrameKind::Error,
        ] {
            let payload = [1u8, 2, 3, 4];
            let mut bytes = [0u8; UI_FRAME_HEADER_BYTES + 4];
            let len = encode_ui_frame(header(kind, payload.len() as u32), &payload, &mut bytes)
                .unwrap();
            let decoded = decode_ui_frame(&bytes[..len]).unwrap();
            assert_eq!(decoded.header, header(kind, payload.len() as u32));
            assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn malformed_headers_and_lengths_fail_closed() {
        let payload = [0xaa; 3];
        let mut bytes = [0u8; UI_FRAME_HEADER_BYTES + 3];
        let len = encode_ui_frame(
            header(UiFrameKind::Patch, payload.len() as u32),
            &payload,
            &mut bytes,
        )
        .unwrap();
        for offset in [0usize, 4, 10, 12] {
            let mut tampered = bytes;
            tampered[offset] ^= 0xff;
            assert!(decode_ui_frame(&tampered[..len]).is_err(), "offset={offset}");
        }
        let mut bad_kind = bytes;
        put_u16(&mut bad_kind, 6, 0);
        assert_eq!(
            decode_ui_frame(&bad_kind[..len]),
            Err(UiProtocolError::BadKind)
        );
        let mut bad_flags = bytes;
        put_u16(&mut bad_flags, 8, 0x8000);
        assert_eq!(
            decode_ui_frame(&bad_flags[..len]),
            Err(UiProtocolError::BadFlags)
        );
        let mut bad_client = bytes;
        put_u64(&mut bad_client, 16, 0);
        assert_eq!(
            decode_ui_frame(&bad_client[..len]),
            Err(UiProtocolError::BadClient)
        );
        let mut bad_request = bytes;
        put_u64(&mut bad_request, 24, 0);
        assert_eq!(
            decode_ui_frame(&bad_request[..len]),
            Err(UiProtocolError::ZeroRequest)
        );
        assert_eq!(decode_ui_frame(&bytes[..len - 1]), Err(UiProtocolError::Truncated));
        let mut extended = [0u8; UI_FRAME_HEADER_BYTES + 4];
        extended[..len].copy_from_slice(&bytes[..len]);
        assert_eq!(
            decode_ui_frame(&extended),
            Err(UiProtocolError::TrailingBytes)
        );
    }

    #[test]
    fn input_record_rejects_noncanonical_boolean_and_reserved_bytes() {
        let input = UiInputRecord {
            code: 30,
            pressed: true,
            modifiers: 3,
        };
        let mut bytes = [0u8; 8];
        assert_eq!(input.encode_into(&mut bytes), Ok(8));
        assert_eq!(UiInputRecord::decode(&bytes), Ok(input));
        for offset in [4usize, 6, 7] {
            let mut malformed = bytes;
            malformed[offset] = 2;
            assert!(UiInputRecord::decode(&malformed).is_err(), "offset={offset}");
        }
    }

    #[test]
    fn payload_ceiling_is_explicit_and_no_truncation_occurs() {
        let mut output = [0u8; UI_FRAME_HEADER_BYTES + MAX_UI_FRAME_PAYLOAD + 1];
        assert_eq!(
            encode_ui_frame(
                header(UiFrameKind::Scene, 0),
                &[0; MAX_UI_FRAME_PAYLOAD + 1],
                &mut output,
            ),
            Err(UiProtocolError::PayloadTooLarge)
        );
    }
}
