//! Shared binary boundary for independently versioned `service.*` protocols.
//! `service.*` 独立版本服务协议的公共二进制边界。
//!
//! The header carries wire identity only. It does not grant authority, select a
//! dispatcher, or make a service a second security root.
//! 此头仅承载线协议身份，不授予权限、不选择分发器，也不建立第二安全根。

/// Fixed service protocol header size.
/// 固定服务协议头长度。
pub const HEADER_BYTES: usize = 8;

/// Versioned service protocol header.
/// 版本化服务协议头。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Protocol identity owned by the specific service.
    /// 具体服务拥有的协议标识。
    pub protocol: u32,
    /// Independently versioned service protocol version.
    /// 独立版本化的服务协议版本。
    pub version: u16,
    /// Total message size declared by the protocol.
    /// 协议声明的完整消息长度。
    pub bytes: u16,
}

impl Header {
    /// Encode the canonical little-endian service header.
    /// 编码规范小端服务头。
    pub fn encode(self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        out[..4].copy_from_slice(&self.protocol.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.bytes.to_le_bytes());
        out
    }

    /// Decode a bounded service header without supplying identity or authority.
    /// 解码有界服务头，不提供身份或权限。
    pub fn decode(bytes: &[u8; HEADER_BYTES]) -> Option<Self> {
        let header = Self {
            protocol: u32::from_le_bytes(bytes[..4].try_into().ok()?),
            version: u16::from_le_bytes(bytes[4..6].try_into().ok()?),
            bytes: u16::from_le_bytes(bytes[6..8].try_into().ok()?),
        };
        (header.protocol != 0 && header.version != 0 && header.bytes as usize >= HEADER_BYTES)
            .then_some(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_requires_protocol_version_and_bounded_size() {
        let header = Header {
            protocol: 1,
            version: 1,
            bytes: HEADER_BYTES as u16,
        };
        let mut bytes = header.encode();
        assert_eq!(Header::decode(&bytes), Some(header));

        for invalid_size in [0u16, 7] {
            bytes[6..8].copy_from_slice(&invalid_size.to_le_bytes());
            assert!(Header::decode(&bytes).is_none());
        }
        bytes[6..8].copy_from_slice(&8u16.to_le_bytes());
        bytes[4..6].fill(0);
        assert!(Header::decode(&bytes).is_none());
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[..4].fill(0);
        assert!(Header::decode(&bytes).is_none());
    }
}
