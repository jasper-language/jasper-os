//! NET-0 network objects, schema, policy and transaction boundary.
//!
//! This module stops below sockets and protocol parsing. It defines the stable
//! identities, deny-by-default policy projection and failure-atomic namespace
//! operations consumed by NET-1 and later protocol layers.

use crate::{
    capability::{AuthorityGrant, AuthoritySnapshot, CapabilityGraph},
    object::Rights,
};

pub const NET_MAJOR: u16 = 1;
pub const NET_MINOR: u16 = 0;
pub const NET_PATCH: u16 = 0;
pub const NET_WIRE_HEADER_BYTES: usize = 16;
pub const MAX_ENDPOINT_NAME_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl NetVersion {
    pub const V1_0_0: Self = Self {
        major: NET_MAJOR,
        minor: NET_MINOR,
        patch: NET_PATCH,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetWireHeader {
    pub version: NetVersion,
    pub bytes: u32,
    pub reserved: u32,
}

impl NetWireHeader {
    pub const fn new(bytes: usize) -> Self {
        Self {
            version: NetVersion::V1_0_0,
            bytes: bytes as u32,
            reserved: 0,
        }
    }

    pub fn encode(self) -> [u8; NET_WIRE_HEADER_BYTES] {
        let mut out = [0u8; NET_WIRE_HEADER_BYTES];
        out[0..2].copy_from_slice(&self.version.major.to_le_bytes());
        out[2..4].copy_from_slice(&self.version.minor.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.patch.to_le_bytes());
        out[8..12].copy_from_slice(&self.bytes.to_le_bytes());
        out[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    pub fn decode(input: [u8; NET_WIRE_HEADER_BYTES]) -> Result<Self, NetError> {
        let version = NetVersion {
            major: u16::from_le_bytes([input[0], input[1]]),
            minor: u16::from_le_bytes([input[2], input[3]]),
            patch: u16::from_le_bytes([input[4], input[5]]),
        };
        let bytes = u32::from_le_bytes(input[8..12].try_into().unwrap());
        let reserved = u32::from_le_bytes(input[12..16].try_into().unwrap());
        if version.major != NET_MAJOR
            || u16::from_le_bytes([input[6], input[7]]) != 0
            || bytes < NET_WIRE_HEADER_BYTES as u32
            || reserved != 0
        {
            return Err(NetError::InvalidVersion);
        }
        Ok(Self {
            version,
            bytes,
            reserved,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    InvalidVersion,
    InvalidIdentity,
    InvalidName,
    InvalidPort,
    InvalidPolicy,
    DuplicateEndpoint,
    NotFound,
    Revoked,
    CapacityExhausted,
    IdsExhausted,
    RightsDenied,
    CapabilityDenied,
    TransactionState,
    InDoubt,
    Expired,
    Cancelled,
    SignatureInvalid,
    RollbackDenied,
    WireTooShort,
}

impl NetError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidVersion => "system.net.error.invalid_version",
            Self::InvalidIdentity => "system.net.error.invalid_identity",
            Self::InvalidName => "system.net.error.invalid_name",
            Self::InvalidPort => "system.net.error.invalid_port",
            Self::InvalidPolicy => "system.net.error.invalid_policy",
            Self::DuplicateEndpoint => "system.net.error.duplicate_endpoint",
            Self::NotFound => "system.net.error.not_found",
            Self::Revoked => "system.net.error.revoked",
            Self::CapacityExhausted => "system.net.error.capacity",
            Self::IdsExhausted => "system.net.error.ids_exhausted",
            Self::RightsDenied => "system.net.error.rights_denied",
            Self::CapabilityDenied => "system.net.error.capability_denied",
            Self::TransactionState => "system.net.error.transaction_state",
            Self::InDoubt => "system.net.error.in_doubt",
            Self::Expired => "system.net.error.expired",
            Self::Cancelled => "system.net.error.cancelled",
            Self::SignatureInvalid => "system.net.error.signature_invalid",
            Self::RollbackDenied => "system.net.error.rollback_denied",
            Self::WireTooShort => "system.net.error.wire_too_short",
        }
    }

    pub const fn display(self, english: bool) -> &'static str {
        if english {
            match self {
                Self::InvalidVersion => "unsupported network schema version",
                Self::InvalidIdentity => "invalid or stale network identity",
                Self::InvalidName => "invalid endpoint name",
                Self::InvalidPort => "invalid endpoint port",
                Self::InvalidPolicy => "invalid network policy",
                Self::DuplicateEndpoint => "endpoint name already exists",
                Self::NotFound => "endpoint not found",
                Self::Revoked => "endpoint revoked",
                Self::CapacityExhausted => "network object capacity exhausted",
                Self::IdsExhausted => "network object ids exhausted",
                Self::RightsDenied => "network handle rights denied",
                Self::CapabilityDenied => "network policy or endpoint denied capability",
                Self::TransactionState => "invalid network transaction state",
                Self::InDoubt => "network transaction outcome is in doubt",
                Self::Expired => "network operation expired",
                Self::Cancelled => "network operation cancelled",
                Self::SignatureInvalid => "network policy signature is invalid",
                Self::RollbackDenied => "network policy rollback denied",
                Self::WireTooShort => "network wire record is truncated",
            }
        } else {
            match self {
                Self::InvalidVersion => "不支持的网络协议版本",
                Self::InvalidIdentity => "网络对象身份无效或已过期",
                Self::InvalidName => "网络端点名称无效",
                Self::InvalidPort => "网络端点端口无效",
                Self::InvalidPolicy => "网络策略无效",
                Self::DuplicateEndpoint => "网络端点名称已存在",
                Self::NotFound => "网络端点不存在",
                Self::Revoked => "网络端点已撤销",
                Self::CapacityExhausted => "网络对象容量已满",
                Self::IdsExhausted => "网络对象编号已耗尽",
                Self::RightsDenied => "网络句柄权限不足",
                Self::CapabilityDenied => "网络策略或端点拒绝该能力",
                Self::TransactionState => "网络事务状态转换无效",
                Self::InDoubt => "网络事务结果未决",
                Self::Expired => "网络操作已过期",
                Self::Cancelled => "网络操作已取消",
                Self::SignatureInvalid => "网络策略签名无效",
                Self::RollbackDenied => "网络策略回滚被拒绝",
                Self::WireTooShort => "网络线格式记录被截断",
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointName {
    bytes: [u8; MAX_ENDPOINT_NAME_BYTES],
    len: u8,
}

impl EndpointName {
    pub fn new(value: &[u8]) -> Result<Self, NetError> {
        if value.is_empty()
            || value.len() > MAX_ENDPOINT_NAME_BYTES
            || !value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_'))
        {
            return Err(NetError::InvalidName);
        }
        let mut bytes = [0u8; MAX_ENDPOINT_NAME_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            bytes,
            len: value.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointIdentity {
    pub namespace_id: u64,
    pub endpoint_id: u64,
    pub generation: u32,
}

impl EndpointIdentity {
    pub const fn is_valid(self) -> bool {
        self.namespace_id != 0 && self.endpoint_id != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetCapabilities(u16);

impl NetCapabilities {
    pub const CONNECT: Self = Self(1 << 0);
    pub const LISTEN: Self = Self(1 << 1);
    pub const ACCEPT: Self = Self(1 << 2);
    pub const SEND: Self = Self(1 << 3);
    pub const RECEIVE: Self = Self(1 << 4);
    pub const RESOLVE: Self = Self(1 << 5);
    pub const ALL: Self = Self(0x003f);
    pub const NONE: Self = Self(0);

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointKind {
    Stream,
    Datagram,
    Message,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointInfo {
    pub identity: EndpointIdentity,
    pub name: EndpointName,
    pub kind: EndpointKind,
    pub port: u16,
    pub capabilities: NetCapabilities,
    pub connections: u16,
    pub max_connections: u16,
    pub revoked: bool,
}

pub const ENDPOINT_RECORD_BYTES: usize = 128;
pub const CONNECTION_REQUEST_BYTES: usize = 96;
pub const CONNECTION_REPLY_BYTES: usize = 64;

impl EndpointKind {
    const fn code(self) -> u8 {
        match self {
            Self::Stream => 1,
            Self::Datagram => 2,
            Self::Message => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Stream),
            2 => Some(Self::Datagram),
            3 => Some(Self::Message),
            _ => None,
        }
    }
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(input[at..at + 2].try_into().unwrap())
}

fn get_u32(input: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(input[at..at + 4].try_into().unwrap())
}

fn get_u64(input: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(input[at..at + 8].try_into().unwrap())
}

impl EndpointInfo {
    pub fn encode(self) -> [u8; ENDPOINT_RECORD_BYTES] {
        let mut out = [0u8; ENDPOINT_RECORD_BYTES];
        out[..NET_WIRE_HEADER_BYTES]
            .copy_from_slice(&NetWireHeader::new(ENDPOINT_RECORD_BYTES).encode());
        out[16] = self.kind.code();
        put_u16(&mut out, 18, self.port);
        put_u16(&mut out, 20, self.capabilities.bits());
        put_u16(&mut out, 22, self.max_connections);
        out[24] = self.name.len;
        out[25] = u8::from(self.revoked);
        out[32..32 + self.name.len as usize].copy_from_slice(self.name.as_bytes());
        put_u64(&mut out, 64, self.identity.namespace_id);
        put_u64(&mut out, 72, self.identity.endpoint_id);
        put_u32(&mut out, 80, self.identity.generation);
        put_u16(&mut out, 84, self.connections);
        out
    }

    pub fn decode(input: [u8; ENDPOINT_RECORD_BYTES]) -> Result<Self, NetError> {
        let header = NetWireHeader::decode(input[..NET_WIRE_HEADER_BYTES].try_into().unwrap())?;
        if header.bytes != ENDPOINT_RECORD_BYTES as u32
            || input[26..32].iter().any(|byte| *byte != 0)
            || input[86..].iter().any(|byte| *byte != 0)
        {
            return Err(NetError::InvalidVersion);
        }
        let kind = EndpointKind::from_code(input[16]).ok_or(NetError::InvalidVersion)?;
        let port = get_u16(&input, 18);
        let capabilities =
            NetCapabilities::from_bits(get_u16(&input, 20)).ok_or(NetError::InvalidPolicy)?;
        let max_connections = get_u16(&input, 22);
        let name_len = input[24] as usize;
        if port == 0
            || max_connections == 0
            || name_len == 0
            || name_len > MAX_ENDPOINT_NAME_BYTES
            || input[32 + name_len..64].iter().any(|byte| *byte != 0)
        {
            return Err(NetError::InvalidName);
        }
        let name = EndpointName::new(&input[32..32 + name_len])?;
        let identity = EndpointIdentity {
            namespace_id: get_u64(&input, 64),
            endpoint_id: get_u64(&input, 72),
            generation: get_u32(&input, 80),
        };
        let connections = get_u16(&input, 84);
        if !identity.is_valid()
            || connections > max_connections
            || matches!(input[25], value if value > 1)
        {
            return Err(NetError::InvalidIdentity);
        }
        Ok(Self {
            identity,
            name,
            kind,
            port,
            capabilities,
            connections,
            max_connections,
            revoked: input[25] == 1,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub source: EndpointIdentity,
    pub target: EndpointIdentity,
    pub requested: NetCapabilities,
    pub rights: Rights,
}

impl ConnectionRequest {
    pub fn encode(self) -> [u8; CONNECTION_REQUEST_BYTES] {
        let mut out = [0u8; CONNECTION_REQUEST_BYTES];
        out[..NET_WIRE_HEADER_BYTES]
            .copy_from_slice(&NetWireHeader::new(CONNECTION_REQUEST_BYTES).encode());
        put_u16(&mut out, 16, self.requested.bits());
        put_u32(&mut out, 20, self.rights.bits());
        put_u64(&mut out, 24, self.source.namespace_id);
        put_u64(&mut out, 32, self.source.endpoint_id);
        put_u32(&mut out, 40, self.source.generation);
        put_u64(&mut out, 48, self.target.namespace_id);
        put_u64(&mut out, 56, self.target.endpoint_id);
        put_u32(&mut out, 64, self.target.generation);
        out
    }

    pub fn decode(input: [u8; CONNECTION_REQUEST_BYTES]) -> Result<Self, NetError> {
        let header = NetWireHeader::decode(input[..NET_WIRE_HEADER_BYTES].try_into().unwrap())?;
        if header.bytes != CONNECTION_REQUEST_BYTES as u32
            || input[18..20].iter().any(|byte| *byte != 0)
            || input[68..].iter().any(|byte| *byte != 0)
        {
            return Err(NetError::InvalidVersion);
        }
        let requested =
            NetCapabilities::from_bits(get_u16(&input, 16)).ok_or(NetError::InvalidPolicy)?;
        let rights_bits = get_u32(&input, 20);
        if rights_bits & !Rights::ALL.bits() != 0 {
            return Err(NetError::RightsDenied);
        }
        let source = EndpointIdentity {
            namespace_id: get_u64(&input, 24),
            endpoint_id: get_u64(&input, 32),
            generation: get_u32(&input, 40),
        };
        let target = EndpointIdentity {
            namespace_id: get_u64(&input, 48),
            endpoint_id: get_u64(&input, 56),
            generation: get_u32(&input, 64),
        };
        if !source.is_valid()
            || !target.is_valid()
            || source.namespace_id != target.namespace_id
            || source == target
        {
            return Err(NetError::InvalidIdentity);
        }
        Ok(Self {
            source,
            target,
            requested,
            rights: Rights::from_bits_truncate(rights_bits),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionReply {
    pub source: EndpointIdentity,
    pub target: EndpointIdentity,
    pub capabilities: NetCapabilities,
    pub policy_epoch: u32,
}

impl ConnectionReply {
    pub fn encode(self) -> [u8; CONNECTION_REPLY_BYTES] {
        let mut out = [0u8; CONNECTION_REPLY_BYTES];
        out[..NET_WIRE_HEADER_BYTES]
            .copy_from_slice(&NetWireHeader::new(CONNECTION_REPLY_BYTES).encode());
        put_u16(&mut out, 16, self.capabilities.bits());
        put_u32(&mut out, 20, self.policy_epoch);
        put_u64(&mut out, 24, self.source.namespace_id);
        put_u64(&mut out, 32, self.source.endpoint_id);
        put_u32(&mut out, 40, self.source.generation);
        put_u64(&mut out, 44, self.target.namespace_id);
        put_u64(&mut out, 52, self.target.endpoint_id);
        put_u32(&mut out, 60, self.target.generation);
        out
    }

    pub fn decode(input: [u8; CONNECTION_REPLY_BYTES]) -> Result<Self, NetError> {
        let header = NetWireHeader::decode(input[..NET_WIRE_HEADER_BYTES].try_into().unwrap())?;
        if header.bytes != CONNECTION_REPLY_BYTES as u32
            || input[18..20].iter().any(|byte| *byte != 0)
        {
            return Err(NetError::InvalidVersion);
        }
        let capabilities =
            NetCapabilities::from_bits(get_u16(&input, 16)).ok_or(NetError::InvalidPolicy)?;
        let source = EndpointIdentity {
            namespace_id: get_u64(&input, 24),
            endpoint_id: get_u64(&input, 32),
            generation: get_u32(&input, 40),
        };
        let target = EndpointIdentity {
            namespace_id: get_u64(&input, 44),
            endpoint_id: get_u64(&input, 52),
            generation: get_u32(&input, 60),
        };
        if !source.is_valid()
            || !target.is_valid()
            || source.namespace_id != target.namespace_id
            || source == target
        {
            return Err(NetError::InvalidIdentity);
        }
        Ok(Self {
            source,
            target,
            capabilities,
            policy_epoch: get_u32(&input, 20),
        })
    }
}

#[derive(Clone, Copy)]
struct Endpoint {
    info: EndpointInfo,
}

pub struct NetCore<const N: usize> {
    namespace_id: u64,
    endpoints: [Option<Endpoint>; N],
    next_id: u64,
}

impl<const N: usize> NetCore<N> {
    pub fn format(namespace_id: u64) -> Result<Self, NetError> {
        if N == 0 || namespace_id == 0 {
            return Err(NetError::InvalidIdentity);
        }
        Ok(Self {
            namespace_id,
            endpoints: [const { None }; N],
            next_id: 1,
        })
    }

    pub fn bind(
        &mut self,
        name: EndpointName,
        kind: EndpointKind,
        port: u16,
        capabilities: NetCapabilities,
        max_connections: u16,
    ) -> Result<EndpointIdentity, NetError> {
        if port == 0 || max_connections == 0 {
            return Err(if port == 0 {
                NetError::InvalidPort
            } else {
                NetError::CapacityExhausted
            });
        }
        if self
            .endpoints
            .iter()
            .flatten()
            .any(|endpoint| !endpoint.info.revoked && endpoint.info.name == name)
        {
            return Err(NetError::DuplicateEndpoint);
        }
        let slot = self
            .endpoints
            .iter()
            .position(Option::is_none)
            .ok_or(NetError::CapacityExhausted)?;
        let endpoint_id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(NetError::IdsExhausted)?;
        let identity = EndpointIdentity {
            namespace_id: self.namespace_id,
            endpoint_id,
            generation: 0,
        };
        self.endpoints[slot] = Some(Endpoint {
            info: EndpointInfo {
                identity,
                name,
                kind,
                port,
                capabilities,
                connections: 0,
                max_connections,
                revoked: false,
            },
        });
        Ok(identity)
    }

    pub fn resolve(&self, name: EndpointName) -> Result<EndpointIdentity, NetError> {
        self.endpoints
            .iter()
            .flatten()
            .find(|endpoint| !endpoint.info.revoked && endpoint.info.name == name)
            .map(|endpoint| endpoint.info.identity)
            .ok_or(NetError::NotFound)
    }

    pub fn info(&self, identity: EndpointIdentity) -> Result<EndpointInfo, NetError> {
        let index = self.index(identity)?;
        let endpoint = self.endpoints[index].expect("validated endpoint");
        if endpoint.info.revoked {
            Err(NetError::Revoked)
        } else {
            Ok(endpoint.info)
        }
    }

    pub fn revoke(&mut self, identity: EndpointIdentity) -> Result<(), NetError> {
        let index = self.index(identity)?;
        let endpoint = self.endpoints[index]
            .as_mut()
            .expect("validated endpoint");
        if endpoint.info.revoked {
            return Ok(());
        }
        endpoint.info.revoked = true;
        Ok(())
    }

    pub fn connect(
        &mut self,
        policy: NetworkPolicy,
        source: EndpointIdentity,
        target: EndpointIdentity,
        requested: NetCapabilities,
        handle_rights: Rights,
    ) -> Result<ConnectionGrant, NetError> {
        if !handle_rights.contains(Rights::READ.union(Rights::WRITE)) {
            return Err(NetError::RightsDenied);
        }
        policy.authorize(requested)?;
        let source_index = self.index(source)?;
        let target_index = self.index(target)?;
        if source_index == target_index {
            return Err(NetError::InvalidIdentity);
        }
        let source_info = self.endpoints[source_index]
            .expect("validated source")
            .info;
        let target_info = self.endpoints[target_index]
            .expect("validated target")
            .info;
        if source_info.revoked || target_info.revoked {
            return Err(NetError::Revoked);
        }
        if !source_info
            .capabilities
            .contains(NetCapabilities::CONNECT.union(NetCapabilities::SEND))
            || !target_info
                .capabilities
                .contains(NetCapabilities::LISTEN.union(NetCapabilities::RECEIVE))
            || !source_info.capabilities.contains(requested)
            || !target_info.capabilities.contains(requested)
        {
            return Err(NetError::CapabilityDenied);
        }
        if source_info.connections == source_info.max_connections
            || target_info.connections == target_info.max_connections
        {
            return Err(NetError::CapacityExhausted);
        }
        self.endpoints[source_index]
            .as_mut()
            .expect("validated source")
            .info
            .connections += 1;
        self.endpoints[target_index]
            .as_mut()
            .expect("validated target")
            .info
            .connections += 1;
        Ok(ConnectionGrant {
            source,
            target,
            capabilities: requested,
            policy_epoch: policy.epoch,
            established: true,
        })
    }

    pub fn connect_authorized<const C: usize>(
        &mut self,
        graph: &mut CapabilityGraph<C>,
        grant: AuthorityGrant,
        current: AuthoritySnapshot,
        policy: NetworkPolicy,
        request: ConnectionRequest,
    ) -> Result<ConnectionGrant, NetError> {
        graph
            .validate_authority(grant, current)
            .map_err(|_| NetError::CapabilityDenied)?;
        self.connect(
            policy,
            request.source,
            request.target,
            request.requested,
            current.rights,
        )
    }

    pub fn release(&mut self, grant: ConnectionGrant) -> Result<(), NetError> {
        if !grant.established {
            return Err(NetError::TransactionState);
        }
        let source = self.index(grant.source)?;
        let target = self.index(grant.target)?;
        for index in [source, target] {
            let endpoint = self.endpoints[index].as_mut().expect("validated endpoint");
            endpoint.info.connections = endpoint
                .info
                .connections
                .checked_sub(1)
                .ok_or(NetError::TransactionState)?;
        }
        Ok(())
    }

    fn index(&self, identity: EndpointIdentity) -> Result<usize, NetError> {
        if !identity.is_valid() || identity.namespace_id != self.namespace_id {
            return Err(NetError::InvalidIdentity);
        }
        self.endpoints
            .iter()
            .position(|endpoint| {
                endpoint.is_some_and(|endpoint| endpoint.info.identity == identity)
            })
            .ok_or(NetError::NotFound)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub version: NetVersion,
    pub allowed: NetCapabilities,
    pub required: NetCapabilities,
    pub epoch: u32,
}

pub const POLICY_RECORD_BYTES: usize = 32;
pub const SIGNED_POLICY_BYTES: usize = 64;

pub trait PolicySignatureVerifier {
    fn verify(&self, policy_record: &[u8; POLICY_RECORD_BYTES], signature: &[u8; 32]) -> bool;
}

impl NetworkPolicy {
    pub fn compile(bytes: [u8; POLICY_RECORD_BYTES]) -> Result<Self, NetError> {
        let header = NetWireHeader::decode(bytes[..NET_WIRE_HEADER_BYTES].try_into().unwrap())?;
        if header.bytes != 32
            || bytes[24..32].iter().any(|byte| *byte != 0)
        {
            return Err(NetError::InvalidPolicy);
        }
        let allowed = NetCapabilities::from_bits(get_u16(&bytes, 16))
            .ok_or(NetError::InvalidPolicy)?;
        let required = NetCapabilities::from_bits(get_u16(&bytes, 18))
            .ok_or(NetError::InvalidPolicy)?;
        if !allowed.contains(required) {
            return Err(NetError::InvalidPolicy);
        }
        Ok(Self {
            version: header.version,
            allowed,
            required,
            epoch: get_u32(&bytes, 20),
        })
    }

    pub fn encode(self) -> [u8; POLICY_RECORD_BYTES] {
        let mut out = [0u8; POLICY_RECORD_BYTES];
        out[..NET_WIRE_HEADER_BYTES]
            .copy_from_slice(&NetWireHeader::new(POLICY_RECORD_BYTES).encode());
        put_u16(&mut out, 16, self.allowed.bits());
        put_u16(&mut out, 18, self.required.bits());
        put_u32(&mut out, 20, self.epoch);
        out
    }

    pub fn default_deny(epoch: u32) -> Self {
        Self {
            version: NetVersion::V1_0_0,
            allowed: NetCapabilities::NONE,
            required: NetCapabilities::NONE,
            epoch,
        }
    }

    pub fn authorize(self, requested: NetCapabilities) -> Result<(), NetError> {
        if requested.contains(self.required) && self.allowed.contains(requested) {
            Ok(())
        } else {
            Err(NetError::CapabilityDenied)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedNetworkPolicy {
    pub policy: NetworkPolicy,
    pub signature: [u8; 32],
}

impl SignedNetworkPolicy {
    pub fn encode(self) -> [u8; SIGNED_POLICY_BYTES] {
        let mut out = [0u8; SIGNED_POLICY_BYTES];
        out[..POLICY_RECORD_BYTES].copy_from_slice(&self.policy.encode());
        out[POLICY_RECORD_BYTES..].copy_from_slice(&self.signature);
        out
    }

    pub fn verify(
        self,
        verifier: &impl PolicySignatureVerifier,
    ) -> Result<NetworkPolicy, NetError> {
        let record: [u8; POLICY_RECORD_BYTES] = self.encode()[..POLICY_RECORD_BYTES]
            .try_into()
            .unwrap();
        if verifier.verify(&record, &self.signature) {
            NetworkPolicy::compile(record)
        } else {
            Err(NetError::SignatureInvalid)
        }
    }
}

pub struct PolicySlot {
    current: NetworkPolicy,
    previous: Option<NetworkPolicy>,
}

impl PolicySlot {
    pub fn new(default_deny: NetworkPolicy) -> Self {
        Self {
            current: default_deny,
            previous: None,
        }
    }

    pub fn current(&self) -> NetworkPolicy {
        self.current
    }

    pub fn replace(&mut self, next: NetworkPolicy) -> Result<NetworkPolicy, NetError> {
        if next.epoch != self.current.epoch.saturating_add(1) {
            return Err(NetError::InvalidPolicy);
        }
        self.previous = Some(self.current);
        self.current = next;
        Ok(self.current)
    }

    pub fn rollback(&mut self, expected_epoch: u32) -> Result<NetworkPolicy, NetError> {
        if self.current.epoch != expected_epoch {
            return Err(NetError::RollbackDenied);
        }
        let previous = self.previous.ok_or(NetError::RollbackDenied)?;
        if previous.epoch.saturating_add(1) != self.current.epoch {
            return Err(NetError::RollbackDenied);
        }
        self.current = previous;
        self.previous = None;
        Ok(self.current)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionGrant {
    pub source: EndpointIdentity,
    pub target: EndpointIdentity,
    pub capabilities: NetCapabilities,
    pub policy_epoch: u32,
    pub established: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetTransactionState {
    Draft,
    Validated,
    Prepared,
    Committed,
    Aborted,
    InDoubt,
    Cancelled,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetTransaction {
    pub id: u64,
    pub request_hash: u64,
    pub state: NetTransactionState,
}

impl NetTransaction {
    pub fn begin(id: u64, request_hash: u64) -> Result<Self, NetError> {
        if id == 0 || request_hash == 0 {
            return Err(NetError::InvalidIdentity);
        }
        Ok(Self {
            id,
            request_hash,
            state: NetTransactionState::Draft,
        })
    }

    pub fn validate(mut self) -> Result<Self, NetError> {
        self.transition(NetTransactionState::Draft, NetTransactionState::Validated)?;
        Ok(self)
    }

    pub fn prepare(mut self) -> Result<Self, NetError> {
        self.transition(
            NetTransactionState::Validated,
            NetTransactionState::Prepared,
        )?;
        Ok(self)
    }

    pub fn commit(mut self) -> Result<Self, NetError> {
        self.transition(
            NetTransactionState::Prepared,
            NetTransactionState::Committed,
        )?;
        Ok(self)
    }

    pub fn abort(mut self) -> Result<Self, NetError> {
        if matches!(
            self.state,
            NetTransactionState::Draft
                | NetTransactionState::Validated
                | NetTransactionState::Prepared
        ) {
            self.state = NetTransactionState::Aborted;
            Ok(self)
        } else {
            Err(NetError::TransactionState)
        }
    }

    pub fn mark_in_doubt(mut self) -> Result<Self, NetError> {
        if self.state == NetTransactionState::Prepared {
            self.state = NetTransactionState::InDoubt;
            Ok(self)
        } else {
            Err(NetError::TransactionState)
        }
    }

    pub fn reconcile(mut self, committed: bool) -> Result<Self, NetError> {
        if self.state != NetTransactionState::InDoubt {
            return Err(NetError::TransactionState);
        }
        self.state = if committed {
            NetTransactionState::Committed
        } else {
            NetTransactionState::Aborted
        };
        Ok(self)
    }

    pub fn cancel(mut self) -> Result<Self, NetError> {
        if matches!(
            self.state,
            NetTransactionState::Draft
                | NetTransactionState::Validated
                | NetTransactionState::Prepared
        ) {
            self.state = NetTransactionState::Cancelled;
            Ok(self)
        } else {
            Err(NetError::TransactionState)
        }
    }

    pub fn expire(mut self) -> Result<Self, NetError> {
        if matches!(
            self.state,
            NetTransactionState::Draft | NetTransactionState::Validated
        ) {
            self.state = NetTransactionState::Expired;
            Ok(self)
        } else {
            Err(NetError::TransactionState)
        }
    }

    fn transition(
        &mut self,
        expected: NetTransactionState,
        next: NetTransactionState,
    ) -> Result<(), NetError> {
        if self.state != expected {
            return Err(NetError::TransactionState);
        }
        self.state = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{AuthorityRequest, PrincipalId};
    use crate::security::{BootId, IdentityClass, ObjectIdentity};
    use crate::syscall_set::SyscallSet;

    const POLICY_BYTES: usize = 32;

    fn policy(allowed: NetCapabilities, required: NetCapabilities) -> NetworkPolicy {
        let mut bytes = [0u8; POLICY_BYTES];
        bytes[..NET_WIRE_HEADER_BYTES]
            .copy_from_slice(&NetWireHeader::new(POLICY_BYTES).encode());
        bytes[16..18].copy_from_slice(&allowed.bits().to_le_bytes());
        bytes[18..20].copy_from_slice(&required.bits().to_le_bytes());
        NetworkPolicy::compile(bytes).unwrap()
    }

    fn name(value: &[u8]) -> EndpointName {
        EndpointName::new(value).unwrap()
    }

    #[test]
    fn endpoint_identity_and_name_are_generation_exact() {
        let mut net = NetCore::<4>::format(9).unwrap();
        let first = net
            .bind(
                name(b"service"),
                EndpointKind::Stream,
                443,
                NetCapabilities::ALL,
                2,
            )
            .unwrap();
        assert_eq!(net.resolve(name(b"service")), Ok(first));
        assert_eq!(
            net.bind(
                name(b"service"),
                EndpointKind::Stream,
                444,
                NetCapabilities::ALL,
                2,
            ),
            Err(NetError::DuplicateEndpoint)
        );
        let foreign = EndpointIdentity {
            namespace_id: 10,
            ..first
        };
        assert_eq!(net.info(foreign), Err(NetError::InvalidIdentity));
        net.revoke(first).unwrap();
        assert_eq!(net.info(first), Err(NetError::Revoked));
        assert_eq!(net.resolve(name(b"service")), Err(NetError::NotFound));
    }

    #[test]
    fn default_deny_and_policy_projection_do_not_allow_escalation() {
        assert_eq!(
            NetworkPolicy::default_deny(1).authorize(NetCapabilities::CONNECT),
            Err(NetError::CapabilityDenied)
        );
        let policy = policy(
            NetCapabilities::CONNECT.union(NetCapabilities::SEND),
            NetCapabilities::CONNECT,
        );
        assert!(policy.authorize(NetCapabilities::CONNECT).is_ok());
        assert_eq!(
            policy.authorize(NetCapabilities::CONNECT.union(NetCapabilities::SEND)),
            Ok(())
        );
        assert_eq!(
            policy.authorize(NetCapabilities::RECEIVE),
            Err(NetError::CapabilityDenied)
        );

        let mut bytes = [0u8; POLICY_BYTES];
        bytes[..NET_WIRE_HEADER_BYTES]
            .copy_from_slice(&NetWireHeader::new(POLICY_BYTES).encode());
        bytes[16..18].copy_from_slice(&NetCapabilities::CONNECT.bits().to_le_bytes());
        bytes[18..20].copy_from_slice(&NetCapabilities::SEND.bits().to_le_bytes());
        assert_eq!(
            NetworkPolicy::compile(bytes),
            Err(NetError::InvalidPolicy)
        );
    }

    #[test]
    fn connection_capacity_and_release_are_failure_atomic() {
        let mut net = NetCore::<4>::format(11).unwrap();
        let source = net
            .bind(
                name(b"client"),
                EndpointKind::Stream,
                1000,
                NetCapabilities::ALL,
                2,
            )
            .unwrap();
        let target = net
            .bind(
                name(b"server"),
                EndpointKind::Stream,
                443,
                NetCapabilities::ALL,
                1,
            )
            .unwrap();
        let policy = policy(NetCapabilities::ALL, NetCapabilities::CONNECT);
        let requested = NetCapabilities::CONNECT.union(NetCapabilities::SEND);
        let grant = net
            .connect(
                policy,
                source,
                target,
                requested,
                Rights::READ.union(Rights::WRITE),
            )
            .unwrap();
        assert_eq!(net.info(target).unwrap().connections, 1);
        assert_eq!(
            net.connect(
                policy,
                source,
                target,
                requested,
                Rights::READ.union(Rights::WRITE),
            ),
            Err(NetError::CapacityExhausted)
        );
        assert_eq!(net.info(source).unwrap().connections, 1);
        net.release(grant).unwrap();
        assert_eq!(net.info(source).unwrap().connections, 0);
        assert_eq!(net.info(target).unwrap().connections, 0);
    }

    #[test]
    fn connect_authorized_revalidates_sec2_grant_before_publication() {
        let mut net = NetCore::<4>::format(12).unwrap();
        let source = net
            .bind(
                name(b"client"),
                EndpointKind::Stream,
                2000,
                NetCapabilities::ALL,
                2,
            )
            .unwrap();
        let target = net
            .bind(
                name(b"server"),
                EndpointKind::Stream,
                443,
                NetCapabilities::ALL,
                2,
            )
            .unwrap();
        let mut graph = CapabilityGraph::<2>::new();
        let object = ObjectIdentity {
            boot_id: BootId::from_words([1, 2]),
            class: IdentityClass::Device,
            object_id: 9,
            generation: 1,
        };
        let capability = graph
            .create_root(object, PrincipalId::new(4).unwrap(), Rights::ALL)
            .unwrap();
        let snapshot = AuthoritySnapshot::new(Rights::ALL, SyscallSet::FULL, 0, 0);
        let authority = AuthorityRequest::new(Rights::READ.union(Rights::WRITE));
        let grant = graph
            .begin_authority(capability, PrincipalId::new(4).unwrap(), authority, snapshot)
            .unwrap();
        graph.revoke(capability).unwrap();
        let request = ConnectionRequest {
            source,
            target,
            requested: NetCapabilities::CONNECT.union(NetCapabilities::SEND),
            rights: Rights::READ.union(Rights::WRITE),
        };
        assert_eq!(
            net.connect_authorized(
                &mut graph,
                grant,
                snapshot,
                policy(NetCapabilities::ALL, NetCapabilities::CONNECT),
                request,
            ),
            Err(NetError::CapabilityDenied)
        );
        assert_eq!(net.info(source).unwrap().connections, 0);
        assert_eq!(net.info(target).unwrap().connections, 0);
        graph.end_authority(grant).unwrap();
    }

    #[test]
    fn transaction_has_one_terminal_and_in_doubt_requires_reconciliation() {
        let tx = NetTransaction::begin(1, 7)
            .unwrap()
            .validate()
            .unwrap()
            .prepare()
            .unwrap();
        assert_eq!(tx.abort().unwrap().state, NetTransactionState::Aborted);
        let tx = NetTransaction::begin(2, 8)
            .unwrap()
            .validate()
            .unwrap()
            .prepare()
            .unwrap();
        let tx = tx.mark_in_doubt().unwrap();
        assert_eq!(tx.commit(), Err(NetError::TransactionState));
        assert_eq!(
            tx.reconcile(true).unwrap().state,
            NetTransactionState::Committed
        );
        let cancelled = NetTransaction::begin(3, 9)
            .unwrap()
            .validate()
            .unwrap()
            .cancel()
            .unwrap();
        assert_eq!(cancelled.state, NetTransactionState::Cancelled);
        let expired = NetTransaction::begin(4, 10).unwrap().expire().unwrap();
        assert_eq!(expired.state, NetTransactionState::Expired);
        assert_eq!(
            cancelled.commit(),
            Err(NetError::TransactionState)
        );
    }

    #[test]
    fn endpoint_and_connection_wire_records_roundtrip_strictly() {
        let source = EndpointIdentity {
            namespace_id: 7,
            endpoint_id: 3,
            generation: 4,
        };
        let target = EndpointIdentity {
            namespace_id: 7,
            endpoint_id: 9,
            generation: 2,
        };
        let info = EndpointInfo {
            identity: source,
            name: name(b"client.api"),
            kind: EndpointKind::Stream,
            port: 8443,
            capabilities: NetCapabilities::ALL,
            connections: 1,
            max_connections: 8,
            revoked: false,
        };
        assert_eq!(EndpointInfo::decode(info.encode()), Ok(info));

        let request = ConnectionRequest {
            source,
            target,
            requested: NetCapabilities::CONNECT.union(NetCapabilities::SEND),
            rights: Rights::READ.union(Rights::WRITE),
        };
        assert_eq!(ConnectionRequest::decode(request.encode()), Ok(request));
        let reply = ConnectionReply {
            source,
            target,
            capabilities: request.requested,
            policy_epoch: 5,
        };
        assert_eq!(ConnectionReply::decode(reply.encode()), Ok(reply));

        let mut bad = request.encode();
        bad[18] = 1;
        assert_eq!(
            ConnectionRequest::decode(bad),
            Err(NetError::InvalidVersion)
        );
    }

    struct TestVerifier;

    impl PolicySignatureVerifier for TestVerifier {
        fn verify(&self, _record: &[u8; POLICY_RECORD_BYTES], signature: &[u8; 32]) -> bool {
            signature == &[0x42; 32]
        }
    }

    #[test]
    fn signed_policy_and_policy_slot_require_versioned_verified_updates() {
        let next = NetworkPolicy {
            epoch: 1,
            ..policy(NetCapabilities::ALL, NetCapabilities::CONNECT)
        };
        let signed = SignedNetworkPolicy {
            policy: next,
            signature: [0x42; 32],
        };
        assert_eq!(signed.verify(&TestVerifier), Ok(next));
        assert_eq!(
            SignedNetworkPolicy {
                policy: next,
                signature: [0; 32],
            }
            .verify(&TestVerifier),
            Err(NetError::SignatureInvalid)
        );

        let mut slot = PolicySlot::new(NetworkPolicy::default_deny(0));
        assert_eq!(
            slot.replace(NetworkPolicy {
                epoch: 2,
                ..next
            }),
            Err(NetError::InvalidPolicy)
        );
        assert_eq!(slot.replace(next), Ok(next));
        assert_eq!(
            slot.replace(NetworkPolicy {
                epoch: 1,
                ..next
            }),
            Err(NetError::InvalidPolicy)
        );
        assert_eq!(slot.rollback(0), Err(NetError::RollbackDenied));
        assert_eq!(slot.rollback(1).unwrap().epoch, 0);
    }

    #[test]
    fn every_error_has_stable_bilingual_text() {
        let errors = [
            NetError::InvalidVersion,
            NetError::InvalidIdentity,
            NetError::InvalidName,
            NetError::InvalidPort,
            NetError::InvalidPolicy,
            NetError::DuplicateEndpoint,
            NetError::NotFound,
            NetError::Revoked,
            NetError::CapacityExhausted,
            NetError::IdsExhausted,
            NetError::RightsDenied,
            NetError::CapabilityDenied,
            NetError::TransactionState,
            NetError::InDoubt,
            NetError::Expired,
            NetError::Cancelled,
            NetError::SignatureInvalid,
            NetError::RollbackDenied,
            NetError::WireTooShort,
        ];
        for error in errors {
            assert!(error.name().starts_with("system.net.error."));
            assert!(!error.display(false).is_empty());
            assert!(!error.display(true).is_empty());
        }
    }
}
