//! NET-0 network objects, schema, policy and transaction boundary.
//!
//! This module stops below sockets and protocol parsing. It defines the stable
//! identities, deny-by-default policy projection and failure-atomic namespace
//! operations consumed by NET-1 and later protocol layers.

use crate::object::Rights;

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

impl NetworkPolicy {
    pub fn compile(bytes: [u8; 32]) -> Result<Self, NetError> {
        let header = NetWireHeader::decode(bytes[..NET_WIRE_HEADER_BYTES].try_into().unwrap())?;
        if header.bytes != 32
            || bytes[16..18].iter().any(|byte| *byte != 0)
            || bytes[22..32].iter().any(|byte| *byte != 0)
        {
            return Err(NetError::InvalidPolicy);
        }
        let allowed = NetCapabilities::from_bits(u16::from_le_bytes([bytes[18], bytes[19]]))
            .ok_or(NetError::InvalidPolicy)?;
        let required = NetCapabilities::from_bits(u16::from_le_bytes([bytes[20], bytes[21]]))
            .ok_or(NetError::InvalidPolicy)?;
        if !allowed.contains(required) {
            return Err(NetError::InvalidPolicy);
        }
        Ok(Self {
            version: header.version,
            allowed,
            required,
            epoch: 0,
        })
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

    const POLICY_BYTES: usize = 32;

    fn policy(allowed: NetCapabilities, required: NetCapabilities) -> NetworkPolicy {
        let mut bytes = [0u8; POLICY_BYTES];
        bytes[..NET_WIRE_HEADER_BYTES]
            .copy_from_slice(&NetWireHeader::new(POLICY_BYTES).encode());
        bytes[18..20].copy_from_slice(&allowed.bits().to_le_bytes());
        bytes[20..22].copy_from_slice(&required.bits().to_le_bytes());
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
        bytes[18..20].copy_from_slice(&NetCapabilities::CONNECT.bits().to_le_bytes());
        bytes[20..22].copy_from_slice(&NetCapabilities::SEND.bits().to_le_bytes());
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
        ];
        for error in errors {
            assert!(error.name().starts_with("system.net.error."));
            assert!(!error.display(false).is_empty());
            assert!(!error.display(true).is_empty());
        }
    }
}
