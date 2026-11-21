//! Hosted network service adapters over Jasper UDP sockets and mature protocols.
//!
//! 职责：把成熟的 WireGuard sans-I/O 状态机绑定到 Jasper 有界 UDP socket、
//! 对端路由、数据报准入、关闭和设备复位生命周期。
//! 边界：本模块不实现任何密码学或 WireGuard 报文格式，也不冒充外部用户态进程；
//! 实际网络帧由网络后端根据返回的 datagram buffer 发送。
//! Responsibility: bind the mature WireGuard protocol state machine to Jasper UDP
//! sockets without implementing protocol cryptography or external process hosting.

use crate::net4_runtime::{
    UdpAddress, UdpHandle, UdpLimits, UdpQuota, UdpRights, UdpRuntimeError, UdpSocketRuntime,
    UdpStats,
};
use crate::service_events::{self, Source as ServiceEventSource};
use crate::wireguard::{
    Config, Encapsulated, EntropySource, Error as WireGuardError, Now, PollOutput, Received,
    Stats as WireGuardStats, Tunnel,
};
use alloc::vec::Vec;

const MAX_POLL_STEPS: usize = 16; // JASPER-HARDCODE-REVIEW: issue=35 source=net4-poll-policy reason=bounded-service-poll-progress

/// 服务与 UDP socket 集成失败的原因。
///
/// Failure categories returned by the hosted service adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetServiceError {
    Udp(UdpRuntimeError),
    Protocol(WireGuardError),
    UnexpectedPeer,
    Inactive,
    PollLimit,
    InvalidEventIdentity,
    EventCapacity,
}

impl From<UdpRuntimeError> for NetServiceError {
    fn from(value: UdpRuntimeError) -> Self {
        Self::Udp(value)
    }
}

impl From<WireGuardError> for NetServiceError {
    fn from(value: WireGuardError) -> Self {
        Self::Protocol(value)
    }
}

/// 一次封装产生的报文类别。
///
/// The category of a datagram produced by encapsulation or timer polling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireGuardEmit {
    Transport,
    HandshakeInitiation,
}

/// 一次解封装得到的服务事件。
///
/// A service event produced by one authenticated input datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireGuardReceive<'a> {
    Data(usize),
    Keepalive,
    Reply(&'a [u8]),
    HandshakeComplete,
    CookieStored,
}

/// 绑定一个本地 UDP socket 和一个 WireGuard 对端的 hosted service 核心。
///
/// A hosted-service core binding one local UDP socket to one WireGuard peer. Datagram
/// buffers remain caller-owned; internal reconstruction buffers are bounded by
/// the admitted runtime limits and never bypass socket quotas.
pub struct WireGuardService {
    runtime: UdpSocketRuntime,
    socket: UdpHandle,
    local: UdpAddress,
    remote: UdpAddress,
    tunnel: Tunnel,
    active: bool,
    events: Option<ServiceEventSource>,
}

impl WireGuardService {
    /// 创建服务并绑定本地 UDP 端口。
    ///
    /// Creates the service and binds its local UDP address with explicit quota.
    pub fn new(
        config: Config,
        local: UdpAddress,
        remote: UdpAddress,
        quota: UdpQuota,
        limits: UdpLimits,
    ) -> Result<Self, NetServiceError> {
        Self::new_inner(config, local, remote, quota, limits, None)
    }

    pub fn new_with_events(
        config: Config,
        local: UdpAddress,
        remote: UdpAddress,
        quota: UdpQuota,
        limits: UdpLimits,
        event_identity: service_events::Identity,
    ) -> Result<Self, NetServiceError> {
        if event_identity.kind != service_events::ServiceKind::Network {
            return Err(NetServiceError::InvalidEventIdentity);
        }
        let events = ServiceEventSource::new(event_identity)
            .map_err(|_| NetServiceError::InvalidEventIdentity)?;
        Self::new_inner(config, local, remote, quota, limits, Some(events))
    }

    fn new_inner(
        config: Config,
        local: UdpAddress,
        remote: UdpAddress,
        quota: UdpQuota,
        limits: UdpLimits,
        events: Option<ServiceEventSource>,
    ) -> Result<Self, NetServiceError> {
        if remote.ip == local.ip && remote.port == local.port {
            return Err(NetServiceError::UnexpectedPeer);
        }
        let mut runtime = UdpSocketRuntime::new(quota, limits)?;
        let socket = runtime.bind(local, UdpRights::SERVICE)?;
        let tunnel = Tunnel::new(config)?;
        Ok(Self {
            runtime,
            socket,
            local,
            remote,
            tunnel,
            active: true,
            events,
        })
    }

    pub const fn event_source(&self) -> Option<&ServiceEventSource> {
        self.events.as_ref()
    }

    pub const fn local(&self) -> UdpAddress {
        self.local
    }

    pub const fn remote(&self) -> UdpAddress {
        self.remote
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// 向当前 socket 投递一个外部接收报文，验证来源后才进入队列。
    ///
    /// Delivers one externally received datagram to the bound socket after checking its peer.
    pub fn deliver(&mut self, source: UdpAddress, datagram: &[u8]) -> Result<(), NetServiceError> {
        if !self.active {
            return Err(NetServiceError::Inactive);
        }
        if source != self.remote {
            return Err(NetServiceError::UnexpectedPeer);
        }
        self.runtime.receive(source, self.local, datagram)?;
        Ok(())
    }

    /// 封装一个待发送负载；首次调用通常在无会话时产生握手发起报文。
    ///
    /// Encapsulates one payload. Without a usable session the mature library emits a handshake
    /// initiation and does not consume the payload; the caller retries after handshake completion.
    pub fn encapsulate<'a>(
        &mut self,
        now: Now,
        payload: &[u8],
        output: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(WireGuardEmit, &'a [u8]), NetServiceError> {
        if !self.active {
            return Err(NetServiceError::Inactive);
        }
        let result = match self.tunnel.encapsulate(now, payload, output, rng)? {
            Encapsulated::Transport(wire) => (WireGuardEmit::Transport, wire),
            Encapsulated::HandshakeInitiation(wire) => (WireGuardEmit::HandshakeInitiation, wire),
        };
        self.runtime.send(self.socket, self.remote, result.1)?;
        Ok(result)
    }

    /// 从 socket 队列取出一个报文并完成认证解密。
    ///
    /// Dequeues one datagram from the Jasper socket and authenticates it with the mature
    /// WireGuard state machine. Reply datagrams are immediately admitted to the send path.
    pub fn receive<'a>(
        &mut self,
        now: Now,
        plaintext: &'a mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<WireGuardReceive<'a>, NetServiceError> {
        if !self.active {
            return Err(NetServiceError::Inactive);
        }
        let mut wire = Vec::new();
        wire.try_reserve_exact(self.runtime.limits().max_datagram_bytes)
            .map_err(|_| NetServiceError::Udp(UdpRuntimeError::Capacity))?;
        wire.resize(self.runtime.limits().max_datagram_bytes, 0);
        let (source, wire_len) = self.runtime.recv(self.socket, &mut wire)?;
        if source != self.remote {
            return Err(NetServiceError::UnexpectedPeer);
        }
        let received: Result<WireGuardReceive<'a>, NetServiceError> = match self.tunnel.decapsulate(
            now,
            &self.remote.ip,
            false,
            &wire[..wire_len],
            plaintext,
            rng,
        )? {
            Received::Data(data) => Ok(WireGuardReceive::Data(data.len())),
            Received::Keepalive => Ok(WireGuardReceive::Keepalive),
            Received::Reply(reply) => {
                self.runtime.send(self.socket, self.remote, reply)?;
                Ok(WireGuardReceive::Reply(reply))
            }
            Received::HandshakeComplete => Ok(WireGuardReceive::HandshakeComplete),
            Received::CookieStored => Ok(WireGuardReceive::CookieStored),
        };
        let received = received?;
        if let Some(events) = self.events.as_mut() {
            let value = match received {
                WireGuardReceive::Data(bytes) => bytes as u64,
                WireGuardReceive::Keepalive => 2,
                WireGuardReceive::Reply(_) => 3,
                WireGuardReceive::HandshakeComplete => 4,
                WireGuardReceive::CookieStored => 5,
            };
            events
                .publish(value)
                .map_err(|_| NetServiceError::EventCapacity)?;
        }
        Ok(received)
    }

    /// 执行成熟状态机在 `now` 时刻要求的定时发送工作。
    ///
    /// Performs timer-driven handshake, rekey and keepalive work emitted by the mature state
    /// machine. The loop is explicitly bounded so a malformed clock cannot stall a service.
    pub fn poll(
        &mut self,
        now: Now,
        output: &mut [u8],
        rng: &mut dyn EntropySource,
    ) -> Result<usize, NetServiceError> {
        if !self.active {
            return Err(NetServiceError::Inactive);
        }
        let mut sent = 0;
        for _ in 0..MAX_POLL_STEPS {
            match self.tunnel.poll(now, output, rng)? {
                PollOutput::Send(wire, _) => {
                    self.runtime.send(self.socket, self.remote, wire)?;
                    sent += 1;
                }
                PollOutput::HandshakeExpired | PollOutput::SessionsExpired | PollOutput::Idle => {
                    return Ok(sent)
                }
            }
        }
        Err(NetServiceError::PollLimit)
    }

    pub fn next_wake(&self) -> Option<crate::wireguard::Ticks> {
        self.tunnel.next_wake()
    }

    pub fn udp_stats(&self) -> UdpStats {
        self.runtime.stats()
    }

    pub fn quota(&self) -> UdpQuota {
        self.runtime.quota()
    }

    pub fn protocol_stats(&self) -> WireGuardStats {
        self.tunnel.stats()
    }

    /// 关闭 socket；旧 socket 句柄与队列随配额一并撤销。
    ///
    /// Closes the socket and returns all queued datagram and socket quota.
    pub fn close(&mut self) -> Result<(), NetServiceError> {
        if !self.active {
            return Err(NetServiceError::Inactive);
        }
        if self
            .events
            .as_ref()
            .is_some_and(|events| !events.can_publish())
        {
            return Err(NetServiceError::EventCapacity);
        }
        self.runtime.close(self.socket)?;
        self.active = false;
        if let Some(events) = self.events.as_mut() {
            events
                .terminate(1)
                .expect("checked network close event publication");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::testing::DeterministicRng;
    use crate::wireguard::StaticSecret;

    fn address(octet: u8) -> UdpAddress {
        UdpAddress::new([10, 0, 0, octet], 51820)
    }

    fn ipv4_packet(payload: &[u8]) -> ([u8; 64], usize) {
        let mut packet = [0u8; 64];
        let total = 20 + payload.len();
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..total].copy_from_slice(payload);
        (packet, total)
    }

    #[test]
    fn hosted_wireguard_service_handshake_data_and_close_use_udp_runtime() {
        let mut key_rng = DeterministicRng::new(0x4e45_5434_5345_5256);
        let a_key = StaticSecret::generate(&mut key_rng).unwrap();
        let b_key = StaticSecret::generate(&mut key_rng).unwrap();
        let a_public = a_key.public_key();
        let b_public = b_key.public_key();
        let quota = UdpQuota::new(2, 4, 4096);
        let limits = UdpLimits::new(2, 4, 1200);
        let event_identity =
            service_events::Identity::new(service_events::ServiceKind::Network, 1, 1).unwrap();
        let mut a = WireGuardService::new_with_events(
            Config::new(a_key, b_public),
            address(1),
            address(2),
            quota,
            limits,
            event_identity,
        )
        .unwrap();
        let observed = a.event_source().unwrap().identity();
        let initial = a.event_source().unwrap().snapshot();
        let mut subscriber =
            crate::subscription::Queue::<2>::new(initial, crate::subscription::Policy::Events);
        let mut b = WireGuardService::new(
            Config::new(b_key, a_public),
            address(2),
            address(1),
            quota,
            limits,
        )
        .unwrap();
        let now = Now::new(0, 1_700_000_000, 0);
        let mut rng = DeterministicRng::new(9);
        let mut a_wire = [0u8; 1200];
        let mut plaintext = [0u8; 2048];
        let (packet, packet_len) = ipv4_packet(b"service");

        let (action, initiation) = a
            .encapsulate(now, &packet[..packet_len], &mut a_wire, &mut rng)
            .unwrap();
        assert_eq!(action, WireGuardEmit::HandshakeInitiation);
        b.deliver(a.local(), initiation).unwrap();
        let reply = match b.receive(now, &mut plaintext, &mut rng).unwrap() {
            WireGuardReceive::Reply(reply) => reply,
            other => panic!("expected WireGuard reply, got {other:?}"),
        };
        a.deliver(b.local(), reply).unwrap();
        assert_eq!(
            a.receive(now, &mut plaintext, &mut rng).unwrap(),
            WireGuardReceive::HandshakeComplete
        );
        service_events::publish(a.event_source().unwrap(), observed, &mut subscriber).unwrap();
        assert_eq!(
            subscriber.take(),
            Some(crate::subscription::Delivery::Event(
                crate::subscription::Event {
                    first: 1,
                    last: 1,
                    value: 4
                }
            ))
        );

        let (action, transport) = a
            .encapsulate(now, &packet[..packet_len], &mut a_wire, &mut rng)
            .unwrap();
        assert_eq!(action, WireGuardEmit::Transport);
        b.deliver(a.local(), transport).unwrap();
        let data_len = match b.receive(now, &mut plaintext, &mut rng).unwrap() {
            WireGuardReceive::Data(len) => len,
            other => panic!("expected WireGuard data, got {other:?}"),
        };
        assert_eq!(&plaintext[..packet_len], &packet[..packet_len]);
        assert!(data_len >= packet_len);
        assert_eq!(a.udp_stats().sent_datagrams, 2);
        assert_eq!(b.udp_stats().received_datagrams, 2);

        a.close().unwrap();
        service_events::publish(a.event_source().unwrap(), observed, &mut subscriber).unwrap();
        assert_eq!(
            subscriber.take(),
            Some(crate::subscription::Delivery::Event(
                crate::subscription::Event {
                    first: 2,
                    last: 2,
                    value: 1
                }
            ))
        );
        assert!(a.event_source().unwrap().is_closed());
        assert!(!a.is_active());
        assert_eq!(a.quota().sockets, 0);
        assert_eq!(a.quota().datagrams, 0);
        assert_eq!(a.quota().bytes, 0);
    }

    #[test]
    fn unexpected_peer_and_inactive_service_fail_without_queueing() {
        let mut key_rng = DeterministicRng::new(0x4e45_5434_5045_4552);
        let local_key = StaticSecret::generate(&mut key_rng).unwrap();
        let peer_key = StaticSecret::generate(&mut key_rng).unwrap();
        let mut service = WireGuardService::new(
            Config::new(local_key, peer_key.public_key()),
            address(1),
            address(2),
            UdpQuota::new(1, 1, 1200),
            UdpLimits::new(1, 1, 1200),
        )
        .unwrap();
        assert_eq!(
            service.deliver(address(3), b"rejected"),
            Err(NetServiceError::UnexpectedPeer)
        );
        assert_eq!(service.udp_stats().received_datagrams, 0);
        service.close().unwrap();
        assert_eq!(
            service.deliver(address(2), b"closed"),
            Err(NetServiceError::Inactive)
        );
    }
}
