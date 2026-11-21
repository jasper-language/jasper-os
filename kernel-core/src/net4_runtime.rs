//! NET-4 bounded UDP socket runtime shared by Jasper network services.
//!
//! 职责：在 Jasper 网络服务层提供有界 UDP socket、接收队列、配额、世代句柄和关闭语义。
//! 边界：这里不实现 QUIC、TLS 或 WireGuard 协议；上层服务仍使用成熟库生成和消费
//! UDP 载荷，本模块只负责真实 Jasper 报文入口与 socket 生命周期。
//! Responsibility: provide bounded UDP socket lifecycle and datagram handoff for Jasper
//! services without implementing transport or cryptographic protocols.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Runtime UDP capacity admitted from the network device and service policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpLimits {
    pub max_sockets: usize,
    pub queue_depth: usize,
    pub max_datagram_bytes: usize,
}

impl UdpLimits {
    pub const fn new(max_sockets: usize, queue_depth: usize, max_datagram_bytes: usize) -> Self {
        Self {
            max_sockets,
            queue_depth,
            max_datagram_bytes,
        }
    }

    pub const fn valid(self) -> bool {
        self.max_sockets != 0
            && self.max_sockets <= u32::MAX as usize
            && self.queue_depth != 0
            && self.queue_depth <= u32::MAX as usize
            && self.max_datagram_bytes != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpAddress {
    pub ip: [u8; 4],
    pub port: u16,
}

impl UdpAddress {
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port }
    }

    fn valid(self) -> bool {
        self.ip != [0; 4] && self.port != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpRights(u8);

impl UdpRights {
    pub const NONE: Self = Self(0);
    pub const BIND: Self = Self(1 << 0);
    pub const RECEIVE: Self = Self(1 << 1);
    pub const SEND: Self = Self(1 << 2);
    pub const CLOSE: Self = Self(1 << 3);
    pub const SERVICE: Self = Self(Self::BIND.0 | Self::RECEIVE.0 | Self::SEND.0 | Self::CLOSE.0);

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpHandle {
    slot: u32,
    generation: u32,
}

impl UdpHandle {
    pub const fn slot(self) -> u32 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpRuntimeError {
    InvalidAddress,
    RightsDenied,
    Capacity,
    Quota,
    InvalidHandle,
    StaleGeneration,
    Closed,
    QueueEmpty,
    QueueFull,
    DatagramTooLarge,
    BufferTooSmall,
    IdsExhausted,
}

impl UdpRuntimeError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidAddress => "system.net.udp.error.invalid_address",
            Self::RightsDenied => "system.net.udp.error.rights",
            Self::Capacity => "system.net.udp.error.capacity",
            Self::Quota => "system.net.udp.error.quota",
            Self::InvalidHandle => "system.net.udp.error.invalid_handle",
            Self::StaleGeneration => "system.net.udp.error.stale_generation",
            Self::Closed => "system.net.udp.error.closed",
            Self::QueueEmpty => "system.net.udp.error.queue_empty",
            Self::QueueFull => "system.net.udp.error.queue_full",
            Self::DatagramTooLarge => "system.net.udp.error.datagram_too_large",
            Self::BufferTooSmall => "system.net.udp.error.buffer_too_small",
            Self::IdsExhausted => "system.net.udp.error.ids_exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpQuota {
    pub sockets: u32,
    pub datagrams: u32,
    pub bytes: u64,
    pub max_sockets: u32,
    pub max_datagrams: u32,
    pub max_bytes: u64,
}

impl UdpQuota {
    pub const fn new(max_sockets: u32, max_datagrams: u32, max_bytes: u64) -> Self {
        Self {
            sockets: 0,
            datagrams: 0,
            bytes: 0,
            max_sockets,
            max_datagrams,
            max_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpStats {
    pub active_sockets: u32,
    pub received_datagrams: u64,
    pub sent_datagrams: u64,
    pub queued_datagrams: u32,
    pub queued_bytes: u64,
    pub rejected_datagrams: u64,
}

struct Datagram {
    source: UdpAddress,
    bytes: Vec<u8>,
}

impl Datagram {
    fn new(source: UdpAddress, bytes: Vec<u8>) -> Self {
        Self { source, bytes }
    }
}

struct UdpSocket {
    handle: UdpHandle,
    local: UdpAddress,
    rights: UdpRights,
    queue: VecDeque<Datagram>,
    bytes: u64,
    active: bool,
}

impl UdpSocket {
    fn empty() -> Self {
        Self {
            handle: UdpHandle {
                slot: 0,
                generation: 0,
            },
            local: UdpAddress::new([0; 4], 0),
            rights: UdpRights::NONE,
            queue: VecDeque::new(),
            bytes: 0,
            active: false,
        }
    }
}

pub struct UdpSocketRuntime {
    sockets: Vec<UdpSocket>,
    limits: UdpLimits,
    quota: UdpQuota,
    next_id: u32,
    next_generation: u32,
    total_received: u64,
    total_sent: u64,
    rejected: u64,
}

impl UdpSocketRuntime {
    /// Allocates the admitted socket slots. Allocation failure is an auditable
    /// capacity rejection and leaves no runtime partially constructed.
    pub fn new(quota: UdpQuota, limits: UdpLimits) -> Result<Self, UdpRuntimeError> {
        if !limits.valid()
            || quota.max_sockets == 0
            || quota.max_sockets as usize > limits.max_sockets
        {
            return Err(UdpRuntimeError::Capacity);
        }
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(quota.max_sockets as usize)
            .map_err(|_| UdpRuntimeError::Capacity)?;
        for _ in 0..quota.max_sockets {
            sockets.push(UdpSocket::empty());
        }
        Ok(Self {
            sockets,
            limits,
            quota,
            next_id: 1,
            next_generation: 1,
            total_received: 0,
            total_sent: 0,
            rejected: 0,
        })
    }

    /// 绑定本地 IPv4 UDP 端口并返回带世代的句柄。
    ///
    /// Binds a local IPv4 UDP port and returns a generation-checked handle.
    pub fn bind(
        &mut self,
        local: UdpAddress,
        rights: UdpRights,
    ) -> Result<UdpHandle, UdpRuntimeError> {
        if !local.valid() {
            return Err(UdpRuntimeError::InvalidAddress);
        }
        if !rights.contains(UdpRights::BIND) {
            return Err(UdpRuntimeError::RightsDenied);
        }
        if self.quota.sockets >= self.quota.max_sockets {
            return Err(UdpRuntimeError::Quota);
        }
        if self
            .sockets
            .iter()
            .any(|socket| socket.active && socket.local == local)
        {
            return Err(UdpRuntimeError::Capacity);
        }
        let slot = self
            .sockets
            .iter()
            .position(|socket| !socket.active)
            .ok_or(UdpRuntimeError::Capacity)?;
        if self.next_id == 0 || self.next_id == u32::MAX {
            return Err(UdpRuntimeError::IdsExhausted);
        }
        if self.next_generation == 0 || self.next_generation == u32::MAX {
            return Err(UdpRuntimeError::IdsExhausted);
        }
        let handle = UdpHandle {
            slot: slot as u32,
            generation: self.next_generation,
        };
        self.next_id += 1;
        self.next_generation += 1;
        self.sockets[slot] = UdpSocket {
            handle,
            local,
            rights,
            ..UdpSocket::empty()
        };
        self.sockets[slot].active = true;
        self.quota.sockets += 1;
        Ok(handle)
    }

    /// 接收一个已解析的 UDP 数据报；所有配额和队列检查在提交前完成。
    ///
    /// Enqueues one parsed datagram after all quota and queue checks pass.
    pub fn receive(
        &mut self,
        source: UdpAddress,
        destination: UdpAddress,
        payload: &[u8],
    ) -> Result<UdpHandle, UdpRuntimeError> {
        if !source.valid() || !destination.valid() {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::InvalidAddress);
        }
        if payload.len() > self.limits.max_datagram_bytes {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::DatagramTooLarge);
        }
        let Some(slot) = self
            .sockets
            .iter()
            .position(|socket| socket.active && socket.local == destination)
        else {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::InvalidHandle);
        };
        let socket = &self.sockets[slot];
        if !socket.rights.contains(UdpRights::RECEIVE) {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::RightsDenied);
        }
        if socket.queue.len() == self.limits.queue_depth {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::QueueFull);
        }
        if self.quota.datagrams >= self.quota.max_datagrams
            || self
                .quota
                .bytes
                .checked_add(payload.len() as u64)
                .is_none_or(|bytes| bytes > self.quota.max_bytes)
        {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::Quota);
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(payload.len()).is_err() {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::Capacity);
        }
        bytes.extend_from_slice(payload);
        let socket = &mut self.sockets[slot];
        if socket.queue.try_reserve(1).is_err() {
            self.rejected = self.rejected.saturating_add(1);
            return Err(UdpRuntimeError::Capacity);
        }
        socket.queue.push_back(Datagram::new(source, bytes));
        socket.bytes += payload.len() as u64;
        self.total_received = self.total_received.saturating_add(1);
        self.quota.datagrams += 1;
        self.quota.bytes += payload.len() as u64;
        Ok(socket.handle)
    }

    /// 从 socket 接收队列复制一个数据报。
    ///
    /// Copies one queued datagram to the caller. A short output buffer leaves the datagram
    /// queued and all accounting unchanged.
    pub fn recv(
        &mut self,
        handle: UdpHandle,
        output: &mut [u8],
    ) -> Result<(UdpAddress, usize), UdpRuntimeError> {
        let slot = self.resolve(handle)?;
        let socket = &self.sockets[slot];
        if !socket.rights.contains(UdpRights::RECEIVE) {
            return Err(UdpRuntimeError::RightsDenied);
        }
        let Some(datagram) = socket.queue.front() else {
            return Err(UdpRuntimeError::QueueEmpty);
        };
        if output.len() < datagram.bytes.len() {
            return Err(UdpRuntimeError::BufferTooSmall);
        }
        output[..datagram.bytes.len()].copy_from_slice(&datagram.bytes);
        let len = datagram.bytes.len();
        let source = datagram.source;
        let socket = &mut self.sockets[slot];
        socket.queue.pop_front();
        socket.bytes -= len as u64;
        self.quota.datagrams -= 1;
        self.quota.bytes -= len as u64;
        Ok((source, len))
    }

    /// 验证一次发送并记录计数；线上 UDP 帧构造由网络后端完成。
    ///
    /// Validates a send and updates counters. The network backend owns wire construction.
    pub fn send(
        &mut self,
        handle: UdpHandle,
        destination: UdpAddress,
        payload: &[u8],
    ) -> Result<(), UdpRuntimeError> {
        if !destination.valid() {
            return Err(UdpRuntimeError::InvalidAddress);
        }
        if payload.len() > self.limits.max_datagram_bytes {
            return Err(UdpRuntimeError::DatagramTooLarge);
        }
        let slot = self.resolve(handle)?;
        let socket = &mut self.sockets[slot];
        if !socket.rights.contains(UdpRights::SEND) {
            return Err(UdpRuntimeError::RightsDenied);
        }
        self.total_sent = self.total_sent.saturating_add(1);
        Ok(())
    }

    /// 关闭 socket 并丢弃接收队列，归还全部配额。
    ///
    /// Closes a socket, drops queued datagrams, and returns every quota unit.
    pub fn close(&mut self, handle: UdpHandle) -> Result<(), UdpRuntimeError> {
        let slot = self.resolve(handle)?;
        if !self.sockets[slot].rights.contains(UdpRights::CLOSE) {
            return Err(UdpRuntimeError::RightsDenied);
        }
        let socket = &mut self.sockets[slot];
        self.quota.datagrams -= socket.queue.len() as u32;
        self.quota.bytes -= socket.bytes;
        socket.active = false;
        socket.rights = UdpRights::NONE;
        socket.queue.clear();
        socket.bytes = 0;
        self.quota.sockets -= 1;
        Ok(())
    }

    /// 撤销全部 socket；设备 reset 后旧句柄全部失效。
    ///
    /// Revokes every socket so device reset cannot leave stale ports active.
    pub fn revoke_all(&mut self) -> usize {
        let count = self.quota.sockets as usize;
        for socket in &mut self.sockets {
            socket.active = false;
            socket.rights = UdpRights::NONE;
            socket.queue.clear();
            socket.bytes = 0;
        }
        self.quota.sockets = 0;
        self.quota.datagrams = 0;
        self.quota.bytes = 0;
        count
    }

    pub const fn quota(&self) -> UdpQuota {
        self.quota
    }

    pub const fn limits(&self) -> UdpLimits {
        self.limits
    }

    pub fn stats(&self) -> UdpStats {
        let mut active = 0u32;
        for socket in &self.sockets {
            if socket.active {
                active += 1;
            }
        }
        UdpStats {
            active_sockets: active,
            received_datagrams: self.total_received,
            sent_datagrams: self.total_sent,
            queued_datagrams: self.quota.datagrams,
            queued_bytes: self.quota.bytes,
            rejected_datagrams: self.rejected,
        }
    }

    fn resolve(&self, handle: UdpHandle) -> Result<usize, UdpRuntimeError> {
        let slot = self
            .sockets
            .get(handle.slot as usize)
            .ok_or(UdpRuntimeError::InvalidHandle)?;
        if !slot.active {
            return Err(UdpRuntimeError::Closed);
        }
        if slot.handle.generation != handle.generation {
            return Err(UdpRuntimeError::StaleGeneration);
        }
        Ok(handle.slot as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> UdpAddress {
        UdpAddress::new([10, 0, 2, 2], 4433)
    }

    fn remote() -> UdpAddress {
        UdpAddress::new([10, 0, 2, 15], 49152)
    }

    #[test]
    fn bind_receive_send_close_and_generation_reuse_are_accounted() {
        let mut runtime =
            UdpSocketRuntime::new(UdpQuota::new(1, 2, 16), UdpLimits::new(2, 2, 16)).unwrap();
        let handle = runtime.bind(local(), UdpRights::SERVICE).unwrap();
        assert!(runtime.receive(remote(), local(), b"payload").is_ok());
        assert_eq!(runtime.stats().queued_bytes, 7);
        let mut short = [0u8; 3];
        assert_eq!(
            runtime.recv(handle, &mut short),
            Err(UdpRuntimeError::BufferTooSmall)
        );
        assert_eq!(runtime.stats().queued_datagrams, 1);
        let mut output = [0u8; 16];
        assert_eq!(runtime.recv(handle, &mut output), Ok((remote(), 7)));
        assert_eq!(&output[..7], b"payload");
        runtime.send(handle, remote(), b"reply").unwrap();
        runtime.close(handle).unwrap();
        assert_eq!(runtime.quota(), UdpQuota::new(1, 2, 16));
        assert_eq!(
            runtime.recv(handle, &mut output),
            Err(UdpRuntimeError::Closed)
        );

        let replacement = runtime.bind(local(), UdpRights::SERVICE).unwrap();
        assert_eq!(replacement.slot(), handle.slot());
        assert_ne!(replacement.generation(), handle.generation());
        assert_eq!(
            runtime.send(handle, remote(), b"x"),
            Err(UdpRuntimeError::StaleGeneration)
        );
    }

    #[test]
    fn rights_queue_quota_and_revoke_fail_without_partial_state() {
        let mut runtime =
            UdpSocketRuntime::new(UdpQuota::new(2, 2, 8), UdpLimits::new(2, 1, 8)).unwrap();
        let receive_only = runtime
            .bind(local(), UdpRights::BIND.union(UdpRights::RECEIVE))
            .unwrap();
        assert_eq!(
            runtime.send(receive_only, remote(), b"x"),
            Err(UdpRuntimeError::RightsDenied)
        );
        runtime.receive(remote(), local(), b"12345678").unwrap();
        assert_eq!(
            runtime.receive(remote(), local(), b"x"),
            Err(UdpRuntimeError::QueueFull)
        );
        assert_eq!(runtime.quota().datagrams, 1);

        let second = runtime
            .bind(UdpAddress::new([10, 0, 2, 2], 4434), UdpRights::SERVICE)
            .unwrap();
        assert_eq!(runtime.revoke_all(), 2);
        assert_eq!(runtime.quota(), UdpQuota::new(2, 2, 8));
        assert_eq!(
            runtime.stats(),
            UdpStats {
                active_sockets: 0,
                received_datagrams: 1,
                sent_datagrams: 0,
                queued_datagrams: 0,
                queued_bytes: 0,
                rejected_datagrams: 1,
            }
        );
        assert_eq!(
            runtime.send(second, remote(), b"x"),
            Err(UdpRuntimeError::Closed)
        );
    }

    #[test]
    fn duplicate_bind_and_invalid_address_are_rejected_atomically() {
        let mut runtime =
            UdpSocketRuntime::new(UdpQuota::new(2, 1, 8), UdpLimits::new(2, 1, 8)).unwrap();
        assert_eq!(
            runtime.bind(UdpAddress::new([0; 4], 4433), UdpRights::SERVICE),
            Err(UdpRuntimeError::InvalidAddress)
        );
        runtime.bind(local(), UdpRights::SERVICE).unwrap();
        assert_eq!(
            runtime.bind(local(), UdpRights::SERVICE),
            Err(UdpRuntimeError::Capacity)
        );
        assert_eq!(runtime.quota().sockets, 1);
    }

    #[test]
    fn admitted_jumbo_datagram_and_deeper_queue_are_not_compile_time_limits() {
        let mut runtime =
            UdpSocketRuntime::new(UdpQuota::new(1, 6, 20_000), UdpLimits::new(1, 6, 9_000))
                .unwrap();
        let handle = runtime.bind(local(), UdpRights::SERVICE).unwrap();
        let payload = vec![0x5a; 2_000];
        for _ in 0..5 {
            runtime
                .receive(remote(), local(), &payload)
                .expect("queue depths above four must be admitted");
        }
        let mut output = vec![0u8; payload.len()];
        let (_, len) = runtime.recv(handle, &mut output).unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(output, payload);
        assert_eq!(runtime.quota().datagrams, 4);
        assert_eq!(runtime.limits(), UdpLimits::new(1, 6, 9_000));
    }

    #[test]
    fn mtu_boundary_rejects_one_extra_byte_without_quota_change() {
        let mut runtime =
            UdpSocketRuntime::new(UdpQuota::new(1, 1, 8), UdpLimits::new(1, 1, 8)).unwrap();
        let handle = runtime.bind(local(), UdpRights::SERVICE).unwrap();
        runtime.receive(remote(), local(), b"12345678").unwrap();
        let before = runtime.quota();
        let stats_before = runtime.stats();
        assert_eq!(
            runtime.receive(remote(), local(), b"123456789"),
            Err(UdpRuntimeError::DatagramTooLarge)
        );
        assert_eq!(runtime.quota(), before);
        assert_eq!(runtime.stats().queued_datagrams, stats_before.queued_datagrams);
        assert_eq!(runtime.stats().rejected_datagrams, stats_before.rejected_datagrams + 1);

        let mut output = [0u8; 8];
        assert_eq!(runtime.recv(handle, &mut output), Ok((remote(), 8)));
        assert_eq!(&output, b"12345678");
    }
}
