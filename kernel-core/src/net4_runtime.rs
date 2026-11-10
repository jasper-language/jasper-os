//! NET-4 bounded UDP socket runtime shared by Jasper network services.
//!
//! 职责：在 Jasper 网络服务层提供有界 UDP socket、接收队列、配额、世代句柄和关闭语义。
//! 边界：这里不实现 QUIC、TLS 或 WireGuard 协议；上层服务仍使用成熟库生成和消费
//! UDP 载荷，本模块只负责真实 Jasper 报文入口与 socket 生命周期。
//! Responsibility: provide bounded UDP socket lifecycle and datagram handoff for Jasper
//! services without implementing transport or cryptographic protocols.

pub const MAX_UDP_DATAGRAM_BYTES: usize = 1200;
pub const DEFAULT_UDP_SOCKETS: usize = 4;
pub const DEFAULT_UDP_QUEUE: usize = 4;

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
    pub const SERVICE: Self = Self(
        Self::BIND.0 | Self::RECEIVE.0 | Self::SEND.0 | Self::CLOSE.0,
    );

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

#[derive(Clone, Copy)]
struct Datagram {
    source: UdpAddress,
    bytes: [u8; MAX_UDP_DATAGRAM_BYTES],
    len: usize,
}

impl Datagram {
    const EMPTY: Self = Self {
        source: UdpAddress::new([0; 4], 0),
        bytes: [0; MAX_UDP_DATAGRAM_BYTES],
        len: 0,
    };
}

#[derive(Clone, Copy)]
struct UdpSocket<const Q: usize> {
    handle: UdpHandle,
    local: UdpAddress,
    rights: UdpRights,
    queue: [Datagram; Q],
    queue_len: usize,
    bytes: u64,
    active: bool,
}

impl<const Q: usize> UdpSocket<Q> {
    const EMPTY: Self = Self {
        handle: UdpHandle {
            slot: 0,
            generation: 0,
        },
        local: UdpAddress::new([0; 4], 0),
        rights: UdpRights::NONE,
        queue: [Datagram::EMPTY; Q],
        queue_len: 0,
        bytes: 0,
        active: false,
    };
}

pub struct UdpSocketRuntime<
    const S: usize = DEFAULT_UDP_SOCKETS,
    const Q: usize = DEFAULT_UDP_QUEUE,
> {
    sockets: [UdpSocket<Q>; S],
    quota: UdpQuota,
    next_id: u32,
    next_generation: u32,
    total_received: u64,
    total_sent: u64,
    rejected: u64,
}

impl<const S: usize, const Q: usize> UdpSocketRuntime<S, Q> {
    pub const fn new(quota: UdpQuota) -> Self {
        Self {
            sockets: [UdpSocket::EMPTY; S],
            quota,
            next_id: 1,
            next_generation: 1,
            total_received: 0,
            total_sent: 0,
            rejected: 0,
        }
    }

    /// 绑定本地 IPv4 UDP 端口并返回带世代的句柄。
    ///
    /// Binds a local IPv4 UDP port and returns a generation-checked handle.
    pub fn bind(&mut self, local: UdpAddress, rights: UdpRights) -> Result<UdpHandle, UdpRuntimeError> {
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
            ..UdpSocket::EMPTY
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
        if payload.len() > MAX_UDP_DATAGRAM_BYTES {
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
        if socket.queue_len == Q {
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
        let socket = &mut self.sockets[slot];
        let mut datagram = Datagram {
            source,
            ..Datagram::EMPTY
        };
        datagram.bytes[..payload.len()].copy_from_slice(payload);
        datagram.len = payload.len();
        socket.queue[socket.queue_len] = datagram;
        socket.queue_len += 1;
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
        let Some(datagram) = socket.queue[..socket.queue_len].first().copied() else {
            return Err(UdpRuntimeError::QueueEmpty);
        };
        if output.len() < datagram.len {
            return Err(UdpRuntimeError::BufferTooSmall);
        }
        output[..datagram.len].copy_from_slice(&datagram.bytes[..datagram.len]);
        let socket = &mut self.sockets[slot];
        socket.queue[socket.queue_len - 1] = Datagram::EMPTY;
        socket.queue.copy_within(1..socket.queue_len, 0);
        socket.queue_len -= 1;
        socket.bytes -= datagram.len as u64;
        self.quota.datagrams -= 1;
        self.quota.bytes -= datagram.len as u64;
        Ok((datagram.source, datagram.len))
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
        if payload.len() > MAX_UDP_DATAGRAM_BYTES {
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
        self.quota.datagrams -= socket.queue_len as u32;
        self.quota.bytes -= socket.bytes;
        socket.active = false;
        socket.rights = UdpRights::NONE;
        socket.queue = [Datagram::EMPTY; Q];
        socket.queue_len = 0;
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
            socket.queue = [Datagram::EMPTY; Q];
            socket.queue_len = 0;
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
        let mut runtime = UdpSocketRuntime::<2, 2>::new(UdpQuota::new(1, 2, 16));
        let handle = runtime.bind(local(), UdpRights::SERVICE).unwrap();
        assert!(runtime
            .receive(remote(), local(), b"payload")
            .is_ok());
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
        assert_eq!(runtime.recv(handle, &mut output), Err(UdpRuntimeError::Closed));

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
        let mut runtime = UdpSocketRuntime::<2, 1>::new(UdpQuota::new(2, 2, 8));
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
        assert_eq!(runtime.stats(), UdpStats {
            active_sockets: 0,
            received_datagrams: 1,
            sent_datagrams: 0,
            queued_datagrams: 0,
            queued_bytes: 0,
            rejected_datagrams: 1,
        });
        assert_eq!(runtime.send(second, remote(), b"x"), Err(UdpRuntimeError::Closed));
    }

    #[test]
    fn duplicate_bind_and_invalid_address_are_rejected_atomically() {
        let mut runtime = UdpSocketRuntime::<2, 1>::new(UdpQuota::new(2, 1, 8));
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
}
