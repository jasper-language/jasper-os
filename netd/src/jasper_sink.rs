//! Bridge from the hosted netd driver to the bounded Jasper UDP runtime.
//!
//! 职责：把 netd 生成的协议数据报交给 Jasper `UdpSocketRuntime`，由 socket
//! 的 Rights、配额、世代和关闭语义统一管理。
//! 边界：该适配器不创建操作系统 socket，也不把宿主 localhost 当作 Jasper 网络路径。
//! Responsibility: route mature-protocol datagrams through Jasper socket lifecycle rules.

use jasper_kernel_core::net4_runtime::{
    UdpAddress, UdpHandle, UdpRuntimeError, UdpSocketRuntime,
};

use crate::wireguard_driver::DatagramSink;

/// A `DatagramSink` borrowing one bound Jasper UDP socket.
///
/// 借用已绑定 Jasper UDP socket 的数据报发送端。
pub struct JasperUdpSink<'a, const S: usize, const Q: usize> {
    runtime: &'a mut UdpSocketRuntime<S, Q>,
    socket: UdpHandle,
    remote: UdpAddress,
}

impl<'a, const S: usize, const Q: usize> JasperUdpSink<'a, S, Q> {
    pub const fn new(
        runtime: &'a mut UdpSocketRuntime<S, Q>,
        socket: UdpHandle,
        remote: UdpAddress,
    ) -> Self {
        Self {
            runtime,
            socket,
            remote,
        }
    }
}

impl<const S: usize, const Q: usize> DatagramSink for JasperUdpSink<'_, S, Q> {
    fn send(&mut self, datagram: &[u8]) -> Result<(), &'static str> {
        self.runtime
            .send(self.socket, self.remote, datagram)
            .map_err(udp_error_name)
    }
}

fn udp_error_name(error: UdpRuntimeError) -> &'static str {
    match error {
        UdpRuntimeError::InvalidAddress => "Jasper UDP address is invalid",
        UdpRuntimeError::RightsDenied => "Jasper UDP send right is missing",
        UdpRuntimeError::Capacity => "Jasper UDP capacity is exhausted",
        UdpRuntimeError::Quota => "Jasper UDP quota is exhausted",
        UdpRuntimeError::InvalidHandle => "Jasper UDP socket handle is invalid",
        UdpRuntimeError::StaleGeneration => "Jasper UDP socket generation is stale",
        UdpRuntimeError::Closed => "Jasper UDP socket is closed",
        UdpRuntimeError::QueueEmpty => "Jasper UDP receive queue is empty",
        UdpRuntimeError::QueueFull => "Jasper UDP receive queue is full",
        UdpRuntimeError::DatagramTooLarge => "datagram exceeds the Jasper UDP limit",
        UdpRuntimeError::BufferTooSmall => "Jasper UDP output buffer is too small",
        UdpRuntimeError::IdsExhausted => "Jasper UDP identity space is exhausted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jasper_kernel_core::net4_runtime::{UdpQuota, UdpRights};
    use jasper_kernel_core::wireguard::{
        testing::DeterministicRng, Config, StaticSecret,
    };

    use crate::wireguard_driver::{WireGuardAction, WireGuardPeer};

    #[test]
    fn wireguard_driver_uses_bound_jasper_socket_and_returns_quota_on_close() {
        let local = UdpAddress::new([10, 0, 0, 1], 51820);
        let remote = UdpAddress::new([10, 0, 0, 2], 51820);
        let mut runtime = UdpSocketRuntime::<1, 1>::new(UdpQuota::new(1, 1, 2048));
        let socket = runtime.bind(local, UdpRights::SERVICE).unwrap();
        let mut keys = DeterministicRng::new(0x4a53_504e_4554_4453);
        let local_key = StaticSecret::generate(&mut keys).unwrap();
        let peer_key = StaticSecret::generate(&mut keys).unwrap();
        let mut peer =
            WireGuardPeer::new(Config::new(local_key, peer_key.public_key())).unwrap();
        let mut rng = DeterministicRng::new(7);
        let mut output = [0u8; 2048];
        let now = jasper_kernel_core::wireguard::Now::new(0, 1_700_000_000, 0);
        {
            let mut sink = JasperUdpSink::new(&mut runtime, socket, remote);
            assert!(matches!(
                peer.encapsulate_to(now, b"payload", &mut output, &mut rng, &mut sink)
                    .unwrap(),
                WireGuardAction::HandshakeInitiation
            ));
        }
        assert_eq!(peer.sent_datagrams(), 1);
        assert_eq!(runtime.stats().sent_datagrams, 1);
        runtime.close(socket).unwrap();
        assert_eq!(runtime.quota().sockets, 0);
    }
}
