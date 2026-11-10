//! NET-4 no_std UDP socket runtime acceptance.
//!
//! 职责：在真实 Jasper QEMU 启动中让完整 UDP 帧经过 virtio-net 后端、运行时 socket、
//! 配额和回复构造路径。边界：不启动 Quinn/rustls hosted 服务，也不代表真实网卡互通。
//! Responsibility: exercise the real UDP frame and socket runtime path inside Jasper while
//! keeping hosted QUIC/WireGuard deployment and physical networking as separate gates.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::net1a::{EthernetFrame, parse_ethernet_payload};
use kernel_core::net1b::UdpDatagram;
use kernel_core::net4_runtime::{
    UdpAddress, UdpQuota, UdpRights, UdpRuntimeError, UdpSocketRuntime,
};
use kernel_core::net4_service::{
    WireGuardEmit, WireGuardReceive, WireGuardService,
};
use kernel_core::virtio_net::{TransmitOutcome, VirtioNetBackend};
use kernel_core::wireguard::{
    testing::DeterministicRng, Config, Now, StaticSecret,
};

use crate::kprintln;

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-NET4-RUNTIME-FAIL] stage={}", stage);
    }
}

fn udp_frame(payload: &[u8]) -> [u8; 46] {
    let mut frame = [0u8; 46];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip_len = 28 + payload.len();
    let ip = &mut frame[14..14 + ip_len];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 0, 2, 15]);
    ip[16..20].copy_from_slice(&[10, 0, 2, 1]);
    let ip_sum = kernel_core::net1a::internet_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    let udp = &mut ip[20..];
    udp[0..2].copy_from_slice(&49152u16.to_be_bytes());
    udp[2..4].copy_from_slice(&4433u16.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let udp_sum = kernel_core::net1b::ipv4_transport_checksum(
        [10, 0, 2, 15],
        [10, 0, 2, 1],
        kernel_core::net1a::IpProtocol::Udp,
        udp,
    );
    udp[6..8].copy_from_slice(&udp_sum.to_be_bytes());
    frame
}

fn verify_wireguard_service() -> bool {
    let mut keys = DeterministicRng::new(0x4e45_5434_5345_5256);
    let a_key = match StaticSecret::generate(&mut keys) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let b_key = match StaticSecret::generate(&mut keys) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let a_public = a_key.public_key();
    let b_public = b_key.public_key();
    let quota = UdpQuota::new(1, 1, 1200);
    let mut a = match WireGuardService::<1, 1>::new(
        Config::new(a_key, b_public),
        UdpAddress::new([10, 0, 3, 1], 51820),
        UdpAddress::new([10, 0, 3, 2], 51820),
        quota,
    ) {
        Ok(service) => service,
        Err(_) => return false,
    };
    let mut b = match WireGuardService::<1, 1>::new(
        Config::new(b_key, a_public),
        UdpAddress::new([10, 0, 3, 2], 51820),
        UdpAddress::new([10, 0, 3, 1], 51820),
        quota,
    ) {
        Ok(service) => service,
        Err(_) => return false,
    };
    let now = Now::new(0, 1_700_000_000, 0);
    let mut rng = DeterministicRng::new(9);
    let mut a_wire = [0u8; kernel_core::net4_runtime::MAX_UDP_DATAGRAM_BYTES];
    let mut plaintext = [0u8; 2048];
    let mut packet = [0u8; 64];
    let total = 26usize;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 3, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 3, 2]);
    packet[20..total].copy_from_slice(b"wg-e2e");
    let ip_sum = kernel_core::net1a::internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    match a.encapsulate(now, &packet[..total], &mut a_wire, &mut rng) {
        Ok((WireGuardEmit::HandshakeInitiation, wire)) => {
            if b.deliver(a.local(), wire).is_err() {
                return false;
            }
        }
        _ => return false,
    }
    match b.receive(now, &mut plaintext, &mut rng) {
        Ok(WireGuardReceive::Reply(reply)) => {
            if a.deliver(b.local(), reply).is_err() {
                return false;
            }
        }
        _ => return false,
    }
    if a.receive(now, &mut plaintext, &mut rng)
        != Ok(WireGuardReceive::HandshakeComplete)
    {
        return false;
    }
    match a.encapsulate(now, &packet[..total], &mut a_wire, &mut rng) {
        Ok((WireGuardEmit::Transport, wire)) => {
            if b.deliver(a.local(), wire).is_err() {
                return false;
            }
        }
        _ => return false,
    }
    let data_len = match b.receive(now, &mut plaintext, &mut rng) {
        Ok(WireGuardReceive::Data(len)) => len,
        _ => return false,
    };
    if data_len < total || &plaintext[..total] != &packet[..total] {
        return false;
    }
    if a.close().is_err() || b.close().is_err() {
        return false;
    }
    let a_quota = a.quota();
    let b_quota = b.quota();
    a_quota.sockets == 0
        && b_quota.sockets == 0
        && a_quota.datagrams == 0
        && b_quota.datagrams == 0
        && a_quota.bytes == 0
        && b_quota.bytes == 0
}

pub fn run() {
    let before = crate::baseline::baseline();
    let mut backend = VirtioNetBackend::new([2, 0, 0, 0, 0, 1], [10, 0, 2, 1]);
    let first_handle = backend.enable_udp_service(4433);
    check(first_handle.is_ok(), "bind");
    check(
        backend.enable_udp_service(4434) == Err(UdpRuntimeError::Capacity),
        "duplicate_service",
    );

    let request = udp_frame(b"quic");
    check(
        backend.transmit(&request) == Ok(TransmitOutcome::UdpEchoReply),
        "receive",
    );
    let reply = backend.pop_rx();
    let reply_ok = reply.is_some_and(|reply| {
        let Ok(ethernet) = EthernetFrame::parse(reply.bytes()) else {
            return false;
        };
        let Ok(kernel_core::net1a::Net1aPacket::Ipv4(ip)) =
            parse_ethernet_payload(ethernet)
        else {
            return false;
        };
        let Ok(udp) = UdpDatagram::parse(ip) else {
            return false;
        };
        ip.source == [10, 0, 2, 1]
            && ip.destination == [10, 0, 2, 15]
            && udp.source_port == 4433
            && udp.destination_port == 49152
            && udp.payload == b"quic"
    });
    check(reply_ok, "reply");

    let stats = backend.udp_stats();
    check(stats.received_datagrams == 1, "received_stats");
    check(stats.sent_datagrams == 1, "sent_stats");
    check(stats.queued_datagrams == 0 && stats.queued_bytes == 0, "queue");

    let mut quota_runtime = UdpSocketRuntime::<1, 1>::new(UdpQuota::new(1, 1, 4));
    let quota_local = UdpAddress::new([10, 0, 2, 2], 5353);
    let quota_remote = UdpAddress::new([10, 0, 2, 15], 49153);
    let quota_socket = quota_runtime.bind(quota_local, UdpRights::SERVICE);
    check(quota_socket.is_ok(), "quota_bind");
    check(
        quota_runtime.receive(quota_remote, quota_local, b"1234").is_ok(),
        "quota_receive",
    );
    check(
        quota_runtime.receive(quota_remote, quota_local, b"5")
            == Err(UdpRuntimeError::QueueFull),
        "quota_reject",
    );
    if let Ok(handle) = quota_socket {
        check(quota_runtime.close(handle).is_ok(), "quota_close");
    }
    let quota = quota_runtime.quota();
    check(
        quota.sockets == 0 && quota.datagrams == 0 && quota.bytes == 0,
        "quota_return",
    );
    let hosted_wireguard = verify_wireguard_service();
    check(hosted_wireguard, "hosted_wireguard");

    let mut malformed = udp_frame(b"quic");
    malformed[40] ^= 0xff;
    check(
        backend.transmit(&malformed)
            == Err(kernel_core::virtio_net::NetError::MalformedChecksum),
        "checksum",
    );
    check(backend.pop_rx().is_none(), "malformed_reply");

    let old_generation = first_handle.map(|handle| handle.generation()).unwrap_or(0);
    backend.reset();
    check(backend.udp_stats().active_sockets == 0, "reset_revoke");
    let replacement = backend.enable_udp_service(4433);
    check(
        replacement.is_ok_and(|handle| handle.generation() > old_generation),
        "generation",
    );
    backend.reset();

    let after = crate::baseline::baseline();
    let resources = before == after;
    check(resources, "resources");
    kprintln!(
        "[JSR-NET4-RUNTIME] wire=true udp=true socket=true quota=true generation=true echo=true service=true wireguard=true reset=true resources={} failed={}",
        resources,
        failed()
    );
}
