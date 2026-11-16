//! NET-4 no_std UDP socket runtime acceptance.
//!
//! 职责：在真实 Jasper QEMU 启动中让完整 UDP 帧经过 virtio-net 后端、运行时 socket、
//! 配额和回复构造路径。边界：不启动 Quinn/rustls hosted 服务，也不代表真实网卡互通。
//! Responsibility: exercise the real UDP frame and socket runtime path inside Jasper while
//! keeping hosted QUIC/WireGuard deployment and physical networking as separate gates.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::net1a::{parse_ethernet_payload, EthernetFrame};
use kernel_core::net1b::UdpDatagram;
use kernel_core::net4_runtime::{
    UdpAddress, UdpLimits, UdpQuota, UdpRights, UdpRuntimeError, UdpSocketRuntime,
};
use kernel_core::net4_service::{WireGuardEmit, WireGuardReceive, WireGuardService};
use kernel_core::virtio_net::{
    NetCapacity, NetPolicy, TransmitOutcome, VirtioNetBackend, VirtioNetFacts, FEATURE_MAC,
    FEATURE_MTU, FEATURE_STATUS,
};
use kernel_core::wireguard::{testing::DeterministicRng, Config, Now, StaticSecret};

use crate::{kprintln, pci, sched, virtio};

static FAILED: AtomicU32 = AtomicU32::new(0);
const FEATURE_MQ: u32 = 1 << 22;

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, stage: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-NET4-RUNTIME-FAIL] stage={}", stage);
    }
}

struct DiscoveredTopology {
    facts: VirtioNetFacts,
    policy: NetPolicy,
    queue_pairs: u16,
}

fn config_u16(device: &virtio::VirtioPci, offset: u64) -> Option<u16> {
    let low = u16::from(device.read_device_config8(offset)?);
    let high = u16::from(device.read_device_config8(offset + 1)?);
    Some(low | high << 8)
}

fn discover_topology() -> Result<DiscoveredTopology, &'static str> {
    let device = pci::table()
        .devices()
        .find(|device| {
            device.header.vendor == virtio::VIRTIO_VENDOR
                && virtio::is_net_device(device.header.device)
        })
        .ok_or("missing_virtio_net")?;
    let transport = virtio::VirtioPci::new(device).map_err(|_| "transport")?;
    transport.reset().map_err(|_| "reset")?;
    let features = transport.device_features(0);
    let negotiated = features & (FEATURE_MAC | FEATURE_MTU | FEATURE_STATUS);
    transport
        .negotiate_features(negotiated)
        .map_err(|_| "negotiate")?;
    let mtu = config_u16(&transport, 10).ok_or("mtu_config")?;
    let queue_pairs = if features & FEATURE_MQ != 0 {
        config_u16(&transport, 8).ok_or("mq_config")?
    } else {
        1
    };
    let device_queue_size = transport.device_queue_size(0).ok_or("queue_size")?;
    let mut queue = virtio::Queue::new().map_err(|_| "queue")?;
    transport
        .setup_queue_polling(&mut queue)
        .map_err(|_| "setup_queue")?;
    let driver_queue_size = queue.size();
    let facts = VirtioNetFacts::discover(features, Some(mtu), device_queue_size, true)
        .map_err(|_| "facts")?;

    let max_frame_bytes = usize::from(mtu).saturating_add(14);
    let memory_budget = usize::try_from(crate::mm::heap::limit() / 64).unwrap_or(0);
    let tasks = sched::capacity().max(1);
    let per_socket = max_frame_bytes.saturating_mul(4).max(1);
    let udp_sockets = tasks.min((memory_budget / per_socket).max(1));
    let per_datagram = max_frame_bytes.saturating_mul(udp_sockets).max(1);
    let udp_queue_depth = usize::from(device_queue_size)
        .min((memory_budget / per_datagram).max(1))
        .max(1);
    let policy = NetPolicy {
        max_frame_bytes,
        rx_queue_limit: usize::from(device_queue_size),
        rx_bytes_budget: max_frame_bytes.saturating_mul(usize::from(device_queue_size)),
        udp_sockets,
        udp_queue_depth,
    };
    let capacity = NetCapacity::admit(facts, policy).map_err(|_| "capacity")?;
    let _ = transport.reset();
    drop(queue);
    kprintln!(
        "[JSR-NET-TOPOLOGY] bdf=0x{:06x} mtu={} queue_pairs={} device_queue={} driver_queue={} features=0x{:08x} max_frame={} udp_sockets={} udp_queue={} max_datagram={} source=hardware",
        kernel_core::device::pack_bdf(device.bdf),
        facts.mtu,
        queue_pairs,
        facts.queue_size,
        driver_queue_size,
        facts.features,
        capacity.max_frame_bytes,
        capacity.udp.max_sockets,
        capacity.udp.queue_depth,
        capacity.udp.max_datagram_bytes
    );
    Ok(DiscoveredTopology {
        facts,
        policy,
        queue_pairs,
    })
}

fn udp_frame(destination_port: u16, payload: &[u8]) -> [u8; 46] {
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
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
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
    let limits = UdpLimits::new(1, 1, 1200);
    let mut a = match WireGuardService::new(
        Config::new(a_key, b_public),
        UdpAddress::new([10, 0, 3, 1], 51820),
        UdpAddress::new([10, 0, 3, 2], 51820),
        quota,
        limits,
    ) {
        Ok(service) => service,
        Err(_) => return false,
    };
    let mut b = match WireGuardService::new(
        Config::new(b_key, a_public),
        UdpAddress::new([10, 0, 3, 2], 51820),
        UdpAddress::new([10, 0, 3, 1], 51820),
        quota,
        limits,
    ) {
        Ok(service) => service,
        Err(_) => return false,
    };
    let now = Now::new(0, 1_700_000_000, 0);
    let mut rng = DeterministicRng::new(9);
    let mut a_wire = alloc::vec![0u8; limits.max_datagram_bytes];
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
    if a.receive(now, &mut plaintext, &mut rng) != Ok(WireGuardReceive::HandshakeComplete) {
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
    let Ok(topology) = discover_topology() else {
        check(false, "net_topology");
        return;
    };
    let Ok(mut backend) = VirtioNetBackend::admit(
        [2, 0, 0, 0, 0, 1],
        [10, 0, 2, 1],
        topology.facts,
        topology.policy,
    ) else {
        check(false, "net_admission");
        return;
    };
    let socket_count = backend.capacity().udp.max_sockets;
    let mut handles = alloc::vec::Vec::new();
    for index in 0..socket_count {
        let Ok(handle) = backend.enable_udp_service(4400 + index as u16) else {
            check(false, "bind");
            break;
        };
        handles.push(handle);
    }
    check(handles.len() == socket_count, "socket_budget");
    check(
        backend.enable_udp_service(4000) == Err(UdpRuntimeError::Capacity),
        "service_budget",
    );
    let first_handle = handles.first().copied();

    let request = udp_frame(4400, b"quic");
    check(
        backend.transmit(&request) == Ok(TransmitOutcome::UdpEchoReply),
        "receive",
    );
    let reply = backend.pop_rx();
    let reply_ok = reply.is_some_and(|reply| {
        let Ok(ethernet) = EthernetFrame::parse(reply.bytes()) else {
            return false;
        };
        let Ok(kernel_core::net1a::Net1aPacket::Ipv4(ip)) = parse_ethernet_payload(ethernet) else {
            return false;
        };
        let Ok(udp) = UdpDatagram::parse(ip) else {
            return false;
        };
        ip.source == [10, 0, 2, 1]
            && ip.destination == [10, 0, 2, 15]
            && udp.source_port == 4400
            && udp.destination_port == 49152
            && udp.payload == b"quic"
    });
    check(reply_ok, "reply");

    let stats = backend.udp_stats();
    check(stats.received_datagrams == 1, "received_stats");
    check(stats.sent_datagrams == 1, "sent_stats");
    check(
        stats.queued_datagrams == 0 && stats.queued_bytes == 0,
        "queue",
    );

    let Ok(mut quota_runtime) =
        UdpSocketRuntime::new(UdpQuota::new(1, 1, 4), UdpLimits::new(1, 1, 4))
    else {
        check(false, "quota_runtime");
        return;
    };
    let quota_local = UdpAddress::new([10, 0, 2, 2], 5353);
    let quota_remote = UdpAddress::new([10, 0, 2, 15], 49153);
    let quota_socket = quota_runtime.bind(quota_local, UdpRights::SERVICE);
    check(quota_socket.is_ok(), "quota_bind");
    check(
        quota_runtime
            .receive(quota_remote, quota_local, b"1234")
            .is_ok(),
        "quota_receive",
    );
    check(
        quota_runtime.receive(quota_remote, quota_local, b"5") == Err(UdpRuntimeError::QueueFull),
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

    let mut malformed = udp_frame(4400, b"quic");
    malformed[40] ^= 0xff;
    check(
        backend.transmit(&malformed) == Err(kernel_core::virtio_net::NetError::MalformedChecksum),
        "checksum",
    );
    check(backend.pop_rx().is_none(), "malformed_reply");

    let old_generation = first_handle.map(|handle| handle.generation()).unwrap_or(0);
    backend.reset();
    check(backend.udp_stats().active_sockets == 0, "reset_revoke");
    let replacement = backend.enable_udp_service(4400);
    check(
        replacement.is_ok_and(|handle| handle.generation() > old_generation),
        "generation",
    );
    backend.reset();

    let after = crate::baseline::baseline();
    let resources = before == after;
    let capacity = backend.capacity();
    check(resources, "resources");
    kprintln!(
        "[JSR-NET4-RUNTIME] wire=true udp=true socket=true quota=true generation=true echo=true service=true wireguard=true reset=true mtu={} max_frame={} rx_queue={} udp_sockets={} udp_queue={} max_datagram={} resources={} failed={}",
        capacity.mtu,
        capacity.max_frame_bytes,
        capacity.rx_queue_depth,
        capacity.udp.max_sockets,
        capacity.udp.queue_depth,
        capacity.udp.max_datagram_bytes,
        resources,
        failed()
    );
    kprintln!(
        "[JSR-NET4-TOPOLOGY] mtu={} queue_pairs={} device_queue={} advertised_rx_queue={} source=hardware",
        capacity.mtu,
        topology.queue_pairs,
        topology.facts.queue_size,
        capacity.rx_queue_depth
    );
}
