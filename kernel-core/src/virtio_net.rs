//! Bounded virtio-net device backend contract.
//!
//! The transport and queue state live in [`crate::vmm_device::VirtioMmio`].
//! This module owns only virtio-net headers, framing, the fixed receive queue
//! and deterministic host replies. A kernel/hypervisor backend still performs
//! guest-memory descriptor walks and interrupt delivery.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::net1a::{parse_ethernet_payload, EthernetFrame, IpProtocol, Ipv4Header, Net1aPacket};
use crate::net1b::{ipv4_transport_checksum, UdpDatagram};
use crate::net4_runtime::{
    UdpAddress, UdpHandle, UdpLimits, UdpQuota, UdpRights, UdpRuntimeError, UdpSocketRuntime,
    UdpStats,
};

pub const MAC_BYTES: usize = 6;
pub const VIRTIO_NET_HEADER_BYTES: usize = 12;
pub const ETHERNET_HEADER_BYTES: usize = 14;
pub const IPV4_UDP_OVERHEAD_BYTES: usize = 28;

pub const FEATURE_CSUM: u32 = 1 << 0;
pub const FEATURE_GUEST_CSUM: u32 = 1 << 1;
pub const FEATURE_MTU: u32 = 1 << 3;
pub const FEATURE_MAC: u32 = 1 << 5;
pub const FEATURE_STATUS: u32 = 1 << 16;
pub const FEATURE_GSO: u32 = 1 << 27;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioNetFacts {
    pub features: u32,
    pub mtu: u16,
    pub queue_size: u16,
    pub link_up: bool,
}

impl VirtioNetFacts {
    pub fn discover(
        features: u32,
        mtu: Option<u16>,
        queue_size: u16,
        link_up: bool,
    ) -> Result<Self, NetAdmissionError> {
        let Some(mtu) = mtu else {
            return Err(NetAdmissionError::MtuUndiscovered);
        };
        if features & FEATURE_MAC == 0 {
            return Err(NetAdmissionError::MacUnsupported);
        }
        if features & FEATURE_MTU == 0 || mtu == 0 {
            return Err(NetAdmissionError::MtuUnsupported);
        }
        if features & FEATURE_STATUS == 0 {
            return Err(NetAdmissionError::StatusUnsupported);
        }
        if queue_size == 0 {
            return Err(NetAdmissionError::QueueUnavailable);
        }
        Ok(Self {
            features,
            mtu,
            queue_size,
            link_up,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetPolicy {
    pub max_frame_bytes: usize,
    pub rx_queue_limit: usize,
    pub rx_bytes_budget: usize,
    pub udp_sockets: usize,
    pub udp_queue_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetCapacity {
    pub mtu: u16,
    pub max_frame_bytes: usize,
    pub rx_queue_depth: usize,
    pub udp: UdpLimits,
}

impl NetCapacity {
    pub fn admit(facts: VirtioNetFacts, policy: NetPolicy) -> Result<Self, NetAdmissionError> {
        let max_frame_bytes = ETHERNET_HEADER_BYTES
            .checked_add(usize::from(facts.mtu))
            .ok_or(NetAdmissionError::Capacity)?;
        if max_frame_bytes > policy.max_frame_bytes {
            return Err(NetAdmissionError::FrameBudget);
        }
        let rx_queue_depth = usize::from(facts.queue_size).min(policy.rx_queue_limit);
        if rx_queue_depth == 0 {
            return Err(NetAdmissionError::QueueUnavailable);
        }
        let rx_bytes = rx_queue_depth
            .checked_mul(max_frame_bytes)
            .ok_or(NetAdmissionError::Capacity)?;
        if rx_bytes > policy.rx_bytes_budget {
            return Err(NetAdmissionError::RxBudget);
        }
        let max_datagram_bytes = usize::from(facts.mtu)
            .checked_sub(IPV4_UDP_OVERHEAD_BYTES)
            .filter(|bytes| *bytes != 0)
            .ok_or(NetAdmissionError::DatagramBudget)?;
        let udp = UdpLimits::new(
            policy.udp_sockets,
            policy.udp_queue_depth,
            max_datagram_bytes,
        );
        if !udp.valid() {
            return Err(NetAdmissionError::DatagramBudget);
        }
        Ok(Self {
            mtu: facts.mtu,
            max_frame_bytes,
            rx_queue_depth,
            udp,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetAdmissionError {
    MacUnsupported,
    MtuUndiscovered,
    MtuUnsupported,
    StatusUnsupported,
    QueueUnavailable,
    FrameBudget,
    RxBudget,
    DatagramBudget,
    Memory,
    Capacity,
}

impl NetAdmissionError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::MacUnsupported => "system.net.error.mac_unsupported",
            Self::MtuUndiscovered => "system.net.error.mtu_undiscovered",
            Self::MtuUnsupported => "system.net.error.mtu_unsupported",
            Self::StatusUnsupported => "system.net.error.status_unsupported",
            Self::QueueUnavailable => "system.net.error.queue_unavailable",
            Self::FrameBudget => "system.net.error.frame_budget",
            Self::RxBudget => "system.net.error.rx_budget",
            Self::DatagramBudget => "system.net.error.datagram_budget",
            Self::Memory => "system.net.error.memory",
            Self::Capacity => "system.net.error.capacity",
        }
    }
}

const NET_HDR_F_NEEDS_CSUM: u8 = 1;
const NET_HDR_F_DATA_VALID: u8 = 2;
const NET_HDR_F_RSC: u8 = 4;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const IP_PROTOCOL_ICMP: u8 = 1;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    HeaderTooShort,
    FrameTooLarge,
    RxQueueFull,
    UnsupportedFlags,
    GsoUnsupported,
    TruncatedHeaders,
    MalformedChecksum,
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub header_length: u16,
    pub gso_size: u16,
    pub checksum_start: u16,
    pub checksum_offset: u16,
}

impl VirtioNetHeader {
    pub const ZERO: Self = Self {
        flags: 0,
        gso_type: 0,
        header_length: 0,
        gso_size: 0,
        checksum_start: 0,
        checksum_offset: 0,
    };

    pub fn decode(raw: &[u8]) -> Result<Self, NetError> {
        if raw.len() < VIRTIO_NET_HEADER_BYTES {
            return Err(NetError::HeaderTooShort);
        }
        let header = Self {
            flags: raw[0],
            gso_type: raw[1],
            header_length: u16::from_le_bytes([raw[2], raw[3]]),
            gso_size: u16::from_le_bytes([raw[4], raw[5]]),
            checksum_start: u16::from_le_bytes([raw[6], raw[7]]),
            checksum_offset: u16::from_le_bytes([raw[8], raw[9]]),
        };
        if header.flags & !(NET_HDR_F_NEEDS_CSUM | NET_HDR_F_DATA_VALID | NET_HDR_F_RSC) != 0 {
            return Err(NetError::UnsupportedFlags);
        }
        if header.gso_type != 0 || header.header_length != 0 || header.gso_size != 0 {
            return Err(NetError::GsoUnsupported);
        }
        if header.flags & NET_HDR_F_RSC != 0 {
            return Err(NetError::GsoUnsupported);
        }
        if header.flags & NET_HDR_F_NEEDS_CSUM == 0
            && (header.checksum_start != 0 || header.checksum_offset != 0)
        {
            return Err(NetError::UnsupportedFlags);
        }
        Ok(header)
    }

    pub fn encode(self) -> [u8; VIRTIO_NET_HEADER_BYTES] {
        let mut raw = [0u8; VIRTIO_NET_HEADER_BYTES];
        raw[0] = self.flags;
        raw[1] = self.gso_type;
        raw[2..4].copy_from_slice(&self.header_length.to_le_bytes());
        raw[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        raw[6..8].copy_from_slice(&self.checksum_start.to_le_bytes());
        raw[8..10].copy_from_slice(&self.checksum_offset.to_le_bytes());
        raw
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransmitOutcome {
    ArpReply,
    IcmpEchoReply,
    UdpEchoReply,
    Accepted,
}

pub struct RxFrame {
    bytes: Vec<u8>,
}

impl RxFrame {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn zeroed(len: usize) -> Result<Self, NetError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| NetError::Capacity)?;
        bytes.resize(len, 0);
        Ok(Self { bytes })
    }
}

pub struct VirtioNetBackend {
    mac: [u8; MAC_BYTES],
    ipv4: [u8; 4],
    link_up: bool,
    capacity: NetCapacity,
    reset_generation: u32,
    tx_frames: u64,
    rx_frames: u64,
    malformed: u64,
    rx: VecDeque<RxFrame>,
    udp: UdpSocketRuntime,
    udp_handles: Vec<(UdpHandle, u16)>,
}

impl VirtioNetBackend {
    pub fn admit(
        mac: [u8; MAC_BYTES],
        ipv4: [u8; 4],
        facts: VirtioNetFacts,
        policy: NetPolicy,
    ) -> Result<Self, NetAdmissionError> {
        let capacity = NetCapacity::admit(facts, policy)?;
        let mut rx = VecDeque::new();
        rx.try_reserve_exact(capacity.rx_queue_depth)
            .map_err(|_| NetAdmissionError::Memory)?;
        let max_datagrams = policy
            .udp_queue_depth
            .checked_mul(policy.udp_sockets)
            .ok_or(NetAdmissionError::Capacity)?;
        let max_bytes = max_datagrams
            .checked_mul(capacity.udp.max_datagram_bytes)
            .ok_or(NetAdmissionError::Capacity)?;
        let sockets = u32::try_from(policy.udp_sockets).map_err(|_| NetAdmissionError::Capacity)?;
        let max_datagrams =
            u32::try_from(max_datagrams).map_err(|_| NetAdmissionError::Capacity)?;
        let udp = UdpSocketRuntime::new(
            UdpQuota::new(sockets, max_datagrams, max_bytes as u64),
            capacity.udp,
        )
        .map_err(|_| NetAdmissionError::Memory)?;
        let mut udp_handles = Vec::new();
        udp_handles
            .try_reserve_exact(capacity.udp.max_sockets)
            .map_err(|_| NetAdmissionError::Memory)?;
        Ok(Self {
            mac,
            ipv4,
            link_up: facts.link_up,
            capacity,
            reset_generation: 1,
            tx_frames: 0,
            rx_frames: 0,
            malformed: 0,
            rx,
            udp,
            udp_handles,
        })
    }

    pub const fn capacity(&self) -> NetCapacity {
        self.capacity
    }

    pub const fn mtu(&self) -> u16 {
        self.capacity.mtu
    }

    pub const fn max_frame_bytes(&self) -> usize {
        self.capacity.max_frame_bytes
    }

    pub const fn mac(&self) -> [u8; MAC_BYTES] {
        self.mac
    }

    pub const fn ipv4(&self) -> [u8; 4] {
        self.ipv4
    }

    pub const fn link_up(&self) -> bool {
        self.link_up
    }

    pub const fn reset_generation(&self) -> u32 {
        self.reset_generation
    }

    pub const fn tx_frames(&self) -> u64 {
        self.tx_frames
    }

    pub const fn rx_frames(&self) -> u64 {
        self.rx_frames
    }

    pub const fn malformed(&self) -> u64 {
        self.malformed
    }

    pub fn reset(&mut self) {
        self.reset_generation = self.reset_generation.saturating_add(1);
        self.rx.clear();
        self.udp.revoke_all();
        self.udp_handles.clear();
    }

    pub fn set_link(&mut self, up: bool) {
        self.link_up = up;
    }

    /// 在本机 IPv4 地址上启用 UDP 服务 socket。
    ///
    /// Enables one UDP service socket on the backend's IPv4 address.
    pub fn enable_udp_service(&mut self, port: u16) -> Result<UdpHandle, UdpRuntimeError> {
        if self.udp_handles.len() >= self.capacity.udp.max_sockets {
            return Err(UdpRuntimeError::Capacity);
        }
        let handle = self
            .udp
            .bind(UdpAddress::new(self.ipv4, port), UdpRights::SERVICE)?;
        // `admit` reserved the complete admitted socket budget before creating
        // the backend, so publication cannot fail after binding has committed.
        self.udp_handles.push((handle, port));
        Ok(handle)
    }

    pub fn udp_stats(&self) -> UdpStats {
        self.udp.stats()
    }

    pub fn transmit(&mut self, bytes: &[u8]) -> Result<TransmitOutcome, NetError> {
        let outcome = classify(bytes, self.mac, self.ipv4, self.capacity.max_frame_bytes)
            .inspect_err(|_| {
                self.malformed = self.malformed.saturating_add(1);
            })?;
        self.tx_frames = self.tx_frames.saturating_add(1);
        let reply = match outcome {
            TransmitOutcome::ArpReply => Some(arp_reply(bytes, self.mac, self.ipv4)?),
            TransmitOutcome::IcmpEchoReply => Some(icmp_echo_reply(bytes, self.mac, self.ipv4)?),
            TransmitOutcome::UdpEchoReply => {
                match udp_echo_reply(
                    bytes,
                    self.mac,
                    self.ipv4,
                    &mut self.udp,
                    &self.udp_handles,
                    self.capacity.max_frame_bytes,
                ) {
                    Ok(Some(reply)) => Some(reply),
                    Ok(None) => return Ok(TransmitOutcome::Accepted),
                    Err(_) => return Ok(TransmitOutcome::Accepted),
                }
            }
            TransmitOutcome::Accepted => None,
        };
        if let Some(reply) = reply {
            self.enqueue(reply)?;
        }
        Ok(outcome)
    }

    pub fn pop_rx(&mut self) -> Option<RxFrame> {
        self.rx.pop_front()
    }

    fn enqueue(&mut self, frame: RxFrame) -> Result<(), NetError> {
        if self.rx.len() == self.capacity.rx_queue_depth {
            return Err(NetError::RxQueueFull);
        }
        self.rx.try_reserve(1).map_err(|_| NetError::Capacity)?;
        self.rx.push_back(frame);
        self.rx_frames = self.rx_frames.saturating_add(1);
        Ok(())
    }
}

fn classify(
    bytes: &[u8],
    mac: [u8; MAC_BYTES],
    ipv4: [u8; 4],
    max_frame_bytes: usize,
) -> Result<TransmitOutcome, NetError> {
    if bytes.len() > max_frame_bytes {
        return Err(NetError::FrameTooLarge);
    }
    if bytes.len() < ETHERNET_HEADER_BYTES {
        return Err(NetError::TruncatedHeaders);
    }
    let destination = &bytes[0..6];
    if destination != mac && destination != [0xff; 6] {
        return Ok(TransmitOutcome::Accepted);
    }
    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    if ethertype == ETHERTYPE_ARP {
        if bytes.len() < ETHERNET_HEADER_BYTES + 28 {
            return Err(NetError::TruncatedHeaders);
        }
        let arp = &bytes[ETHERNET_HEADER_BYTES..];
        if u16::from_be_bytes([arp[6], arp[7]]) == ARP_REQUEST && arp[24..28] == ipv4 {
            return Ok(TransmitOutcome::ArpReply);
        }
        return Ok(TransmitOutcome::Accepted);
    }
    if ethertype == ETHERTYPE_IPV4 {
        let ip = &bytes[ETHERNET_HEADER_BYTES..];
        if ip.len() < 20 || ip[0] >> 4 != 4 {
            return Err(NetError::TruncatedHeaders);
        }
        let header_length = usize::from(ip[0] & 0x0f) * 4;
        if header_length < 20 || header_length > ip.len() {
            return Err(NetError::TruncatedHeaders);
        }
        if checksum(&ip[..header_length]) != 0 {
            return Err(NetError::MalformedChecksum);
        }
        if ip[9] == IP_PROTOCOL_ICMP
            && ip[16..20] == ipv4
            && ip.len() >= header_length + 8
            && ip[header_length] == ICMP_ECHO_REQUEST
            && checksum(&ip[header_length..]) == 0
        {
            return Ok(TransmitOutcome::IcmpEchoReply);
        }
        if ip[9] == 17 && ip[16..20] == ipv4 {
            let header = Ipv4Header::parse(ip).map_err(|_| NetError::MalformedChecksum)?;
            UdpDatagram::parse(header).map_err(|_| NetError::MalformedChecksum)?;
            return Ok(TransmitOutcome::UdpEchoReply);
        }
        return Ok(TransmitOutcome::Accepted);
    }
    Ok(TransmitOutcome::Accepted)
}

fn arp_reply(request: &[u8], mac: [u8; MAC_BYTES], ipv4: [u8; 4]) -> Result<RxFrame, NetError> {
    let mut frame = RxFrame::zeroed(ETHERNET_HEADER_BYTES + 28)?;
    frame.bytes[..6].copy_from_slice(&request[6..12]);
    frame.bytes[6..12].copy_from_slice(&mac);
    frame.bytes[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    let arp = &request[ETHERNET_HEADER_BYTES..ETHERNET_HEADER_BYTES + 28];
    let out = &mut frame.bytes[ETHERNET_HEADER_BYTES..ETHERNET_HEADER_BYTES + 28];
    out.copy_from_slice(arp);
    out[6..8].copy_from_slice(&ARP_REPLY.to_be_bytes());
    out[8..14].copy_from_slice(&mac);
    out[14..18].copy_from_slice(&ipv4);
    out[18..24].copy_from_slice(&arp[8..14]);
    out[24..28].copy_from_slice(&arp[14..18]);
    Ok(frame)
}

fn icmp_echo_reply(
    request: &[u8],
    mac: [u8; MAC_BYTES],
    ipv4: [u8; 4],
) -> Result<RxFrame, NetError> {
    let ip = &request[ETHERNET_HEADER_BYTES..];
    let ip_header = usize::from(ip[0] & 0x0f) * 4;
    let ip_total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ip_total < ip_header + 8 || ip_total > ip.len() {
        return Err(NetError::TruncatedHeaders);
    }
    let frame_len = ETHERNET_HEADER_BYTES
        .checked_add(ip_total)
        .ok_or(NetError::Capacity)?;
    let mut frame = RxFrame::zeroed(frame_len)?;
    frame.bytes[..6].copy_from_slice(&request[6..12]);
    frame.bytes[6..12].copy_from_slice(&mac);
    frame.bytes[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    let out_ip = &mut frame.bytes[ETHERNET_HEADER_BYTES..ETHERNET_HEADER_BYTES + ip_total];
    out_ip.copy_from_slice(&ip[..ip_total]);
    out_ip[8] = 64;
    out_ip[12..16].copy_from_slice(&ip[16..20]);
    out_ip[16..20].copy_from_slice(&ipv4);
    out_ip[10..12].fill(0);
    let ip_sum = checksum(&out_ip[..ip_header]);
    out_ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    out_ip[ip_header] = ICMP_ECHO_REPLY;
    out_ip[ip_header + 2..ip_header + 4].fill(0);
    let icmp_sum = checksum(&out_ip[ip_header..ip_total]);
    out_ip[ip_header + 2..ip_header + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Ok(frame)
}

fn udp_echo_reply(
    request: &[u8],
    mac: [u8; MAC_BYTES],
    ipv4: [u8; 4],
    runtime: &mut UdpSocketRuntime,
    handles: &[(UdpHandle, u16)],
    max_frame_bytes: usize,
) -> Result<Option<RxFrame>, UdpRuntimeError> {
    let ethernet = EthernetFrame::parse_bounded(request, max_frame_bytes)
        .map_err(|_| UdpRuntimeError::InvalidAddress)?;
    let Net1aPacket::Ipv4(ip) =
        parse_ethernet_payload(ethernet).map_err(|_| UdpRuntimeError::InvalidAddress)?
    else {
        return Err(UdpRuntimeError::InvalidAddress);
    };
    let datagram = UdpDatagram::parse(ip).map_err(|_| UdpRuntimeError::InvalidAddress)?;
    let Some((handle, _)) = handles
        .iter()
        .find(|(_, port)| *port == datagram.destination_port)
    else {
        return Ok(None);
    };
    let handle = *handle;
    let source = UdpAddress::new(ip.source, datagram.source_port);
    let destination = UdpAddress::new(ip.destination, datagram.destination_port);
    runtime.receive(source, destination, datagram.payload)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(runtime.limits().max_datagram_bytes)
        .map_err(|_| UdpRuntimeError::Capacity)?;
    payload.resize(runtime.limits().max_datagram_bytes, 0);
    let (reply_to, payload_len) = runtime.recv(handle, &mut payload)?;
    let reply = build_udp_reply(
        request,
        mac,
        ipv4,
        ip.source,
        datagram.destination_port,
        datagram.source_port,
        &payload[..payload_len],
        max_frame_bytes,
    )?;
    runtime.send(handle, reply_to, &payload[..payload_len])?;
    Ok(Some(reply))
}

fn build_udp_reply(
    request: &[u8],
    mac: [u8; MAC_BYTES],
    ipv4: [u8; 4],
    peer_ip: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    max_frame_bytes: usize,
) -> Result<RxFrame, UdpRuntimeError> {
    let ip_bytes = 28usize
        .checked_add(payload.len())
        .ok_or(UdpRuntimeError::DatagramTooLarge)?;
    let frame_len = ETHERNET_HEADER_BYTES
        .checked_add(ip_bytes)
        .ok_or(UdpRuntimeError::DatagramTooLarge)?;
    if frame_len > max_frame_bytes || ip_bytes > u16::MAX as usize {
        return Err(UdpRuntimeError::DatagramTooLarge);
    }
    let mut frame = RxFrame::zeroed(frame_len).map_err(|error| match error {
        NetError::Capacity => UdpRuntimeError::Capacity,
        _ => UdpRuntimeError::DatagramTooLarge,
    })?;
    frame.bytes[..6].copy_from_slice(&request[6..12]);
    frame.bytes[6..12].copy_from_slice(&mac);
    frame.bytes[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    let ip = &mut frame.bytes[ETHERNET_HEADER_BYTES..ETHERNET_HEADER_BYTES + ip_bytes];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_bytes as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&ipv4);
    ip[16..20].copy_from_slice(&peer_ip);
    let ip_checksum = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    let udp = &mut ip[20..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let udp_checksum = ipv4_transport_checksum(ipv4, peer_ip, IpProtocol::Udp, udp);
    udp[6..8].copy_from_slice(
        &(if udp_checksum == 0 {
            u16::MAX
        } else {
            udp_checksum
        })
        .to_be_bytes(),
    );
    Ok(frame)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend_with(
        mtu: u16,
        queue_size: u16,
        rx_queue_limit: usize,
        udp_queue_depth: usize,
    ) -> VirtioNetBackend {
        let features = FEATURE_MAC | FEATURE_MTU | FEATURE_STATUS;
        let facts = VirtioNetFacts::discover(features, Some(mtu), queue_size, true).unwrap();
        VirtioNetBackend::admit(
            [2, 0, 0, 0, 0, 1],
            [10, 0, 2, 1],
            facts,
            NetPolicy {
                max_frame_bytes: 16 * 1024,
                rx_queue_limit,
                rx_bytes_budget: 256 * 1024,
                udp_sockets: 2,
                udp_queue_depth,
            },
        )
        .unwrap()
    }

    fn backend() -> VirtioNetBackend {
        backend_with(1500, 16, 4, 4)
    }

    fn arp_request() -> [u8; 42] {
        let mut frame = [0u8; 42];
        frame[..6].fill(0xff);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        frame[14..16].copy_from_slice(&1u16.to_be_bytes());
        frame[16..18].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&ARP_REQUEST.to_be_bytes());
        frame[22..28].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[28..32].copy_from_slice(&[10, 0, 2, 15]);
        frame[32..38].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[38..42].copy_from_slice(&[10, 0, 2, 1]);
        frame
    }

    #[test]
    fn header_rejects_gso_and_unknown_flags() {
        let mut raw = VirtioNetHeader::ZERO.encode();
        assert_eq!(VirtioNetHeader::decode(&raw), Ok(VirtioNetHeader::ZERO));
        raw[0] = 0x80;
        assert_eq!(
            VirtioNetHeader::decode(&raw),
            Err(NetError::UnsupportedFlags)
        );
        raw[0] = 0;
        raw[1] = 1;
        assert_eq!(VirtioNetHeader::decode(&raw), Err(NetError::GsoUnsupported));
    }

    #[test]
    fn arp_request_gets_bounded_reply() {
        let request = arp_request();
        assert_eq!(&request[..6], &[0xff; 6]);
        assert_eq!(&request[12..14], &ETHERTYPE_ARP.to_be_bytes());
        assert_eq!(&request[20..22], &ARP_REQUEST.to_be_bytes());
        assert_eq!(&request[38..42], &[10, 0, 2, 1]);
        let mut backend = backend();
        assert_eq!(backend.transmit(&request), Ok(TransmitOutcome::ArpReply));
        let reply = backend.pop_rx().unwrap();
        assert_eq!(backend.tx_frames(), 1);
        assert_eq!(backend.rx_frames(), 1);
        assert_eq!(&reply.bytes()[0..6], &[2, 0, 0, 0, 0, 2]);
        assert_eq!(&reply.bytes()[6..12], &[2, 0, 0, 0, 0, 1]);
        assert_eq!(&reply.bytes()[22..28], &[2, 0, 0, 0, 0, 1]);
        assert_eq!(&reply.bytes()[28..32], &[10, 0, 2, 1]);
        assert_eq!(&reply.bytes()[38..42], &[10, 0, 2, 15]);
    }

    #[test]
    fn malformed_and_oversized_frames_fail_without_queue_mutation() {
        let mut backend = backend();
        assert_eq!(backend.transmit(&[0; 13]), Err(NetError::TruncatedHeaders));
        let oversized = vec![0; backend.max_frame_bytes() + 1];
        assert_eq!(backend.transmit(&oversized), Err(NetError::FrameTooLarge));
        assert!(backend.pop_rx().is_none());
        assert_eq!(backend.malformed(), 2);
        assert_eq!(backend.tx_frames(), 0);
    }

    #[test]
    fn reset_advances_generation_and_drops_queued_rx() {
        let mut backend = backend();
        backend.transmit(&arp_request()).unwrap();
        assert!(backend.pop_rx().is_some());
        backend.transmit(&arp_request()).unwrap();
        backend.reset();
        assert_eq!(backend.reset_generation(), 2);
        assert!(backend.pop_rx().is_none());
    }

    #[test]
    fn rx_queue_exhaustion_is_distinct_from_oversized_frames() {
        let mut backend = backend();
        let depth = backend.capacity().rx_queue_depth;
        for _ in 0..depth {
            assert_eq!(
                backend.transmit(&arp_request()),
                Ok(TransmitOutcome::ArpReply)
            );
        }
        assert_eq!(backend.transmit(&arp_request()), Err(NetError::RxQueueFull));
        assert_ne!(NetError::RxQueueFull, NetError::FrameTooLarge);
    }

    fn udp_frame(payload: &[u8]) -> [u8; 46] {
        udp_frame_to(payload, 4433)
    }

    fn udp_frame_to(payload: &[u8], destination_port: u16) -> [u8; 46] {
        let mut frame = [0u8; 46];
        frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = &mut frame[ETHERNET_HEADER_BYTES..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[10, 0, 2, 15]);
        ip[16..20].copy_from_slice(&[10, 0, 2, 1]);
        let ip_sum = checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        let udp = &mut ip[20..];
        udp[0..2].copy_from_slice(&49152u16.to_be_bytes());
        udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp[8..].copy_from_slice(payload);
        let udp_sum = ipv4_transport_checksum([10, 0, 2, 15], [10, 0, 2, 1], IpProtocol::Udp, udp);
        udp[6..8].copy_from_slice(&udp_sum.to_be_bytes());
        frame
    }

    #[test]
    fn udp_runtime_socket_echoes_real_frame_and_returns_quota() {
        let mut backend = backend();
        backend.enable_udp_service(4433).unwrap();
        backend.enable_udp_service(4434).unwrap();
        assert_eq!(
            backend.enable_udp_service(4435),
            Err(UdpRuntimeError::Capacity)
        );
        assert_eq!(backend.udp_stats().active_sockets, 2);
        let request = udp_frame(b"quic");
        assert_eq!(
            backend.transmit(&request),
            Ok(TransmitOutcome::UdpEchoReply)
        );
        let reply = backend.pop_rx().unwrap();
        let EthernetFrame { payload, .. } = EthernetFrame::parse(reply.bytes()).unwrap();
        let ip = Ipv4Header::parse(payload).unwrap();
        assert_eq!(ip.source, [10, 0, 2, 1]);
        assert_eq!(ip.destination, [10, 0, 2, 15]);
        let udp = UdpDatagram::parse(ip).unwrap();
        assert_eq!(udp.source_port, 4433);
        assert_eq!(udp.destination_port, 49152);
        assert_eq!(udp.payload, b"quic");
        let request = udp_frame_to(b"next", 4434);
        assert_eq!(
            backend.transmit(&request),
            Ok(TransmitOutcome::UdpEchoReply)
        );
        let reply = backend.pop_rx().unwrap();
        let EthernetFrame { payload, .. } = EthernetFrame::parse(reply.bytes()).unwrap();
        let ip = Ipv4Header::parse(payload).unwrap();
        let udp = UdpDatagram::parse(ip).unwrap();
        assert_eq!(udp.source_port, 4434);
        assert_eq!(udp.payload, b"next");
        let stats = backend.udp_stats();
        assert_eq!(stats.received_datagrams, 2);
        assert_eq!(stats.sent_datagrams, 2);
        assert_eq!(stats.queued_datagrams, 0);
        backend.reset();
        assert_eq!(backend.udp_stats().active_sockets, 0);
        assert_eq!(backend.transmit(&request), Ok(TransmitOutcome::Accepted));
        assert!(backend.pop_rx().is_none());
    }

    #[test]
    fn malformed_udp_checksum_is_rejected_without_reply() {
        let mut backend = backend();
        backend.enable_udp_service(4433).unwrap();
        let mut request = udp_frame(b"quic");
        request[40] ^= 0xff;
        assert_eq!(backend.transmit(&request), Err(NetError::MalformedChecksum));
        assert!(backend.pop_rx().is_none());
        assert_eq!(backend.malformed(), 1);
    }

    #[test]
    fn device_facts_and_policy_produce_distinct_runtime_capacities() {
        let standard = backend_with(1500, 16, 4, 3);
        let jumbo = backend_with(9000, 32, 8, 7);
        assert_eq!(standard.max_frame_bytes(), 1514);
        assert_eq!(standard.capacity().rx_queue_depth, 4);
        assert_eq!(standard.capacity().udp.max_datagram_bytes, 1472);
        assert_eq!(jumbo.max_frame_bytes(), 9014);
        assert_eq!(jumbo.capacity().rx_queue_depth, 8);
        assert_eq!(jumbo.capacity().udp.max_datagram_bytes, 8972);
        assert_ne!(standard.capacity(), jumbo.capacity());
    }

    #[test]
    fn missing_mtu_and_policy_budget_fail_closed() {
        assert_eq!(
            VirtioNetFacts::discover(FEATURE_MAC | FEATURE_STATUS, None, 16, true),
            Err(NetAdmissionError::MtuUndiscovered)
        );
        let facts = VirtioNetFacts::discover(
            FEATURE_MAC | FEATURE_MTU | FEATURE_STATUS,
            Some(9000),
            16,
            true,
        )
        .unwrap();
        assert_eq!(
            NetCapacity::admit(
                facts,
                NetPolicy {
                    max_frame_bytes: 1514,
                    rx_queue_limit: 16,
                    rx_bytes_budget: 256 * 1024,
                    udp_sockets: 2,
                    udp_queue_depth: 4,
                }
            ),
            Err(NetAdmissionError::FrameBudget)
        );
    }
}
