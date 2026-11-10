//! Bounded virtio-net device backend contract.
//!
//! The transport and queue state live in [`crate::vmm_device::VirtioMmio`].
//! This module owns only virtio-net headers, framing, the fixed receive queue
//! and deterministic host replies. A kernel/hypervisor backend still performs
//! guest-memory descriptor walks and interrupt delivery.

pub const MAC_BYTES: usize = 6;
pub const VIRTIO_NET_HEADER_BYTES: usize = 12;
pub const ETHERNET_HEADER_BYTES: usize = 14;
pub const MAX_FRAME_BYTES: usize = 1514;
pub const RX_QUEUE_CAPACITY: usize = 4;

pub const FEATURE_CSUM: u32 = 1 << 0;
pub const FEATURE_GUEST_CSUM: u32 = 1 << 1;
pub const FEATURE_MAC: u32 = 1 << 5;
pub const FEATURE_GSO: u32 = 1 << 27;

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
    UnsupportedFlags,
    GsoUnsupported,
    TruncatedHeaders,
    MalformedChecksum,
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
    Accepted,
}

#[derive(Clone, Copy)]
pub struct RxFrame {
    bytes: [u8; MAX_FRAME_BYTES],
    len: usize,
}

impl RxFrame {
    const EMPTY: Self = Self {
        bytes: [0; MAX_FRAME_BYTES],
        len: 0,
    };

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub struct VirtioNetBackend {
    mac: [u8; MAC_BYTES],
    ipv4: [u8; 4],
    link_up: bool,
    reset_generation: u32,
    tx_frames: u64,
    rx_frames: u64,
    malformed: u64,
    rx: [RxFrame; RX_QUEUE_CAPACITY],
    rx_head: usize,
    rx_len: usize,
}

impl VirtioNetBackend {
    pub const fn new(mac: [u8; MAC_BYTES], ipv4: [u8; 4]) -> Self {
        Self {
            mac,
            ipv4,
            link_up: true,
            reset_generation: 1,
            tx_frames: 0,
            rx_frames: 0,
            malformed: 0,
            rx: [RxFrame::EMPTY; RX_QUEUE_CAPACITY],
            rx_head: 0,
            rx_len: 0,
        }
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
        self.rx_head = 0;
        self.rx_len = 0;
        self.rx = [RxFrame::EMPTY; RX_QUEUE_CAPACITY];
    }

    pub fn set_link(&mut self, up: bool) {
        self.link_up = up;
    }

    pub fn transmit(&mut self, bytes: &[u8]) -> Result<TransmitOutcome, NetError> {
        let outcome = classify(bytes, self.mac, self.ipv4).inspect_err(|_| {
            self.malformed = self.malformed.saturating_add(1);
        })?;
        self.tx_frames = self.tx_frames.saturating_add(1);
        let reply = match outcome {
            TransmitOutcome::ArpReply => Some(arp_reply(bytes, self.mac, self.ipv4)?),
            TransmitOutcome::IcmpEchoReply => Some(icmp_echo_reply(bytes, self.mac, self.ipv4)?),
            TransmitOutcome::Accepted => None,
        };
        if let Some(reply) = reply {
            self.enqueue(reply)?;
        }
        Ok(outcome)
    }

    pub fn pop_rx(&mut self) -> Option<RxFrame> {
        if self.rx_len == 0 {
            return None;
        }
        let frame = self.rx[self.rx_head];
        self.rx[self.rx_head] = RxFrame::EMPTY;
        self.rx_head = (self.rx_head + 1) % RX_QUEUE_CAPACITY;
        self.rx_len -= 1;
        Some(frame)
    }

    fn enqueue(&mut self, frame: RxFrame) -> Result<(), NetError> {
        if self.rx_len == RX_QUEUE_CAPACITY {
            return Err(NetError::FrameTooLarge);
        }
        let index = (self.rx_head + self.rx_len) % RX_QUEUE_CAPACITY;
        self.rx[index] = frame;
        self.rx_len += 1;
        self.rx_frames = self.rx_frames.saturating_add(1);
        Ok(())
    }
}

fn classify(
    bytes: &[u8],
    mac: [u8; MAC_BYTES],
    ipv4: [u8; 4],
) -> Result<TransmitOutcome, NetError> {
    if bytes.len() > MAX_FRAME_BYTES {
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
        if u16::from_be_bytes([arp[6], arp[7]]) == ARP_REQUEST
            && arp[24..28] == ipv4
        {
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
        return Ok(TransmitOutcome::Accepted);
    }
    Ok(TransmitOutcome::Accepted)
}

fn arp_reply(request: &[u8], mac: [u8; MAC_BYTES], ipv4: [u8; 4]) -> Result<RxFrame, NetError> {
    let mut frame = RxFrame::EMPTY;
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
    frame.len = ETHERNET_HEADER_BYTES + 28;
    Ok(frame)
}

fn icmp_echo_reply(request: &[u8], mac: [u8; MAC_BYTES], ipv4: [u8; 4]) -> Result<RxFrame, NetError> {
    let ip = &request[ETHERNET_HEADER_BYTES..];
    let ip_header = usize::from(ip[0] & 0x0f) * 4;
    let ip_total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if ip_total < ip_header + 8 || ip_total > ip.len() {
        return Err(NetError::TruncatedHeaders);
    }
    let mut frame = RxFrame::EMPTY;
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
    frame.len = ETHERNET_HEADER_BYTES + ip_total;
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
        assert_eq!(
            VirtioNetHeader::decode(&raw),
            Err(NetError::GsoUnsupported)
        );
    }

    #[test]
    fn arp_request_gets_bounded_reply() {
        let request = arp_request();
        assert_eq!(&request[..6], &[0xff; 6]);
        assert_eq!(&request[12..14], &ETHERTYPE_ARP.to_be_bytes());
        assert_eq!(&request[20..22], &ARP_REQUEST.to_be_bytes());
        assert_eq!(&request[38..42], &[10, 0, 2, 1]);
        let mut backend = VirtioNetBackend::new([2, 0, 0, 0, 0, 1], [10, 0, 2, 1]);
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
        let mut backend = VirtioNetBackend::new([2, 0, 0, 0, 0, 1], [10, 0, 2, 1]);
        assert_eq!(backend.transmit(&[0; 13]), Err(NetError::TruncatedHeaders));
        assert_eq!(
            backend.transmit(&[0; MAX_FRAME_BYTES + 1]),
            Err(NetError::FrameTooLarge)
        );
        assert!(backend.pop_rx().is_none());
        assert_eq!(backend.malformed(), 2);
        assert_eq!(backend.tx_frames(), 0);
    }

    #[test]
    fn reset_advances_generation_and_drops_queued_rx() {
        let mut backend = VirtioNetBackend::new([2, 0, 0, 0, 0, 1], [10, 0, 2, 1]);
        backend.transmit(&arp_request()).unwrap();
        assert!(backend.pop_rx().is_some());
        backend.transmit(&arp_request()).unwrap();
        backend.reset();
        assert_eq!(backend.reset_generation(), 2);
        assert!(backend.pop_rx().is_none());
    }
}
