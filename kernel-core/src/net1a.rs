//! NET-1a bounded Ethernet, ARP-over-IPv4 and IPv4 parsing foundation.

use crate::net::NetError;

pub const ETHERNET_HEADER_BYTES: usize = 14;
pub const ETHERNET_MIN_FRAME_BYTES: usize = 60;
/// Largest Ethernet II frame (excluding the four-byte FCS) accepted by this
/// parser. Network drivers normally remove the FCS before handing a frame to
/// the protocol stack; accepting the on-wire size here would admit four
/// trailing bytes as protocol payload.
pub const ETHERNET_MAX_FRAME_BYTES: usize = 1514;
pub const ARP_IPV4_BYTES: usize = 28;
pub const IPV4_MIN_HEADER_BYTES: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Ipv6,
    Unknown(u16),
}

impl EtherType {
    pub const fn from_raw(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ether_type: EtherType,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, NetError> {
        if bytes.len() < ETHERNET_HEADER_BYTES {
            return Err(NetError::WireTooShort);
        }
        if bytes.len() > ETHERNET_MAX_FRAME_BYTES {
            return Err(NetError::InvalidPolicy);
        }
        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];
        destination.copy_from_slice(&bytes[..6]);
        source.copy_from_slice(&bytes[6..12]);
        Ok(Self {
            destination: MacAddress(destination),
            source: MacAddress(source),
            ether_type: EtherType::from_raw(u16::from_be_bytes([bytes[12], bytes[13]])),
            payload: &bytes[ETHERNET_HEADER_BYTES..],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpIpv4 {
    pub operation: ArpOperation,
    pub sender_mac: MacAddress,
    pub sender_ip: [u8; 4],
    pub target_mac: MacAddress,
    pub target_ip: [u8; 4],
}

impl ArpIpv4 {
    pub fn parse(bytes: &[u8]) -> Result<Self, NetError> {
        if bytes.len() < ARP_IPV4_BYTES {
            return Err(NetError::WireTooShort);
        }
        if u16::from_be_bytes([bytes[0], bytes[1]]) != 1
            || u16::from_be_bytes([bytes[2], bytes[3]]) != 0x0800
            || bytes[4] != 6
            || bytes[5] != 4
        {
            return Err(NetError::InvalidPolicy);
        }
        let operation = match u16::from_be_bytes([bytes[6], bytes[7]]) {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            _ => return Err(NetError::InvalidPolicy),
        };
        let mut sender_mac = [0u8; 6];
        let mut target_mac = [0u8; 6];
        sender_mac.copy_from_slice(&bytes[8..14]);
        target_mac.copy_from_slice(&bytes[18..24]);
        let mut sender_ip = [0u8; 4];
        let mut target_ip = [0u8; 4];
        sender_ip.copy_from_slice(&bytes[14..18]);
        target_ip.copy_from_slice(&bytes[24..28]);
        Ok(Self {
            operation,
            sender_mac: MacAddress(sender_mac),
            sender_ip,
            target_mac: MacAddress(target_mac),
            target_ip,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Unknown(u8),
}

impl IpProtocol {
    pub const fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header<'a> {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub protocol: IpProtocol,
    pub ttl: u8,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub payload: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, NetError> {
        if bytes.len() < IPV4_MIN_HEADER_BYTES {
            return Err(NetError::WireTooShort);
        }
        if bytes[0] >> 4 != 4 {
            return Err(NetError::InvalidVersion);
        }
        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < IPV4_MIN_HEADER_BYTES || header_len > bytes.len() {
            return Err(NetError::InvalidPolicy);
        }
        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total_len < header_len || total_len > bytes.len() {
            return Err(NetError::WireTooShort);
        }
        if internet_checksum(&bytes[..header_len]) != 0 {
            return Err(NetError::InvalidPolicy);
        }
        let flags_fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
        if flags_fragment & 0x8000 != 0 {
            return Err(NetError::InvalidPolicy);
        }
        let mut source = [0u8; 4];
        let mut destination = [0u8; 4];
        source.copy_from_slice(&bytes[12..16]);
        destination.copy_from_slice(&bytes[16..20]);
        Ok(Self {
            source,
            destination,
            protocol: IpProtocol::from_raw(bytes[9]),
            ttl: bytes[8],
            dont_fragment: flags_fragment & 0x4000 != 0,
            more_fragments: flags_fragment & 0x2000 != 0,
            fragment_offset: flags_fragment & 0x1fff,
            payload: &bytes[header_len..total_len],
        })
    }
}

pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net1aPacket<'a> {
    Arp(ArpIpv4),
    Ipv4(Ipv4Header<'a>),
    Ipv6(&'a [u8]),
    Unknown,
}

pub fn parse_ethernet_payload<'a>(frame: EthernetFrame<'a>) -> Result<Net1aPacket<'a>, NetError> {
    match frame.ether_type {
        EtherType::Arp => ArpIpv4::parse(frame.payload).map(Net1aPacket::Arp),
        EtherType::Ipv4 => Ipv4Header::parse(frame.payload).map(Net1aPacket::Ipv4),
        EtherType::Ipv6 => Ok(Net1aPacket::Ipv6(frame.payload)),
        EtherType::Unknown(_) => Ok(Net1aPacket::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet() -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&24u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let checksum = internet_checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes
    }

    #[test]
    fn ethernet_and_ipv4_roundtrip_bounded_payload() {
        let ip = ipv4_packet();
        let mut frame = [0u8; ETHERNET_HEADER_BYTES + 24];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14..].copy_from_slice(&ip);
        let parsed = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(parsed.ether_type, EtherType::Ipv4);
        assert_eq!(parsed.source, MacAddress([1, 2, 3, 4, 5, 6]));
        let Net1aPacket::Ipv4(header) = parse_ethernet_payload(parsed).unwrap() else {
            panic!("expected IPv4");
        };
        assert_eq!(header.source, [10, 0, 0, 1]);
        assert_eq!(header.destination, [10, 0, 0, 2]);
        assert_eq!(header.protocol, IpProtocol::Udp);
        assert!(header.dont_fragment);
        assert_eq!(header.payload.len(), 4);
    }

    #[test]
    fn arp_request_parses_exact_layout_and_accepts_padding() {
        let mut bytes = [0u8; 28];
        bytes[0..2].copy_from_slice(&1u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        bytes[4] = 6;
        bytes[5] = 4;
        bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
        bytes[8..14].copy_from_slice(&[1, 1, 1, 1, 1, 1]);
        bytes[14..18].copy_from_slice(&[192, 168, 1, 1]);
        bytes[24..28].copy_from_slice(&[192, 168, 1, 2]);
        let arp = ArpIpv4::parse(&bytes).unwrap();
        assert_eq!(arp.operation, ArpOperation::Request);
        let mut padded = [0u8; 46];
        padded[..28].copy_from_slice(&bytes);
        assert_eq!(ArpIpv4::parse(&padded), Ok(arp));
        assert_eq!(ArpIpv4::parse(&bytes[..27]), Err(NetError::WireTooShort));
        bytes[4] = 8;
        assert_eq!(ArpIpv4::parse(&bytes), Err(NetError::InvalidPolicy));
    }

    #[test]
    fn malformed_lengths_checksums_and_versions_fail_closed() {
        assert_eq!(EthernetFrame::parse(&[0; 13]), Err(NetError::WireTooShort));
        assert!(EthernetFrame::parse(&[0; ETHERNET_MAX_FRAME_BYTES]).is_ok());
        assert_eq!(
            EthernetFrame::parse(&[0; ETHERNET_MAX_FRAME_BYTES + 1]),
            Err(NetError::InvalidPolicy)
        );
        let mut ip = ipv4_packet();
        ip[10] ^= 1;
        assert_eq!(Ipv4Header::parse(&ip), Err(NetError::InvalidPolicy));
        let mut ip = ipv4_packet();
        ip[0] = 0x65;
        assert_eq!(Ipv4Header::parse(&ip), Err(NetError::InvalidVersion));
        let mut ip = ipv4_packet();
        ip[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(Ipv4Header::parse(&ip), Err(NetError::WireTooShort));
        let mut ip = ipv4_packet();
        ip[6..8].copy_from_slice(&0x8000u16.to_be_bytes());
        ip[10..12].fill(0);
        let checksum = internet_checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(Ipv4Header::parse(&ip), Err(NetError::InvalidPolicy));
    }

    #[test]
    fn fixed_seed_mutations_never_panic() {
        let mut seed = 0x4e45_5431_4100_0001u64;
        let ipv4 = ipv4_packet();
        let mut ethernet = [0u8; ETHERNET_HEADER_BYTES + 24];
        ethernet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        ethernet[14..].copy_from_slice(&ipv4);
        let mut arp = [0u8; ARP_IPV4_BYTES];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&1u16.to_be_bytes());
        for _ in 0..60_000 {
            let mut ipv4_mut = ipv4;
            let mut ethernet_mut = ethernet;
            let mut arp_mut = arp;
            for _ in 0..(seed as usize % 5 + 1) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                ipv4_mut[seed as usize % ipv4_mut.len()] ^= (seed >> 32) as u8;
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                ethernet_mut[seed as usize % ethernet_mut.len()] ^= (seed >> 32) as u8;
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                arp_mut[seed as usize % arp_mut.len()] ^= (seed >> 32) as u8;
            }
            let _ = Ipv4Header::parse(&ipv4_mut);
            if let Ok(frame) = EthernetFrame::parse(&ethernet_mut) {
                let _ = parse_ethernet_payload(frame);
            }
            let _ = ArpIpv4::parse(&arp_mut);
        }
    }
}
