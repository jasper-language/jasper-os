//! NET-1b bounded UDP and ICMPv4 echo parsing above the IPv4 boundary.
//!
//! This layer deliberately does not reassemble IP fragments, implement TCP,
//! expose sockets, or retain connection state. Fragmented transport input is
//! rejected until a reassembly gate exists.

use crate::net::NetError;
use crate::net1a::{IpProtocol, Ipv4Header, internet_checksum};

pub const UDP_HEADER_BYTES: usize = 8;
pub const ICMP_ECHO_HEADER_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    pub fn parse(ip: Ipv4Header<'a>) -> Result<Self, NetError> {
        require_unfragmented(ip)?;
        if ip.protocol != IpProtocol::Udp {
            return Err(NetError::InvalidPolicy);
        }
        let bytes = ip.payload;
        if bytes.len() < UDP_HEADER_BYTES {
            return Err(NetError::WireTooShort);
        }
        let declared = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if declared < UDP_HEADER_BYTES {
            return Err(NetError::InvalidPolicy);
        }
        if declared > bytes.len() {
            return Err(NetError::WireTooShort);
        }
        let datagram = &bytes[..declared];
        let checksum = u16::from_be_bytes([bytes[6], bytes[7]]);
        // UDP checksum zero means "not computed" for IPv4 only. A present
        // checksum covers exactly the declared datagram, not IP/Ethernet pad.
        if checksum != 0
            && ipv4_transport_checksum(ip.source, ip.destination, IpProtocol::Udp, datagram) != 0
        {
            return Err(NetError::InvalidPolicy);
        }
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            checksum,
            payload: &datagram[UDP_HEADER_BYTES..],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpEchoKind {
    Request,
    Reply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Icmpv4Echo<'a> {
    pub kind: IcmpEchoKind,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}

impl<'a> Icmpv4Echo<'a> {
    pub fn parse(ip: Ipv4Header<'a>) -> Result<Self, NetError> {
        require_unfragmented(ip)?;
        if ip.protocol != IpProtocol::Icmp {
            return Err(NetError::InvalidPolicy);
        }
        let bytes = ip.payload;
        if bytes.len() < ICMP_ECHO_HEADER_BYTES {
            return Err(NetError::WireTooShort);
        }
        let kind = match bytes[0] {
            0 if bytes[1] == 0 => IcmpEchoKind::Reply,
            8 if bytes[1] == 0 => IcmpEchoKind::Request,
            _ => return Err(NetError::InvalidPolicy),
        };
        if internet_checksum(bytes) != 0 {
            return Err(NetError::InvalidPolicy);
        }
        Ok(Self {
            kind,
            identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: &bytes[ICMP_ECHO_HEADER_BYTES..],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net1bPacket<'a> {
    Udp(UdpDatagram<'a>),
    IcmpEcho(Icmpv4Echo<'a>),
    Unsupported(IpProtocol),
}

pub fn parse_ipv4_transport(ip: Ipv4Header<'_>) -> Result<Net1bPacket<'_>, NetError> {
    require_unfragmented(ip)?;
    match ip.protocol {
        IpProtocol::Udp => UdpDatagram::parse(ip).map(Net1bPacket::Udp),
        IpProtocol::Icmp => Icmpv4Echo::parse(ip).map(Net1bPacket::IcmpEcho),
        protocol => Ok(Net1bPacket::Unsupported(protocol)),
    }
}

pub(crate) fn ipv4_transport_checksum(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: IpProtocol,
    bytes: &[u8],
) -> u16 {
    let mut sum = 0u32;
    sum = add_words(
        sum,
        &[
            source[0],
            source[1],
            source[2],
            source[3],
            destination[0],
            destination[1],
            destination[2],
            destination[3],
            0,
            protocol_number(protocol),
        ],
    );
    sum = add_words(sum, &(bytes.len() as u16).to_be_bytes());
    sum = add_words(sum, bytes);
    fold_checksum(sum)
}

fn require_unfragmented(ip: Ipv4Header<'_>) -> Result<(), NetError> {
    if ip.more_fragments || ip.fragment_offset != 0 {
        Err(NetError::InvalidPolicy)
    } else {
        Ok(())
    }
}

const fn protocol_number(protocol: IpProtocol) -> u8 {
    match protocol {
        IpProtocol::Icmp => 1,
        IpProtocol::Tcp => 6,
        IpProtocol::Udp => 17,
        IpProtocol::Unknown(value) => value,
    }
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(last) << 8);
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::net1a::{
        internet_checksum, parse_ethernet_payload, EthernetFrame, Net1aPacket,
    };

    fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 20 + payload.len()];
        let total_len = bytes.len() as u16;
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&total_len.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let checksum = internet_checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes[20..].copy_from_slice(payload);
        bytes
    }

    fn udp(payload: &[u8], checksum: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; UDP_HEADER_BYTES + payload.len()];
        let total_len = bytes.len() as u16;
        bytes[0..2].copy_from_slice(&1234u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&53u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&total_len.to_be_bytes());
        bytes[8..].copy_from_slice(payload);
        if checksum {
            let value =
                ipv4_transport_checksum([10, 0, 0, 1], [10, 0, 0, 2], IpProtocol::Udp, &bytes);
            bytes[6..8].copy_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    fn icmp(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; ICMP_ECHO_HEADER_BYTES + payload.len()];
        bytes[0] = kind;
        bytes[4..6].copy_from_slice(&7u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&9u16.to_be_bytes());
        bytes[8..].copy_from_slice(payload);
        let value = internet_checksum(&bytes);
        bytes[2..4].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn ethernet(payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 14 + core::cmp::max(46, payload.len())];
        bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        bytes[14..14 + payload.len()].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn udp_ports_length_checksum_and_payload_are_bounded() {
        let with_checksum = udp(b"hello", true);
        let packet = ipv4(17, &with_checksum);
        let ip = Ipv4Header::parse(&packet).unwrap();
        let parsed = UdpDatagram::parse(ip).unwrap();
        assert_eq!(parsed.source_port, 1234);
        assert_eq!(parsed.destination_port, 53);
        assert_eq!(parsed.payload, b"hello");
        assert_ne!(parsed.checksum, 0);

        let without_checksum = udp(b"world", false);
        let packet = ipv4(17, &without_checksum);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(UdpDatagram::parse(ip).unwrap().payload, b"world");
    }

    #[test]
    fn malformed_udp_fails_closed() {
        let mut bytes = udp(b"payload", true);
        bytes[6] ^= 1;
        let packet = ipv4(17, &bytes);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(UdpDatagram::parse(ip), Err(NetError::InvalidPolicy));

        let mut bytes = udp(b"", true);
        bytes[4..6].copy_from_slice(&7u16.to_be_bytes());
        let packet = ipv4(17, &bytes);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(UdpDatagram::parse(ip), Err(NetError::InvalidPolicy));

        let mut bytes = udp(b"", true);
        bytes[4..6].copy_from_slice(&9u16.to_be_bytes());
        let packet = ipv4(17, &bytes);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(UdpDatagram::parse(ip), Err(NetError::WireTooShort));

        let packet = ipv4(17, &[0; 7]);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(UdpDatagram::parse(ip), Err(NetError::WireTooShort));
        let transport = udp(b"", false);
        let packet = ipv4(6, &transport);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(UdpDatagram::parse(ip), Err(NetError::InvalidPolicy));
    }

    #[test]
    fn icmp_echo_request_and_reply_are_exact_and_checksummed() {
        for (kind, expected) in [(8, IcmpEchoKind::Request), (0, IcmpEchoKind::Reply)] {
            let bytes = icmp(kind, b"ping");
            let packet = ipv4(1, &bytes);
            let ip = Ipv4Header::parse(&packet).unwrap();
            let parsed = Icmpv4Echo::parse(ip).unwrap();
            assert_eq!(parsed.kind, expected);
            assert_eq!(parsed.identifier, 7);
            assert_eq!(parsed.sequence, 9);
            assert_eq!(parsed.payload, b"ping");
        }
    }

    #[test]
    fn malformed_icmp_and_fragments_fail_closed() {
        let mut bytes = icmp(8, b"");
        bytes[0] = 3;
        let packet = ipv4(1, &bytes);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(Icmpv4Echo::parse(ip), Err(NetError::InvalidPolicy));

        let mut bytes = icmp(8, b"");
        bytes[2] ^= 1;
        let packet = ipv4(1, &bytes);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(Icmpv4Echo::parse(ip), Err(NetError::InvalidPolicy));

        let packet = ipv4(1, &[8; 7]);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(Icmpv4Echo::parse(ip), Err(NetError::WireTooShort));

        let mut fragmented = ipv4(17, &udp(b"", false));
        fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        fragmented[10..12].fill(0);
        let checksum = internet_checksum(&fragmented[..20]);
        fragmented[10..12].copy_from_slice(&checksum.to_be_bytes());
        let ip = Ipv4Header::parse(&fragmented).unwrap();
        assert_eq!(UdpDatagram::parse(ip), Err(NetError::InvalidPolicy));

        let mut fragmented = ipv4(1, &icmp(8, b""));
        fragmented[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        fragmented[10..12].fill(0);
        let checksum = internet_checksum(&fragmented[..20]);
        fragmented[10..12].copy_from_slice(&checksum.to_be_bytes());
        let ip = Ipv4Header::parse(&fragmented).unwrap();
        assert_eq!(Icmpv4Echo::parse(ip), Err(NetError::InvalidPolicy));
    }

    #[test]
    fn ethernet_dispatch_preserves_ipv4_transport_boundaries() {
        let datagram = udp(b"hello", true);
        let mut padded = datagram.clone();
        padded.extend_from_slice(b"IP-tail-is-not-UDP-payload");
        let ip_bytes = ipv4(17, &padded);
        let frame = ethernet(&ip_bytes);
        let parsed_frame = EthernetFrame::parse(&frame).unwrap();
        let Net1aPacket::Ipv4(ip) = parse_ethernet_payload(parsed_frame).unwrap() else {
            panic!("expected IPv4");
        };
        let udp = UdpDatagram::parse(ip).unwrap();
        assert_eq!(udp.payload, b"hello");

        let ip_bytes = ipv4(1, &icmp(8, b"ping"));
        let frame = ethernet(&ip_bytes);
        let parsed_frame = EthernetFrame::parse(&frame).unwrap();
        let Net1aPacket::Ipv4(ip) = parse_ethernet_payload(parsed_frame).unwrap() else {
            panic!("expected IPv4");
        };
        let echo = Icmpv4Echo::parse(ip).unwrap();
        assert_eq!(echo.kind, IcmpEchoKind::Request);
        assert_eq!(echo.payload, b"ping");
    }

    #[test]
    fn dispatch_keeps_tcp_and_unknown_transport_unimplemented() {
        let packet = ipv4(6, &[0; 20]);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(
            parse_ipv4_transport(ip),
            Ok(Net1bPacket::Unsupported(IpProtocol::Tcp))
        );
        let packet = ipv4(99, &[0; 20]);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(
            parse_ipv4_transport(ip),
            Ok(Net1bPacket::Unsupported(IpProtocol::Unknown(99)))
        );
    }

    #[test]
    fn fixed_seed_mutations_never_panic() {
        let udp = udp(b"mutation", true);
        let icmp = icmp(8, b"mutation");
        let mut ipv4_udp = ipv4(17, &udp);
        let mut ipv4_icmp = ipv4(1, &icmp);
        let mut seed = 0x4e45_5431_4200_0001u64;
        for _ in 0..100_000 {
            let udp_len = ipv4_udp.len();
            let icmp_len = ipv4_icmp.len();
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ipv4_udp[seed as usize % udp_len] ^= (seed >> 32) as u8;
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ipv4_icmp[seed as usize % icmp_len] ^= (seed >> 32) as u8;
            if let Ok(ip) = Ipv4Header::parse(&ipv4_udp) {
                let _ = UdpDatagram::parse(ip);
            }
            if let Ok(ip) = Ipv4Header::parse(&ipv4_icmp) {
                let _ = Icmpv4Echo::parse(ip);
            }
        }
    }
}
