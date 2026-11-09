//! NET-1c bounded TCP segment parsing above IPv4.
//!
//! This layer validates one segment. It intentionally does not own TCP
//! connection state, handshakes, retransmission, sockets or IP reassembly.

use crate::net::NetError;
use crate::net1a::{IpProtocol, Ipv4Header};
use crate::net1b::ipv4_transport_checksum;

pub const TCP_MIN_HEADER_BYTES: usize = 20;
pub const TCP_MAX_HEADER_BYTES: usize = 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpFlags {
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn parse(ip: Ipv4Header<'a>) -> Result<Self, NetError> {
        if ip.more_fragments || ip.fragment_offset != 0 {
            return Err(NetError::InvalidPolicy);
        }
        if ip.protocol != IpProtocol::Tcp {
            return Err(NetError::InvalidPolicy);
        }
        let bytes = ip.payload;
        if bytes.len() < TCP_MIN_HEADER_BYTES {
            return Err(NetError::WireTooShort);
        }
        if bytes[12] & 0x0e != 0 {
            return Err(NetError::InvalidPolicy);
        }
        let header_len = usize::from(bytes[12] >> 4) * 4;
        if !(TCP_MIN_HEADER_BYTES..=TCP_MAX_HEADER_BYTES).contains(&header_len)
            || header_len > bytes.len()
        {
            return Err(NetError::InvalidPolicy);
        }
        let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        if checksum == 0
            || ipv4_transport_checksum(ip.source, ip.destination, IpProtocol::Tcp, bytes) != 0
        {
            return Err(NetError::InvalidPolicy);
        }
        let raw_flags = bytes[13];
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            sequence: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            acknowledgement: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            flags: TcpFlags {
                ns: bytes[12] & 1 != 0,
                cwr: raw_flags & 0x80 != 0,
                ece: raw_flags & 0x40 != 0,
                urg: raw_flags & 0x20 != 0,
                ack: raw_flags & 0x10 != 0,
                psh: raw_flags & 0x08 != 0,
                rst: raw_flags & 0x04 != 0,
                syn: raw_flags & 0x02 != 0,
                fin: raw_flags & 0x01 != 0,
            },
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            checksum,
            urgent_pointer: u16::from_be_bytes([bytes[18], bytes[19]]),
            options: &bytes[TCP_MIN_HEADER_BYTES..header_len],
            payload: &bytes[header_len..],
        })
    }
}

pub fn parse_tcp(ip: Ipv4Header<'_>) -> Result<TcpSegment<'_>, NetError> {
    TcpSegment::parse(ip)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::net1a::{EtherType, EthernetFrame, internet_checksum};

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

    fn tcp(options: &[u8], payload: &[u8]) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let header_len = TCP_MIN_HEADER_BYTES + options.len();
        let mut bytes = vec![0u8; header_len + payload.len()];
        bytes[0..2].copy_from_slice(&1234u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&443u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&0x5566_7788u32.to_be_bytes());
        bytes[12] = ((header_len / 4) as u8) << 4 | 1;
        bytes[13] = 0x12;
        bytes[14..16].copy_from_slice(&4096u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&17u16.to_be_bytes());
        bytes[20..header_len].copy_from_slice(options);
        bytes[header_len..].copy_from_slice(payload);
        let value = ipv4_transport_checksum([10, 0, 0, 1], [10, 0, 0, 2], IpProtocol::Tcp, &bytes);
        bytes[16..18].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    #[test]
    fn tcp_header_options_flags_and_payload_are_parsed_exactly() {
        let segment = tcp(&[2, 4, 0x05, 0xb4], b"data");
        let packet = ipv4(6, &segment);
        let ip = Ipv4Header::parse(&packet).unwrap();
        let parsed = TcpSegment::parse(ip).unwrap();
        assert_eq!(parsed.source_port, 1234);
        assert_eq!(parsed.destination_port, 443);
        assert_eq!(parsed.sequence, 0x1122_3344);
        assert_eq!(parsed.acknowledgement, 0x5566_7788);
        assert!(parsed.flags.ns);
        assert!(parsed.flags.syn);
        assert!(parsed.flags.ack);
        assert_eq!(parsed.window, 4096);
        assert_eq!(parsed.urgent_pointer, 17);
        assert_eq!(parsed.options, &[2, 4, 0x05, 0xb4]);
        assert_eq!(parsed.payload, b"data");

        let maximum_options = [1u8; TCP_MAX_HEADER_BYTES - TCP_MIN_HEADER_BYTES];
        let segment = tcp(&maximum_options, b"");
        let packet = ipv4(6, &segment);
        let ip = Ipv4Header::parse(&packet).unwrap();
        let parsed = TcpSegment::parse(ip).unwrap();
        assert_eq!(parsed.options.len(), 40);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn tcp_rejects_truncation_header_bounds_and_reserved_bits() {
        let packet = ipv4(6, &[0; TCP_MIN_HEADER_BYTES - 1]);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::WireTooShort));

        let mut segment = tcp(b"", b"");
        segment[12] = 4 << 4;
        let packet = ipv4(6, &segment);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::InvalidPolicy));

        let mut segment = tcp(b"", b"");
        segment[12] = 16 << 4;
        let packet = ipv4(6, &segment);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::InvalidPolicy));

        let mut segment = tcp(b"", b"");
        segment[12] |= 0x02;
        let packet = ipv4(6, &segment);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::InvalidPolicy));
    }

    #[test]
    fn tcp_checksum_protocol_and_fragments_fail_closed() {
        let mut segment = tcp(b"", b"");
        segment[16] ^= 1;
        let packet = ipv4(6, &segment);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::InvalidPolicy));

        let mut segment = tcp(b"", b"");
        segment[16..18].fill(0);
        let packet = ipv4(6, &segment);
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::InvalidPolicy));

        let packet = ipv4(17, &tcp(b"", b""));
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::InvalidPolicy));

        let mut packet = ipv4(6, &tcp(b"", b""));
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        let ip = Ipv4Header::parse(&packet).unwrap();
        assert_eq!(TcpSegment::parse(ip), Err(NetError::InvalidPolicy));
    }

    #[test]
    fn ethernet_to_tcp_chain_preserves_bounded_payload() {
        let transport = tcp(&[1, 1, 1, 1], b"chain");
        let network = ipv4(6, &transport);
        let mut frame = vec![0u8; 14 + network.len()];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14..].copy_from_slice(&network);
        let ethernet = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(ethernet.ether_type, EtherType::Ipv4);
        let ip = Ipv4Header::parse(ethernet.payload).unwrap();
        assert_eq!(TcpSegment::parse(ip).unwrap().payload, b"chain");
    }

    #[test]
    fn fixed_seed_tcp_mutations_never_panic() {
        let mut packet = ipv4(6, &tcp(&[1, 3, 3, 7], b"mutation"));
        let mut seed = 0x4e45_5431_4300_0001u64;
        for _ in 0..100_000 {
            let len = packet.len();
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            packet[seed as usize % len] ^= (seed >> 32) as u8;
            if let Ok(ip) = Ipv4Header::parse(&packet) {
                let _ = TcpSegment::parse(ip);
            }
        }
    }
}
