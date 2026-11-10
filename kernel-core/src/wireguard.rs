//! WireGuard protocol support supplied by a mature `no_std` implementation.
//!
//! 职责：公开成熟的 WireGuard Noise/传输状态机，不自行实现密码学或握手。
//! 调用方仍负责 socket、熵源、单调时钟和多 peer 路由。
//! Responsibility: expose a mature sans-I/O WireGuard state machine.
//! Socket, entropy, clock and multi-peer routing remain caller-owned.

pub use wireguard_sans_io::*;

#[cfg(test)]
mod tests {
    use super::*;
    use wireguard_sans_io::testing::DeterministicRng;

    fn ipv4(payload: &[u8]) -> [u8; 64] {
        let mut packet = [0u8; 64];
        let total = 20 + payload.len();
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..total].copy_from_slice(payload);
        let mut sum = 0u32;
        for chunk in packet[..20].chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        packet
    }

    #[test]
    fn mature_wireguard_handshake_transport_and_replay_paths_pass() {
        let mut key_rng = DeterministicRng::new(0x4a41_5350_4552_5747);
        let a_key = StaticSecret::generate(&mut key_rng).unwrap();
        let b_key = StaticSecret::generate(&mut key_rng).unwrap();
        let a_public = a_key.public_key();
        let b_public = b_key.public_key();
        let mut a = Tunnel::new(Config::new(a_key, b_public)).unwrap();
        let mut b = Tunnel::new(Config::new(b_key, a_public)).unwrap();
        let now = Now::new(0, 1_700_000_000, 0);
        let mut rng = DeterministicRng::new(7);
        let mut a_out = [0u8; 2048];
        let mut b_out = [0u8; 2048];
        let mut payload = ipv4(b"hello");
        payload[20..25].copy_from_slice(b"hello");

        let initiation = match a
            .encapsulate(now, &payload[..25], &mut a_out, &mut rng)
            .unwrap()
        {
            Encapsulated::HandshakeInitiation(wire) => wire.to_vec(),
            _ => panic!("first packet must initiate a handshake"),
        };
        let response = match b
            .decapsulate(
                now,
                &[10, 0, 0, 2],
                false,
                &initiation,
                &mut b_out,
                &mut rng,
            )
            .unwrap()
        {
            Received::Reply(wire) => wire.to_vec(),
            _ => panic!("responder did not produce a handshake response"),
        };
        assert!(matches!(
            a.decapsulate(now, &[10, 0, 0, 1], false, &response, &mut a_out, &mut rng)
                .unwrap(),
            Received::HandshakeComplete
        ));

        let transport = match a
            .encapsulate(now, &payload[..25], &mut a_out, &mut rng)
            .unwrap()
        {
            Encapsulated::Transport(wire) => wire.to_vec(),
            _ => panic!("established tunnel did not encrypt transport data"),
        };
        let plaintext = match b
            .decapsulate(now, &[10, 0, 0, 1], false, &transport, &mut b_out, &mut rng)
            .unwrap()
        {
            Received::Data(data) => data.to_vec(),
            _ => panic!("authenticated transport was not delivered"),
        };
        assert_eq!(&plaintext[..25], &payload[..25]);
        assert!(b.stats().replays_dropped == 0);
        assert!(b
            .decapsulate(now, &[10, 0, 0, 1], false, &transport, &mut b_out, &mut rng,)
            .is_err());
        assert_eq!(b.stats().replays_dropped, 1);
    }
}
