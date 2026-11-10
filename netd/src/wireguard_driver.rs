//! Hosted driver boundary for the mature sans-I/O WireGuard tunnel.

use crate::wireguard::{self, Encapsulated, EntropySource, Now, PollOutput, Received, Tunnel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Active,
    Closed,
    Failed,
}

#[derive(Debug)]
pub enum WireGuardAction {
    Transport,
    HandshakeInitiation,
    Data(Vec<u8>),
    Keepalive,
    Reply,
    HandshakeComplete,
    CookieStored,
}

pub trait DatagramSink {
    fn send(&mut self, datagram: &[u8]) -> Result<(), &'static str>;
}

#[derive(Debug)]
pub enum WireGuardDriverError {
    Tunnel(wireguard::Error),
    Sink(&'static str),
}

pub struct WireGuardPeer {
    tunnel: Tunnel,
    state: PeerState,
    sent_datagrams: u64,
    received_datagrams: u64,
}

impl WireGuardPeer {
    pub fn new(config: wireguard::Config) -> Result<Self, wireguard::Error> {
        Ok(Self {
            tunnel: Tunnel::new(config)?,
            state: PeerState::Active,
            sent_datagrams: 0,
            received_datagrams: 0,
        })
    }

    pub fn state(&self) -> PeerState {
        self.state
    }

    pub fn protocol_stats(&self) -> wireguard::Stats {
        self.tunnel.stats()
    }

    pub fn sent_datagrams(&self) -> u64 {
        self.sent_datagrams
    }

    pub fn received_datagrams(&self) -> u64 {
        self.received_datagrams
    }

    pub fn next_wake(&self) -> Option<wireguard::Ticks> {
        self.tunnel.next_wake()
    }

    pub fn encapsulate_to(
        &mut self,
        now: Now,
        payload: &[u8],
        out: &mut [u8],
        rng: &mut dyn EntropySource,
        sink: &mut dyn DatagramSink,
    ) -> Result<WireGuardAction, WireGuardDriverError> {
        if self.state != PeerState::Active {
            return Err(WireGuardDriverError::Sink("peer is not active"));
        }
        let action = match self
            .tunnel
            .encapsulate(now, payload, out, rng)
            .map_err(WireGuardDriverError::Tunnel)?
        {
            Encapsulated::Transport(wire) => {
                sink.send(wire).map_err(WireGuardDriverError::Sink)?;
                self.sent_datagrams = self.sent_datagrams.saturating_add(1);
                WireGuardAction::Transport
            }
            Encapsulated::HandshakeInitiation(wire) => {
                sink.send(wire).map_err(WireGuardDriverError::Sink)?;
                self.sent_datagrams = self.sent_datagrams.saturating_add(1);
                WireGuardAction::HandshakeInitiation
            }
        };
        Ok(action)
    }

    pub fn decapsulate_from(
        &mut self,
        now: Now,
        remote: &[u8],
        under_load: bool,
        datagram: &[u8],
        out: &mut [u8],
        rng: &mut dyn EntropySource,
        sink: &mut dyn DatagramSink,
    ) -> Result<WireGuardAction, WireGuardDriverError> {
        if self.state != PeerState::Active {
            return Err(WireGuardDriverError::Sink("peer is not active"));
        }
        self.received_datagrams = self.received_datagrams.saturating_add(1);
        match self
            .tunnel
            .decapsulate(now, remote, under_load, datagram, out, rng)
            .map_err(WireGuardDriverError::Tunnel)?
        {
            Received::Data(bytes) => Ok(WireGuardAction::Data(bytes.to_vec())),
            Received::Keepalive => Ok(WireGuardAction::Keepalive),
            Received::Reply(wire) => {
                sink.send(wire).map_err(WireGuardDriverError::Sink)?;
                self.sent_datagrams = self.sent_datagrams.saturating_add(1);
                Ok(WireGuardAction::Reply)
            }
            Received::HandshakeComplete => Ok(WireGuardAction::HandshakeComplete),
            Received::CookieStored => Ok(WireGuardAction::CookieStored),
        }
    }

    pub fn poll_to(
        &mut self,
        now: Now,
        out: &mut [u8],
        rng: &mut dyn EntropySource,
        sink: &mut dyn DatagramSink,
    ) -> Result<usize, WireGuardDriverError> {
        let mut sent = 0;
        loop {
            match self
                .tunnel
                .poll(now, out, rng)
                .map_err(WireGuardDriverError::Tunnel)?
            {
                PollOutput::Send(wire, _) => {
                    sink.send(wire).map_err(WireGuardDriverError::Sink)?;
                    self.sent_datagrams = self.sent_datagrams.saturating_add(1);
                    sent += 1;
                }
                PollOutput::HandshakeExpired => {
                    self.state = PeerState::Failed;
                    break;
                }
                PollOutput::SessionsExpired => {
                    self.state = PeerState::Closed;
                    break;
                }
                PollOutput::Idle => break,
            }
        }
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::{testing::DeterministicRng, Config, StaticSecret};

    #[derive(Default)]
    struct BufferSink(Vec<Vec<u8>>);

    impl DatagramSink for BufferSink {
        fn send(&mut self, datagram: &[u8]) -> Result<(), &'static str> {
            self.0.push(datagram.to_vec());
            Ok(())
        }
    }

    #[test]
    fn peer_driver_handshake_transport_and_sink_boundary() {
        let mut key_rng = DeterministicRng::new(0x4e45_5434_5747);
        let a_key = StaticSecret::generate(&mut key_rng).unwrap();
        let b_key = StaticSecret::generate(&mut key_rng).unwrap();
        let a_public = a_key.public_key();
        let b_public = b_key.public_key();
        let mut a = WireGuardPeer::new(Config::new(a_key, b_public)).unwrap();
        let mut b = WireGuardPeer::new(Config::new(b_key, a_public)).unwrap();
        let now = Now::new(0, 1_700_000_000, 0);
        let mut rng = DeterministicRng::new(9);
        let mut a_out = [0u8; 2048];
        let mut b_out = [0u8; 2048];
        let mut a_sink = BufferSink::default();
        let mut b_sink = BufferSink::default();

        assert!(matches!(
            a.encapsulate_to(now, b"payload", &mut a_out, &mut rng, &mut a_sink)
                .unwrap(),
            WireGuardAction::HandshakeInitiation
        ));
        assert!(matches!(
            b.decapsulate_from(
                now,
                &[10, 0, 0, 2],
                false,
                &a_sink.0[0],
                &mut b_out,
                &mut rng,
                &mut b_sink,
            )
            .unwrap(),
            WireGuardAction::Reply
        ));
        assert!(matches!(
            a.decapsulate_from(
                now,
                &[10, 0, 0, 1],
                false,
                &b_sink.0[0],
                &mut a_out,
                &mut rng,
                &mut a_sink,
            )
            .unwrap(),
            WireGuardAction::HandshakeComplete
        ));
        assert!(matches!(
            a.encapsulate_to(now, b"payload", &mut a_out, &mut rng, &mut a_sink)
                .unwrap(),
            WireGuardAction::Transport
        ));
        let transport = a_sink.0.last().unwrap().clone();
        match b
            .decapsulate_from(
                now,
                &[10, 0, 0, 1],
                false,
                &transport,
                &mut b_out,
                &mut rng,
                &mut b_sink,
            )
            .unwrap()
        {
            WireGuardAction::Data(bytes) => assert_eq!(&bytes[..7], b"payload"),
            _ => panic!("transport data was not returned"),
        }
        assert!(b.sent_datagrams() > 0);
        assert!(b.received_datagrams() >= 2);
        assert!(matches!(
            b.decapsulate_from(
                now,
                &[10, 0, 0, 1],
                false,
                &transport,
                &mut b_out,
                &mut rng,
                &mut b_sink,
            ),
            Err(WireGuardDriverError::Tunnel(_))
        ));
    }
}
