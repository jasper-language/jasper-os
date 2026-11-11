//! Hosted driver boundary for the mature sans-I/O WireGuard tunnel.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

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

pub type PeerId = u32;

/// One canonical IPv4 route accepted by a WireGuard peer.
/// 某个 WireGuard peer 接受的一条规范 IPv4 路由。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireGuardRoute {
    network: u32,
    prefix: u8,
}

impl WireGuardRoute {
    pub fn new(address: Ipv4Addr, prefix: u8) -> Result<Self, WireGuardRouterError> {
        if prefix > 32 {
            return Err(WireGuardRouterError::InvalidRoute);
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        Ok(Self {
            network: u32::from(address) & mask,
            prefix,
        })
    }

    pub fn contains(self, address: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        };
        u32::from(address) & mask == self.network
    }
}

#[derive(Debug)]
pub enum WireGuardRouterError {
    Capacity,
    InvalidRoute,
    InvalidRate,
    DuplicateEndpoint,
    DuplicateRoute,
    NotFound,
    UnknownEndpoint,
    RateLimited,
    BucketCapacity,
    Driver(WireGuardDriverError),
}

#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    tokens: u64,
    last_ns: u64,
}

struct RoutedPeer {
    id: PeerId,
    endpoint: SocketAddr,
    routes: Vec<WireGuardRoute>,
    peer: WireGuardPeer,
    rate_per_second: u32,
    burst: u64,
    buckets: HashMap<Ipv4Addr, TokenBucket>,
    rate_limited: u64,
}

/// Bounded multi-peer routing, endpoint binding and per-destination-IP pacing.
/// 有界多 peer 路由、端点绑定和按目的 IP 的发送限速。
pub struct WireGuardRouter {
    peers: Vec<RoutedPeer>,
    max_peers: usize,
    max_routes: usize,
    max_buckets_per_peer: usize,
    route_count: usize,
    sent_datagrams: u64,
    rate_limited: u64,
}

impl WireGuardRouter {
    pub fn new(
        max_peers: usize,
        max_routes: usize,
        max_buckets_per_peer: usize,
    ) -> Result<Self, WireGuardRouterError> {
        if max_peers == 0 || max_routes == 0 || max_buckets_per_peer == 0 {
            return Err(WireGuardRouterError::Capacity);
        }
        Ok(Self {
            peers: Vec::new(),
            max_peers,
            max_routes,
            max_buckets_per_peer,
            route_count: 0,
            sent_datagrams: 0,
            rate_limited: 0,
        })
    }

    pub fn add_peer(
        &mut self,
        config: wireguard::Config,
        endpoint: SocketAddr,
        routes: &[WireGuardRoute],
        rate_per_second: u32,
        burst: u64,
    ) -> Result<PeerId, WireGuardRouterError> {
        if self.peers.len() == self.max_peers
            || routes.is_empty()
            || self.route_count.saturating_add(routes.len()) > self.max_routes
        {
            return Err(WireGuardRouterError::Capacity);
        }
        if rate_per_second == 0 || burst == 0 {
            return Err(WireGuardRouterError::InvalidRate);
        }
        if self.peers.iter().any(|peer| peer.endpoint == endpoint) {
            return Err(WireGuardRouterError::DuplicateEndpoint);
        }
        if routes.iter().any(|route| {
            self.peers
                .iter()
                .flat_map(|peer| peer.routes.iter())
                .any(|existing| existing == route)
        }) {
            return Err(WireGuardRouterError::DuplicateRoute);
        }
        if routes
            .iter()
            .enumerate()
            .any(|(index, route)| routes[..index].contains(route))
        {
            return Err(WireGuardRouterError::DuplicateRoute);
        }
        let id = u32::try_from(self.peers.len()).map_err(|_| WireGuardRouterError::Capacity)?;
        let peer = WireGuardPeer::new(config)
            .map_err(WireGuardDriverError::Tunnel)
            .map_err(WireGuardRouterError::Driver)?;
        self.peers.push(RoutedPeer {
            id,
            endpoint,
            routes: routes.to_vec(),
            peer,
            rate_per_second,
            burst,
            buckets: HashMap::new(),
            rate_limited: 0,
        });
        self.route_count += routes.len();
        Ok(id)
    }

    fn route_index(&self, destination: Ipv4Addr) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .flat_map(|(index, peer)| {
                peer.routes
                    .iter()
                    .filter(move |route| route.contains(destination))
                    .map(move |route| (index, route.prefix))
            })
            .max_by_key(|(_, prefix)| *prefix)
            .map(|(index, _)| index)
    }

    pub fn encapsulate_to(
        &mut self,
        now: Now,
        destination: Ipv4Addr,
        payload: &[u8],
        out: &mut [u8],
        rng: &mut dyn EntropySource,
        sink: &mut dyn DatagramSink,
    ) -> Result<(PeerId, WireGuardAction), WireGuardRouterError> {
        let index = self
            .route_index(destination)
            .ok_or(WireGuardRouterError::NotFound)?;
        let routed = &mut self.peers[index];
        if !Self::bucket_allows(
            &mut routed.buckets,
            destination,
            now.ticks.nanos(),
            routed.rate_per_second,
            routed.burst,
            self.max_buckets_per_peer,
        )? {
            routed.rate_limited = routed.rate_limited.saturating_add(1);
            self.rate_limited = self.rate_limited.saturating_add(1);
            return Err(WireGuardRouterError::RateLimited);
        }
        let action = routed
            .peer
            .encapsulate_to(now, payload, out, rng, sink)
            .map_err(WireGuardRouterError::Driver)?;
        self.sent_datagrams = self.sent_datagrams.saturating_add(1);
        Ok((routed.id, action))
    }

    pub fn decapsulate_from(
        &mut self,
        now: Now,
        endpoint: SocketAddr,
        under_load: bool,
        datagram: &[u8],
        out: &mut [u8],
        rng: &mut dyn EntropySource,
        sink: &mut dyn DatagramSink,
    ) -> Result<(PeerId, WireGuardAction), WireGuardRouterError> {
        let routed = self
            .peers
            .iter_mut()
            .find(|peer| peer.endpoint == endpoint)
            .ok_or(WireGuardRouterError::UnknownEndpoint)?;
        let remote = match endpoint.ip() {
            std::net::IpAddr::V4(address) => address.octets().to_vec(),
            std::net::IpAddr::V6(address) => address.octets().to_vec(),
        };
        let action = routed
            .peer
            .decapsulate_from(now, &remote, under_load, datagram, out, rng, sink)
            .map_err(WireGuardRouterError::Driver)?;
        Ok((routed.id, action))
    }

    pub fn peer_state(&self, id: PeerId) -> Option<PeerState> {
        self.peers
            .iter()
            .find(|peer| peer.id == id)
            .map(|peer| peer.peer.state())
    }

    /// Returns the earliest protocol timer across all bound peers.
    /// 返回全部已绑定 peer 中最早的协议定时器。
    pub fn next_wake(&self) -> Option<wireguard::Ticks> {
        self.peers
            .iter()
            .filter_map(|peer| peer.peer.next_wake())
            .min()
    }

    pub fn stats(&self) -> (usize, usize, u64, u64) {
        (
            self.peers.len(),
            self.route_count,
            self.sent_datagrams,
            self.rate_limited,
        )
    }

    pub fn peer_rate_limited(&self, id: PeerId) -> Option<u64> {
        self.peers
            .iter()
            .find(|peer| peer.id == id)
            .map(|peer| peer.rate_limited)
    }

    fn bucket_allows(
        buckets: &mut HashMap<Ipv4Addr, TokenBucket>,
        address: Ipv4Addr,
        now_ns: u64,
        rate_per_second: u32,
        burst: u64,
        max_buckets: usize,
    ) -> Result<bool, WireGuardRouterError> {
        if !buckets.contains_key(&address) && buckets.len() == max_buckets {
            return Err(WireGuardRouterError::BucketCapacity);
        }
        let bucket = buckets.entry(address).or_insert(TokenBucket {
            tokens: burst,
            last_ns: now_ns,
        });
        if bucket.tokens >= burst {
            bucket.last_ns = now_ns;
        } else if now_ns > bucket.last_ns {
            let elapsed = u128::from(now_ns - bucket.last_ns);
            let refill = elapsed.saturating_mul(u128::from(rate_per_second)) / 1_000_000_000;
            let added = u64::try_from(refill).unwrap_or(u64::MAX);
            if added != 0 {
                bucket.tokens = bucket.tokens.saturating_add(added).min(burst);
                if bucket.tokens >= burst {
                    bucket.last_ns = now_ns;
                } else {
                    let consumed = u128::from(added).saturating_mul(1_000_000_000)
                        / u128::from(rate_per_second);
                    bucket.last_ns = bucket
                        .last_ns
                        .saturating_add(u64::try_from(consumed).unwrap_or(u64::MAX));
                }
            }
        }
        if bucket.tokens == 0 {
            return Ok(false);
        }
        bucket.tokens -= 1;
        Ok(true)
    }
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

    #[test]
    fn router_uses_longest_prefix_bound_endpoint_and_per_destination_limit() {
        let mut key_rng = DeterministicRng::new(0x524f_5554_4552_5747);
        let first_key = StaticSecret::generate(&mut key_rng).unwrap();
        let second_key = StaticSecret::generate(&mut key_rng).unwrap();
        let remote_key = StaticSecret::generate(&mut key_rng).unwrap();
        let remote_public = remote_key.public_key();
        let mut router = WireGuardRouter::new(2, 4, 4).unwrap();
        let first = router
            .add_peer(
                Config::new(first_key, remote_public),
                "10.0.0.2:51820".parse().unwrap(),
                &[WireGuardRoute::new(Ipv4Addr::new(10, 0, 0, 0), 24).unwrap()],
                2,
                2,
            )
            .unwrap();
        let second = router
            .add_peer(
                Config::new(second_key, remote_public),
                "10.0.0.3:51820".parse().unwrap(),
                &[WireGuardRoute::new(Ipv4Addr::new(10, 0, 0, 128), 25).unwrap()],
                1,
                1,
            )
            .unwrap();
        assert_ne!(first, second);

        let mut rng = DeterministicRng::new(77);
        let mut out = [0u8; 2048];
        let mut sink = BufferSink::default();
        let now = Now::new(0, 1_700_000_000, 0);
        let first_destination = Ipv4Addr::new(10, 0, 0, 10);
        assert_eq!(
            router
                .encapsulate_to(
                    now,
                    first_destination,
                    b"first",
                    &mut out,
                    &mut rng,
                    &mut sink,
                )
                .unwrap()
                .0,
            first
        );
        assert!(matches!(
            router.encapsulate_to(
                now,
                first_destination,
                b"second",
                &mut out,
                &mut rng,
                &mut sink,
            ),
            Err(WireGuardRouterError::Driver(WireGuardDriverError::Tunnel(
                wireguard::Error::NotEstablished
            )))
        ));
        assert!(matches!(
            router.encapsulate_to(
                now,
                first_destination,
                b"limited",
                &mut out,
                &mut rng,
                &mut sink,
            ),
            Err(WireGuardRouterError::RateLimited)
        ));
        let first_peer = router
            .peers
            .iter_mut()
            .find(|peer| peer.id == first)
            .unwrap();
        assert!(!WireGuardRouter::bucket_allows(
            &mut first_peer.buckets,
            first_destination,
            250_000_000,
            first_peer.rate_per_second,
            first_peer.burst,
            4,
        )
        .unwrap());
        assert!(WireGuardRouter::bucket_allows(
            &mut first_peer.buckets,
            first_destination,
            500_000_000,
            first_peer.rate_per_second,
            first_peer.burst,
            4,
        )
        .unwrap());
        assert_eq!(
            router
                .encapsulate_to(
                    now,
                    Ipv4Addr::new(10, 0, 0, 200),
                    b"longest-prefix",
                    &mut out,
                    &mut rng,
                    &mut sink,
                )
                .unwrap()
                .0,
            second
        );
        assert!(matches!(
            router.encapsulate_to(
                now,
                Ipv4Addr::new(192, 0, 2, 1),
                b"unrouted",
                &mut out,
                &mut rng,
                &mut sink,
            ),
            Err(WireGuardRouterError::NotFound)
        ));
        assert!(matches!(
            router.decapsulate_from(
                now,
                "10.0.0.99:51820".parse().unwrap(),
                false,
                b"unbound",
                &mut out,
                &mut rng,
                &mut sink,
            ),
            Err(WireGuardRouterError::UnknownEndpoint)
        ));
        assert_eq!(router.peer_rate_limited(first), Some(1));
        assert_eq!(router.stats(), (2, 2, 2, 1));
        assert_eq!(router.peer_state(first), Some(PeerState::Active));
    }
}
