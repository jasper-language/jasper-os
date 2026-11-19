//! Bounded Linux pipe byte stream shared by reader/writer endpoints.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use kernel_core::sync::SpinLock;

/// Default capacity of a newly created Linux pipe.
///
/// This is compatibility-profile behavior, not a kernel-wide maximum. The
/// per-endpoint maximum is admitted from the caller's runtime resource budget.
pub const LINUX_PIPE_DEFAULT_CAPACITY: usize = 64 * 1024; // JASPER-HARDCODE-REVIEW: issue=35 source=linux-pipe-uapi-v1 reason=compat-default-not-runtime-maximum
pub const PIPE_BUF: usize = 4096;
pub const UNIX_SOCKET_NAME_MAX: usize = 108;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnixCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeRead {
    Data(usize),
    WouldBlock,
    Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeWrite {
    Data(usize),
    WouldBlock,
    Broken,
    NoMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeCapacityError {
    BelowMinimum,
    AboveBudget,
    Buffered,
}

#[derive(Debug)]
struct PipeState {
    bytes: VecDeque<u8>,
    readers: u32,
    writers: u32,
    capacity: usize,
    max_capacity: Option<usize>,
}

pub struct PipeEndpoint {
    state: Arc<SpinLock<PipeState>>,
    reader: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnixSocketName {
    bytes: [u8; UNIX_SOCKET_NAME_MAX],
    len: u8,
}

impl UnixSocketName {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; UNIX_SOCKET_NAME_MAX],
            len: 0,
        }
    }

    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > UNIX_SOCKET_NAME_MAX {
            return None;
        }
        let mut name = Self::empty();
        name.bytes[..bytes.len()].copy_from_slice(bytes);
        name.len = bytes.len() as u8;
        Some(name)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// One endpoint of a bounded bidirectional Unix stream socket.
pub struct UnixSocketEndpoint {
    link: SpinLock<Option<SocketLink>>,
    identity: SpinLock<Option<Arc<SocketIdentity>>>,
    side: AtomicU8,
    default_capacity: usize,
    max_capacity: Option<usize>,
}

struct SocketLink {
    rx: PipeEndpoint,
    tx: PipeEndpoint,
}

struct SocketIdentity {
    names: SpinLock<SocketNames>,
    credentials: SpinLock<[UnixCredentials; 2]>,
    first: AtomicU32,
    second: AtomicU32,
}

struct SocketNames {
    first: UnixSocketName,
    second: UnixSocketName,
}

impl UnixSocketEndpoint {
    pub fn pair() -> (Self, Self) {
        Self::pair_with_budget(LINUX_PIPE_DEFAULT_CAPACITY, usize::MAX)
            .expect("default Unix socket pipe allocation")
    }

    /// Creates a socket pair whose pipe buffers are bounded by an admitted
    /// runtime byte budget. Allocation failure returns `None` without
    /// publishing a partial pair.
    pub fn pair_with_budget(default_capacity: usize, byte_budget: usize) -> Option<(Self, Self)> {
        let per_direction = byte_budget / 2;
        if per_direction < default_capacity {
            return None;
        }
        Self::connected_pair(default_capacity, Some(per_direction))
    }

    fn connected_pair(
        default_capacity: usize,
        max_capacity: Option<usize>,
    ) -> Option<(Self, Self)> {
        let identity = Arc::new(SocketIdentity::new());
        let (a_to_b_rx, a_to_b_tx) = PipeEndpoint::try_pair(default_capacity, max_capacity)?;
        let (b_to_a_rx, b_to_a_tx) = PipeEndpoint::try_pair(default_capacity, max_capacity)?;
        Some((
            Self {
                link: SpinLock::new(Some(SocketLink {
                    rx: b_to_a_rx,
                    tx: a_to_b_tx,
                })),
                identity: SpinLock::new(Some(Arc::clone(&identity))),
                side: AtomicU8::new(0),
                default_capacity,
                max_capacity,
            },
            Self {
                link: SpinLock::new(Some(SocketLink {
                    rx: a_to_b_rx,
                    tx: b_to_a_tx,
                })),
                identity: SpinLock::new(Some(identity)),
                side: AtomicU8::new(1),
                default_capacity,
                max_capacity,
            },
        ))
    }

    /// Creates a socket placeholder that may later be connected without
    /// replacing its fd handle. Fork inheritance shares this transition.
    pub fn unconnected() -> Self {
        Self::unconnected_with_budget(LINUX_PIPE_DEFAULT_CAPACITY, usize::MAX)
            .expect("default Unix socket endpoint")
    }

    /// Creates an unconnected endpoint with an admitted pipe-buffer budget.
    pub fn unconnected_with_budget(default_capacity: usize, byte_budget: usize) -> Option<Self> {
        let per_direction = byte_budget / 2;
        if default_capacity < PIPE_BUF || per_direction < default_capacity {
            return None;
        }
        Some(Self::unconnected_with_capacity(
            default_capacity,
            Some(per_direction),
        ))
    }

    fn unconnected_with_capacity(default_capacity: usize, max_capacity: Option<usize>) -> Self {
        Self {
            link: SpinLock::new(None),
            identity: SpinLock::new(None),
            side: AtomicU8::new(0),
            default_capacity,
            max_capacity,
        }
    }

    /// Atomically joins two unconnected endpoints as opposite sides of one
    /// bidirectional stream. The operation has no partial result.
    pub fn connect_pair(client: &Self, server: &Self) -> bool {
        if core::ptr::eq(client, server) {
            return false;
        }
        let max_capacity = match (client.max_capacity, server.max_capacity) {
            (Some(first), Some(second)) => Some(first.min(second)),
            (None, Some(limit)) | (Some(limit), None) => Some(limit),
            (None, None) => None,
        };
        let default_capacity = client.default_capacity.max(server.default_capacity);
        let Some((a_to_b_rx, a_to_b_tx)) = PipeEndpoint::try_pair(default_capacity, max_capacity)
        else {
            return false;
        };
        let Some((b_to_a_rx, b_to_a_tx)) = PipeEndpoint::try_pair(default_capacity, max_capacity)
        else {
            return false;
        };
        let mut client_link = client.link.lock();
        let mut server_link = server.link.lock();
        if client_link.is_some() || server_link.is_some() {
            return false;
        }
        let identity = Arc::new(SocketIdentity::new());
        client.side.store(0, Ordering::Release);
        server.side.store(1, Ordering::Release);
        *client_link = Some(SocketLink {
            rx: b_to_a_rx,
            tx: a_to_b_tx,
        });
        *server_link = Some(SocketLink {
            rx: a_to_b_rx,
            tx: b_to_a_tx,
        });
        *client.identity.lock() = Some(Arc::clone(&identity));
        *server.identity.lock() = Some(identity);
        true
    }

    pub fn default_capacity(&self) -> usize {
        self.default_capacity
    }

    pub fn max_capacity(&self) -> Option<usize> {
        self.max_capacity
    }

    pub fn is_connected(&self) -> bool {
        self.link.lock().is_some()
    }

    pub fn set_names(&self, local: UnixSocketName, peer: UnixSocketName) -> bool {
        let Some(identity) = self.identity() else {
            return false;
        };
        let mut names = identity.names.lock();
        if self.is_first() {
            names.first = local;
            names.second = peer;
        } else {
            names.second = local;
            names.first = peer;
        }
        true
    }

    pub fn local_name(&self) -> Option<UnixSocketName> {
        let identity = self.identity()?;
        let names = identity.names.lock();
        Some(if self.is_first() {
            names.first
        } else {
            names.second
        })
    }

    pub fn peer_name(&self) -> Option<UnixSocketName> {
        let identity = self.identity()?;
        let names = identity.names.lock();
        Some(if self.is_first() {
            names.second
        } else {
            names.first
        })
    }

    pub fn set_credentials(&self, local: UnixCredentials, peer: UnixCredentials) -> bool {
        let Some(identity) = self.identity() else {
            return false;
        };
        let mut credentials = identity.credentials.lock();
        if self.is_first() {
            credentials[0] = local;
            credentials[1] = peer;
        } else {
            credentials[1] = local;
            credentials[0] = peer;
        }
        true
    }

    pub fn peer_credentials(&self) -> Option<UnixCredentials> {
        let identity = self.identity()?;
        let credentials = identity.credentials.lock();
        Some(if self.is_first() {
            credentials[1]
        } else {
            credentials[0]
        })
    }

    pub fn read(&self, output: &mut [u8]) -> PipeRead {
        const SHUT_RD: u32 = 1;
        const SHUT_WR: u32 = 2;
        if self.flags() & SHUT_RD != 0 {
            return PipeRead::Eof;
        }
        let link = self.link.lock();
        let Some(link) = link.as_ref() else {
            return PipeRead::Eof;
        };
        match link.rx.read(output) {
            PipeRead::WouldBlock if self.peer_flags() & SHUT_WR != 0 => PipeRead::Eof,
            result => result,
        }
    }

    pub fn write(&self, input: &[u8]) -> PipeWrite {
        const SHUT_RD: u32 = 1;
        const SHUT_WR: u32 = 2;
        if self.flags() & SHUT_WR != 0 || self.peer_flags() & SHUT_RD != 0 {
            return PipeWrite::Broken;
        }
        let link = self.link.lock();
        let Some(link) = link.as_ref() else {
            return PipeWrite::Broken;
        };
        link.tx.write(input)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.link
            .lock()
            .as_ref()
            .map(|link| link.rx.buffered_bytes())
            .unwrap_or(0)
    }

    /// Current admitted byte capacity of the outbound pipe.
    pub fn capacity(&self) -> usize {
        self.link
            .lock()
            .as_ref()
            .map(|link| link.tx.capacity())
            .unwrap_or(0)
    }

    pub fn is_readable(&self) -> bool {
        self.flags() & 1 != 0
            || self.peer_flags() & 2 != 0
            || self
                .link
                .lock()
                .as_ref()
                .is_none_or(|link| link.rx.is_readable())
    }

    pub fn is_writable(&self) -> bool {
        self.flags() & 2 == 0
            && self.peer_flags() & 1 == 0
            && self
                .link
                .lock()
                .as_ref()
                .is_some_and(|link| link.tx.is_writable())
    }

    pub fn peer_read_gone(&self) -> bool {
        self.link
            .lock()
            .as_ref()
            .is_none_or(|link| link.tx.readers_gone())
            || self.peer_flags() & 1 != 0
    }

    pub fn peer_write_gone(&self) -> bool {
        self.link
            .lock()
            .as_ref()
            .is_none_or(|link| link.rx.writers_gone())
            || self.peer_flags() & 2 != 0
    }

    pub fn shutdown(&self, how: u32) -> bool {
        let bits = match how {
            0 => 1,
            1 => 2,
            2 => 3,
            _ => return false,
        };
        let Some(identity) = self.identity() else {
            return false;
        };
        let state = if self.is_first() {
            &identity.first
        } else {
            &identity.second
        };
        state.fetch_or(bits, Ordering::AcqRel);
        true
    }

    fn identity(&self) -> Option<Arc<SocketIdentity>> {
        self.identity.lock().as_ref().map(Arc::clone)
    }

    fn is_first(&self) -> bool {
        self.side.load(Ordering::Acquire) == 0
    }

    fn flags(&self) -> u32 {
        let Some(identity) = self.identity() else {
            return 0;
        };
        if self.is_first() {
            identity.first.load(Ordering::Acquire)
        } else {
            identity.second.load(Ordering::Acquire)
        }
    }

    fn peer_flags(&self) -> u32 {
        let Some(identity) = self.identity() else {
            return 0;
        };
        if self.is_first() {
            identity.second.load(Ordering::Acquire)
        } else {
            identity.first.load(Ordering::Acquire)
        }
    }
}

impl SocketIdentity {
    fn new() -> Self {
        Self {
            names: SpinLock::new(SocketNames {
                first: UnixSocketName::empty(),
                second: UnixSocketName::empty(),
            }),
            credentials: SpinLock::new([UnixCredentials::default(); 2]),
            first: AtomicU32::new(0),
            second: AtomicU32::new(0),
        }
    }
}

impl PipeEndpoint {
    pub fn pair() -> (Self, Self) {
        Self::try_pair(LINUX_PIPE_DEFAULT_CAPACITY, None).expect("default pipe allocation")
    }

    /// Allocates both endpoints only when the complete initial capacity can be
    /// reserved. `max_capacity` is an admitted byte budget, not a product
    /// constant; `None` leaves admission to the allocator.
    pub fn try_pair(default_capacity: usize, max_capacity: Option<usize>) -> Option<(Self, Self)> {
        if default_capacity < PIPE_BUF
            || max_capacity.is_some_and(|maximum| maximum < default_capacity)
        {
            return None;
        }
        let mut bytes = VecDeque::new();
        bytes
            .try_reserve_exact(default_capacity.min(PIPE_BUF))
            .ok()?;
        let state = Arc::new(SpinLock::new(PipeState {
            bytes,
            readers: 1,
            writers: 1,
            capacity: default_capacity,
            max_capacity,
        }));
        Some((
            Self {
                state: Arc::clone(&state),
                reader: true,
            },
            Self {
                state,
                reader: false,
            },
        ))
    }

    /// Creates a pipe whose starting and maximum capacities come from the
    /// caller's runtime byte budget.
    pub fn pair_with_budget(default_capacity: usize, byte_budget: usize) -> Option<(Self, Self)> {
        Self::try_pair(default_capacity, Some(byte_budget))
    }

    pub const fn is_reader(&self) -> bool {
        self.reader
    }

    pub fn read(&self, output: &mut [u8]) -> PipeRead {
        let mut state = self.state.lock();
        if output.is_empty() {
            return PipeRead::Data(0);
        }
        if state.bytes.is_empty() {
            return if state.writers == 0 {
                PipeRead::Eof
            } else {
                PipeRead::WouldBlock
            };
        }
        let count = output.len().min(state.bytes.len());
        for byte in &mut output[..count] {
            *byte = state.bytes.pop_front().expect("checked pipe bytes");
        }
        PipeRead::Data(count)
    }

    /// Copies buffered bytes without consuming the pipe stream.
    pub fn peek(&self, output: &mut [u8]) -> PipeRead {
        let state = self.state.lock();
        if output.is_empty() {
            return PipeRead::Data(0);
        }
        if state.bytes.is_empty() {
            return if state.writers == 0 {
                PipeRead::Eof
            } else {
                PipeRead::WouldBlock
            };
        }
        let count = output.len().min(state.bytes.len());
        for (destination, source) in output[..count].iter_mut().zip(state.bytes.iter()) {
            *destination = *source;
        }
        PipeRead::Data(count)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.state.lock().bytes.len()
    }

    pub fn capacity(&self) -> usize {
        self.state.lock().capacity
    }

    /// Resizes the shared pipe without discarding buffered bytes.
    ///
    /// This publishes the logical capacity only. Actual backing storage is
    /// admitted at write time with `try_reserve`, so a large empty pipe cannot
    /// force permanent kernel-heap growth merely by being resized.
    pub fn set_capacity(&self, capacity: usize) -> Result<usize, PipeCapacityError> {
        let mut state = self.state.lock();
        if capacity < PIPE_BUF {
            return Err(PipeCapacityError::BelowMinimum);
        }
        if state.max_capacity.is_some_and(|maximum| capacity > maximum) {
            return Err(PipeCapacityError::AboveBudget);
        }
        if state.bytes.len() > capacity {
            return Err(PipeCapacityError::Buffered);
        }
        state.capacity = capacity;
        Ok(capacity)
    }

    pub fn is_readable(&self) -> bool {
        let state = self.state.lock();
        !state.bytes.is_empty() || state.writers == 0
    }

    pub fn is_writable(&self) -> bool {
        let state = self.state.lock();
        state.readers != 0 && state.bytes.len() < state.capacity
    }

    pub fn readers_gone(&self) -> bool {
        self.state.lock().readers == 0
    }

    pub fn writers_gone(&self) -> bool {
        self.state.lock().writers == 0
    }

    pub fn write(&self, input: &[u8]) -> PipeWrite {
        if self.reader {
            return PipeWrite::Broken;
        }
        let mut state = self.state.lock();
        if input.is_empty() {
            return PipeWrite::Data(0);
        }
        if state.readers == 0 {
            return PipeWrite::Broken;
        }
        let available = state.capacity.saturating_sub(state.bytes.len());
        if available == 0 {
            return PipeWrite::WouldBlock;
        }
        if input.len() <= PIPE_BUF && available < input.len() {
            return PipeWrite::WouldBlock;
        }
        let count = input.len().min(available);
        if state.bytes.try_reserve(count).is_err() {
            return PipeWrite::NoMemory;
        }
        state.bytes.extend(input[..count].iter().copied());
        PipeWrite::Data(count)
    }
}

impl Clone for PipeEndpoint {
    fn clone(&self) -> Self {
        let mut state = self.state.lock();
        if self.reader {
            state.readers = state.readers.saturating_add(1);
        } else {
            state.writers = state.writers.saturating_add(1);
        }
        drop(state);
        Self {
            state: Arc::clone(&self.state),
            reader: self.reader,
        }
    }
}

impl Drop for PipeEndpoint {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if self.reader {
            state.readers = state.readers.saturating_sub(1);
        } else {
            state.writers = state.writers.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_stream_eof_broken_and_atomic_small_write() {
        let (reader, writer) = PipeEndpoint::pair();
        let forked = writer.clone();
        assert_eq!(reader.read(&mut [0; 4]), PipeRead::WouldBlock);
        assert_eq!(writer.write(b"hello"), PipeWrite::Data(5));
        let mut output = [0; 4];
        assert_eq!(reader.read(&mut output), PipeRead::Data(4));
        assert_eq!(&output, b"hell");
        drop(writer);
        drop(forked);
        assert_eq!(reader.read(&mut output), PipeRead::Data(1));
        assert_eq!(reader.read(&mut output), PipeRead::Eof);
        assert_eq!(reader.write(b"x"), PipeWrite::Broken);
    }

    #[test]
    fn pipe_capacity_resizes_without_losing_buffered_bytes() {
        let (reader, writer) = PipeEndpoint::pair_with_budget(
            LINUX_PIPE_DEFAULT_CAPACITY,
            LINUX_PIPE_DEFAULT_CAPACITY * 4,
        )
        .unwrap();
        assert_eq!(reader.capacity(), LINUX_PIPE_DEFAULT_CAPACITY);
        assert_eq!(writer.write(b"data"), PipeWrite::Data(4));
        assert_eq!(reader.set_capacity(PIPE_BUF), Ok(PIPE_BUF));
        assert_eq!(reader.capacity(), PIPE_BUF);
        assert_eq!(reader.set_capacity(1), Err(PipeCapacityError::BelowMinimum));
        assert_eq!(
            reader.set_capacity(LINUX_PIPE_DEFAULT_CAPACITY * 4 + 1),
            Err(PipeCapacityError::AboveBudget)
        );
        let mut bytes = [0; 4];
        assert_eq!(reader.read(&mut bytes), PipeRead::Data(4));
        assert_eq!(&bytes, b"data");
    }

    #[test]
    fn pipe_capacity_follows_runtime_budget_above_linux_default() {
        let target = 2 * 1024 * 1024;
        let (reader, writer) =
            PipeEndpoint::pair_with_budget(LINUX_PIPE_DEFAULT_CAPACITY, target).unwrap();
        assert_eq!(reader.set_capacity(target), Ok(target));
        assert_eq!(reader.capacity(), target);

        let payload = alloc::vec![0x5a; 512 * 1024];
        assert_eq!(writer.write(&payload), PipeWrite::Data(payload.len()));
        assert_eq!(reader.buffered_bytes(), payload.len());
    }

    #[test]
    fn rejected_pipe_resize_is_transactional() {
        let (reader, writer) =
            PipeEndpoint::pair_with_budget(LINUX_PIPE_DEFAULT_CAPACITY, 2 * 1024 * 1024).unwrap();
        assert_eq!(writer.write(b"retained"), PipeWrite::Data(8));
        assert_eq!(
            reader.set_capacity(PIPE_BUF / 2),
            Err(PipeCapacityError::BelowMinimum)
        );
        assert_eq!(reader.capacity(), LINUX_PIPE_DEFAULT_CAPACITY);
        assert_eq!(reader.buffered_bytes(), 8);
    }

    #[test]
    fn cloned_endpoint_keeps_stream_alive_after_original_drop() {
        let (reader, writer) = PipeEndpoint::pair();
        let inherited = writer.clone();
        drop(writer);
        assert_eq!(inherited.write(b"x"), PipeWrite::Data(1));
        drop(inherited);
        let mut byte = [0];
        assert_eq!(reader.read(&mut byte), PipeRead::Data(1));
    }

    #[test]
    fn unix_socket_pair_is_bidirectional_and_reports_peer_close() {
        let (a, b) = UnixSocketEndpoint::pair();
        assert_eq!(a.write(b"ab"), PipeWrite::Data(2));
        let mut bytes = [0; 2];
        assert_eq!(b.read(&mut bytes), PipeRead::Data(2));
        assert_eq!(&bytes, b"ab");
        assert_eq!(b.write(b"cd"), PipeWrite::Data(2));
        assert_eq!(a.read(&mut bytes), PipeRead::Data(2));
        assert_eq!(&bytes, b"cd");
        drop(b);
        assert!(a.peer_read_gone());
        assert!(a.peer_write_gone());
        assert_eq!(a.write(b"x"), PipeWrite::Broken);
    }

    #[test]
    fn unix_socket_budget_covers_both_directions() {
        let budget = 2 * LINUX_PIPE_DEFAULT_CAPACITY;
        let (a, b) =
            UnixSocketEndpoint::pair_with_budget(LINUX_PIPE_DEFAULT_CAPACITY, budget).unwrap();
        assert_eq!(a.max_capacity(), Some(LINUX_PIPE_DEFAULT_CAPACITY));
        assert_eq!(b.max_capacity(), Some(LINUX_PIPE_DEFAULT_CAPACITY));
        assert!(
            UnixSocketEndpoint::pair_with_budget(LINUX_PIPE_DEFAULT_CAPACITY, budget - 1).is_none()
        );
    }

    #[test]
    fn unix_socket_shutdown_is_directional() {
        let (a, b) = UnixSocketEndpoint::pair();
        assert!(a.shutdown(0));
        assert_eq!(a.write(b"ok"), PipeWrite::Data(2));
        assert_eq!(b.read(&mut [0; 2]), PipeRead::Data(2));
        assert_eq!(b.write(b"x"), PipeWrite::Broken);
        assert_eq!(a.read(&mut [0; 1]), PipeRead::Eof);
        assert!(!a.shutdown(3));
    }

    #[test]
    fn unconnected_endpoints_can_be_joined_once_and_carry_names() {
        let client = UnixSocketEndpoint::unconnected();
        let server = UnixSocketEndpoint::unconnected();
        assert!(!client.is_connected());
        assert!(UnixSocketEndpoint::connect_pair(&client, &server));
        assert!(client.is_connected());
        assert!(server.is_connected());
        assert!(!UnixSocketEndpoint::connect_pair(
            &client,
            &UnixSocketEndpoint::unconnected()
        ));
        assert!(client.set_names(
            UnixSocketName::empty(),
            UnixSocketName::new(b"srv").unwrap()
        ));
        assert!(server.set_names(
            UnixSocketName::new(b"srv").unwrap(),
            UnixSocketName::empty()
        ));
        assert_eq!(client.peer_name().unwrap().as_bytes(), b"srv");
        assert_eq!(server.local_name().unwrap().as_bytes(), b"srv");
        let client_cred = UnixCredentials {
            pid: 11,
            uid: 12,
            gid: 13,
        };
        let server_cred = UnixCredentials {
            pid: 21,
            uid: 22,
            gid: 23,
        };
        assert!(client.set_credentials(client_cred, server_cred));
        assert!(server.set_credentials(server_cred, client_cred));
        assert_eq!(client.peer_credentials(), Some(server_cred));
        assert_eq!(server.peer_credentials(), Some(client_cred));
        assert_eq!(client.write(b"x"), PipeWrite::Data(1));
        assert_eq!(server.read(&mut [0; 1]), PipeRead::Data(1));
    }
}
