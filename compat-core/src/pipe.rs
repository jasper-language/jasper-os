//! Bounded Linux pipe byte stream shared by reader/writer endpoints.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use kernel_core::sync::SpinLock;

pub const PIPE_CAPACITY: usize = 64 * 1024;
pub const PIPE_BUF: usize = 4096;
pub const UNIX_SOCKET_NAME_MAX: usize = 108;

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
}

#[derive(Debug)]
struct PipeState {
    bytes: VecDeque<u8>,
    readers: u32,
    writers: u32,
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
}

struct SocketLink {
    rx: PipeEndpoint,
    tx: PipeEndpoint,
}

struct SocketIdentity {
    names: SpinLock<SocketNames>,
    first: AtomicU32,
    second: AtomicU32,
}

struct SocketNames {
    first: UnixSocketName,
    second: UnixSocketName,
}

impl UnixSocketEndpoint {
    pub fn pair() -> (Self, Self) {
        Self::connected_pair()
    }

    fn connected_pair() -> (Self, Self) {
        let identity = Arc::new(SocketIdentity::new());
        let (a_to_b_rx, a_to_b_tx) = PipeEndpoint::pair();
        let (b_to_a_rx, b_to_a_tx) = PipeEndpoint::pair();
        (
            Self {
                link: SpinLock::new(Some(SocketLink {
                    rx: b_to_a_rx,
                    tx: a_to_b_tx,
                })),
                identity: SpinLock::new(Some(Arc::clone(&identity))),
                side: AtomicU8::new(0),
            },
            Self {
                link: SpinLock::new(Some(SocketLink {
                    rx: a_to_b_rx,
                    tx: b_to_a_tx,
                })),
                identity: SpinLock::new(Some(identity)),
                side: AtomicU8::new(1),
            },
        )
    }

    /// Creates a socket placeholder that may later be connected without
    /// replacing its fd handle. Fork inheritance shares this transition.
    pub fn unconnected() -> Self {
        Self {
            link: SpinLock::new(None),
            identity: SpinLock::new(None),
            side: AtomicU8::new(0),
        }
    }

    /// Atomically joins two unconnected endpoints as opposite sides of one
    /// bidirectional stream. The operation has no partial result.
    pub fn connect_pair(client: &Self, server: &Self) -> bool {
        if core::ptr::eq(client, server) {
            return false;
        }
        let mut client_link = client.link.lock();
        let mut server_link = server.link.lock();
        if client_link.is_some() || server_link.is_some() {
            return false;
        }
        let identity = Arc::new(SocketIdentity::new());
        let (a_to_b_rx, a_to_b_tx) = PipeEndpoint::pair();
        let (b_to_a_rx, b_to_a_tx) = PipeEndpoint::pair();
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
            first: AtomicU32::new(0),
            second: AtomicU32::new(0),
        }
    }
}

impl PipeEndpoint {
    pub fn pair() -> (Self, Self) {
        let state = Arc::new(SpinLock::new(PipeState {
            bytes: VecDeque::with_capacity(PIPE_CAPACITY.min(PIPE_BUF)),
            readers: 1,
            writers: 1,
        }));
        (
            Self {
                state: Arc::clone(&state),
                reader: true,
            },
            Self {
                state,
                reader: false,
            },
        )
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

    pub fn buffered_bytes(&self) -> usize {
        self.state.lock().bytes.len()
    }

    pub fn is_readable(&self) -> bool {
        let state = self.state.lock();
        !state.bytes.is_empty() || state.writers == 0
    }

    pub fn is_writable(&self) -> bool {
        let state = self.state.lock();
        state.readers != 0 && state.bytes.len() < PIPE_CAPACITY
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
        let available = PIPE_CAPACITY.saturating_sub(state.bytes.len());
        if available == 0 {
            return PipeWrite::WouldBlock;
        }
        if input.len() <= PIPE_BUF && available < input.len() {
            return PipeWrite::WouldBlock;
        }
        let count = input.len().min(available);
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
        assert_eq!(client.write(b"x"), PipeWrite::Data(1));
        assert_eq!(server.read(&mut [0; 1]), PipeRead::Data(1));
    }
}
