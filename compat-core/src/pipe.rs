//! Bounded Linux pipe byte stream shared by reader/writer endpoints.

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use kernel_core::sync::SpinLock;

pub const PIPE_CAPACITY: usize = 64 * 1024;
pub const PIPE_BUF: usize = 4096;

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

/// One endpoint of a bounded bidirectional Unix stream socket.
pub struct UnixSocketEndpoint {
    rx: PipeEndpoint,
    tx: PipeEndpoint,
}

impl UnixSocketEndpoint {
    pub fn pair() -> (Self, Self) {
        let (a_to_b_rx, a_to_b_tx) = PipeEndpoint::pair();
        let (b_to_a_rx, b_to_a_tx) = PipeEndpoint::pair();
        (
            Self {
                rx: b_to_a_rx,
                tx: a_to_b_tx,
            },
            Self {
                rx: a_to_b_rx,
                tx: b_to_a_tx,
            },
        )
    }

    pub fn read(&self, output: &mut [u8]) -> PipeRead {
        self.rx.read(output)
    }

    pub fn write(&self, input: &[u8]) -> PipeWrite {
        self.tx.write(input)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.rx.buffered_bytes()
    }

    pub fn is_readable(&self) -> bool {
        self.rx.is_readable()
    }

    pub fn is_writable(&self) -> bool {
        self.tx.is_writable()
    }

    pub fn peer_read_gone(&self) -> bool {
        self.tx.readers_gone()
    }

    pub fn peer_write_gone(&self) -> bool {
        self.rx.writers_gone()
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
}
