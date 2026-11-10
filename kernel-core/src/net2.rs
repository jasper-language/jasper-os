//! NET-2 bounded TCP service and socket lifecycle.
//!
//! Parsing lives in NET-1c. This module owns connection state, sequence
//! bookkeeping, receive buffers, cancellation, timeout and resource quotas.

pub const MAX_SOCKETS: usize = 32;
pub const MAX_RX_BYTES: usize = 4096;
pub const MAX_EVENTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpAddress {
    pub ip: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
    Listen,
    SynReceived,
    Established,
    FinWait,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net2Error {
    Capacity,
    NotFound,
    Busy,
    InvalidState,
    InvalidAddress,
    Sequence,
    Window,
    BufferFull,
    Timeout,
    Cancelled,
    Quota,
    StaleGeneration,
    EventQueueFull,
}

impl Net2Error {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Capacity => "system.net.error.capacity",
            Self::NotFound => "system.net.error.not_found",
            Self::Busy => "system.net.error.busy",
            Self::InvalidState => "system.net.error.invalid_state",
            Self::InvalidAddress => "system.net.error.invalid_address",
            Self::Sequence => "system.net.error.sequence",
            Self::Window => "system.net.error.window",
            Self::BufferFull => "system.net.error.buffer_full",
            Self::Timeout => "system.net.error.timeout",
            Self::Cancelled => "system.net.error.cancelled",
            Self::Quota => "system.net.error.quota",
            Self::StaleGeneration => "system.net.error.stale_generation",
            Self::EventQueueFull => "system.net.error.event_queue_full",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpEvent {
    Syn {
        socket: u32,
        sequence: u32,
    },
    SynAck {
        socket: u32,
        sequence: u32,
        acknowledgement: u32,
    },
    Established {
        socket: u32,
    },
    Data {
        socket: u32,
        bytes: u16,
    },
    Closed {
        socket: u32,
    },
    Reset {
        socket: u32,
    },
    Timeout {
        socket: u32,
        retries: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub source: TcpAddress,
    pub destination: TcpAddress,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub window: u16,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketView {
    pub id: u32,
    pub generation: u32,
    pub state: TcpState,
    pub local: TcpAddress,
    pub remote: TcpAddress,
    pub receive_bytes: u16,
    pub retries: u8,
    pub deadline: u64,
}

#[derive(Clone, Copy)]
struct Socket {
    id: u32,
    generation: u32,
    state: TcpState,
    local: TcpAddress,
    remote: TcpAddress,
    irs: u32,
    iss: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    peer_window: u16,
    receive: [u8; MAX_RX_BYTES],
    receive_len: usize,
    retries: u8,
    deadline: u64,
}

impl Socket {
    const EMPTY: Self = Self {
        id: 0,
        generation: 0,
        state: TcpState::Closed,
        local: TcpAddress { ip: [0; 4], port: 0 },
        remote: TcpAddress { ip: [0; 4], port: 0 },
        irs: 0,
        iss: 0,
        snd_nxt: 0,
        rcv_nxt: 0,
        peer_window: 0,
        receive: [0; MAX_RX_BYTES],
        receive_len: 0,
        retries: 0,
        deadline: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpQuota {
    pub sockets: u32,
    pub bytes: u64,
    pub max_sockets: u32,
    pub max_bytes: u64,
}

impl TcpQuota {
    pub const fn new(max_sockets: u32, max_bytes: u64) -> Self {
        Self {
            sockets: 0,
            bytes: 0,
            max_sockets,
            max_bytes,
        }
    }
}

pub struct TcpService<const N: usize = MAX_SOCKETS, const E: usize = MAX_EVENTS> {
    sockets: [Socket; N],
    events: [Option<TcpEvent>; E],
    event_head: usize,
    event_len: usize,
    next_id: u32,
    quota: TcpQuota,
    retry_limit: u8,
    timeout_ticks: u64,
}

impl<const N: usize, const E: usize> TcpService<N, E> {
    pub fn new(quota: TcpQuota, retry_limit: u8, timeout_ticks: u64) -> Self {
        Self {
            sockets: [Socket::EMPTY; N],
            events: [None; E],
            event_head: 0,
            event_len: 0,
            next_id: 1,
            quota,
            retry_limit,
            timeout_ticks,
        }
    }

    pub fn listen(
        &mut self,
        local: TcpAddress,
        iss: u32,
        now: u64,
    ) -> Result<u32, Net2Error> {
        self.insert(Socket {
            state: TcpState::Listen,
            local,
            iss,
            snd_nxt: iss,
            rcv_nxt: 0,
            deadline: now.saturating_add(self.timeout_ticks),
            ..Socket::EMPTY
        })
    }

    pub fn connect(
        &mut self,
        local: TcpAddress,
        remote: TcpAddress,
        iss: u32,
        now: u64,
    ) -> Result<u32, Net2Error> {
        if local.port == 0 || remote.port == 0 || local.ip == [0; 4] || remote.ip == [0; 4] {
            return Err(Net2Error::InvalidAddress);
        }
        let id = self.insert(Socket {
            state: TcpState::SynSent,
            local,
            remote,
            iss,
            snd_nxt: iss.wrapping_add(1),
            rcv_nxt: 0,
            deadline: now.saturating_add(self.timeout_ticks),
            ..Socket::EMPTY
        })?;
        self.push_event(TcpEvent::Syn { socket: id, sequence: iss })?;
        Ok(id)
    }

    pub fn cancel(&mut self, id: u32, generation: u32) -> Result<(), Net2Error> {
        let slot = self.slot(id, generation)?;
        self.push_event(TcpEvent::Closed { socket: id })?;
        self.quota.bytes = self.quota.bytes.saturating_sub(self.sockets[slot].receive_len as u64);
        self.sockets[slot] = Socket::EMPTY;
        self.quota.sockets = self.quota.sockets.saturating_sub(1);
        Ok(())
    }

    pub fn receive(
        &mut self,
        id: u32,
        generation: u32,
        segment: Segment<'_>,
        now: u64,
    ) -> Result<(), Net2Error> {
        let slot = self.slot(id, generation)?;
        if segment.destination != self.sockets[slot].local {
            return Err(Net2Error::InvalidAddress);
        }
        if segment.rst {
            self.sockets[slot].state = TcpState::Failed;
            self.push_event(TcpEvent::Reset { socket: id })?;
            return Ok(());
        }
        match self.sockets[slot].state {
            TcpState::Listen => {
                if !segment.syn {
                    return Err(Net2Error::InvalidState);
                }
                let (iss, acknowledgement) = {
                    let socket = &mut self.sockets[slot];
                    socket.remote = segment.source;
                    socket.irs = segment.sequence;
                    socket.rcv_nxt = segment.sequence.wrapping_add(1);
                    socket.peer_window = segment.window;
                    socket.state = TcpState::SynReceived;
                    socket.deadline = now.saturating_add(self.timeout_ticks);
                    (socket.iss, socket.rcv_nxt)
                };
                self.push_event(TcpEvent::SynAck {
                    socket: id,
                    sequence: iss,
                    acknowledgement,
                })?;
            }
            TcpState::SynSent => {
                if !segment.syn || !segment.ack {
                    return Err(Net2Error::Sequence);
                }
                if segment.acknowledgement != self.sockets[slot].iss.wrapping_add(1) {
                    return Err(Net2Error::Sequence);
                }
                let socket = &mut self.sockets[slot];
                socket.remote = segment.source;
                socket.irs = segment.sequence;
                socket.rcv_nxt = segment.sequence.wrapping_add(1);
                socket.peer_window = segment.window;
                socket.state = TcpState::Established;
                socket.retries = 0;
                socket.deadline = 0;
                self.push_event(TcpEvent::Established { socket: id })?;
            }
            TcpState::SynReceived => {
                if !segment.ack
                    || segment.acknowledgement != self.sockets[slot].iss.wrapping_add(1)
                {
                    return Err(Net2Error::Sequence);
                }
                let socket = &mut self.sockets[slot];
                socket.state = TcpState::Established;
                socket.retries = 0;
                socket.deadline = 0;
                self.push_event(TcpEvent::Established { socket: id })?;
            }
            TcpState::Established => {
                if segment.sequence != self.sockets[slot].rcv_nxt {
                    return Err(Net2Error::Sequence);
                }
                if segment.payload.len() > usize::from(segment.window) {
                    return Err(Net2Error::Window);
                }
                let (data_len, closed) = {
                    let socket = &mut self.sockets[slot];
                    let end = socket
                        .receive_len
                        .checked_add(segment.payload.len())
                        .ok_or(Net2Error::Window)?;
                    if end > MAX_RX_BYTES
                        || self.quota.bytes.checked_add(segment.payload.len() as u64)
                            .is_none_or(|bytes| bytes > self.quota.max_bytes)
                    {
                        return Err(Net2Error::BufferFull);
                    }
                    socket.receive[socket.receive_len..end].copy_from_slice(segment.payload);
                    socket.receive_len = end;
                    socket.rcv_nxt = socket
                        .rcv_nxt
                        .wrapping_add(segment.payload.len() as u32);
                    if segment.fin {
                        socket.rcv_nxt = socket.rcv_nxt.wrapping_add(1);
                        socket.state = TcpState::FinWait;
                    }
                    (segment.payload.len(), segment.fin)
                };
                self.quota.bytes = self.quota.bytes.saturating_add(segment.payload.len() as u64);
                if data_len != 0 {
                    self.push_event(TcpEvent::Data {
                        socket: id,
                        bytes: data_len.min(u16::MAX as usize) as u16,
                    })?;
                }
                if closed {
                    self.push_event(TcpEvent::Closed { socket: id })?;
                }
            }
            TcpState::FinWait | TcpState::Closed | TcpState::Failed => {
                return Err(Net2Error::InvalidState);
            }
        }
        Ok(())
    }

    pub fn send(&mut self, id: u32, generation: u32, bytes: u16) -> Result<u32, Net2Error> {
        let slot = self.slot(id, generation)?;
        let socket = &mut self.sockets[slot];
        if socket.state != TcpState::Established {
            return Err(Net2Error::InvalidState);
        }
        if bytes > socket.peer_window {
            return Err(Net2Error::Window);
        }
        let sequence = socket.snd_nxt;
        socket.snd_nxt = socket.snd_nxt.wrapping_add(u32::from(bytes));
        Ok(sequence)
    }

    pub fn recv(
        &mut self,
        id: u32,
        generation: u32,
        out: &mut [u8],
    ) -> Result<usize, Net2Error> {
        let slot = self.slot(id, generation)?;
        let socket = &mut self.sockets[slot];
        let count = out.len().min(socket.receive_len);
        out[..count].copy_from_slice(&socket.receive[..count]);
        socket.receive.copy_within(count..socket.receive_len, 0);
        socket.receive_len -= count;
        self.quota.bytes = self.quota.bytes.saturating_sub(count as u64);
        Ok(count)
    }

    pub fn tick(&mut self, id: u32, generation: u32, now: u64) -> Result<bool, Net2Error> {
        let slot = self.slot(id, generation)?;
        let (failed, retries) = {
            let socket = &mut self.sockets[slot];
            if socket.deadline == 0 || now < socket.deadline {
                return Ok(false);
            }
            if socket.retries >= self.retry_limit {
                socket.state = TcpState::Failed;
                (true, socket.retries)
            } else {
                socket.retries = socket.retries.saturating_add(1);
                socket.deadline = now.saturating_add(self.timeout_ticks);
                (false, socket.retries)
            }
        };
        self.push_event(TcpEvent::Timeout {
            socket: id,
            retries,
        })?;
        Ok(failed)
    }

    pub fn view(&self, id: u32, generation: u32) -> Result<SocketView, Net2Error> {
        let slot = self.slot(id, generation)?;
        let socket = &self.sockets[slot];
        Ok(SocketView {
            id: socket.id,
            generation: socket.generation,
            state: socket.state,
            local: socket.local,
            remote: socket.remote,
            receive_bytes: socket.receive_len.min(u16::MAX as usize) as u16,
            retries: socket.retries,
            deadline: socket.deadline,
        })
    }

    pub fn pop_event(&mut self) -> Option<TcpEvent> {
        if self.event_len == 0 {
            return None;
        }
        let event = self.events[self.event_head];
        self.events[self.event_head] = None;
        self.event_head = (self.event_head + 1) % E;
        self.event_len -= 1;
        event
    }

    pub const fn quota(&self) -> TcpQuota {
        self.quota
    }

    fn insert(&mut self, socket: Socket) -> Result<u32, Net2Error> {
        if self.quota.sockets >= self.quota.max_sockets {
            return Err(Net2Error::Quota);
        }
        let slot = self
            .sockets
            .iter()
            .position(|entry| entry.state == TcpState::Closed)
            .ok_or(Net2Error::Capacity)?;
        if self.next_id == 0 || self.next_id == u32::MAX {
            return Err(Net2Error::StaleGeneration);
        }
        let id = self.next_id;
        self.next_id += 1;
        let generation = 1;
        self.sockets[slot] = Socket {
            id,
            generation,
            ..socket
        };
        self.quota.sockets += 1;
        Ok(id)
    }

    fn slot(&self, id: u32, generation: u32) -> Result<usize, Net2Error> {
        let slot = self
            .sockets
            .iter()
            .position(|socket| socket.id == id && socket.generation != 0)
            .ok_or(Net2Error::NotFound)?;
        if self.sockets[slot].generation != generation {
            return Err(Net2Error::StaleGeneration);
        }
        Ok(slot)
    }

    fn push_event(&mut self, event: TcpEvent) -> Result<(), Net2Error> {
        if E == 0 || self.event_len == E {
            return Err(Net2Error::EventQueueFull);
        }
        let index = (self.event_head + self.event_len) % E;
        self.events[index] = Some(event);
        self.event_len += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> TcpAddress {
        TcpAddress { ip: [10, 0, 2, 2], port: 8080 }
    }
    fn remote() -> TcpAddress {
        TcpAddress { ip: [10, 0, 2, 15], port: 40000 }
    }

    fn service() -> TcpService<8, 16> {
        TcpService::new(TcpQuota::new(4, 64), 2, 10)
    }

    #[test]
    fn client_and_server_complete_handshake_and_bounded_data() {
        let mut client = service();
        let c = client.connect(local(), remote(), 100, 0).unwrap();
        assert_eq!(
            client.receive(
                c,
                1,
                Segment {
                    source: remote(),
                    destination: local(),
                    sequence: 900,
                    acknowledgement: 101,
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                    window: 32,
                    payload: &[],
                },
                1,
            ),
            Ok(())
        );
        assert_eq!(client.view(c, 1).unwrap().state, TcpState::Established);
        assert_eq!(client.send(c, 1, 16).unwrap(), 101);
        assert_eq!(
            client.receive(
                c,
                1,
                Segment {
                    source: remote(),
                    destination: local(),
                    sequence: 901,
                    acknowledgement: 117,
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                    window: 32,
                    payload: b"ping",
                },
                2,
            ),
            Ok(())
        );
        let mut out = [0u8; 4];
        assert_eq!(client.recv(c, 1, &mut out), Ok(4));
        assert_eq!(&out, b"ping");
    }

    #[test]
    fn sequence_window_quota_and_stale_generation_fail_closed() {
        let mut service = service();
        let c = service.connect(local(), remote(), 1, 0).unwrap();
        service
            .receive(
                c,
                1,
                Segment {
                    source: remote(),
                    destination: local(),
                    sequence: 9,
                    acknowledgement: 2,
                    syn: true,
                    ack: true,
                    fin: false,
                    rst: false,
                    window: 2,
                    payload: &[],
                },
                1,
            )
            .unwrap();
        assert_eq!(service.send(c, 1, 3), Err(Net2Error::Window));
        assert_eq!(
            service.receive(
                c,
                1,
                Segment {
                    source: remote(),
                    destination: local(),
                    sequence: 99,
                    acknowledgement: 2,
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                    window: 2,
                    payload: b"x",
                },
                2,
            ),
            Err(Net2Error::Sequence)
        );
        assert_eq!(service.view(c, 2), Err(Net2Error::StaleGeneration));
    }

    #[test]
    fn listen_accept_timeout_cancel_and_event_queue_are_explicit() {
        let mut service = service();
        let listener = service.listen(local(), 7, 0).unwrap();
        service
            .receive(
                listener,
                1,
                Segment {
                    source: remote(),
                    destination: local(),
                    sequence: 50,
                    acknowledgement: 0,
                    syn: true,
                    ack: false,
                    fin: false,
                    rst: false,
                    window: 8,
                    payload: &[],
                },
                1,
            )
            .unwrap();
        assert_eq!(service.view(listener, 1).unwrap().state, TcpState::SynReceived);
        assert!(!service.tick(listener, 1, 11).unwrap());
        assert!(!service.tick(listener, 1, 21).unwrap());
        assert!(service.tick(listener, 1, 31).unwrap());
        assert_eq!(service.view(listener, 1).unwrap().state, TcpState::Failed);
        assert_eq!(service.quota().sockets, 1);
        assert!(service.cancel(listener, 1).is_ok());
        assert_eq!(service.quota().sockets, 0);
        assert!(service.pop_event().is_some());
    }
}
