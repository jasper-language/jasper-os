//! Native file-change observation service contract.
//!
//! An event is published after the corresponding filesystem state transition.
//! Callers retain an opaque cursor; restart or bounded-history loss forces an
//! authoritative rescan. Linux inotify/fanotify records remain compatibility
//! protocol data outside this module.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Created,
    Changed,
    Removed,
    Renamed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileEvent {
    pub sequence: u64,
    pub object: u64,
    pub generation: u64,
    pub kind: EventKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub instance: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInstance,
    Closed,
    SequenceExhausted,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replay {
    pub delivered: usize,
    pub latest: Cursor,
    pub resync: bool,
}

/// Bounded event source with a durable caller-held cursor.
pub struct FileEventService<const N: usize> {
    instance: u64,
    state_generation: u64,
    next_sequence: u64,
    events: [Option<FileEvent>; N],
    head: usize,
    len: usize,
    closed: bool,
}

impl<const N: usize> FileEventService<N> {
    pub fn new(instance: u64, state_generation: u64) -> Result<Self, Error> {
        if instance == 0 || state_generation == 0 || N == 0 {
            return Err(Error::InvalidInstance);
        }
        Ok(Self {
            instance,
            state_generation,
            next_sequence: 1,
            events: [None; N],
            head: 0,
            len: 0,
            closed: false,
        })
    }

    pub const fn instance(&self) -> u64 {
        self.instance
    }

    pub const fn state_generation(&self) -> u64 {
        self.state_generation
    }

    pub const fn latest(&self) -> Cursor {
        Cursor {
            instance: self.instance,
            sequence: self.next_sequence - 1,
        }
    }

    /// Publish one event after the corresponding file state commit.
    pub fn publish(
        &mut self,
        object: u64,
        generation: u64,
        kind: EventKind,
    ) -> Result<FileEvent, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if object == 0 || generation == 0 {
            return Err(Error::InvalidInstance);
        }
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        let event = FileEvent {
            sequence,
            object,
            generation,
            kind,
        };
        let index = (self.head + self.len) % N;
        self.events[index] = Some(event);
        if self.len == N {
            self.head = (self.head + 1) % N;
        } else {
            self.len += 1;
        }
        Ok(event)
    }

    /// Replay events newer than a caller cursor.
    ///
    /// If the exact successor is no longer retained, all retained events and
    /// `resync=true` are returned so the caller can reconstruct authoritative
    /// state rather than silently skip changes.
    pub fn replay(&self, cursor: Cursor, output: &mut [FileEvent]) -> Result<Replay, Error> {
        if self.closed || cursor.instance != self.instance {
            return Err(Error::Closed);
        }
        let latest = self.latest();
        if cursor.sequence > latest.sequence {
            return Err(Error::InvalidInstance);
        }
        let first = self.events[self.head]
            .map_or(latest.sequence.saturating_add(1), |event| event.sequence);
        let resync =
            cursor.sequence != latest.sequence && first > cursor.sequence.saturating_add(1);
        let retained = if resync {
            self.len
        } else {
            self.len.saturating_sub(
                first
                    .saturating_sub(cursor.sequence.saturating_add(1))
                    .try_into()
                    .unwrap_or(self.len),
            )
        };
        let available = if resync { self.len } else { retained };
        if output.len() < available {
            return Err(Error::OutputTooSmall);
        }
        let mut delivered = 0;
        for offset in 0..self.len {
            let event = self.events[(self.head + offset) % N].ok_or(Error::Closed)?;
            if !resync && event.sequence <= cursor.sequence {
                continue;
            }
            output[delivered] = event;
            delivered += 1;
        }
        Ok(Replay {
            delivered,
            latest,
            resync,
        })
    }

    /// Restart the service and invalidate every old-instance cursor.
    pub fn restart(&mut self, instance: u64, state_generation: u64) -> Result<(), Error> {
        if instance <= self.instance || state_generation <= self.state_generation {
            return Err(Error::InvalidInstance);
        }
        self.instance = instance;
        self.state_generation = state_generation;
        self.next_sequence = 1;
        self.events = [None; N];
        self.head = 0;
        self.len = 0;
        self.closed = false;
        Ok(())
    }

    pub fn close(&mut self) {
        self.closed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_event() -> FileEvent {
        FileEvent {
            sequence: 0,
            object: 0,
            generation: 0,
            kind: EventKind::Created,
        }
    }

    #[test]
    fn cursor_replays_only_committed_successors() {
        let mut service = FileEventService::<8>::new(1, 1).unwrap();
        service.publish(10, 1, EventKind::Created).unwrap();
        let cursor = service.latest();
        service.publish(10, 2, EventKind::Changed).unwrap();
        service.publish(10, 3, EventKind::Renamed).unwrap();
        let mut output = [empty_event(); 8];
        let replay = service.replay(cursor, &mut output).unwrap();
        assert_eq!(replay.delivered, 2);
        assert!(!replay.resync);
        assert_eq!(output[0].sequence, 2);
        assert_eq!(output[1].generation, 3);
    }

    #[test]
    fn overflow_and_short_output_are_failure_atomic() {
        let mut service = FileEventService::<3>::new(7, 1).unwrap();
        for generation in 1..=5 {
            service.publish(42, generation, EventKind::Changed).unwrap();
        }
        let mut short = [empty_event(); 2];
        assert_eq!(
            service.replay(
                Cursor {
                    instance: 7,
                    sequence: 0
                },
                &mut short
            ),
            Err(Error::OutputTooSmall)
        );
        let mut output = [empty_event(); 3];
        let replay = service
            .replay(
                Cursor {
                    instance: 7,
                    sequence: 0,
                },
                &mut output,
            )
            .unwrap();
        assert!(replay.resync);
        assert_eq!(replay.delivered, 3);
        assert_eq!(output[0].sequence, 3);
        assert_eq!(output[2].sequence, 5);
    }

    #[test]
    fn restart_invalidates_old_cursor_and_requires_new_instance() {
        let mut service = FileEventService::<4>::new(2, 4).unwrap();
        service.publish(9, 1, EventKind::Created).unwrap();
        let old = service.latest();
        service.restart(3, 5).unwrap();
        let mut output = [empty_event(); 4];
        assert_eq!(service.replay(old, &mut output), Err(Error::Closed));
        let replay = service.replay(service.latest(), &mut output).unwrap();
        assert_eq!(replay.delivered, 0);
        assert_eq!(service.instance(), 3);
        assert_eq!(service.state_generation(), 5);
        assert_eq!(service.restart(3, 6), Err(Error::InvalidInstance));
    }

    #[test]
    fn close_rejects_publication_and_replay() {
        let mut service = FileEventService::<2>::new(1, 1).unwrap();
        let cursor = service.latest();
        service.close();
        assert_eq!(
            service.publish(1, 1, EventKind::Changed),
            Err(Error::Closed)
        );
        let mut output = [empty_event(); 2];
        assert_eq!(service.replay(cursor, &mut output), Err(Error::Closed));
    }
}
