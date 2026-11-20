//! Native service semantic-event identity and monotonic source state.
//!
//! Domain services publish only after their state mutation commits. The
//! identity here is service-local plumbing; it does not change the versioned
//! subscription ABI. A subscriber that retains an old generation can never
//! mistake a restarted service for the previous instance.

use crate::subscription::{self, Delivery, Queue, Snapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceKind {
    File,
    Network,
    DriverHost,
    Graphics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub kind: ServiceKind,
    pub object: u64,
    pub generation: u64,
}

impl Identity {
    pub const fn new(kind: ServiceKind, object: u64, generation: u64) -> Option<Self> {
        if object == 0 || generation == 0 {
            None
        } else {
            Some(Self {
                kind,
                object,
                generation,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIdentity,
    Closed,
    StaleGeneration,
    VersionExhausted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    identity: Identity,
    snapshot: Snapshot,
    closed: bool,
}

impl Source {
    pub fn new(identity: Identity) -> Result<Self, Error> {
        if Identity::new(identity.kind, identity.object, identity.generation) != Some(identity) {
            return Err(Error::InvalidIdentity);
        }
        Ok(Self {
            identity,
            snapshot: Snapshot { version: 0, value: 0 },
            closed: false,
        })
    }

    pub const fn identity(&self) -> Identity {
        self.identity
    }

    pub const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    pub const fn can_publish(&self) -> bool {
        !self.closed && self.snapshot.version != u64::MAX
    }

    pub const fn can_restart(&self, generation: u64) -> bool {
        generation > self.identity.generation && self.snapshot.version != u64::MAX
    }

    pub fn accepts(&self, identity: Identity, version: u64) -> bool {
        !self.closed
            && identity == self.identity
            && self.snapshot.version.checked_add(1) == Some(version)
    }

    /// Publish one committed semantic state transition.
    pub fn publish(&mut self, value: u64) -> Result<Snapshot, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        self.snapshot
            .publish(value)
            .map_err(|_| Error::VersionExhausted)
    }

    /// Publish a terminal state. Further events fail until an explicit restart.
    pub fn terminate(&mut self, value: u64) -> Result<Snapshot, Error> {
        let snapshot = self.publish(value)?;
        self.closed = true;
        Ok(snapshot)
    }

    /// Start a new service generation. Version remains monotonic so old
    /// subscriber queues are forced through authoritative resync rather than
    /// accepting a restarted service as a continuation.
    pub fn restart(&mut self, generation: u64, value: u64) -> Result<Snapshot, Error> {
        if generation <= self.identity.generation {
            return Err(Error::StaleGeneration);
        }
        let next = self
            .snapshot
            .version
            .checked_add(1)
            .ok_or(Error::VersionExhausted)?;
        self.identity.generation = generation;
        self.snapshot = Snapshot {
            version: next,
            value,
        };
        self.closed = false;
        Ok(self.snapshot)
    }

    pub const fn resync(&self) -> Delivery {
        Delivery::Resync(self.snapshot)
    }
}

/// Feed one real producer snapshot into a subscriber queue under the source
/// identity that the subscriber originally observed.
pub fn publish<const N: usize>(
    source: &Source,
    observed: Identity,
    queue: &mut Queue<N>,
) -> Result<(), subscription::Error> {
    if source.identity != observed {
        queue.resync_to(source.snapshot);
        return Ok(());
    }
    queue.publish(source.snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_rejects_old_generation_and_requires_resync() {
        let identity = Identity::new(ServiceKind::Graphics, 7, 1).unwrap();
        let mut source = Source::new(identity).unwrap();
        let initial = source.snapshot();
        let mut queue = Queue::<2>::new(initial, subscription::Policy::Events);

        source.publish(11).unwrap();
        publish(&source, identity, &mut queue).unwrap();
        assert_eq!(
            queue.take(),
            Some(Delivery::Event(subscription::Event {
                first: 1,
                last: 1,
                value: 11
            }))
        );

        source.terminate(12).unwrap();
        publish(&source, identity, &mut queue).unwrap();
        assert_eq!(
            queue.take(),
            Some(Delivery::Event(subscription::Event {
                first: 2,
                last: 2,
                value: 12
            }))
        );
        let next = source.restart(2, 20).unwrap();
        publish(&source, identity, &mut queue).unwrap();
        assert_eq!(queue.take(), Some(Delivery::Resync(next)));
        assert_eq!(queue.take(), None);
        assert!(!source.accepts(identity, 3));
        assert!(source.accepts(source.identity(), 4));
    }
}
