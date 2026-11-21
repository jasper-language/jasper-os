//! Post-effect security observations with explicit capacity preflight.
//!
//! This module is not an authorization authority. The caller obtains its
//! pre-effect decision from the existing PEP/domain table, reserves an
//! observation slot before applying the side effect, and commits an event only
//! after the effect outcome is known. If capacity cannot be reserved, the
//! effect must not run.

use crate::security_domain::{Access, DomainKey, GatewayKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Platform,
    Subject(DomainKey),
    Owner(DomainKey),
}

impl Scope {
    fn permits(self, fact: Fact) -> bool {
        match self {
            Self::Platform => true,
            Self::Subject(key) => key == fact.actor,
            Self::Owner(key) => key == fact.owner,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fact {
    pub actor: DomainKey,
    pub owner: DomainKey,
    pub object: u64,
    pub channel: Option<GatewayKind>,
    pub requested: u32,
    pub decision: Access,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub sequence: u64,
    pub fact: Fact,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    sequence: u64,
}

impl Reservation {
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Capacity,
    Busy,
    InvalidReservation,
    SequenceExhausted,
}

pub struct Service<const N: usize> {
    events: [Option<Event>; N],
    head: usize,
    len: usize,
    next_sequence: u64,
    reserved: bool,
}

impl<const N: usize> Service<N> {
    pub const fn new() -> Self {
        Self {
            events: [None; N],
            head: 0,
            len: 0,
            next_sequence: 1,
            reserved: false,
        }
    }

    pub const fn queued(&self) -> usize {
        self.len
    }

    pub const fn reserved(&self) -> bool {
        self.reserved
    }

    /// Reserve the bounded observation before the caller performs its effect.
    pub fn reserve(&mut self) -> Result<Reservation, Error> {
        if self.reserved {
            return Err(Error::Busy);
        }
        if N == 0 || self.len == N {
            return Err(Error::Capacity);
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        self.reserved = true;
        Ok(Reservation { sequence })
    }

    /// Release a reservation when the effect could not be attempted.
    pub fn abort(&mut self, reservation: Reservation) -> Result<(), Error> {
        if !self.reserved || reservation.sequence.checked_add(1) != Some(self.next_sequence) {
            return Err(Error::InvalidReservation);
        }
        self.reserved = false;
        Ok(())
    }

    /// Commit the observation only after the effect reached a terminal outcome.
    pub fn commit(
        &mut self,
        reservation: Reservation,
        fact: Fact,
        outcome: Outcome,
    ) -> Result<Event, Error> {
        if !self.reserved || reservation.sequence.checked_add(1) != Some(self.next_sequence) {
            return Err(Error::InvalidReservation);
        }
        if self.len == N || N == 0 {
            return Err(Error::Capacity);
        }
        let event = Event {
            sequence: reservation.sequence,
            fact,
            outcome,
        };
        self.events[(self.head + self.len) % N] = Some(event);
        self.len += 1;
        self.reserved = false;
        Ok(event)
    }

    /// Return events visible to one externally granted observation scope.
    pub fn visible(&self, scope: Scope) -> impl Iterator<Item = Event> + '_ {
        (0..self.len).filter_map(move |offset| {
            let event = self.events[(self.head + offset) % N].expect("queued observation");
            scope.permits(event.fact).then_some(event)
        })
    }

    /// Drop one delivered event. The caller must consume observations in order.
    pub fn pop(&mut self) -> Option<Event> {
        if self.len == 0 {
            return None;
        }
        let event = self.events[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        event
    }

    pub fn clear(&mut self) {
        self.events = [None; N];
        self.head = 0;
        self.len = 0;
        self.reserved = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (DomainKey, DomainKey) {
        (
            DomainKey {
                id: 1,
                generation: 1,
            },
            DomainKey {
                id: 2,
                generation: 1,
            },
        )
    }

    fn fact() -> Fact {
        let (actor, owner) = keys();
        Fact {
            actor,
            owner,
            object: 7,
            channel: Some(GatewayKind::Ipc),
            requested: 1,
            decision: Access::Allowed,
        }
    }

    #[test]
    fn capacity_is_reserved_before_effect_and_scope_is_exact() {
        let mut service = Service::<1>::new();
        let reservation = service.reserve().unwrap();
        assert!(service.reserve().is_err());
        assert_eq!(service.queued(), 0);
        service.commit(reservation, fact(), Outcome::Applied).unwrap();
        assert!(service.reserve().is_err());

        let (actor, owner) = keys();
        assert_eq!(service.visible(Scope::Platform).count(), 1);
        assert_eq!(service.visible(Scope::Subject(actor)).count(), 1);
        assert_eq!(service.visible(Scope::Owner(owner)).count(), 1);
        let other = DomainKey {
            id: 3,
            generation: 1,
        };
        assert_eq!(service.visible(Scope::Subject(other)).count(), 0);
        assert_eq!(service.visible(Scope::Owner(other)).count(), 0);
    }

    #[test]
    fn abort_releases_reservation_without_event() {
        let mut service = Service::<2>::new();
        let reservation = service.reserve().unwrap();
        service.abort(reservation).unwrap();
        assert!(!service.reserved());
        assert_eq!(service.queued(), 0);
        let fresh = service.reserve().unwrap();
        assert_eq!(fresh.sequence(), 2);
    }

    #[test]
    fn stale_reservation_cannot_commit() {
        let mut service = Service::<2>::new();
        let old = service.reserve().unwrap();
        let event = service.commit(old, fact(), Outcome::Failed).unwrap();
        assert_eq!(event.sequence, 1);
        assert_eq!(
            service.commit(old, fact(), Outcome::Applied),
            Err(Error::InvalidReservation)
        );
    }
}
