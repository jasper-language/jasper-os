//! Native address-condition synchronization over an existing MemoryObject.
//!
//! This is a pure state machine. The caller validates the address grant against
//! its live software-memory-capability table, reads the backing word, and enters
//! this state machine under the same object critical section. It then parks the
//! task without releasing that critical section. No raw pointer, fd, futex key
//! or compatibility errno is stored here.

use crate::event_wait::{Enroll, Key, Registration, SetError, WaitSet};
use crate::memory_capability::{BackingIdentity, MemoryCapability, MemoryRights};
use crate::task_index::Token;

/// Identity of one fixed-width synchronization word in a MemoryObject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    backing: BackingIdentity,
    start: u64,
    width: u32,
}

impl AddressRange {
    fn new(
        backing: BackingIdentity,
        start: u64,
        width: u32,
    ) -> Result<Self, AddressSyncError> {
        if width == 0
            || !width.is_power_of_two()
            || start
                .checked_add(u64::from(width))
                .is_none_or(|end| !start.is_multiple_of(u64::from(width)) || end == 0)
        {
            return Err(AddressSyncError::InvalidRange);
        }
        Ok(Self {
            backing,
            start,
            width,
        })
    }

    pub const fn backing(self) -> BackingIdentity {
        self.backing
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn width(self) -> u32 {
        self.width
    }
}

/// A capability-backed grant for one synchronization word.
///
/// Different processes may hold different capability IDs for the same shared
/// MemoryObject. The grant therefore carries capability identity for authority,
/// while [`AddressRange`] identifies the shared condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressGrant {
    range: AddressRange,
    capability: u64,
    epoch: u32,
    rights: MemoryRights,
}

impl AddressGrant {
    pub fn from_capability(
        capability: MemoryCapability,
        start: u64,
        width: u32,
        required: MemoryRights,
    ) -> Result<Self, AddressSyncError> {
        if !capability.covers(start, u64::from(width), required) {
            return Err(AddressSyncError::GrantRejected);
        }
        Ok(Self {
            range: AddressRange::new(capability.backing, start, width)?,
            capability: capability.id,
            epoch: capability.epoch,
            rights: required,
        })
    }

    pub const fn range(self) -> AddressRange {
        self.range
    }

    pub const fn capability(self) -> u64 {
        self.capability
    }

    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    pub const fn rights(self) -> MemoryRights {
        self.rights
    }
}

/// The condition observed atomically with registration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AddressState {
    pub version: u64,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressWait {
    Ready(AddressState),
    TimedOut,
    Armed(Key),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSyncError {
    InvalidRange,
    GrantRejected,
    WrongObject,
    Busy,
    Full,
    Exhausted,
    StaleWaiter,
    InternalSet,
}

/// One address condition with caller-selected waiter capacity.
///
/// `Registration` remains the per-task wait identity. This object owns only the
/// condition's armed/ready keys and does not create a second task lifecycle.
#[derive(Clone, Debug)]
pub struct AddressSync<const N: usize> {
    range: AddressRange,
    state: AddressState,
    armed: WaitSet<N>,
    ready: WaitSet<N>,
}

impl<const N: usize> AddressSync<N> {
    pub fn new(range: AddressRange, initial: AddressState) -> Self {
        Self {
            range,
            state: initial,
            armed: WaitSet::new(),
            ready: WaitSet::new(),
        }
    }

    pub const fn range(&self) -> AddressRange {
        self.range
    }

    pub const fn state(&self) -> AddressState {
        self.state
    }

    pub fn armed(&self) -> usize {
        self.armed.len()
    }

    pub fn ready(&self) -> usize {
        self.ready.len()
    }

    /// Atomically compare the caller's observation and arm one wait.
    ///
    /// The caller must invoke this while holding the MemoryObject critical
    /// section used to read `expected`, then perform the scheduler transition to
    /// parked before releasing that section.
    pub fn wait(
        &mut self,
        registration: &mut Registration,
        grant: AddressGrant,
        task: Token,
        expected: AddressState,
        now: u64,
        deadline: Option<u64>,
    ) -> Result<AddressWait, AddressSyncError> {
        if grant.range() != self.range {
            return Err(AddressSyncError::WrongObject);
        }
        match registration.enroll(task, self.state != expected, now, deadline) {
            Enroll::Ready => Ok(AddressWait::Ready(self.state)),
            Enroll::TimedOut => Ok(AddressWait::TimedOut),
            Enroll::Busy => Err(AddressSyncError::Busy),
            Enroll::Exhausted => Err(AddressSyncError::Exhausted),
            Enroll::Armed(key) => {
                if let Err(error) = self.armed.insert(key) {
                    let _ = registration.finish(key);
                    return Err(match error {
                        SetError::Full => AddressSyncError::Full,
                        SetError::DuplicateTask => AddressSyncError::Busy,
                    });
                }
                Ok(AddressWait::Armed(key))
            }
        }
    }

    /// Publish one new condition version and wake at most `count` waiters.
    ///
    /// Version advances even when `value` is unchanged, so a waiter observing
    /// the old state before publication cannot be lost.
    pub fn publish(
        &mut self,
        range: AddressRange,
        value: u64,
        count: usize,
    ) -> Result<usize, AddressSyncError> {
        if range != self.range {
            return Err(AddressSyncError::WrongObject);
        }
        let version = self
            .state
            .version
            .checked_add(1)
            .ok_or(AddressSyncError::Exhausted)?;
        self.state = AddressState { version, value };
        let mut woken = 0;
        while woken < count {
            let Some(key) = self.armed.pop() else {
                break;
            };
            if self.ready.insert(key).is_err() {
                let _ = self.armed.insert(key);
                return Err(AddressSyncError::InternalSet);
            }
            woken += 1;
        }
        Ok(woken)
    }

    /// Consume one ready or still-armed key.
    ///
    /// A key can be consumed once. An armed key remains busy because no matching
    /// publication has won it yet.
    pub fn take(
        &mut self,
        registration: &mut Registration,
        key: Key,
    ) -> Result<AddressWait, AddressSyncError> {
        if self.ready.remove(key) {
            if !registration.finish(key) {
                return Err(AddressSyncError::StaleWaiter);
            }
            return Ok(AddressWait::Ready(self.state));
        }
        if self.armed.remove(key) {
            let _ = self.armed.insert(key);
            if registration.pending() != Some(key) {
                return Err(AddressSyncError::StaleWaiter);
            }
            return Err(AddressSyncError::Busy);
        }
        Err(AddressSyncError::StaleWaiter)
    }

    /// Cancel exactly one waiter. Stale rounds and duplicate cancellation are
    /// side-effect free.
    pub fn cancel(&mut self, registration: &mut Registration, key: Key) -> bool {
        let removed = self.ready.remove(key) | self.armed.remove(key);
        let finished = registration.finish(key);
        removed && finished
    }

    /// Cancel every round owned by one task after task exit or generation loss.
    pub fn cancel_task(&mut self, registration: &mut Registration, task: Token) -> usize {
        let mut removed = 0;
        while let Some(key) = self.ready.pop() {
            if key.task == task {
                let _ = registration.finish(key);
                removed += 1;
            } else if self.ready.insert(key).is_err() {
                let _ = self.armed.insert(key);
            }
        }
        while let Some(key) = self.armed.pop() {
            if key.task == task {
                let _ = registration.finish(key);
                removed += 1;
            } else if self.armed.insert(key).is_err() {
                let _ = self.ready.insert(key);
            }
        }
        removed
    }

    /// Expire a deadline under the caller's monotonic clock.
    pub fn expire(
        &mut self,
        registration: &mut Registration,
        key: Key,
        now: u64,
    ) -> bool {
        if !registration.expire(key, now) {
            return false;
        }
        let _ = self.ready.remove(key);
        let _ = self.armed.remove(key);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_capability::{
        CapabilityState, MEMORY_CAPABILITY_FORMAT_VERSION, MemoryKind,
    };

    fn cap(id: u64, generation: u32, state: CapabilityState) -> MemoryCapability {
        MemoryCapability {
            id,
            format_version: MEMORY_CAPABILITY_FORMAT_VERSION,
            state,
            kind: MemoryKind::Shared,
            rights: MemoryRights::READ.union(MemoryRights::WRITE),
            start: 0x4000,
            end: 0x8000,
            backing: BackingIdentity::new(9, generation).unwrap(),
            epoch: 3,
        }
    }

    fn grant(id: u64) -> AddressGrant {
        AddressGrant::from_capability(
            cap(id, 7, CapabilityState::Active),
            0x4010,
            8,
            MemoryRights::READ,
        )
        .unwrap()
    }

    fn token(generation: u64) -> Token {
        Token {
            slot: 2,
            generation,
        }
    }

    #[test]
    fn aliases_share_the_condition_but_keep_capability_identity() {
        let first = grant(1);
        let second = grant(2);
        assert_eq!(first.range(), second.range());
        assert_ne!(first.capability(), second.capability());
        let mut sync = AddressSync::<2>::new(first.range(), AddressState::default());
        let mut registration = Registration::new();
        let task = token(1);
        let AddressWait::Armed(key) =
            sync.wait(&mut registration, second, task, AddressState::default(), 0, None)
                .unwrap()
        else {
            panic!("wait should arm")
        };
        assert_eq!(sync.publish(first.range(), 0, 1).unwrap(), 1);
        assert_eq!(sync.take(&mut registration, key), Ok(AddressWait::Ready(AddressState { version: 1, value: 0 })));
    }

    #[test]
    fn lost_wake_is_prevented_even_when_value_is_unchanged() {
        let grant = grant(1);
        let mut sync = AddressSync::<2>::new(grant.range(), AddressState::default());
        let observed = sync.state();
        assert_eq!(sync.publish(grant.range(), 0, 0).unwrap(), 0);
        let mut registration = Registration::new();
        assert_eq!(
            sync.wait(&mut registration, grant, token(1), observed, 0, None),
            Ok(AddressWait::Ready(AddressState { version: 1, value: 0 }))
        );
        assert_eq!(sync.armed(), 0);
    }

    #[test]
    fn generation_scope_and_revocation_fail_closed() {
        let current = grant(1);
        let mut sync = AddressSync::<2>::new(current.range(), AddressState::default());
        let stale = AddressGrant::from_capability(
            cap(2, 8, CapabilityState::Active),
            0x4010,
            8,
            MemoryRights::READ,
        )
        .unwrap();
        let mut registration = Registration::new();
        assert_eq!(
            sync.wait(&mut registration, stale, token(1), AddressState::default(), 0, None),
            Err(AddressSyncError::WrongObject)
        );
        assert_eq!(
            AddressGrant::from_capability(
                cap(3, 7, CapabilityState::Revoked),
                0x4010,
                8,
                MemoryRights::READ,
            ),
            Err(AddressSyncError::GrantRejected)
        );
        let mut read_only = cap(4, 7, CapabilityState::Active);
        read_only.rights = MemoryRights::READ;
        assert_eq!(
            AddressGrant::from_capability(
                read_only,
                0x4010,
                8,
                MemoryRights::READ.union(MemoryRights::WRITE),
            ),
            Err(AddressSyncError::GrantRejected)
        );
        assert_eq!(
            AddressGrant::from_capability(
                cap(5, 7, CapabilityState::Active),
                0x4010,
                3,
                MemoryRights::READ,
            ),
            Err(AddressSyncError::InvalidRange)
        );
        assert_eq!(
            AddressGrant::from_capability(
                cap(6, 7, CapabilityState::Active),
                0x4011,
                8,
                MemoryRights::READ,
            ),
            Err(AddressSyncError::InvalidRange)
        );
    }

    #[test]
    fn duplicate_capacity_cancel_exit_and_deadline_are_explicit() {
        let grant = grant(1);
        let mut sync = AddressSync::<1>::new(grant.range(), AddressState::default());
        let mut first = Registration::new();
        let task1 = token(1);
        let AddressWait::Armed(key) =
            sync.wait(&mut first, grant, task1, AddressState::default(), 0, Some(10)).unwrap()
        else {
            panic!("first waiter should arm")
        };
        assert_eq!(
            sync.wait(&mut first, grant, task1, AddressState::default(), 0, None),
            Err(AddressSyncError::Busy)
        );
        let mut second = Registration::new();
        assert_eq!(
            sync.wait(&mut second, grant, token(2), AddressState::default(), 0, None),
            Err(AddressSyncError::Full)
        );
        assert!(!sync.expire(&mut first, key, 9));
        assert!(sync.expire(&mut first, key, 10));
        assert_eq!(sync.armed(), 0);

        let AddressWait::Armed(key) =
            sync.wait(&mut second, grant, token(2), AddressState::default(), 10, None).unwrap()
        else {
            panic!("second waiter should arm")
        };
        assert!(sync.cancel(&mut second, key));
        assert!(!sync.cancel(&mut second, key));
        let AddressWait::Armed(key) =
            sync.wait(&mut second, grant, token(2), AddressState::default(), 10, None).unwrap()
        else {
            panic!("second waiter should re-arm")
        };
        assert_eq!(sync.cancel_task(&mut second, token(2)), 1);
        assert_eq!(second.pending(), None);
        assert!(!sync.cancel(&mut second, key));
    }

    #[test]
    fn version_exhaustion_does_not_mutate_condition() {
        let grant = grant(1);
        let initial = AddressState {
            version: u64::MAX,
            value: 7,
        };
        let mut sync = AddressSync::<1>::new(grant.range(), initial);
        assert_eq!(
            sync.publish(grant.range(), 8, 1),
            Err(AddressSyncError::Exhausted)
        );
        assert_eq!(sync.state(), initial);
    }
}
