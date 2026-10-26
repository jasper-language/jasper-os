//! Checked protocol primitives for KRN-3 per-CPU run-queue migration.
//!
//! This module contains no locks.  It makes the lock order, transient owner,
//! generation identity and single-consume PI message explicit so the kernel can
//! use the same state machine while its queue storage is split per CPU.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskToken {
    pub slot: u32,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuPair {
    pub first: u16,
    pub second: u16,
}

impl CpuPair {
    pub fn ordered(source: u16, destination: u16) -> Option<Self> {
        if source == destination { return None; }
        Some(Self { first: source.min(destination), second: source.max(destination) })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Cpu(u16),
    /// Detached while both ordered queue locks remain held by this transaction.
    Transit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationError { SameCpu, WrongOwner, WrongPhase }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Migration {
    pub token: TaskToken,
    source: u16,
    destination: u16,
    owner: Owner,
}

impl Migration {
    pub fn begin(token: TaskToken, owner: Owner, destination: u16) -> Result<Self, MigrationError> {
        let Owner::Cpu(source) = owner else { return Err(MigrationError::WrongOwner); };
        CpuPair::ordered(source, destination).ok_or(MigrationError::SameCpu)?;
        Ok(Self { token, source, destination, owner })
    }
    pub fn locks(&self) -> CpuPair { CpuPair::ordered(self.source, self.destination).unwrap() }
    pub fn owner(&self) -> Owner { self.owner }
    pub fn detach(&mut self) -> Result<(), MigrationError> {
        if self.owner != Owner::Cpu(self.source) { return Err(MigrationError::WrongPhase); }
        self.owner = Owner::Transit;
        Ok(())
    }
    pub fn commit(&mut self) -> Result<(), MigrationError> {
        if self.owner != Owner::Transit { return Err(MigrationError::WrongPhase); }
        self.owner = Owner::Cpu(self.destination);
        Ok(())
    }
    pub fn abort(&mut self) -> Result<(), MigrationError> {
        if self.owner != Owner::Transit { return Err(MigrationError::WrongPhase); }
        self.owner = Owner::Cpu(self.source);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PiMessage {
    pub token: TaskToken,
    pub round: u64,
    pub priority: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PiSlot { pending: Option<PiMessage>, last_round: u64 }

impl PiSlot {
    pub const fn new() -> Self { Self { pending: None, last_round: 0 } }
    pub fn publish(&mut self, message: PiMessage) -> bool {
        if self.pending.is_some() || message.round <= self.last_round { return false; }
        self.pending = Some(message);
        true
    }
    pub fn consume(&mut self, live: TaskToken) -> Option<PiMessage> {
        let message = self.pending.take()?;
        self.last_round = self.last_round.max(message.round);
        (message.token == live).then_some(message)
    }
    pub fn pending(&self) -> bool { self.pending.is_some() }
}

impl Default for PiSlot { fn default() -> Self { Self::new() } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PiEnqueue { Queued, Replaced, Stale, Full }

/// Bounded target-CPU PI notification queue. The caller supplies locking.
/// A newer round for the same task replaces the queued older round, so a
/// producer cannot fill the queue by repeatedly changing one task's priority.
pub struct PiMailbox<const N: usize> {
    entries: [Option<PiMessage>; N],
    head: usize,
    len: usize,
}

impl<const N: usize> PiMailbox<N> {
    pub const fn new() -> Self { Self { entries: [None; N], head: 0, len: 0 } }
    pub fn len(&self) -> usize { self.len }
    pub fn push(&mut self, message: PiMessage) -> PiEnqueue {
        for offset in 0..self.len {
            let at = (self.head + offset) % N;
            if self.entries[at].is_some_and(|old| old.token == message.token) {
                let old = self.entries[at].unwrap();
                if message.round <= old.round { return PiEnqueue::Stale; }
                self.entries[at] = Some(message);
                return PiEnqueue::Replaced;
            }
        }
        if self.len == N { return PiEnqueue::Full; }
        self.entries[(self.head + self.len) % N] = Some(message);
        self.len += 1;
        PiEnqueue::Queued
    }
    pub fn pop(&mut self) -> Option<PiMessage> {
        if self.len == 0 { return None; }
        let message = self.entries[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token(generation: u64) -> TaskToken { TaskToken { slot: 7, generation } }
    #[test]
    fn ordered_pair_and_transaction_keep_one_owner() {
        let mut m = Migration::begin(token(2), Owner::Cpu(5), 1).unwrap();
        assert_eq!(m.locks(), CpuPair { first: 1, second: 5 });
        m.detach().unwrap(); assert_eq!(m.owner(), Owner::Transit);
        m.commit().unwrap(); assert_eq!(m.owner(), Owner::Cpu(1));
        assert_eq!(m.commit(), Err(MigrationError::WrongPhase));
    }
    #[test]
    fn abort_restores_source_and_pi_is_single_consume() {
        let mut m = Migration::begin(token(4), Owner::Cpu(0), 1).unwrap();
        m.detach().unwrap(); m.abort().unwrap(); assert_eq!(m.owner(), Owner::Cpu(0));
        let mut slot = PiSlot::new();
        let msg = PiMessage { token: token(4), round: 1, priority: 9 };
        assert!(slot.publish(msg)); assert!(!slot.publish(msg));
        assert_eq!(slot.consume(token(4)), Some(msg)); assert_eq!(slot.consume(token(4)), None);
        assert!(!slot.publish(msg));
    }
    #[test]
    fn stale_generation_is_consumed_without_application() {
        let mut slot = PiSlot::new();
        assert!(slot.publish(PiMessage { token: token(3), round: 8, priority: 2 }));
        assert_eq!(slot.consume(token(4)), None); assert!(!slot.pending());
    }
    #[test]
    fn pi_mailbox_replaces_only_newer_round_for_same_identity() {
        let mut q = PiMailbox::<2>::new();
        let first = PiMessage { token: token(1), round: 4, priority: 2 };
        let newer = PiMessage { token: token(1), round: 5, priority: 1 };
        assert_eq!(q.push(first), PiEnqueue::Queued);
        assert_eq!(q.push(first), PiEnqueue::Stale);
        assert_eq!(q.push(newer), PiEnqueue::Replaced);
        assert_eq!(q.push(PiMessage { token: token(2), round: 1, priority: 3 }), PiEnqueue::Queued);
        assert_eq!(q.push(PiMessage { token: token(3), round: 1, priority: 0 }), PiEnqueue::Full);
        assert_eq!(q.pop(), Some(newer));
        assert_eq!(q.pop().unwrap().token, token(2));
        assert_eq!(q.pop(), None);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn ordered_pair_is_strict_and_migration_has_one_owner() {
        let source: u16 = kani::any(); let destination: u16 = kani::any();
        kani::assume(source != destination);
        let token = TaskToken { slot: kani::any(), generation: kani::any() };
        let mut m = Migration::begin(token, Owner::Cpu(source), destination).unwrap();
        let pair = m.locks(); assert!(pair.first < pair.second);
        m.detach().unwrap(); assert_eq!(m.owner(), Owner::Transit);
        if kani::any() { m.commit().unwrap(); assert_eq!(m.owner(), Owner::Cpu(destination)); }
        else { m.abort().unwrap(); assert_eq!(m.owner(), Owner::Cpu(source)); }
    }
    #[kani::proof]
    fn pi_message_applies_at_most_once_to_matching_generation() {
        let live = TaskToken { slot: kani::any(), generation: kani::any() };
        let message = PiMessage { token: TaskToken { slot: kani::any(), generation: kani::any() }, round: 1, priority: kani::any() };
        let mut slot = PiSlot::new(); assert!(slot.publish(message));
        let first = slot.consume(live); let second = slot.consume(live);
        assert!(second.is_none()); assert_eq!(first.is_some(), message.token == live);
    }
    #[kani::proof]
    fn pi_mailbox_preserves_latest_round_without_duplicate_entry() {
        let token = TaskToken { slot: kani::any(), generation: kani::any() };
        let first = PiMessage { token, round: 1, priority: kani::any() };
        let second = PiMessage { token, round: 2, priority: kani::any() };
        let mut mailbox = PiMailbox::<2>::new();
        assert_eq!(mailbox.push(first), PiEnqueue::Queued);
        assert_eq!(mailbox.push(second), PiEnqueue::Replaced);
        assert_eq!(mailbox.len(), 1);
        assert_eq!(mailbox.pop(), Some(second));
        assert_eq!(mailbox.pop(), None);
    }
}
