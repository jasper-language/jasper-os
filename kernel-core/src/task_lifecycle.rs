//! Author: chatgpt. Serialized slot reservation/publication lifecycle.
//!
//! A reservation burns a generation even if aborted. Historical identity stays
//! readable until successful publication, including failed reservations at the
//! u64 limit. The caller must atomically update its label index with publication
//! under the same scheduler lock. No concurrent/lock-free publication is offered.
use crate::task_index::Token;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation { label: u64, token: Token }
impl Reservation {
    pub fn label(self) -> u64 { self.label }
    pub fn token(self) -> Token { self.token }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Busy, Exhausted, Stale }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Vacant, Live, Exited }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotLifecycle {
    slot: usize,
    sequence: u64,
    phase: Phase,
    published: Option<Reservation>,
    pending: Option<Reservation>,
    on_cpu: bool,
}
impl SlotLifecycle {
    pub const fn new(slot: usize) -> Self {
        Self { slot, sequence: 0, phase: Phase::Vacant, published: None, pending: None, on_cpu: false }
    }
    /// Initial published identity for a reserved bootstrap slot, never a worker
    /// reuse operation. Only use before the scheduler becomes externally visible.
    pub const fn initial(slot: usize, label: u64) -> Self {
        Self { slot, sequence: 1, phase: Phase::Live,
            published: Some(Reservation { label, token: Token { slot, generation: 1 } }),
            pending: None, on_cpu: false }
    }
    /// An exhausted slot is never reused; existing historical identity survives.
    pub fn reserve(&mut self, label: u64) -> Result<Reservation, Error> {
        if self.phase == Phase::Live || self.on_cpu || self.pending.is_some() { return Err(Error::Busy); }
        let generation = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let r = Reservation { label, token: Token { slot: self.slot, generation } };
        self.sequence = generation;
        self.pending = Some(r);
        Ok(r)
    }
    /// Returns the old historical identity for the caller's atomic index update.
    /// Before calling, preflight index capacity, label uniqueness and task setup.
    pub fn publish(&mut self, r: Reservation) -> Result<Option<Reservation>, Error> {
        if self.pending != Some(r) { return Err(Error::Stale); }
        let old = self.published.replace(r);
        self.pending = None;
        self.phase = Phase::Live;
        Ok(old)
    }
    pub fn abort(&mut self, r: Reservation) -> Result<(), Error> {
        if self.pending != Some(r) { return Err(Error::Stale); }
        self.pending = None;
        Ok(())
    }
    pub fn live(&self, token: Token) -> bool {
        self.phase == Phase::Live && self.published.is_some_and(|r| r.token == token)
    }
    pub fn history(&self) -> Option<Reservation> { self.published }
    pub fn dispatch(&mut self, token: Token) -> Result<(), Error> {
        if !self.live(token) { return Err(Error::Stale); }
        if self.on_cpu { return Err(Error::Busy); }
        self.on_cpu = true;
        Ok(())
    }
    /// Exiting does not release the executing stack; detach is separate.
    pub fn exit(&mut self, token: Token) -> Result<(), Error> {
        if !self.live(token) { return Err(Error::Stale); }
        self.phase = Phase::Exited;
        Ok(())
    }
    pub fn detach(&mut self, token: Token) -> Result<(), Error> {
        if !self.on_cpu || !self.published.is_some_and(|r| r.token == token) { return Err(Error::Stale); }
        self.on_cpu = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserve_history_and_burn_aborted_generation() {
        let mut s = SlotLifecycle::new(7);
        let first = s.reserve(1000).unwrap();
        assert_eq!(s.publish(first), Ok(None));
        s.dispatch(first.token()).unwrap();
        s.exit(first.token()).unwrap();
        assert_eq!(s.reserve(1001), Err(Error::Busy));
        s.detach(first.token()).unwrap();
        let aborted = s.reserve(1001).unwrap();
        assert_eq!(s.history(), Some(first));
        s.abort(aborted).unwrap();
        let next = s.reserve(1001).unwrap();
        assert_eq!(next.token().generation, 3);
        let before = s;
        assert_eq!(s.publish(aborted), Err(Error::Stale));
        assert_eq!(s.abort(aborted), Err(Error::Stale));
        assert_eq!(s, before);
        assert_eq!(s.publish(next), Ok(Some(first)));
        assert!(!s.live(first.token()));
        assert!(s.live(next.token()));
        assert_eq!(s.exit(first.token()), Err(Error::Stale));
        assert_eq!(s.detach(first.token()), Err(Error::Stale));
    }
    #[test]
    fn overflow_and_foreign_slot_do_not_change_state() {
        let mut a = SlotLifecycle::new(1);
        let mut b = SlotLifecycle::new(2);
        let ra = a.reserve(u64::MAX).unwrap();
        let rb = b.reserve(u64::MAX).unwrap();
        assert_eq!(a.publish(rb), Err(Error::Stale));
        a.publish(ra).unwrap();
        a.exit(ra.token()).unwrap();
        a.sequence = u64::MAX - 1;
        let last = a.reserve(0).unwrap();
        assert_eq!(last.token().generation, u64::MAX);
        a.abort(last).unwrap();
        let before = a;
        assert_eq!(a.reserve(0), Err(Error::Exhausted));
        assert_eq!(a, before);
        assert_eq!(a.history(), Some(ra));
        assert_eq!(a.publish(last), Err(Error::Stale));
    }
}
