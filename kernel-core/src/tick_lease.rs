//! Author: chatgpt. One-tick lease, serialized by the caller's per-CPU leaf lock.
//! The scheduler transaction holds every leaf from drain through publication.
//! Caller allocates shared budget credits and leaves RT headroom before grant.
//! All budget/configuration mutation must drain first; this type owns no budget.
use crate::task_index::Token;
#[derive(Debug)]
pub struct TickLease { owner: Option<Token>, permits: u8, pending: u8, peak: u8, hits: u32 }
impl TickLease {
    pub const fn new() -> Self { Self { owner: None, permits: 0, pending: 0, peak: 0, hits: 0 } }
    /// Must follow drain while the same leaf lock stays held.
    pub fn publish(&mut self, owner: Option<Token>, permits: u8) {
        assert_eq!(self.pending, 0, "publish requires drained accounting");
        assert_eq!(owner.is_some(), permits != 0, "owner and permits must agree");
        self.owner = owner;
        self.permits = permits;
    }
    pub fn try_tick(&mut self) -> bool {
        self.try_tick_owner().is_some()
    }
    /// Consume one permit and return the exact task identity that owns the
    /// tick.  The caller can update owner-local state immediately while it
    /// still holds the per-CPU lease lock.
    pub fn try_tick_owner(&mut self) -> Option<Token> {
        if self.permits == 0 { return None; }
        self.permits -= 1;
        self.pending = self.pending.checked_add(1).expect("bounded tick lease pending count");
        self.peak = self.peak.max(self.pending);
        self.hits = self.hits.wrapping_add(1);
        self.owner
    }
    pub fn drain(&mut self) -> Option<(Token, u8)> {
        let pending = core::mem::replace(&mut self.pending, 0);
        self.permits = 0;
        if pending != 0 { Some((self.owner.expect("pending lease owner"), pending)) } else { None }
    }
    pub fn hits(&self) -> u32 { self.hits }
    pub fn peak(&self) -> u8 { self.peak }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_credit_exactly_once_and_owner_changes_after_drain() {
        let a = Token { slot: 2, generation: 1 };
        let b = Token { slot: 2, generation: 2 };
        let mut l = TickLease::new();
        assert!(!l.try_tick());
        l.publish(Some(a), 2);
        assert_eq!(l.try_tick_owner(), Some(a));
        assert!(l.try_tick());
        assert!(!l.try_tick());
        assert_eq!(l.drain(), Some((a, 2)));
        assert_eq!(l.drain(), None);
        l.publish(Some(b), 1);
        assert_eq!(l.try_tick_owner(), Some(b));
        assert_eq!(l.drain(), Some((b, 1)));
        l.publish(None, 0);
        assert!(!l.try_tick());
        assert_eq!(l.hits(), 3);
        assert_eq!(l.peak(), 2);
    }
    #[test]
    #[should_panic(expected="publish requires drained accounting")]
    fn undrained_republication_is_rejected() {
        let mut l = TickLease::new();
        l.publish(Some(Token { slot: 1, generation: 1 }), 1);
        assert!(l.try_tick());
        l.publish(None, 0);
    }
}
