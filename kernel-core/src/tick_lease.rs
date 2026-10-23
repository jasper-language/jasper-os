//! Author: chatgpt. One-tick lease, serialized by the caller's per-CPU leaf lock.
//! The scheduler transaction holds every leaf from drain through publication.
//! Caller allocates shared limit credits and leaves RT headroom before grant.
//! All limit/configuration mutation must drain first; this type owns no limit.
use crate::task_index::Token;
#[derive(Debug)]
pub struct TickLease { owner: Option<Token>, permit: bool, pending: bool, hits: u32 }
impl TickLease {
    pub const fn new() -> Self { Self { owner: None, permit: false, pending: false, hits: 0 } }
    /// Must follow drain while the same leaf lock stays held.
    pub fn publish(&mut self, owner: Option<Token>) {
        assert!(!self.pending, "publish requires drained accounting");
        self.owner = owner;
        self.permit = owner.is_some();
    }
    pub fn try_tick(&mut self) -> bool {
        if !self.permit { return false; }
        self.permit = false;
        self.pending = true;
        self.hits = self.hits.wrapping_add(1);
        true
    }
    pub fn drain(&mut self) -> Option<Token> {
        let pending = core::mem::replace(&mut self.pending, false);
        if pending { self.owner } else { None }
    }
    pub fn hits(&self) -> u32 { self.hits }
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
        l.publish(Some(a));
        assert!(l.try_tick());
        assert!(!l.try_tick());
        assert_eq!(l.drain(), Some(a));
        assert_eq!(l.drain(), None);
        l.publish(Some(b));
        assert!(l.try_tick());
        assert_eq!(l.drain(), Some(b));
        l.publish(None);
        assert!(!l.try_tick());
        assert_eq!(l.hits(), 2);
    }
    #[test]
    #[should_panic(expected="publish requires drained accounting")]
    fn undrained_republication_is_rejected() {
        let mut l = TickLease::new();
        l.publish(Some(Token { slot: 1, generation: 1 }));
        assert!(l.try_tick());
        l.publish(None);
    }
}
