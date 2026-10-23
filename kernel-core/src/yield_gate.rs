//! Author: chatgpt. Advisory no-competitor yield permit. Scheduler lock owns
//! publication. This never suppresses timer/preempt/sleep/exit or IPI handling.
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
pub struct YieldGate { permit: AtomicBool, yielded: AtomicBool, hits: AtomicU32 }
impl Default for YieldGate { fn default() -> Self { Self::new() } }
impl YieldGate {
    pub const fn new() -> Self { Self { permit: AtomicBool::new(false), yielded: AtomicBool::new(false), hits: AtomicU32::new(0) } }
    pub fn revoke(&self) { self.permit.store(false, Ordering::Release); }
    pub fn publish(&self, permit: bool) { self.permit.store(permit, Ordering::Release); }
    /// Calling CPU has IRQs disabled: its current task cannot change until after
    /// this call returns. A concurrent remote transaction publishes its updated permit at commit.
    /// The old snapshot linearizes before that commit; unchanged periodic timer
    /// checks remain the progress backstop even if an old value was observed.
    pub fn try_yield(&self) -> bool {
        if !self.permit.load(Ordering::Acquire) { return false; }
        self.yielded.store(true, Ordering::Release);
        self.hits.fetch_add(1, Ordering::Relaxed);
        true
    }
    /// Only under the scheduler lock, before any owner/current-slot mutation.
    /// Multiple voluntary yields coalesce, since Watchdog::yielded resets state.
    pub fn take_yielded(&self) -> bool { self.yielded.swap(false, Ordering::AcqRel) }
    pub fn pending_yield(&self) -> bool { self.yielded.load(Ordering::Acquire) }
    pub fn hits(&self) -> u32 { self.hits.load(Ordering::Relaxed) }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn revoked_permit_and_coalesced_watchdog_reset() {
        let g = YieldGate::new();
        assert!(!g.try_yield()); assert!(!g.take_yielded());
        g.publish(true);
        for _ in 0..100 { assert!(g.try_yield()); }
        assert_eq!(g.hits(), 100);
        g.revoke(); assert!(!g.try_yield());
        assert!(g.take_yielded()); assert!(!g.take_yielded());
    }
    #[test]
    fn empty_arbiter_demand_is_a_noop_even_in_multi_mode() {
        use crate::arbiter::{Arbiter, ArbiterParams, Demand, Window};
        let mut arbiter = Arbiter::new(ArbiterParams::DEFAULT);
        let window = Window::default();
        let _ = arbiter.pick(Demand { interactive: true, batch: true, ..Demand::default() }, &window);
        let before = arbiter.batch_wait();
        for _ in 0..100 {
            assert_eq!(arbiter.pick(Demand::default(), &window), None);
            assert_eq!(arbiter.batch_wait(), before);
        }
        let gate = YieldGate::new();
        let wd = crate::sched::watchdog::Watchdog::new(3);
        let mut streak = crate::sched::watchdog::RunStreak::new();
        assert!(wd.charge(&mut streak).is_none());
        assert!(wd.charge(&mut streak).is_none());
        gate.publish(true); assert!(gate.try_yield());
        if gate.take_yielded() { wd.yielded(&mut streak); }
        assert!(wd.charge(&mut streak).is_none());
        assert_eq!(streak.ticks(), 1);
    }
    #[test]
    fn cross_thread_yield_is_published_to_drain() {
        let g = YieldGate::new(); g.publish(true);
        std::thread::scope(|s| { s.spawn(|| assert!(g.try_yield())); });
        assert!(g.take_yielded());
        g.revoke(); assert!(!g.try_yield());
    }
}
