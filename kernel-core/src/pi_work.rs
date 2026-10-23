//! Author: chatgpt. Serial PI work counters; caller owns synchronization.
//! Saturating counts of executed PI work, not elapsed time or a WCET bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PiWork {
    pub calls: u64,
    pub slots: u64,
    pub live: u64,
    pub steps: u64,
    pub max_walk: u64,
    pub truncated: u64,
    pub overflow: bool,
}
impl PiWork {
    pub const EMPTY: Self = Self { calls: 0, slots: 0, live: 0, steps: 0, max_walk: 0, truncated: 0, overflow: false };
    pub fn slots(&mut self, n: u64) { self.slots = Self::sum(self.slots, n, &mut self.overflow); }
    pub fn live(&mut self) { self.live = Self::sum(self.live, 1, &mut self.overflow); }
    pub fn step(&mut self, walk: u64) { self.steps = Self::sum(self.steps, 1, &mut self.overflow); self.max_walk = self.max_walk.max(walk); }
    pub fn truncate(&mut self) { self.truncated = Self::sum(self.truncated, 1, &mut self.overflow); }
    fn sum(a: u64, b: u64, overflow: &mut bool) -> u64 {
        match a.checked_add(b) { Some(v) => v, None => { *overflow = true; u64::MAX } }
    }
    pub fn merge(&mut self, r: Self) {
        self.overflow |= r.overflow;
        self.calls = Self::sum(self.calls, r.calls, &mut self.overflow);
        self.slots = Self::sum(self.slots, r.slots, &mut self.overflow);
        self.live = Self::sum(self.live, r.live, &mut self.overflow);
        self.steps = Self::sum(self.steps, r.steps, &mut self.overflow);
        self.truncated = Self::sum(self.truncated, r.truncated, &mut self.overflow);
        self.max_walk = self.max_walk.max(r.max_walk);
    }
}
// Kernel should keep total+window accumulators, resetting only window at the
// synchronized barrier. Snapshot/print both, so a yield-only window with zero PI
// cannot erase or conceal PI demonstrations performed earlier in the boot.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overflow_is_explicit_and_maxima_are_not_added() {
        let mut work = PiWork { calls: u64::MAX - 1, steps: u64::MAX,
            max_walk: 9, ..PiWork::default() };
        work.merge(PiWork { calls: 1, max_walk: 4, ..PiWork::default() });
        assert_eq!(work.calls, u64::MAX); assert!(!work.overflow);
        assert_eq!(work.max_walk, 9);
        work.merge(PiWork { calls: 1, steps: 1, max_walk: 12, ..PiWork::default() });
        assert_eq!(work.calls, u64::MAX); assert_eq!(work.steps, u64::MAX);
        assert_eq!(work.max_walk, 12); assert!(work.overflow);
    }
    #[test]
    fn total_and_window_do_not_alias() {
        let first = PiWork { calls: 3, slots: 48, live: 4, steps: 7,
            max_walk: 3, truncated: 0, overflow: false };
        let second = PiWork { calls: 2, slots: 32, live: 2, steps: 1,
            max_walk: 1, truncated: 0, overflow: false };
        let mut total = PiWork::default();
        total.merge(first);
        let mut window = PiWork::default();
        total.merge(second); window.merge(second);
        assert_eq!(total.calls, 5); assert_eq!(total.steps, 8);
        assert_eq!(window, second); assert_eq!(total.max_walk, 3);
    }
}
