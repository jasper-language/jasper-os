//! Explicitly armed, one-shot fault countdown.
//! A seed chooses the failing invocation; concurrent callers have no fixed order.
//! Arming/disarming must occur while the tested workload is quiescent.
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct FaultPoint { remaining: AtomicUsize }
impl FaultPoint {
    pub const fn new() -> Self { Self { remaining: AtomicUsize::new(0) } }
    /// Arm one failure in the next 1..=window invocations. Zero window is rejected.
    pub fn arm(&self, seed: u64, window: usize) -> Result<usize, &'static str> {
        if window == 0 { return Err("zero fault window"); }
        let mixed = seed.wrapping_add(0x9e3779b97f4a7c15).wrapping_mul(0xbf58476d1ce4e5b9);
        let nth = (mixed % window as u64) as usize + 1;
        self.remaining.store(nth, Ordering::SeqCst);
        Ok(nth)
    }
    pub fn disarm(&self) { self.remaining.store(0, Ordering::SeqCst); }
    /// True exactly once per arm, at the selected invocation. Does not allocate.
    pub fn hit(&self) -> bool {
        self.remaining.try_update(Ordering::SeqCst, Ordering::SeqCst,
            |n| n.checked_sub(1)).is_ok_and(|n| n == 1)
    }
}
impl Default for FaultPoint { fn default() -> Self { Self::new() } }
