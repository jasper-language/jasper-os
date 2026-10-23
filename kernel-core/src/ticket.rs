//! Author: chatgpt. FIFO ticket lock for KRN-2, using only 32-bit atomics.
//! Fewer than 2^32 outstanding acquisitions; a holder must not recursively lock.
//! Pure mechanism: interrupt masking and rank validation remain caller duties.
use core::{cell::UnsafeCell, ops::{Deref, DerefMut}, sync::atomic::{AtomicU32, Ordering}};

pub struct TicketLock<T> { next: AtomicU32, serving: AtomicU32, value: UnsafeCell<T> }
// SAFETY: only the unique serving ticket may access value. Release unlock and
// acquire observation publish prior writes. Moving T between holders needs Send.
unsafe impl<T: Send> Sync for TicketLock<T> {}
unsafe impl<T: Send> Send for TicketLock<T> {}
impl<T> TicketLock<T> {
    pub const fn new(value: T) -> Self {
        Self { next: AtomicU32::new(0), serving: AtomicU32::new(0), value: UnsafeCell::new(value) }
    }
    /// Returns spin count for contention-only diagnostics, never writes a shared
    /// diagnostic cache line while waiting. Ticket allocation itself is FIFO.
    pub fn lock_counted(&self) -> (TicketGuard<'_, T>, u32) {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let mut spins = 0u32;
        while self.serving.load(Ordering::Acquire) != ticket {
            spins = spins.wrapping_add(1);
            core::hint::spin_loop();
        }
        (TicketGuard { lock: self, ticket, _borrow: core::marker::PhantomData }, spins)
    }
    pub fn lock(&self) -> TicketGuard<'_, T> { self.lock_counted().0 }
    /// Failure must not allocate a ticket: that would leave an unserviceable hole.
    pub fn try_lock(&self) -> Option<TicketGuard<'_, T>> {
        let ticket = self.serving.load(Ordering::Acquire);
        self.next.compare_exchange(ticket, ticket.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
            .ok().map(|_| TicketGuard { lock: self, ticket, _borrow: core::marker::PhantomData })
    }
    pub fn is_locked(&self) -> bool {
        self.next.load(Ordering::Relaxed) != self.serving.load(Ordering::Relaxed)
    }
}
/// Sharing a guard requires T: Sync, even though the lock only requires T: Send.
/// ```compile_fail
/// use kernel_core::ticket::TicketGuard;
/// fn require_sync<T: Sync>() {}
/// require_sync::<TicketGuard<'static, core::cell::Cell<u8>>>();
/// ```
pub struct TicketGuard<'a, T> { lock: &'a TicketLock<T>, ticket: u32, _borrow: core::marker::PhantomData<&'a mut T> }
impl<T> Deref for TicketGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard owns the serving ticket until Drop.
        unsafe { &*self.lock.value.get() }
    }
}
impl<T> DerefMut for TicketGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: only one serving ticket exists and mutable guard borrow is unique.
        unsafe { &mut *self.lock.value.get() }
    }
}
impl<T> Drop for TicketGuard<'_, T> {
    fn drop(&mut self) { self.lock.serving.store(self.ticket.wrapping_add(1), Ordering::Release); }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};
    #[test]
    fn contended_publication_and_mutual_exclusion() {
        let lock = Arc::new(TicketLock::new(0u64));
        thread::scope(|s| {
            for _ in 0..8 {
                let lock = Arc::clone(&lock);
                s.spawn(move || { for _ in 0..4000 { *lock.lock() += 1; } });
            }
        });
        assert_eq!(*lock.lock(), 32000);
    }
    #[test]
    fn failed_try_lock_does_not_leave_queue_hole() {
        let lock = TicketLock::new(7);
        let guard = lock.lock();
        for _ in 0..100 { assert!(lock.try_lock().is_none()); }
        assert_eq!(lock.next.load(Ordering::Relaxed), 1);
        drop(guard);
        assert_eq!(*lock.try_lock().unwrap(), 7);
    }
    #[test]
    fn wraps_only_after_serving_existing_tickets() {
        let lock = TicketLock::new(0);
        lock.next.store(u32::MAX, Ordering::Relaxed);
        lock.serving.store(u32::MAX, Ordering::Relaxed);
        *lock.lock() = 5;
        assert_eq!(lock.next.load(Ordering::Relaxed), 0);
        assert_eq!(lock.serving.load(Ordering::Relaxed), 0);
        assert_eq!(*lock.try_lock().unwrap(), 5);
    }
    #[test]
    fn queued_tickets_cannot_be_bypassed_by_try_lock() {
        let lock = Arc::new(TicketLock::new(std::vec::Vec::new()));
        let holder = lock.lock();
        let mut workers = std::vec::Vec::new();
        for id in 0..4 {
            let c = Arc::clone(&lock);
            workers.push(thread::spawn(move || c.lock().push(id)));
            // Wait for ticket allocation, not a timing-based sleep.
            while lock.next.load(Ordering::Acquire) != id + 2 { thread::yield_now(); }
            assert!(lock.try_lock().is_none());
        }
        drop(holder);
        for w in workers { w.join().unwrap(); }
        assert_eq!(*lock.lock(), [0, 1, 2, 3]);
    }
}
