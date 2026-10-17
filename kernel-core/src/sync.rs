//! 同步原语：自旋锁。
//!
//! # 职责
//! [`SpinLock<T>`]：`AtomicBool` + `UnsafeCell` 的互斥锁，RAII 守卫解锁。
//!
//! # 边界（为什么关中断版本不在这里）
//! 「加锁时关中断」需要读写 CPU 中断标志，是 ISA 相关操作；本 crate 不碰硬件。
//! 内核在 `kernel/src/sync.rs` 中用 `arch::irq_save_disable/irq_restore` 包一层得到
//! `IrqSpinLock`（中断处理程序与任务共享数据时必须用它，否则单 CPU 上也会自锁）。

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// 自旋互斥锁。
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY：锁保证同一时刻只有一个守卫能访问 `data`；跨线程转移 `T` 要求 `T: Send`。
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// 新建（未加锁）。
    pub const fn new(data: T) -> Self {
        SpinLock { locked: AtomicBool::new(false), data: UnsafeCell::new(data) }
    }

    /// 加锁（忙等直到成功）。
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        loop {
            if let Some(g) = self.try_lock() {
                return g;
            }
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    /// 尝试加锁一次；已被占用则返回 `None`。
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }

    /// 是否已被占用（仅供诊断，结果可能立刻过时）。
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

/// 锁守卫：存活期间独占访问数据，析构时解锁。
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY：持有守卫即持有锁。
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY：持有守卫即持有锁，且 `&mut self` 保证守卫本身未被共享。
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_unlocks_on_drop() {
        let l = SpinLock::new(1);
        {
            let mut g = l.lock();
            *g += 1;
            assert!(l.try_lock().is_none(), "持锁期间不能再次加锁");
        }
        assert!(!l.is_locked());
        assert_eq!(*l.lock(), 2);
    }

    #[test]
    fn mutual_exclusion_across_threads() {
        use std::sync::Arc;
        let l = Arc::new(SpinLock::new(0u64));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let l = l.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        *l.lock() += 1;
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(*l.lock(), 40_000);
    }
}
