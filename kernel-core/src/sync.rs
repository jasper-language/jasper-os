//! 同步原语：自旋锁与可移植的 64 位原子单元。
//!
//! # 职责
//! * [`SpinLock<T>`]：`AtomicBool` + `UnsafeCell` 的互斥锁，RAII 守卫解锁。
//! * [`Atomic64`]：64 位原子单元。有 64 位原子指令的目标（x86_64、AArch64、RISC-V64）直接用硬件原子；
//!   没有的目标（RISC-V32 等）用 [`LockedU64`]（自旋锁模拟）。两种实现接口相同，调用者不需要分情况。
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

/// 以自旋锁模拟的 64 位原子单元（用于没有 64 位原子指令的目标；任何目标上都可编译，便于宿主测试）。
///
/// **约束**：模拟依赖一把锁，因此同一个实例**不得在中断处理程序与被它中断的代码之间共享**——
/// 否则中断处理程序会在单 CPU 上自锁。在这类目标上，内核须用关中断的锁保护这样的共享，或改用单写者计数。
/// Spin-lock emulated 64-bit atomic for targets without native 64-bit atomics.
pub struct LockedU64 {
    v: SpinLock<u64>,
}

impl LockedU64 {
    /// 新建。
    pub const fn new(v: u64) -> Self {
        LockedU64 { v: SpinLock::new(v) }
    }
    /// 读取。
    pub fn load(&self, _o: Ordering) -> u64 {
        *self.v.lock()
    }
    /// 写入。
    pub fn store(&self, x: u64, _o: Ordering) {
        *self.v.lock() = x;
    }
    /// 加上 `x`（回绕），返回旧值。
    pub fn fetch_add(&self, x: u64, _o: Ordering) -> u64 {
        let mut g = self.v.lock();
        let old = *g;
        *g = old.wrapping_add(x);
        old
    }
    /// 若当前值为 `cur` 则写入 `new`；返回 `Ok(旧值)` 或 `Err(实际值)`。
    pub fn compare_exchange(&self, cur: u64, new: u64, _s: Ordering, _f: Ordering) -> Result<u64, u64> {
        let mut g = self.v.lock();
        if *g == cur {
            *g = new;
            Ok(cur)
        } else {
            Err(*g)
        }
    }
    /// 同 [`compare_exchange`](Self::compare_exchange)（模拟实现不会伪失败）。
    pub fn compare_exchange_weak(&self, cur: u64, new: u64, s: Ordering, f: Ordering) -> Result<u64, u64> {
        self.compare_exchange(cur, new, s, f)
    }
}

/// 本目标使用的 64 位原子单元（见模块文档）。
#[cfg(target_has_atomic = "64")]
pub type Atomic64 = core::sync::atomic::AtomicU64;
/// 本目标使用的 64 位原子单元（见模块文档；本目标没有 64 位原子指令，以自旋锁模拟）。
#[cfg(not(target_has_atomic = "64"))]
pub type Atomic64 = LockedU64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_u64_matches_native_semantics() {
        let a = LockedU64::new(u64::MAX - 1);
        assert_eq!(a.fetch_add(1, Ordering::Relaxed), u64::MAX - 1);
        assert_eq!(a.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(a.fetch_add(1, Ordering::Relaxed), u64::MAX, "与原生一样回绕");
        assert_eq!(a.load(Ordering::Relaxed), 0);
        assert_eq!(a.compare_exchange(1, 5, Ordering::AcqRel, Ordering::Relaxed), Err(0));
        assert_eq!(a.compare_exchange_weak(0, 5, Ordering::AcqRel, Ordering::Relaxed), Ok(0));
        a.store(9, Ordering::Relaxed);
        assert_eq!(a.load(Ordering::Relaxed), 9);
        // 多线程下 fetch_add 不丢更新
        use std::sync::Arc;
        let c = Arc::new(LockedU64::new(0));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(c.load(Ordering::Relaxed), 40_000);
    }

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
