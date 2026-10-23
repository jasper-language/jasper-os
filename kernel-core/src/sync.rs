//! 同步原语：自旋锁与可移植的 64 位原子单元。
//!
//! # 职责
//! * [`SpinLock<T>`]：`AtomicBool` + `UnsafeCell` 的互斥锁，RAII 守卫解锁。
//! * [`Atomic64`]：64 位原子单元。有 64 位原子指令的目标（x86_64、AArch64、RISC-V64）直接用硬件原子；
//!   没有的目标（RISC-V32 等）用 [`LockedU64`]（自旋锁模拟）。两种实现接口相同，调用者不需要分情况。
//! * [`IrqSafeU64`]：**中断处理程序与任务之间可共享**的 64 位单元（时钟 tick 等由中断递增的计数）。
//!   有 64 位原子指令时同样直接用硬件原子；没有时用 [`IrqLockedU64`]：先经 [`IrqMask`] 关本处理器的中断、
//!   再取自旋锁——持锁期间本处理器不会被中断，中断处理程序就不会在同一处理器上自锁；其他处理器只需等一个极短的临界区，
//!   因此多核下同样正确（没有全局串行的大锁，每个计数各自一把锁）。
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
            .map(|_| SpinLockGuard { lock: self, _borrow: core::marker::PhantomData })
    }

    /// 是否已被占用（仅供诊断，结果可能立刻过时）。
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

/// 锁守卫：存活期间独占访问数据，析构时解锁。
/// Author: chatgpt. A guard may not share a !Sync payload across threads.
/// ```compile_fail
/// use kernel_core::sync::SpinLockGuard;
/// fn require_sync<T: Sync>() {}
/// require_sync::<SpinLockGuard<'static, core::cell::Cell<u8>>>();
/// ```
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    _borrow: core::marker::PhantomData<&'a mut T>,
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

/// 中断屏蔽策略：关闭本处理器的中断并返回之前是否开着、按返回值恢复。由内核按指令集提供（本 crate 不碰硬件）。
/// Strategy for masking interrupts on the current processor (provided by the kernel per ISA).
pub trait IrqMask {
    /// 关中断，返回之前是否开着。
    fn save_disable() -> bool;
    /// 按 [`IrqMask::save_disable`] 的返回值恢复。
    fn restore(was_enabled: bool);
}

/// 「关中断 + 自旋锁」实现的 64 位单元：中断处理程序与任务可以共享（见模块文档）。任何目标上都可编译，便于宿主测试。
/// 64-bit cell guarded by interrupt masking plus a spin lock; safe to share with interrupt handlers.
pub struct IrqLockedU64<M: IrqMask> {
    cell: SpinLock<u64>,
    _mask: core::marker::PhantomData<fn() -> M>,
}

impl<M: IrqMask> IrqLockedU64<M> {
    /// 新建。
    pub const fn new(v: u64) -> Self {
        IrqLockedU64 { cell: SpinLock::new(v), _mask: core::marker::PhantomData }
    }
    /// 关中断、持锁执行 `f`，然后先解锁再恢复中断（顺序保证中断不会在解锁前进来抢同一把锁）。
    fn with<R>(&self, f: impl FnOnce(&mut u64) -> R) -> R {
        let was = M::save_disable();
        let r = {
            let mut g = self.cell.lock();
            f(&mut g)
        };
        M::restore(was);
        r
    }
    /// 读取。
    pub fn load(&self, _o: Ordering) -> u64 {
        self.with(|v| *v)
    }
    /// 写入。
    pub fn store(&self, x: u64, _o: Ordering) {
        self.with(|v| *v = x)
    }
    /// 加上 `x`（回绕），返回旧值。
    pub fn fetch_add(&self, x: u64, _o: Ordering) -> u64 {
        self.with(|v| core::mem::replace(v, v.wrapping_add(x)))
    }
    /// 减去 `x`（回绕），返回旧值。
    pub fn fetch_sub(&self, x: u64, _o: Ordering) -> u64 {
        self.with(|v| core::mem::replace(v, v.wrapping_sub(x)))
    }
    /// 取当前值与 `x` 的较大者写入，返回旧值。
    pub fn fetch_max(&self, x: u64, _o: Ordering) -> u64 {
        self.with(|v| core::mem::replace(v, (*v).max(x)))
    }
    /// 写入 `x`，返回旧值（取走并清零窗口计数一类用途）。
    /// Store `x` and return the previous value.
    pub fn swap(&self, x: u64, _o: Ordering) -> u64 {
        self.with(|v| core::mem::replace(v, x))
    }
}

/// 中断安全的 64 位单元（见模块文档）：有 64 位原子指令时为硬件原子，否则为 [`IrqLockedU64`]。
/// Interrupt-safe 64-bit cell: native atomics where available, otherwise [`IrqLockedU64`].
#[cfg(target_has_atomic = "64")]
pub type IrqSafeU64<M> = NativeU64<M>;
/// 中断安全的 64 位单元（见模块文档；本目标没有 64 位原子指令，以「关中断 + 自旋锁」实现）。
#[cfg(not(target_has_atomic = "64"))]
pub type IrqSafeU64<M> = IrqLockedU64<M>;

/// 硬件 64 位原子的薄包装：与 [`IrqLockedU64`] 接口相同（屏蔽策略参数只为统一类型，不使用）。
/// Thin wrapper over a native 64-bit atomic with the same interface as [`IrqLockedU64`].
#[cfg(target_has_atomic = "64")]
pub struct NativeU64<M: IrqMask> {
    v: core::sync::atomic::AtomicU64,
    _mask: core::marker::PhantomData<fn() -> M>,
}

#[cfg(target_has_atomic = "64")]
impl<M: IrqMask> NativeU64<M> {
    /// 新建。
    pub const fn new(v: u64) -> Self {
        NativeU64 { v: core::sync::atomic::AtomicU64::new(v), _mask: core::marker::PhantomData }
    }
    /// 读取。
    pub fn load(&self, o: Ordering) -> u64 {
        self.v.load(o)
    }
    /// 写入。
    pub fn store(&self, x: u64, o: Ordering) {
        self.v.store(x, o)
    }
    /// 加上 `x`（回绕），返回旧值。
    pub fn fetch_add(&self, x: u64, o: Ordering) -> u64 {
        self.v.fetch_add(x, o)
    }
    /// 减去 `x`（回绕），返回旧值。
    pub fn fetch_sub(&self, x: u64, o: Ordering) -> u64 {
        self.v.fetch_sub(x, o)
    }
    /// 取当前值与 `x` 的较大者写入，返回旧值。
    pub fn fetch_max(&self, x: u64, o: Ordering) -> u64 {
        self.v.fetch_max(x, o)
    }
    /// 写入 `x`，返回旧值。
    /// Store `x` and return the previous value.
    pub fn swap(&self, x: u64, o: Ordering) -> u64 {
        self.v.swap(x, o)
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

    use std::cell::Cell;

    std::thread_local! {
        /// 模拟的「本处理器中断开关」（每个测试线程一份）。
        static IRQ_ON: Cell<bool> = const { Cell::new(true) };
    }

    /// 测试用屏蔽策略：记录开关状态。
    struct MockMask;
    impl IrqMask for MockMask {
        fn save_disable() -> bool {
            IRQ_ON.with(|c| c.replace(false))
        }
        fn restore(was: bool) {
            IRQ_ON.with(|c| c.set(was));
        }
    }

    #[test]
    fn irq_locked_u64_masks_and_restores() {
        let c: IrqLockedU64<MockMask> = IrqLockedU64::new(u64::MAX);
        assert!(IRQ_ON.with(|x| x.get()));
        // 临界区内中断关闭；结束后恢复为进入前的状态（开）
        let inside = c.with(|_| IRQ_ON.with(|x| x.get()));
        assert!(!inside, "持锁期间中断必须关闭");
        assert!(IRQ_ON.with(|x| x.get()), "结束后恢复为开");
        // 进入前已关（例如在中断处理程序里）⇒ 结束后仍关，不得被误开
        IRQ_ON.with(|x| x.set(false));
        assert_eq!(c.fetch_add(1, Ordering::Relaxed), u64::MAX);
        assert!(!IRQ_ON.with(|x| x.get()), "进入前关着 ⇒ 结束后仍关着");
        IRQ_ON.with(|x| x.set(true));
        // 与原生原子相同的语义：回绕、fetch_sub、fetch_max（较小值不改动）
        assert_eq!(c.load(Ordering::Relaxed), 0, "与原生一样回绕");
        assert_eq!(c.fetch_sub(1, Ordering::Relaxed), 0);
        assert_eq!(c.load(Ordering::Relaxed), u64::MAX);
        c.store(10, Ordering::Relaxed);
        assert_eq!(c.fetch_max(3, Ordering::Relaxed), 10);
        assert_eq!(c.load(Ordering::Relaxed), 10, "较小值不改动");
        assert_eq!(c.fetch_max(1 << 40, Ordering::Relaxed), 10);
        assert_eq!(c.load(Ordering::Relaxed), 1 << 40, "超过 32 位的值完整保存");
        assert!(!c.cell.is_locked(), "每次操作后锁都已释放");
    }

    #[test]
    fn irq_locked_u64_no_lost_updates_across_threads() {
        use std::sync::Arc;
        let c: Arc<IrqLockedU64<MockMask>> = Arc::new(IrqLockedU64::new(0));
        let hs: Vec<_> = (0..4)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                    IRQ_ON.with(|x| x.get())
                })
            })
            .collect();
        for h in hs {
            assert!(h.join().unwrap(), "每个线程结束时中断状态已恢复");
        }
        assert_eq!(c.load(Ordering::Relaxed), 40_000);
    }

    #[test]
    fn native_u64_matches_locked_semantics() {
        let n: IrqSafeU64<MockMask> = IrqSafeU64::new(u64::MAX);
        assert_eq!(n.fetch_add(1, Ordering::Relaxed), u64::MAX);
        assert_eq!(n.fetch_sub(1, Ordering::Relaxed), 0);
        assert_eq!(n.fetch_max(5, Ordering::Relaxed), u64::MAX);
        n.store(7, Ordering::Relaxed);
        assert_eq!(n.load(Ordering::Relaxed), 7);
        assert_eq!(n.swap(0, Ordering::Relaxed), 7);
        assert_eq!(n.load(Ordering::Relaxed), 0);
        // 无 64 位原子目标上的实现：语义相同
        let l: IrqLockedU64<MockMask> = IrqLockedU64::new(9);
        assert_eq!(l.swap(3, Ordering::Relaxed), 9);
        assert_eq!(l.load(Ordering::Relaxed), 3);
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
