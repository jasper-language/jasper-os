//! 内核同步原语：在 `kernel-core` 的自旋锁之上加「关中断」这一层硬件语义。
//!
//! # 职责
//! * 重新导出 [`kernel_core::sync::SpinLock`]（纯机制，宿主已测）
//! * [`IrqSpinLock`]：加锁前保存并关闭中断，解锁后恢复——中断处理程序与任务共享的数据
//!   必须用它，否则单 CPU 上任务持锁时来一个中断去抢同一把锁就会永远自旋
//! * [`IrqU64`]：中断处理程序与任务可共享的 64 位计数单元——有 64 位原子指令的目标上是硬件原子，
//!   没有的目标（RISC-V32）上是「关中断 + 自旋锁」（`kernel_core::sync::IrqSafeU64`，屏蔽策略为 [`ArchIrqMask`]）。
//!   内核中凡是 64 位的共享计数一律用它，不直接用 `AtomicU64`（后者在 32 位目标上不存在）
//!
//! # 边界
//! 中断开关只经 `arch::irq_save_disable` / `arch::irq_restore`（Platform 契约），本文件不含 ISA 代码。

use core::ops::{Deref, DerefMut};

use crate::arch;
pub use kernel_core::sync::{SpinLock, SpinLockGuard};

/// 经平台契约关 / 开本处理器中断的屏蔽策略。
/// Interrupt-mask strategy backed by the platform contract.
pub struct ArchIrqMask;

impl kernel_core::sync::IrqMask for ArchIrqMask {
    #[inline(always)]
    fn save_disable() -> bool {
        arch::irq_save_disable()
    }
    #[inline(always)]
    fn restore(was_enabled: bool) {
        arch::irq_restore(was_enabled)
    }
}

/// 中断安全的 64 位计数单元（见模块文档）。
/// Interrupt-safe 64-bit counter cell.
pub type IrqU64 = kernel_core::sync::IrqSafeU64<ArchIrqMask>;

/// 关中断自旋锁。
pub struct IrqSpinLock<T> {
    inner: SpinLock<T>,
}

impl<T> IrqSpinLock<T> {
    /// 新建（未加锁）。
    pub const fn new(data: T) -> Self {
        IrqSpinLock { inner: SpinLock::new(data) }
    }

    /// 关中断并加锁；守卫析构时先解锁、再恢复进入前的中断状态。
    pub fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let was_enabled = arch::irq_save_disable();
        IrqSpinLockGuard { guard: Some(self.inner.lock()), was_enabled }
    }
}

/// [`IrqSpinLock`] 的守卫。
pub struct IrqSpinLockGuard<'a, T> {
    /// `Option` 只为在 `drop` 里先于恢复中断释放锁。
    guard: Option<SpinLockGuard<'a, T>>,
    was_enabled: bool,
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().expect("守卫已释放")
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().expect("守卫已释放")
    }
}

impl<T> Drop for IrqSpinLockGuard<'_, T> {
    fn drop(&mut self) {
        // 顺序很重要：先解锁，再开中断；反过来的话中断可能在解锁前进来抢同一把锁。
        self.guard.take();
        arch::irq_restore(self.was_enabled);
    }
}
