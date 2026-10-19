//! 内核同步原语：在 `kernel-core` 的自旋锁之上加「关中断」这一层硬件语义。
//!
//! # 职责
//! * 重新导出 [`kernel_core::sync::SpinLock`]（纯机制，宿主已测）
//! * [`IrqSpinLock`]：加锁前保存并关闭中断，解锁后恢复——中断处理程序与任务共享的数据
//!   必须用它，否则单 CPU 上任务持锁时来一个中断去抢同一把锁就会永远自旋
//! * 全局锁以 [`IrqSpinLock::ranked`] 新建并在 `crate::lockorder` 登记级别：加锁时按本处理器的持有集合检查顺序，
//!   违反顺序即停机（多处理器下逆序加锁会死锁，宁可第一次运行就暴露）；局部锁用 [`IrqSpinLock::new`]，不参与顺序
//! * [`IrqU64`]：中断处理程序与任务可共享的 64 位计数单元——有 64 位原子指令的目标上是硬件原子，
//!   没有的目标（RISC-V32）上是「关中断 + 自旋锁」（`kernel_core::sync::IrqSafeU64`，屏蔽策略为 [`ArchIrqMask`]）。
//!   内核中凡是 64 位的共享计数一律用它，不直接用 `AtomicU64`（后者在 32 位目标上不存在）
//!
//! # 边界
//! 中断开关只经 `arch::irq_save_disable` / `arch::irq_restore`（Platform 契约），本文件不含 ISA 代码。

use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::lockorder::{HeldRanks, LockClass, LockOrderError};

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

/// 关中断自旋锁；全局锁以 [`IrqSpinLock::ranked`] 新建，加锁时按登记的级别检查顺序。
/// Interrupt-disabling spin lock, optionally ranked in the global lock order.
pub struct IrqSpinLock<T> {
    inner: SpinLock<T>,
    class: Option<LockClass>,
    contended: AtomicU32,
}

impl<T> IrqSpinLock<T> {
    /// 新建不登记顺序的局部锁（未加锁）。持有期间不得获取其他锁。
    /// Create an unranked, local lock.
    pub const fn new(data: T) -> Self {
        IrqSpinLock { inner: SpinLock::new(data), class: None, contended: AtomicU32::new(0) }
    }

    /// 新建登记了级别的全局锁（未加锁）；级别见 [`crate::lockorder`]。
    /// Create a lock ranked by `class`.
    pub const fn ranked(class: LockClass, data: T) -> Self {
        IrqSpinLock { inner: SpinLock::new(data), class: Some(class), contended: AtomicU32::new(0) }
    }

    /// 关中断并加锁；守卫析构时先解锁、再恢复进入前的中断状态。
    /// 登记了级别的锁若违反加锁顺序，打印双方名称后停机（这是内核缺陷，继续运行可能死锁）。
    /// Disable interrupts and lock; halts on a lock-order violation.
    pub fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let was_enabled = arch::irq_save_disable();
        if let Some(c) = self.class {
            if let Err(e) = held().acquire(c.rank) {
                order_violation(c, e);
            }
        }
        let guard = match self.inner.try_lock() {
            Some(g) => g,
            None => {
                self.contended.fetch_add(1, Ordering::Relaxed);
                self.inner.lock()
            }
        };
        IrqSpinLockGuard { guard: Some(guard), rank: self.class.map(|c| c.rank), was_enabled }
    }

    /// 先检查加锁顺序再加锁：顺序不合法时返回错误，不加锁、不改动持有集合、中断状态不变。
    /// Lock only if the order is legal; otherwise refuse without side effects.
    pub fn lock_checked(&self) -> Result<IrqSpinLockGuard<'_, T>, LockOrderError> {
        if let Some(c) = self.class {
            let was_enabled = arch::irq_save_disable();
            let r = held().check(c.rank);
            arch::irq_restore(was_enabled);
            r?;
        }
        Ok(self.lock())
    }

    /// 绕过顺序登记的尝试加锁：只给停机前的紧急输出使用（那时不能再因顺序问题停机）。
    /// Try-lock bypassing rank accounting; for emergency output only.
    pub fn try_lock_bypass(&self) -> Option<SpinLockGuard<'_, T>> {
        self.inner.try_lock()
    }

    /// 加锁时遇到占用（需要等待）的次数。
    /// Number of contended acquisitions.
    pub fn contended(&self) -> u32 {
        self.contended.load(Ordering::Relaxed)
    }

    /// 登记的锁类别（局部锁为 `None`）。
    /// Registered class.
    pub fn class(&self) -> Option<LockClass> {
        self.class
    }
}

/// 本处理器的锁持有集合。
fn held() -> &'static HeldRanks {
    crate::smp::percpu::this().held_locks()
}

/// 加锁顺序被违反：经紧急输出打印双方名称后停机。
#[cold]
fn order_violation(class: LockClass, e: LockOrderError) -> ! {
    let held = match e {
        LockOrderError::OutOfOrder { highest_held, .. } => crate::lockorder::name_of(highest_held),
        _ => "-",
    };
    crate::console::emergency_print(format_args!(
        "[JSR-LOCK-ORDER] {} acquiring={} rank={} highest_held={} cpu={}\n",
        e.name(),
        class.name,
        class.rank,
        held,
        arch::cpu_index()
    ));
    panic!("锁顺序违反");
}

/// [`IrqSpinLock`] 的守卫。
pub struct IrqSpinLockGuard<'a, T> {
    /// `Option` 只为在 `drop` 里先于恢复中断释放锁。
    guard: Option<SpinLockGuard<'a, T>>,
    rank: Option<u8>,
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
        if let Some(r) = self.rank {
            // 守卫只由加锁成功产生，级别必然已登记为持有；失败说明持有集合被破坏。
            if let Err(e) = held().release(r) {
                crate::console::emergency_print(format_args!("[JSR-LOCK-ORDER] {} rank={}\n", e.name(), r));
                panic!("锁持有集合不一致");
            }
        }
        arch::irq_restore(self.was_enabled);
    }
}
