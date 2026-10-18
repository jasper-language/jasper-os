//! 会阻塞的内核锁（turnstile 式优先级继承）。
//! A blocking kernel mutex with turnstile-style priority inheritance.
//!
//! # 职责
//! [`KMutex`] 用于可能持有较久（跨越时钟中断、期间可被抢占）的内核临界区：
//! * 拿不到锁的任务**阻塞**而不是自旋，处理器交给别的任务；
//! * 阻塞期间把自己的有效档位借给持有者（沿等待链传递）——低档持有者不会被中档任务挡住，
//!   高档等待者的等待时长只取决于持有者剩余的临界区；
//! * 放锁时**直接交接**给有效档位最高（同档先来先得）的等待者，并在它比自己优先时立即让出，
//!   借来的档位同时归还。
//!
//! # 边界
//! 等待关系与有效档位由调度机制维护（`Scheduler::block_on` / `hand_off`），本文件只实现锁的状态机。
//! 关中断自旋锁（`IrqSpinLock`）仍用于中断处理程序与任务共享、且极短的临界区；中断上下文不得使用 `KMutex`。
//!
//! # 失败与恢复
//! * 递归加锁、成环（死锁）与过长的等待链在阻塞**之前**被拒绝，锁与调度器状态都不变。
//! * 持有者未放锁就退出：等待者全部被唤醒，第一个重新尝试的任务接管这把锁（锁内数据保持持有者退出时的样子）。

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

use super::scheduler::{BlockError, Cause};
use crate::arch as cpu;
use crate::task::TaskId;

/// 锁空闲时 `owner` 的取值。
const FREE: u64 = u64::MAX;

/// 会阻塞、带优先级继承的内核锁。
/// Blocking kernel mutex with priority inheritance and direct hand-off.
pub struct KMutex<T> {
    /// 持有者的任务号（[`FREE`] = 空闲）。只在关中断状态下读写（单 CPU）。
    owner: AtomicU64,
    data: UnsafeCell<T>,
}

// SAFETY：对 `data` 的访问只经守卫，而守卫只由持有者得到；`owner` 的修改都在关中断临界区内完成。
unsafe impl<T: Send> Sync for KMutex<T> {}
// SAFETY：同上，锁本身只是数据加一个持有者标识。
unsafe impl<T: Send> Send for KMutex<T> {}

impl<T> KMutex<T> {
    /// 新建（空闲）。
    pub const fn new(data: T) -> Self {
        KMutex { owner: AtomicU64::new(FREE), data: UnsafeCell::new(data) }
    }

    /// 等待对象的标识：锁自身的地址（按字对齐，不会与「等任务退出」的标识重合）。
    fn key(&self) -> u64 {
        self as *const Self as usize as u64
    }

    /// 当前持有者（空闲时 `None`；诊断与验收用）。
    pub fn owner(&self) -> Option<TaskId> {
        match self.owner.load(Ordering::Relaxed) {
            FREE => None,
            id => Some(TaskId(id)),
        }
    }

    /// 加锁：空闲则立即拿到；被占用则阻塞并把有效档位借给持有者，直到持有者交接或退出。
    ///
    /// 已持有这把锁（递归）、或阻塞会成环 / 等待链过长时返回错误，锁与调度器状态都不变。
    /// 在引导线程上锁被占用时不阻塞：让出并休眠到下一个中断后重试。
    /// Locks, blocking (and lending priority to the holder) while contended.
    pub fn lock(&self) -> Result<KMutexGuard<'_, T>, BlockError> {
        let key = self.key();
        let mut blocked = false;
        loop {
            let was_enabled = cpu::irq_save_disable();
            let step = super::with_mut(|s| {
                let me = s.current().0;
                match self.owner.load(Ordering::Relaxed) {
                    // 空闲，或持有者已退出（未放锁）：接管。
                    o if o == FREE || !s.is_live(TaskId(o)) => {
                        self.owner.store(me.0, Ordering::Relaxed);
                        Ok(Step::Acquired)
                    }
                    // 阻塞之后醒来发现锁已交接给自己。
                    o if o == me.0 && blocked => Ok(Step::Acquired),
                    // 第一次尝试就发现自己持有：递归加锁。
                    o if o == me.0 => Err(BlockError::Refused(super::policy::inherit::EdgeError::SelfWait)),
                    _ if s.on_boot() => Ok(Step::Retry),
                    o => s.block_on(TaskId(o), key).map(|_| Step::Blocked),
                }
            });
            match step {
                Ok(Step::Acquired) => {
                    cpu::irq_restore(was_enabled);
                    return Ok(KMutexGuard { lock: self });
                }
                Ok(Step::Blocked) => {
                    blocked = true;
                    super::yield_with_cause(Cause::BLOCK);
                }
                Ok(Step::Retry) => {
                    super::yield_now();
                    cpu::wait_for_interrupt();
                }
                Err(e) => {
                    cpu::irq_restore(was_enabled);
                    return Err(e);
                }
            }
            cpu::irq_restore(was_enabled);
        }
    }

    /// 放锁：交接给最优先的等待者（没有则置空闲），归还借来的档位；有更优先的任务可运行且抢占开启时立即让出。
    fn unlock(&self) {
        let was_enabled = cpu::irq_save_disable();
        let outranked = super::with_mut(|s| {
            let next = s.hand_off(self.key());
            self.owner.store(next.map(|t| t.0).unwrap_or(FREE), Ordering::Relaxed);
            s.outranked()
        });
        if outranked && super::PREEMPTION.load(Ordering::Relaxed) {
            super::yield_with_cause(Cause::PREEMPT);
        }
        cpu::irq_restore(was_enabled);
    }
}

/// 加锁循环的一步。
enum Step {
    Acquired,
    Blocked,
    Retry,
}

/// [`KMutex`] 的守卫：析构时放锁并交接。
/// Guard of a [`KMutex`]; unlocks and hands off on drop.
pub struct KMutexGuard<'a, T> {
    lock: &'a KMutex<T>,
}

impl<T> Deref for KMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY：守卫存在 ⇔ 当前任务持有这把锁，没有其他访问者。
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for KMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY：同上。
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for KMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}
