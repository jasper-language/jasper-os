//! 用户态互斥锁：争用时让出处理器（`system.task.yield`）而不是空转。
//! A user-space mutex that yields the processor on contention.
//!
//! 持锁线程可能被时钟中断换下；等待者若空转会白白耗尽自己的时间片，让出则把处理器还给持锁者。

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{ids, sys};

/// 互斥锁。
pub struct Mutex<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY：数据只经持锁守卫访问，同一时刻至多一个线程持锁。
unsafe impl<T: Send> Sync for Mutex<T> {}
// SAFETY：同上。
unsafe impl<T: Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    /// 新建（未上锁）。
    pub const fn new(data: T) -> Self {
        Mutex { locked: AtomicBool::new(false), data: UnsafeCell::new(data) }
    }

    /// 上锁；争用时让出处理器后重试。
    pub fn lock(&self) -> MutexGuard<'_, T> {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            sys::call(ids::SYSTEM_TASK_YIELD, 0, 0, 0);
        }
        MutexGuard { lock: self }
    }
}

/// 持锁守卫：离开作用域即解锁。
pub struct MutexGuard<'a, T> {
    lock: &'a Mutex<T>,
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY：持锁期间独占访问。
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY：持锁期间独占访问。
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}
