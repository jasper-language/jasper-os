//! 用户态互斥锁：争用时让出处理器（`system.task.yield`）而不是空转。
//! A user-space mutex that yields the processor on contention.
//!
//! 持锁线程可能被时钟中断换下；等待者若空转会白白耗尽自己的时间片，让出则把处理器还给持锁者。

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::error::{check, Error, Result};
use crate::handle::Handle;
use crate::{ids, sys};

/// 内核提供的优先级继承互斥对象句柄。
///
/// `try_lock` 使用登记表中的高编号操作 `system.sync.mutex.try.acquire`（ID 64）。
/// 本类型只持有既有 Mutex 句柄；授权仍由任务现有的 `SyscallSet` 统一判定。
/// Handle to a kernel priority-inheriting mutex; no separate authorization channel.
pub struct PriorityMutex {
    handle: Handle,
}

impl PriorityMutex {
    /// 创建未持有的互斥对象。
    /// Creates an unheld kernel mutex.
    pub fn create() -> Result<Self> {
        let raw = check(sys::call(ids::SYSTEM_SYNC_MUTEX_CREATE, 0, 0, 0))?;
        // SAFETY：内核刚把新句柄放入本进程句柄表，尚无人拥有。
        Ok(Self { handle: unsafe { Handle::from_raw(raw) } })
    }

    /// 底层句柄。
    /// Underlying handle.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// 尝试取得互斥对象；成功返回 `true`，已被其他活动任务持有时返回 `false`。
    ///
    /// 递归取得、关闭对象和句柄错误仍返回明确错误，不会把故障伪装成普通争用。
    /// Attempts one non-blocking acquisition; live contention is reported as `Ok(false)`.
    pub fn try_lock(&self) -> Result<bool> {
        let ret = sys::call(ids::SYSTEM_SYNC_MUTEX_TRY_ACQUIRE, self.handle.raw(), 0, 0);
        if ret >= 0 {
            return Ok(true);
        }
        let error = Error(ret.unsigned_abs());
        if error == Error::SYNC_BUSY {
            Ok(false)
        } else {
            Err(error)
        }
    }

    /// 阻塞取得互斥对象，并继承当前持有者的有效服务质量。
    /// Acquires the mutex, preserving the kernel's priority-inheritance behavior.
    pub fn lock(&self) -> Result<()> {
        check(sys::call(ids::SYSTEM_SYNC_MUTEX_ACQUIRE, self.handle.raw(), 0, 0)).map(|_| ())
    }

    /// 释放调用线程持有的互斥对象。
    /// Releases the mutex held by the calling thread.
    pub fn unlock(&self) -> Result<()> {
        check(sys::call(ids::SYSTEM_SYNC_MUTEX_RELEASE, self.handle.raw(), 0, 0)).map(|_| ())
    }
}

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
