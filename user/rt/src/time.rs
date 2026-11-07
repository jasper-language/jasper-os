//! 时间：读取单调时刻（时钟 tick）、周期计数器与同步等待。
//! Monotonic time in clock ticks, plus the raw cycle counter.

use crate::error::{check, Result};
use crate::handle::Handle;
use crate::{ids, sys};

/// 当前时刻（自启动以来的时钟 tick 数）。
pub fn now() -> u64 {
    sys::call(ids::SYSTEM_TIME_NOW, 0, 0, 0).max(0) as u64
}

/// 让出处理器，直到时钟前进 `ticks` 个 tick。进程终止时提前以 `ASYNC_CANCELLED` 返回。
pub fn sleep(ticks: u64) -> Result<()> {
    check(sys::call(ids::SYSTEM_TIME_WAIT, ticks, 0, 0)).map(|_| ())
}

/// 当前单调整数纳秒。 / Current monotonic nanoseconds.
pub fn monotonic_ns() -> Result<u64> {
    check(sys::call(ids::SYSTEM_TIME_DEADLINE_GET, 0, 0, 0))
}

/// 周期计数器读数（单调递增；用于测量短操作的耗时，与 tick 的换算关系由内核侧校准给出）。
/// Raw cycle counter, for timing short operations.
pub fn cycles() -> u64 {
    sys::cycles()
}

/// 用户可见定时器对象。
///
/// `period_ns=0` 为一次性；非零为固定周期。`slack_ns>0` 允许内核在
/// `[deadline, deadline+slack]` 内合并处理，`0` 为精确期限。
/// A user-visible one-shot or fixed-period timer object.
pub struct Timer {
    handle: Handle,
}

impl Timer {
    /// 创建一次性精确定时器。 / Create a precise one-shot timer.
    pub fn one_shot() -> Result<Self> { Self::create(0, 0) }

    /// 创建允许 `slack_ns` 合并窗口的一次性定时器。 / Create a coalescible one-shot timer.
    pub fn one_shot_with_slack(slack_ns: u64) -> Result<Self> { Self::create(0, slack_ns) }

    /// 创建固定周期、可带容差的定时器。 / Create a periodic timer with optional slack.
    pub fn periodic(period_ns: u64, slack_ns: u64) -> Result<Self> {
        if period_ns == 0 { return Err(crate::Error::INVALID_ARGUMENT); }
        Self::create(period_ns, slack_ns)
    }

    fn create(period_ns: u64, slack_ns: u64) -> Result<Self> {
        let raw = check(sys::call(ids::SYSTEM_TIME_TIMER_CREATE, period_ns, slack_ns, 0))?;
        // SAFETY: create returned a fresh handle owned by the current process.
        Ok(Self { handle: unsafe { Handle::from_raw(raw) } })
    }

    /// 从当前时刻起装填。 / Arm relative to now.
    pub fn arm_after(&self, after_ns: u64) -> Result<()> {
        check(sys::call(ids::SYSTEM_TIME_TIMER_ARM, self.handle.raw(), after_ns, 0)).map(|_| ())
    }

    /// 按单调绝对纳秒时刻装填。 / Arm at an absolute monotonic nanosecond instant.
    pub fn arm_at(&self, at_ns: u64) -> Result<()> {
        check(sys::call(ids::SYSTEM_TIME_TIMER_ARM, self.handle.raw(), at_ns, 1)).map(|_| ())
    }

    /// 取消当前装填；返回此前是否已装填。 / Cancel; returns whether a request was armed.
    pub fn cancel(&self) -> Result<bool> {
        Ok(check(sys::call(ids::SYSTEM_TIME_TIMER_CANCEL, self.handle.raw(), 0, 0))? != 0)
    }

    /// 等待下一次到期。周期定时器返回后会自动推进到下一周期。
    /// Wait for the next expiry; periodic timers advance automatically.
    pub fn wait(&self) -> Result<()> {
        check(sys::call(ids::SYSTEM_TIME_TIMER_WAIT, self.handle.raw(), 0, 0)).map(|_| ())
    }

    /// 查询距离当前请求最晚可处理时刻的剩余纳秒。 / Remaining nanoseconds to the latest acceptable instant.
    pub fn remaining(&self) -> Result<u64> {
        check(sys::call(ids::SYSTEM_TIME_TIMER_GET, self.handle.raw(), 0, 0))
    }

    /// 底层句柄。 / Underlying handle.
    pub fn handle(&self) -> &Handle { &self.handle }

    /// 放弃定时器包装并保留底层句柄。 / Unwrap while preserving the underlying handle.
    pub fn into_handle(self) -> Handle { self.handle }
}
