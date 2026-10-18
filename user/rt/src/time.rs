//! 时间：读取单调时刻（时钟 tick）与同步等待。
//! Monotonic time in clock ticks.

use crate::error::{check, Result};
use crate::{ids, sys};

/// 当前时刻（自启动以来的时钟 tick 数）。
pub fn now() -> u64 {
    sys::call(ids::SYSTEM_TIME_NOW, 0, 0, 0).max(0) as u64
}

/// 让出处理器，直到时钟前进 `ticks` 个 tick。进程终止时提前以 `ASYNC_CANCELLED` 返回。
pub fn sleep(ticks: u64) -> Result<()> {
    check(sys::call(ids::SYSTEM_TIME_WAIT, ticks, 0, 0)).map(|_| ())
}
