//! 错误类型：系统调用失败时返回的登记表错误 ID。
//! Error type: the registered error ID a failed system call returned.

use core::fmt;

/// 一个系统接口错误（登记表中 `error` 种类条目的 ID）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub u64);

/// 运行时的结果类型。
pub type Result<T> = core::result::Result<T, Error>;

include!(concat!(env!("OUT_DIR"), "/errors.rs"));

impl Error {
    /// 错误 ID。
    pub const fn id(self) -> u64 {
        self.0
    }

    /// 规范名（如 `system.handle.error.invalid`）；未登记的 ID 返回 `"unregistered"`。
    pub fn name(self) -> &'static str {
        error_name(self.0).unwrap_or("unregistered")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name(), self.0)
    }
}

/// 把系统调用返回值转换为结果：非负 = 成功值；负数 = `-(错误 ID)`。
pub fn check(ret: i64) -> Result<u64> {
    if ret >= 0 {
        Ok(ret as u64)
    } else {
        Err(Error(ret.unsigned_abs()))
    }
}
