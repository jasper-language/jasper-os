//! 匿名内存：在本进程私有窗口内映射 / 取消映射清零的匿名页。
//! Anonymous memory: map and unmap zeroed pages in the caller's private window.

use crate::error::{check, Result};
use crate::{ids, sys};

/// `system.memory.map` / `protect` 的标志：可写。
pub const WRITE: u64 = 1 << 0;
/// `system.memory.protect` 的标志：可执行（不能与 [`WRITE`] 同时使用）。
pub const EXEC: u64 = 1 << 1;

/// 从 `va`（页对齐）起映射 `pages` 个清零的匿名页；全有或全无。
/// 区间内已有映射 ⇒ `MEMORY_ALREADY_MAPPED`；超出进程帧配额 ⇒ `QUOTA_EXCEEDED`。
pub fn map(va: u64, pages: u64, flags: u64) -> Result<()> {
    check(sys::call(ids::SYSTEM_MEMORY_MAP, va, pages, flags)).map(|_| ())
}

/// 取消 `[va, va + pages 页)` 的映射；全有或全无（区间内有未映射的页 ⇒ `MEMORY_INVALID_ADDRESS`，不做任何改动）。
pub fn unmap(va: u64, pages: u64) -> Result<()> {
    check(sys::call(ids::SYSTEM_MEMORY_UNMAP, va, pages, 0)).map(|_| ())
}

/// 修改 `[va, va + pages 页)` 的权限：`flags` 为 0（只读）、[`WRITE`] 或 [`EXEC`]；
/// `WRITE | EXEC` ⇒ `INVALID_ARGUMENT`（W^X）。全有或全无。
pub fn protect(va: u64, pages: u64, flags: u64) -> Result<()> {
    check(sys::call(ids::SYSTEM_MEMORY_PROTECT, va, pages, flags)).map(|_| ())
}
