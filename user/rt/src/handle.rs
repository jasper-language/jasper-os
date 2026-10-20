//! 句柄：本进程句柄表中的一项。[`Handle`] 离开作用域即关闭（释放其外部所有权）。
//! Handles with RAII close.

use core::mem::ManuallyDrop;

use kernel_core::object::Rights;

use crate::error::{check, Result};
use crate::{ids, sys};

/// 一个句柄（拥有者负责关闭）。
#[derive(Debug, PartialEq, Eq)]
pub struct Handle(u64);

impl Handle {
    /// 接管一个原始句柄值。
    ///
    /// # Safety
    /// `raw` 必须是本进程句柄表中、尚无其他 [`Handle`] 拥有的句柄：否则会被关闭两次或关错对象。
    pub const unsafe fn from_raw(raw: u64) -> Handle {
        Handle(raw)
    }

    /// 原始句柄值（所有权不变）。
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// 放弃所有权并返回原始值（不再自动关闭）。
    pub fn into_raw(self) -> u64 {
        ManuallyDrop::new(self).0
    }

    /// 复制出一个权限不高于 `rights` 的新句柄（需要 DUPLICATE 权限；只可降权）。
    pub fn duplicate(&self, rights: Rights) -> Result<Handle> {
        let raw = check(sys::call(ids::SYSTEM_HANDLE_DUPLICATE, self.0 as u64, rights.bits() as u64, 0))?;
        // SAFETY：内核刚为本进程放入的新句柄，尚无人拥有。
        Ok(unsafe { Handle::from_raw(raw) })
    }

    /// 把本句柄的权限降为 `rights`（只能去掉权限，不能增加）。
    pub fn restrict(&self, rights: Rights) -> Result<()> {
        check(sys::call(ids::SYSTEM_HANDLE_RESTRICT, self.0 as u64, rights.bits() as u64, 0)).map(|_| ())
    }

    /// 显式关闭并取回结果（`drop` 会丢弃关闭的结果）。
    pub fn close(self) -> Result<()> {
        let raw = self.into_raw();
        check(sys::call(ids::SYSTEM_HANDLE_CLOSE, raw as u64, 0, 0)).map(|_| ())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = sys::call(ids::SYSTEM_HANDLE_CLOSE, self.0 as u64, 0, 0);
    }
}
