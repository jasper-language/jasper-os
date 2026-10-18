//! jaso-sha2：sha2 的 `.jaso` 模块封装（纯软件后端）。
//! The sha2 crate as a `.jaso` module.
//!
//! | 导出 | 说明 |
//! |---|---|
//! | `sha256(data, len, out)` | 把 `[data, data+len)` 的 SHA-256 写入 `out`（32 字节），返回 0 |
//! | `sha512(data, len, out)` | 同上，SHA-512（64 字节） |
#![no_std]
#![no_main]

use jaso_module as _;
use sha2::{Digest, Sha256, Sha512};

/// SHA-256。
///
/// # Safety
/// `data` 可读 `len` 字节；`out` 可写 32 字节。
#[no_mangle]
pub unsafe extern "C" fn sha256(data: *const u8, len: usize, out: *mut u8) -> i32 {
    let d = Sha256::digest(core::slice::from_raw_parts(data, len));
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, 32);
    0
}

/// SHA-512。
///
/// # Safety
/// `data` 可读 `len` 字节；`out` 可写 64 字节。
#[no_mangle]
pub unsafe extern "C" fn sha512(data: *const u8, len: usize, out: *mut u8) -> i32 {
    let d = Sha512::digest(core::slice::from_raw_parts(data, len));
    core::ptr::copy_nonoverlapping(d.as_ptr(), out, 64);
    0
}
