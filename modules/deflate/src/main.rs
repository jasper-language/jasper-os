//! jaso-deflate：miniz_oxide 的 `.jaso` 模块封装。
//! The miniz_oxide crate as a `.jaso` module.
//!
//! 输出缓冲由模块经宿主接口表分配，所有权交给调用者，用完以 `buffer_free(ptr, len)` 归还（不得用其它方式释放）。
//! miniz_oxide 内部的分配失败无法以返回值报告：宿主拒绝分配时模块 panic，所在进程被终止。
//!
//! | 导出 | 返回 |
//! |---|---|
//! | `zlib_compress(in, len, level, out_ptr, out_len)` | 0 成功；-1 参数非法 |
//! | `zlib_decompress(in, len, out_ptr, out_len)` | 0 成功；-2 数据损坏 |
//! | `inflate_raw(in, len, out_ptr, out_len)` | 同上（原始 DEFLATE 流，无 zlib 头尾） |
//! | `buffer_free(ptr, len)` | 归还上述函数交出的缓冲 |
#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use jaso_module as _;
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::{decompress_to_vec, decompress_to_vec_zlib};

/// 把结果的所有权交给调用者。
///
/// # Safety
/// `out_ptr` / `out_len` 可写。
unsafe fn hand_over(v: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    let b: Box<[u8]> = v.into_boxed_slice();
    *out_len = b.len();
    *out_ptr = Box::into_raw(b) as *mut u8;
    0
}

/// zlib 压缩（`level` 0–10）。
///
/// # Safety
/// `input` 可读 `len` 字节；`out_ptr` / `out_len` 可写。
#[no_mangle]
pub unsafe extern "C" fn zlib_compress(input: *const u8, len: usize, level: u32, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    if level > 10 {
        return -1;
    }
    let v = compress_to_vec_zlib(core::slice::from_raw_parts(input, len), level as u8);
    hand_over(v, out_ptr, out_len)
}

/// zlib 解压。
///
/// # Safety
/// `input` 可读 `len` 字节；`out_ptr` / `out_len` 可写。
#[no_mangle]
pub unsafe extern "C" fn zlib_decompress(input: *const u8, len: usize, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    match decompress_to_vec_zlib(core::slice::from_raw_parts(input, len)) {
        Ok(v) => hand_over(v, out_ptr, out_len),
        Err(_) => -2,
    }
}

/// 原始 DEFLATE 流解压。
///
/// # Safety
/// `input` 可读 `len` 字节；`out_ptr` / `out_len` 可写。
#[no_mangle]
pub unsafe extern "C" fn inflate_raw(input: *const u8, len: usize, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    match decompress_to_vec(core::slice::from_raw_parts(input, len)) {
        Ok(v) => hand_over(v, out_ptr, out_len),
        Err(_) => -2,
    }
}

/// 归还由本模块交出的缓冲。
///
/// # Safety
/// `(ptr, len)` 必须是本模块某个导出交出、且尚未归还的缓冲。
#[no_mangle]
pub unsafe extern "C" fn buffer_free(ptr: *mut u8, len: usize) {
    drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len)));
}
