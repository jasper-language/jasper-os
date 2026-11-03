//! jaso-l1demo：L1 生命周期验收模块。
//! Lifecycle acceptance module for the L1 loader.
//!
//! `jaso_init` 由 `jaso-module` 提供；`jaso_start` / `jaso_stop` 经宿主接口表各输出一行并记录阶段；
//! `l1_fail` 恒返回 7，验收程序把它改名为 `jaso_start` 造出「启动失败」的变体。
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use jaso_module::log;

/// 0 = 已初始化，1 = 已启动，2 = 已停止。
static STATE: AtomicU32 = AtomicU32::new(0);

/// 启动。返回 0 表示成功。
#[no_mangle]
pub extern "C" fn jaso_start() -> i32 {
    STATE.store(1, Ordering::Release);
    log("jaso-l1: started");
    0
}

/// 停止。返回 0 表示成功。
#[no_mangle]
pub extern "C" fn jaso_stop() -> i32 {
    STATE.store(2, Ordering::Release);
    log("jaso-l1: stopped");
    0
}

/// 回绕加法。
#[no_mangle]
pub extern "C" fn l1_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// 恒返回 7。
#[no_mangle]
pub extern "C" fn l1_fail() -> i32 {
    7
}

/// 当前阶段。
#[no_mangle]
pub extern "C" fn l1_state() -> u32 {
    STATE.load(Ordering::Acquire)
}
