//! jasper-rt：jasper-os 用户态最小运行时。
//! Minimal user-space runtime for jasper-os (`no_std` + `alloc`).
//!
//! # 提供什么
//! | 模块 | 内容 |
//! |---|---|
//! | [`entry!`] / 启动 | 程序入口（栈对齐后调用用户的 `main`，以其返回值结束进程）与 panic 处理 |
//! | [`heap`] | 全局分配器：在私有窗口的固定区间上经 `system.memory.map` 按需增长 |
//! | [`io`] | `print!` / `println!`（`system.console.write`） |
//! | [`handle`] | 句柄 RAII（离开作用域即关闭）、复制与降权 |
//! | [`task`] | 线程（`spawn` / `join`）、让出、服务质量档位、线程与进程退出、等待 |
//! | [`time`] | 读取时刻、同步等待 |
//! | [`mem`] | 匿名页映射与取消映射 |
//! | [`channel`] | Channel 端点：收发消息与句柄 |
//! | [`ring`] | 异步环：提交 → 完成、取消 |
//! | [`module`] | `.jaso` 模块装载器：校验 → 装入 → 重定位 → 设权限 → 初始化；卸载 |
//!
//! # 约定
//! * 所有系统调用失败都以 [`Error`]（登记表中的错误 ID）返回，不吞错误
//! * 运行时只用调用者进程被授予的系统调用；未授予的调用照常返回 `rights_denied`
//! * 目前只实现 x86_64 的系统调用指令与地址布局；其它指令集随内核移植加入（见 [`sys`]）
#![no_std]

extern crate alloc;

pub mod channel;
pub mod error;
pub mod handle;
pub mod heap;
pub mod io;
pub mod mem;
pub mod module;
pub mod ring;
mod start;
pub mod sync;
pub mod sys;
pub mod task;
pub mod time;

pub use error::{Error, Result};
pub use handle::Handle;
pub use kernel_core::object::Rights;

/// 系统调用号（构建期从登记表生成）。
#[allow(missing_docs)]
pub mod ids {
    include!(concat!(env!("OUT_DIR"), "/ids.rs"));
}

/// 声明程序入口：`entry!(main)`，`main` 的签名为 `fn(u64, u64) -> i32`（两个参数是创建者给主线程的入口参数）。
/// 返回值作为进程退出码（经 `system.process.exit`，同时结束本进程的全部线程）。
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[no_mangle]
        extern "C" fn __jsr_main(a: u64, b: u64) -> i32 {
            let f: fn(u64, u64) -> i32 = $main;
            f(a, b)
        }
    };
}
