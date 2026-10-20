//! user-modbox：隔离模块的容器程序。
//! The container program for isolated modules.
//!
//! 创建者（宿主）经 `system.process.spawn` 启动本程序，入口参数 0 是引导通道在本进程中的端点；
//! 本程序只把它交给运行时的服务循环：收齐模块文件 → 重新校验并装入 → 绑定句柄 → 逐条执行调用请求，
//! 直到宿主关闭通道（以 0 退出）。本进程只拥有宿主授予的系统调用与句柄；模块崩溃只终止本进程。
#![no_std]
#![no_main]

use jasper_rt::channel::Channel;
use jasper_rt::{entry, isolate, Handle};

entry!(main);

fn main(channel: u64, _: u64) -> i32 {
    // SAFETY：内核创建本进程时放入的引导通道端点，尚无人拥有。
    let ch = Channel::from_handle(unsafe { Handle::from_raw(channel) });
    isolate::serve(ch)
}
