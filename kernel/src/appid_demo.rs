//! DRV-0 演练：进程的应用身份（装载时写入、进程不可改）。
//! DRV-0 drill: process application identity, bound once at load time.
//!
//! # 覆盖
//! 1. 新进程的身份为 0（未绑定）；
//! 2. 装载时绑定一次后可以读到；
//! 3. 再次绑定被拒（身份不可改）；
//! 4. 非法身份（0）被拒。
//!
//! # 边界
//! 这里只验证"身份事实"的写入与不可变性；事件与消息上的身份章在服务接口阶段接入。

use core::sync::atomic::{AtomicU32, Ordering};

use crate::proc::{self, ProcError};
use crate::syscall::SyscallSet;
use crate::kprintln;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-APPID-FAIL] {}", what);
    }
}

/// 本演练的失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 演练入口。
pub fn run() {
    let Ok(pid) = proc::create("appid-demo", SyscallSet::EMPTY) else {
        check(false, "创建进程失败");
        kprintln!("[JSR-APPID] summary checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
        return;
    };
    check(proc::app(pid) == Some(0), "新进程的身份应为未绑定");
    check(proc::set_app(pid, 0).is_err(), "身份 0 应被拒绝");
    check(proc::set_app(pid, 0x5157).is_ok(), "首次绑定应成功");
    check(proc::app(pid) == Some(0x5157), "绑定后应能读到身份");
    check(proc::set_app(pid, 0x9999) == Err(ProcError::BadApp), "二次绑定必须被拒");
    check(proc::app(pid) == Some(0x5157), "被拒后身份保持不变");
    // 收尾：进程没有任何线程，先让它进入 exited 再回收（否则对象会留在表里）。
    check(proc::exit_idle(pid, 0), "无线程进程应能进入 exited");
    check(proc::reap(pid).is_some(), "exited 的进程应能被回收");
    kprintln!(
        "[JSR-APPID] summary pid={:#x} app={:#x} checks={} failed={}",
        pid.raw(),
        0x5157,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
