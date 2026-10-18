//! S-1 系统调用健壮性演练：运行内嵌的 `user/robust`，检查真机上的返回约定与资源回收。
//! Robustness drill for the system-call boundary: run the embedded `user/robust` program.
//!
//! # 为什么在 QEMU 里做
//! 宿主侧的确定性随机测试只能覆盖 `kernel-core` 的纯数据结构和解析器；系统调用入口、权限检查、
//! 用户指针复制与句柄解析只存在于真实内核里。本演练让一个独立用户进程经真实的 `syscall` / `svc` / `ecall`
//! 陷入路径发起 2 万次有界探测，再由内核侧核对：进程正常退出、系统调用计数确实增长、回收后资源回到基线。
//!
//! # 安静日志
//! 2 万次调用会各产生「进入 / 返回」事件行。演练期间临时关闭逐次系统调用日志（`syscall::set_trace(false)`），
//! 只保留程序自己的失败行与最终汇总；分发、权限检查与执行完全不变。结束后恢复原设置。

use core::sync::atomic::{AtomicU32, Ordering};

use crate::baseline::baseline;
use crate::proc::ProcState;
use crate::rt_demo::run_program;
use crate::syscall::{self, table as abi, SyscallSet};
use crate::kprintln;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 用户程序 `user/robust` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_ROBUST: &[u8] = include_bytes!(env!("JSR_USER_ROBUST"));

/// 程序承诺发起的有界调用次数；内核侧据此防止「程序提前退出却仍算通过」。
const MIN_CALLS: u64 = 20_000;

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-ROBUST-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 授予测试进程全部已登记操作：只有拿到权限，调用才会真正进入各处理函数的参数校验路径。
fn all_calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_TASK_EXIT,
        abi::SYSTEM_TASK_YIELD,
        abi::SYSTEM_TIME_NOW,
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_TASK_SPAWN,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_RESTRICT,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_ASYNC_CANCEL,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_CHANNEL_CREATE,
        abi::SYSTEM_CHANNEL_SEND,
        abi::SYSTEM_CHANNEL_RECV,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_TASK_WAIT,
        abi::SYSTEM_PROCESS_WAIT,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_MEMORY_UNMAP,
        abi::SYSTEM_MEMORY_PROTECT,
        abi::SYSTEM_TASK_QOS_SET,
    ])
}

/// 运行健壮性演练并输出一行可供 accept 检查的汇总。
pub fn run() {
    let before = baseline();
    let calls_before = syscall::call_count();
    let trace = syscall::set_trace(false);
    let result = run_program("robust", USER_ROBUST, 0, all_calls());
    syscall::set_trace(trace);
    let calls = syscall::call_count().wrapping_sub(calls_before) as u64;
    let after = baseline();

    let (state, code) = match result {
        Some(v) => v,
        None => {
            check(false, "user/robust 装载失败");
            kprintln!("[JSR-ROBUST] summary calls={} exit=None reclaimed=false kernel_alive=true checks={} failed={}", calls, CHECKS.load(Ordering::Relaxed), failed());
            return;
        }
    };
    check(state == Some(ProcState::Exited { code: 0 }) && code == Some(0), "用户程序未以 0 退出");
    check(calls >= MIN_CALLS, "系统调用计数未达到承诺的下界");
    check(after == before, "演练结束后资源未回到基线");
    kprintln!(
        "[JSR-ROBUST] summary calls={} min_calls={} exit={:?} free_frames={}/{} objects={}/{} pending={} pinned={:?} reclaimed={} checks={} failed={}",
        calls,
        MIN_CALLS,
        code,
        after.free_frames,
        before.free_frames,
        after.objects,
        before.objects,
        after.pending,
        after.pins,
        after == before,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
