//! 最小非特权程序验收演练：从 ELF 装载 `user/prog`，逐项证明隔离与回收。
//! Acceptance drill for the minimal unprivileged program: isolation and full reclamation.
//!
//! # 为什么单独成文件
//! 这是「独立内核」阶段的总验收：前面各演练分别证明了一个机制，这里只用**真实装载的用户程序**、
//! 只经系统调用与进程层的公开接口，把它们串起来验证一次。演练本身不引入任何新机制。
//!
//! # 用例（每个用例一个或两个进程；`user/prog` 的 `role` 选择行为，见该程序的文档表）
//! 1. **正常运行**：读代码段选择子证明运行在特权级 3，以退出码 0 结束
//! 2. **读内核内存**：该进程被终止（退出码 -1）；同时运行的旁观进程照常以 0 结束（只杀该进程）
//! 3. **特权指令**、4. **无效指令**：用户态异常只终止该进程，内核继续运行
//! 5. **坏系统调用指针**：以内核地址作为指针调用被拒（`invalid_address`），进程随后正常退出
//! 6. **多线程进程终止 + 父进程等待**：子进程有一个只在用户态空转的线程，主线程 `process.exit(9)`
//!    ⇒ 空转线程在下一次时钟中断时停止；父进程经 ring 等待子进程，取消其中一个 wait 并关闭子进程句柄，
//!    另一个 wait 仍得到 9（退出状态独立于句柄存活）
//! 7. **内核内阻塞时终止**：线程停在内核等待里（同步 time.wait / 同步 recv / ring enter / 同步 task.wait）
//!    时进程终止 ⇒ 等待被打断、线程停止、进程以 7 结束（不会停留在 exiting）
//!
//! 每个用例结束后回收（reap + 清理过程），检查**空闲页帧数、存活对象数、清理队列、固定帧**全部回到用例前的基线。
//! 内核在全部故障之后仍在运行本身就是「用户异常不致内核崩溃」的证据。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::object::{ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::paging::{MapError, MapFlags};

use crate::kobj;
use crate::mm::{frame, pin};
use crate::proc::{self, ProcError, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::{arch, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-PROG-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 用户程序 `user/prog` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_PROG: &[u8] = include_bytes!(env!("JSR_USER_PROG"));

/// 用户栈顶相对用户窗口起点的偏移与页数。
const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;

/// 故障终止的退出码（与故障处理路径一致）。
const FAULT_CODE: i64 = -1;

/// `user/prog` 可用的系统调用（只授予它真正用到的）。
fn user_calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_TASK_EXIT,
        abi::SYSTEM_TASK_SPAWN,
        abi::SYSTEM_TASK_WAIT,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_PROCESS_WAIT,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_ASYNC_CANCEL,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_CHANNEL_CREATE,
        abi::SYSTEM_CHANNEL_RECV,
    ])
}

/// 一个内核地址（内核镜像中的只读数据）：用户态读它、或把它当系统调用指针，都必须被拒。
fn kernel_address() -> u64 {
    USER_PROG.as_ptr() as u64
}

/// 资源基线：空闲页帧、存活对象、清理队列、固定帧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Baseline {
    free_frames: usize,
    objects: usize,
    pending: usize,
    pins: (usize, usize),
}

fn baseline() -> Baseline {
    kobj::run_cleanup(usize::MAX);
    let (objects, pending, _) = kobj::stats();
    Baseline { free_frames: frame::free_frames(), objects, pending, pins: pin::stats() }
}

/// 创建进程并装载 `user/prog`，主线程入口参数为 `(role, arg)`。
fn launch(name: &'static str, role: u64, arg: u64) -> Option<ObjId> {
    let pid = proc::create(name, user_calls()).ok()?;
    if start(pid, name, role, arg) {
        Some(pid)
    } else {
        check(false, "user-prog 装载失败");
        None
    }
}

/// 装载 ELF、映射用户栈并创建主线程。
fn start(pid: ObjId, name: &'static str, role: u64, arg: u64) -> bool {
    let base = arch::USER_WINDOW.0;
    let r = (|| {
        let entry = proc::load_elf(pid, USER_PROG).map_err(|_| ProcError::Map(MapError::InvalidAddress))?;
        for i in 1..=STACK_PAGES {
            proc::map_new(pid, base + STACK_TOP_OFF - i * FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
        }
        proc::spawn_thread(pid, name, entry, base + STACK_TOP_OFF, role, arg)
    })();
    r.is_ok()
}

/// 回收进程（创建者释放外部所有权）并运行清理过程；返回其退出码。
fn reap(pid: ObjId) -> Option<i64> {
    let code = proc::reap(pid).map(|i| i.code);
    kobj::run_cleanup(usize::MAX);
    code
}

/// 运行一个单进程用例：期望退出码 `expect`，并检查回到基线。返回实际退出码。
fn single(label: &str, name: &'static str, role: u64, arg: u64, expect: i64) -> Option<i64> {
    let before = baseline();
    let Some(pid) = launch(name, role, arg) else { return None };
    sched::run();
    let st = proc::state(pid);
    let code = reap(pid);
    let after = baseline();
    let ok = st == Some(ProcState::Exited { code: expect }) && code == Some(expect);
    check(ok, label);
    check(after == before, "用例结束后资源未回到基线");
    kprintln!("[JSR-PROG] case={} exit={:?} expect={} reclaimed={}", label, code, expect, after == before);
    code
}

/// 运行全部用例。
///
/// 整个演练期间开启时间片抢占：用例 6 的空转线程从不主动让出处理器，只有时钟中断能把它换下——
/// 这正是「从用户态被中断」这一调度点要证明的情形。演练结束后恢复关闭，后续流程保持可复现。
pub fn run() {
    sched::set_preemption(true);
    run_cases();
    sched::set_preemption(false);
}

fn run_cases() {
    let start_line = baseline();

    // 1. 正常运行：退出码 0 当且仅当程序读到的特权级是 3
    let code = single("cpl3", "prog-hello", 0, 0, 0);
    kprintln!("[JSR-PROG] exit={} ring3={}", code.unwrap_or(-99), code == Some(0));

    // 2. 读内核内存：只杀该进程；旁观进程照常结束
    kernel_read_isolated();

    // 3–4. 用户态异常：特权指令、无效指令
    single("privileged_instruction", "prog-priv", 2, 0, FAULT_CODE);
    single("invalid_instruction", "prog-ud", 3, 0, FAULT_CODE);

    // 5. 坏系统调用指针：被拒后正常退出（程序自己检查返回值为 invalid_address）
    single("bad_syscall_pointer", "prog-badptr", 4, kernel_address(), 0);

    // 6. 多线程进程终止 + 父进程经 ring 等待
    exit_and_wait();

    // 7. 内核内阻塞时终止（四种等待方式）
    for variant in 0..4u64 {
        single(["blocked_time_wait", "blocked_recv", "blocked_ring_enter", "blocked_task_wait"][variant as usize], "prog-blocked", 7, variant, 7);
    }

    let end_line = baseline();
    let reclaimed = end_line == start_line;
    check(reclaimed, "演练结束后资源未回到起点");
    kprintln!(
        "[JSR-PROG] summary free_frames={}/{} objects={}/{} pending={} pinned={:?} reclaimed={} kernel_alive=true checks={} failed={}",
        end_line.free_frames,
        start_line.free_frames,
        end_line.objects,
        start_line.objects,
        end_line.pending,
        end_line.pins,
        reclaimed,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 用例 2：读内核地址的进程被终止，同时运行的旁观进程不受影响。
fn kernel_read_isolated() {
    let before = baseline();
    let (Some(bad), Some(bystander)) = (launch("prog-kread", 1, kernel_address()), launch("prog-bystander", 0, 0)) else {
        check(false, "进程创建失败");
        return;
    };
    sched::run();
    let (sb, sy) = (proc::state(bad), proc::state(bystander));
    let (cb, cy) = (reap(bad), reap(bystander));
    let after = baseline();
    check(sb == Some(ProcState::Exited { code: FAULT_CODE }), "读内核地址的进程应被终止");
    check(sy == Some(ProcState::Exited { code: 0 }), "旁观进程应正常结束");
    check(after == before, "用例结束后资源未回到基线");
    kprintln!(
        "[JSR-PROG] case=kernel_read exit={:?} bystander_exit={:?} only_offender_killed={} reclaimed={}",
        cb,
        cy,
        cb == Some(FAULT_CODE) && cy == Some(0),
        after == before
    );
}

/// 用例 6：子进程（主线程 + 用户态空转线程）`process.exit(9)`；父进程持子进程句柄（WAIT）经 ring 等待。
///
/// 子进程同时登记在父进程的子进程表里（父 → 子内部引用）：父进程退出时释放；
/// 内核作为两者的创建者各持一份外部所有权，最后分别回收。
fn exit_and_wait() {
    let before = baseline();
    let Ok(child) = proc::create("prog-child", user_calls()) else {
        check(false, "进程创建失败");
        return;
    };
    let Ok(parent) = proc::create("prog-parent", user_calls()) else {
        check(false, "进程创建失败");
        return;
    };
    let h = proc::grant(parent, child, ObjectType::Process, Rights::WAIT);
    let adopted = proc::adopt(parent, child).is_ok();
    let started = match h {
        Ok(h) => start(child, "prog-child", 5, 0) && start(parent, "prog-parent", 6, h.raw() as u64),
        Err(_) => false,
    };
    check(h.is_ok() && adopted && started, "父子进程准备失败");
    if started {
        sched::run();
    }
    let (sc, sp) = (proc::state(child), proc::state(parent));
    let threads = proc::thread_counts(child);
    let (cc, cp) = (reap(child), reap(parent));
    let after = baseline();
    check(sc == Some(ProcState::Exited { code: 9 }), "子进程应以 process.exit 的退出码 9 结束");
    check(threads == Some((0, 2)), "子进程的两个线程都应已停止");
    check(sp == Some(ProcState::Exited { code: 0 }), "父进程的 wait 检查未全部通过");
    check(after == before, "用例结束后资源未回到基线");
    kprintln!(
        "[JSR-PROG] case=process_exit child_exit={:?} child_threads={:?} parent_exit={:?} reclaimed={}",
        cc,
        threads,
        cp,
        after == before
    );
}
