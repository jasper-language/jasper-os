//! 用户态运行时验收演练：匿名内存系统调用的内核侧语义 + 用运行时写成的普通 Rust 程序在 Ring 3 运行。
//! Acceptance drill for the user-space runtime and the anonymous-memory system calls.
//!
//! # 用例
//! 1. **匿名内存（内核侧直接调用）**：映射清零页；重叠 / 部分重叠被拒且不留任何映射、帧数不变；
//!    取消映射区间含空洞被拒且原映射与数据不变；各类非法区间；帧配额到顶被拒、被拒那次不消耗帧；
//!    已退出的进程拒绝映射；回收后回到基线
//! 2. **`user/rtdemo` role 0**：堆（集合、格式化、增长与回收）、匿名内存、线程、Channel（字节 + 句柄往返）、
//!    异步环（取消、等待线程）、错误名——程序自己逐步检查，以 0 退出
//! 3. **role 1**：`panic!` ⇒ 运行时输出信息，以 101 终止进程
//! 4. **role 2**：线程栈溢出触到保护区 ⇒ 页故障终止整个进程（退出码 -1）
//! 5. **`user/libcheck`**：现有 Rust 库（sha2、crc、miniz_oxide、smoltcp）在运行时之上通过已知答案测试，以 0 退出
//! 6. **`user/jasodemo`**：`.jaso` 模块装入、调用导出、两个实例、卸载、各类拒绝，以 0 退出
//! 7. **`user/modhost`**：sha2 / crc / deflate / net 作为 `.jaso` 模块装入，已知答案检查与模块串联，以 0 退出
//!
//! 每个用例结束后检查空闲页帧、存活对象、清理队列、固定帧都回到用例前的基线。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::objtable::ObjId;
use kernel_core::paging::{MapError, MapFlags};

use crate::kobj;
use crate::mm::{frame, pin};
use crate::proc::{self, MemError, ProcError, ProcState, MAX_PROCESS_FRAMES};
use crate::syscall::{table as abi, SyscallSet};
use crate::{arch, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-RT-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 运行时验收程序 `user/rtdemo` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_RTDEMO: &[u8] = include_bytes!(env!("JSR_USER_RTDEMO"));
/// 库可移植性验收程序 `user/libcheck` 的 ELF 镜像。
static USER_LIBCHECK: &[u8] = include_bytes!(env!("JSR_USER_LIBCHECK"));
/// `.jaso` 装载器验收程序 `user/jasodemo` 的 ELF 镜像（内嵌构建期打包的模块）。
static USER_JASODEMO: &[u8] = include_bytes!(env!("JSR_USER_JASODEMO"));
/// 库模块验收程序 `user/modhost` 的 ELF 镜像（内嵌构建期打包的四个库模块）。
static USER_MODHOST: &[u8] = include_bytes!(env!("JSR_USER_MODHOST"));

/// 主线程栈顶相对私有窗口起点的偏移与页数（与其它演练相同的布局）。
const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;
/// 故障终止的退出码。
const FAULT_CODE: i64 = -1;

/// 运行时用到的系统调用。
/// 运行时（jasper-rt）写成的程序所需的系统调用集合（其它演练在此基础上追加）。
pub(crate) fn rt_calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_TASK_EXIT,
        abi::SYSTEM_TASK_YIELD,
        abi::SYSTEM_TASK_SPAWN,
        abi::SYSTEM_TASK_WAIT,
        abi::SYSTEM_TIME_NOW,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_PROCESS_EXIT,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_RESTRICT,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_ASYNC_CANCEL,
        abi::SYSTEM_CHANNEL_CREATE,
        abi::SYSTEM_CHANNEL_SEND,
        abi::SYSTEM_CHANNEL_RECV,
        abi::SYSTEM_MEMORY_MAP,
        abi::SYSTEM_MEMORY_UNMAP,
        abi::SYSTEM_MEMORY_PROTECT,
    ])
}

/// 资源基线：用例前后比较，判定没有泄漏。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Baseline {
    /// 空闲页帧数。
    pub(crate) free_frames: usize,
    /// 存活内核对象数。
    pub(crate) objects: usize,
    /// 清理队列中待处理的对象数。
    pub(crate) pending: usize,
    /// 固定帧统计。
    pub(crate) pins: (usize, usize),
}

/// 先跑完清理过程，再读取资源基线。
pub(crate) fn baseline() -> Baseline {
    kobj::run_cleanup(usize::MAX);
    let (objects, pending, _) = kobj::stats();
    Baseline { free_frames: frame::free_frames(), objects, pending, pins: pin::stats() }
}

fn reap(pid: ObjId) -> Option<i64> {
    let code = proc::reap(pid).map(|i| i.code);
    kobj::run_cleanup(usize::MAX);
    code
}

/// 运行全部用例。演练期间开启时间片抢占（与 M5.1 演练相同：用户线程可被时钟中断换下）。
pub fn run() {
    let prev_preemption = sched::set_preemption(true);
    let start = baseline();
    memory_kernel_side();
    program("rt-main", USER_RTDEMO, 0, 0);
    program("rt-panic", USER_RTDEMO, 1, 101);
    program("rt-overflow", USER_RTDEMO, 2, FAULT_CODE);
    program("libcheck", USER_LIBCHECK, 0, 0);
    program("jasodemo", USER_JASODEMO, 0, 0);
    program("modhost", USER_MODHOST, 0, 0);
    let end = baseline();
    check(end == start, "演练结束后资源未回到起点");
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-RT] summary free_frames={}/{} objects={}/{} pending={} pinned={:?} reclaimed={} checks={} failed={}",
        end.free_frames,
        start.free_frames,
        end.objects,
        start.objects,
        end.pending,
        end.pins,
        end == start,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 用例 1：匿名内存的内核侧语义（进程没有线程，直接调用进程层接口）。
fn memory_kernel_side() {
    let before = baseline();
    let Ok(pid) = proc::create("rt-mem", rt_calls()) else {
        check(false, "进程创建失败");
        return;
    };
    let w = arch::USER_WINDOW.0;
    let base = w + 0x3000_0000;
    let page = FRAME_SIZE;

    // 映射清零页、可写
    let ok = proc::map_anon(pid, base, 4, true);
    let zero = proc::read_u64(pid, base) == Some(0) && proc::read_u64(pid, base + 4 * page - 8) == Some(0);
    let wrote = proc::write(pid, base + 8, &0x1234_5678u64.to_le_bytes()).is_ok() && proc::read_u64(pid, base + 8) == Some(0x1234_5678);
    let owned = proc::frame_count(pid);
    let rw = proc::page_flags(pid, base).is_some_and(|f| f.contains(MapFlags::USER) && f.contains(MapFlags::WRITE) && !f.contains(MapFlags::EXECUTE));
    check(ok.is_ok() && zero && wrote && rw && owned == Some(4), "匿名映射：清零、用户可写不可执行、记账 4 帧");

    // 重叠与部分重叠：被拒；前一页仍未映射；帧数与空闲帧不变
    let free = frame::free_frames();
    let dup = proc::map_anon(pid, base, 1, true);
    let partial = proc::map_anon(pid, base - page, 2, true);
    let prev_unmapped = proc::read_u64(pid, base - page).is_none();
    let untouched = proc::frame_count(pid) == Some(4) && frame::free_frames() == free;
    check(
        dup == Err(MemError::AlreadyMapped) && partial == Err(MemError::AlreadyMapped) && prev_unmapped && untouched,
        "重叠映射应被拒且不留下任何映射",
    );
    kprintln!(
        "[JSR-RT] memory map={:?} zeroed={} user_rw_nx={} overlap={:?} partial={:?} untouched={}",
        ok,
        zero,
        wrote && rw,
        dup,
        partial,
        prev_unmapped && untouched
    );

    // 取消映射：区间含空洞 ⇒ 什么也不改
    let hole = proc::unmap_range(pid, base, 5);
    let kept = proc::read_u64(pid, base + 8) == Some(0x1234_5678) && proc::frame_count(pid) == Some(4);
    check(hole == Err(MemError::NotMapped) && kept, "含空洞的取消映射应被拒且不改动");

    // 非法区间：未对齐、0 页、超过单次上限、窗口外、越过窗口末端、长度溢出；不可执行标志无从表达（接口只有 writable）
    let bad = [
        proc::map_anon(pid, base + 1, 1, true),
        proc::map_anon(pid, base + 16 * page, 0, true),
        proc::map_anon(pid, base + 16 * page, proc::MAX_MAP_PAGES + 1, true),
        proc::map_anon(pid, 0x1000, 1, true),
        proc::map_anon(pid, arch::USER_WINDOW.1 - page, 2, true),
        proc::map_anon(pid, base + 16 * page, u64::MAX / page, true),
    ];
    check(bad.iter().all(|r| *r == Err(MemError::InvalidRange)), "非法区间应被拒");

    // 只读映射：用户权限、不可写、不可执行
    let ro = proc::map_anon(pid, base + 16 * page, 1, false);
    let ro_ok = ro.is_ok()
        && proc::page_flags(pid, base + 16 * page)
            .is_some_and(|f| f.contains(MapFlags::USER) && !f.contains(MapFlags::WRITE) && !f.contains(MapFlags::EXECUTE));
    check(ro_ok, "只读匿名映射不可写");

    // 改权限：只读 → 可执行（W^X：同时可写可执行被拒）；区间含空洞 ⇒ 什么也不改
    let rx = proc::protect_range(pid, base, 2, false, true);
    let rx_flags = proc::page_flags(pid, base + page)
        .is_some_and(|f| f.contains(MapFlags::USER) && f.contains(MapFlags::EXECUTE) && !f.contains(MapFlags::WRITE));
    let wx = proc::protect_range(pid, base, 1, true, true);
    let gap = proc::protect_range(pid, base + 2 * page, 3, false, false); // 第 3、4 页已映射，第 5 页没有
    let gap_kept = proc::page_flags(pid, base + 2 * page).is_some_and(|f| f.contains(MapFlags::WRITE));
    let back = proc::protect_range(pid, base, 2, true, false);
    let rw_again = proc::page_flags(pid, base).is_some_and(|f| f.contains(MapFlags::WRITE) && !f.contains(MapFlags::EXECUTE));
    check(
        rx.is_ok() && rx_flags && wx == Err(MemError::InvalidRange) && gap == Err(MemError::NotMapped) && gap_kept && back.is_ok() && rw_again,
        "改权限：W^X、全有或全无",
    );
    kprintln!(
        "[JSR-RT] protect rx={:?} rx_flags={} wx={:?} gap={:?} gap_kept={} back_to_rw={}",
        rx,
        rx_flags,
        wx,
        gap,
        gap_kept,
        back.is_ok() && rw_again
    );

    // 帧配额：每次 1024 页直到被拒；被拒那次不消耗帧
    let qbase = w + 0x4_0000_0000;
    let mut n = 0u64;
    let refused = loop {
        match proc::map_anon(pid, qbase + n * 1024 * page, 1024, true) {
            Ok(()) => n += 1,
            Err(e) => break Some(e),
        }
        if n > 16 {
            break None;
        }
    };
    let at_refusal = proc::frame_count(pid);
    let free_at_refusal = frame::free_frames();
    // 再试一次同样的请求：仍被拒，空闲帧不变
    let again = proc::map_anon(pid, qbase + n * 1024 * page, 1024, true);
    let no_charge = frame::free_frames() == free_at_refusal && proc::frame_count(pid) == at_refusal;
    let within = at_refusal.is_some_and(|c| c <= MAX_PROCESS_FRAMES);
    check(refused == Some(MemError::Quota) && again == Err(MemError::Quota) && no_charge && within, "帧配额到顶应被拒且不消耗帧");
    let mut unmapped = true;
    for i in 0..n {
        unmapped &= proc::unmap_range(pid, qbase + i * 1024 * page, 1024).is_ok();
    }
    check(unmapped && proc::frame_count(pid) == Some(5), "配额用例的映射应全部取消");
    kprintln!(
        "[JSR-RT] memory hole={:?} bad_ranges_refused={} readonly={} quota_chunks={} refused={:?} no_charge={} owned_at_refusal={:?}",
        hole,
        bad.iter().all(|r| *r == Err(MemError::InvalidRange)),
        ro_ok,
        n,
        refused,
        no_charge,
        at_refusal
    );

    // 已退出的进程拒绝映射
    let exited = proc::exit_idle(pid, 0);
    let after_exit = proc::map_anon(pid, base + 32 * page, 1, true);
    check(exited && after_exit == Err(MemError::NoSuchProcess), "已退出的进程应拒绝映射");
    let _ = reap(pid);
    let after = baseline();
    check(after == before, "匿名内存用例结束后资源未回到基线");
    kprintln!("[JSR-RT] memory exited_refused={:?} reclaimed={}", after_exit, after == before);
}

/// 装载用户程序 `image` 并以 `role` 运行到结束，检查退出码与回到基线。
fn program(name: &'static str, image: &[u8], role: u64, expect: i64) {
    let before = baseline();
    let Some((st, code)) = run_program(name, image, role, rt_calls()) else {
        check(false, "用户程序装载失败");
        return;
    };
    let after = baseline();
    check(st == Some(ProcState::Exited { code: expect }) && code == Some(expect), name);
    check(after == before, "用例结束后资源未回到基线");
    kprintln!("[JSR-RT] case={} exit={:?} expect={} reclaimed={}", name, code, expect, after == before);
}

/// 装载并运行一个内嵌的用户程序到结束，然后回收进程。
/// 返回 (回收前的进程状态, 退出码)；进程创建或装载失败时返回 `None`（已创建的进程同样被回收）。
/// 主线程栈布局与其它演练相同；`calls` 是授予该进程的系统调用集合。
/// Loads, runs to completion and reaps an embedded user program.
pub(crate) fn run_program(name: &'static str, image: &[u8], role: u64, calls: SyscallSet) -> Option<(Option<ProcState>, Option<i64>)> {
    run_program_arg(name, image, role, 0, calls)
}

/// 同 [`run_program`]，并把 `arg` 作为主线程的第二个入口参数。
/// Same as [`run_program`], passing `arg` as the main thread's second entry argument.
pub(crate) fn run_program_arg(name: &'static str, image: &[u8], role: u64, arg: u64, calls: SyscallSet) -> Option<(Option<ProcState>, Option<i64>)> {
    let (pid, started) = start_program_arg(name, image, role, arg, calls, |_| Ok(()))?;
    if started {
        sched::run();
    }
    finish_program(pid, started)
}

/// 创建进程、装载程序、映射主线程栈，执行 `configure`（例如设置 CPU 上限），最后创建主线程（尚未运行）。
/// 返回 (进程, 是否成功启动)；进程创建本身失败时返回 `None`。启动失败的进程同样须经 [`finish_program`] 回收。
/// Creates and prepares a process; `configure` runs before the main thread is spawned.
pub(crate) fn start_program(
    name: &'static str,
    image: &[u8],
    role: u64,
    calls: SyscallSet,
    configure: impl FnOnce(ObjId) -> Result<(), ProcError>,
) -> Option<(ObjId, bool)> {
    start_program_arg(name, image, role, 0, calls, configure)
}

/// 同 [`start_program`]，并把 `arg` 作为主线程的第二个入口参数。
fn start_program_arg(
    name: &'static str,
    image: &[u8],
    role: u64,
    arg: u64,
    calls: SyscallSet,
    configure: impl FnOnce(ObjId) -> Result<(), ProcError>,
) -> Option<(ObjId, bool)> {
    let pid = proc::create(name, calls).ok()?;
    let base = arch::USER_WINDOW.0;
    let started = (|| {
        let entry = proc::load_elf(pid, image).map_err(|_| ProcError::Map(MapError::InvalidAddress))?;
        for i in 1..=STACK_PAGES {
            proc::map_new(pid, base + STACK_TOP_OFF - i * FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
        }
        configure(pid)?;
        proc::spawn_thread(pid, name, entry, base + STACK_TOP_OFF, role, arg)
    })()
    .is_ok();
    Some((pid, started))
}

/// 读取进程状态并回收（[`start_program`] 的另一半）；返回 (回收前的进程状态, 退出码)，未成功启动时返回 `None`。
pub(crate) fn finish_program(pid: ObjId, started: bool) -> Option<(Option<ProcState>, Option<i64>)> {
    if !started {
        // 没有线程的进程不会自己进入 exited：先让它退出，才能回收
        proc::exit_idle(pid, -1);
    }
    let st = proc::state(pid);
    let code = reap(pid);
    started.then_some((st, code))
}
