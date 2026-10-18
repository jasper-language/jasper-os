//! M3.1 / M3.2 演练：真实进入 Ring 3；用户态异常只终止该任务；系统调用经登记表与统一权限检查。
//!
//! 每个探针一个独立地址空间（代码页：用户可执行只读；数据页、栈页：用户可写），由一个内核任务
//! 切到该空间后 `enter_user`。三个探针（机器码由 arch 提供，本文件不含 ISA 代码）：
//! 1. 上报特权级：把代码段选择子写进数据页 → 引导线程读出后验证 RPL=3（真的在 Ring 3）
//! 2. 读内核地址：读一个内核堆对象 → 必须在读处缺页被终止，数据页里不得出现泄漏的值
//! 3. 特权指令：执行停机指令 → 保护错误被终止，其后的标记不得出现
//!
//! 每个探针结束后：页帧全部归还，空闲帧数回到探针前；三次故障之后内核继续调度并退出成功。

use core::sync::atomic::{AtomicU32, Ordering};

use alloc::boxed::Box;
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapFlags, VirtPage};

use crate::arch::{self, UserProbe};
use crate::fault::{self, UserFaultKind};
use crate::mm::space::VmSpace;
use crate::mm::{frame, phys_to_virt};
use crate::sync::IrqSpinLock;
use crate::syscall::{self, table as abi, SyscallSet};
use crate::task::TaskId;
use crate::{kprintln, sched};

/// 私有窗口内的布局（相对窗口起点）。
const CODE_OFF: u64 = 0x40_0000;
const DATA_OFF: u64 = 0x80_0000;
const STACK_OFF: u64 = 0xC0_0000;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-USER] CHECK FAILED: {}", what);
    }
}

/// 断言失败次数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 交给用户任务的启动参数（引导线程准备，用户任务读取）。
#[derive(Clone, Copy)]
struct Job {
    space: arch::SpaceRoot,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
    /// 授予该用户任务的系统调用集合。
    syscalls: SyscallSet,
}

static JOB: IrqSpinLock<Option<Job>> = IrqSpinLock::new(None);

/// 用户任务体：切到探针的地址空间并进入 Ring 3（永不返回；靠用户态异常被终止）。
fn user_task() {
    let Some(job) = *JOB.lock() else {
        return;
    };
    sched::set_current_space(Some(job.space));
    sched::set_current_syscalls(job.syscalls);
    // SAFETY：job 中的地址都已在该空间按用户权限映射；调度器在切入本任务时已设置内核栈顶。
    unsafe { arch::enter_user(job.entry, job.stack, job.arg0, job.arg1) }
}

/// 一组由调用者独占的数据帧（RAII）：丢弃时全部归还，因此任何中途失败都不会泄漏。
/// Exclusively owned data frames, returned to the frame service on drop.
struct OwnedFrames<const N: usize> {
    frames: [Option<PhysFrame>; N],
}

impl<const N: usize> OwnedFrames<N> {
    /// 逐个分配 `N` 帧并清零；任一失败 ⇒ 已分配的帧随返回的 `None` 一并被丢弃（归还）。
    fn allocate_zeroed() -> Option<Self> {
        let mut set = OwnedFrames { frames: [None; N] };
        for slot in set.frames.iter_mut() {
            let f = frame::allocate().ok()?;
            *slot = Some(f);
            // SAFETY：帧刚分出、尚未映射给任何人；经全物理内存映射清零。
            unsafe { core::ptr::write_bytes(phys_to_virt(f.start())?, 0, FRAME_SIZE as usize) };
        }
        Some(set)
    }

    /// 第 `i` 帧（分配成功后总是存在）。
    fn get(&self, i: usize) -> Option<PhysFrame> {
        self.frames.get(i).copied().flatten()
    }

    /// 归还全部帧，返回是否全部归还成功（之后再丢弃不会重复归还）。
    fn release(&mut self) -> bool {
        let mut ok = true;
        for slot in self.frames.iter_mut() {
            if let Some(f) = slot.take() {
                ok &= frame::deallocate(f).is_ok();
            }
        }
        ok
    }
}

impl<const N: usize> Drop for OwnedFrames<N> {
    fn drop(&mut self) {
        self.release();
    }
}

/// 一个探针的资源：地址空间 + 三个数据帧（代码、数据、栈）。
/// 字段按声明顺序丢弃：先销毁地址空间（不再有映射指向数据帧），再归还数据帧。
struct Probe {
    space: VmSpace,
    frames: OwnedFrames<3>,
}

/// 为探针建立地址空间并装入机器码；`prefill` 中的 (偏移, 字节) 预先写进数据页。
/// 任一步失败都返回 `None`，已建立的地址空间与已分配的帧由 RAII 全部回收。
fn build(probe: UserProbe, prefill: &[(usize, &[u8])]) -> Option<Probe> {
    let base = arch::USER_WINDOW.0;
    let frames = OwnedFrames::<3>::allocate_zeroed()?;
    let mut p = Probe { space: VmSpace::new().ok()?, frames };
    let (code, data, stack) = (p.frames.get(0)?, p.frames.get(1)?, p.frames.get(2)?);
    let bytes = arch::user_probe(probe);
    if bytes.len() > FRAME_SIZE as usize {
        return None;
    }
    // SAFETY：三帧由本探针独占、尚未映射；经全物理内存映射写入，长度已检查不越过页尾。
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys_to_virt(code.start())?, bytes.len());
        for (off, data_bytes) in prefill {
            let end = off.checked_add(data_bytes.len())?;
            if end > FRAME_SIZE as usize {
                return None;
            }
            core::ptr::copy_nonoverlapping(data_bytes.as_ptr(), phys_to_virt(data.start())?.add(*off), data_bytes.len());
        }
    }
    p.space.map(VirtPage::containing(base + CODE_OFF), code, MapFlags::USER | MapFlags::EXECUTE).ok()?;
    p.space.map(VirtPage::containing(base + DATA_OFF), data, MapFlags::USER | MapFlags::WRITE).ok()?;
    p.space.map(VirtPage::containing(base + STACK_OFF - FRAME_SIZE), stack, MapFlags::USER | MapFlags::WRITE).ok()?;
    Some(p)
}

/// 读数据页第 `i` 个 64 位字（经全物理内存映射，不依赖用户映射）。
fn data_word(p: &Probe, i: usize) -> u64 {
    match p.frames.get(1).and_then(|f| phys_to_virt(f.start())) {
        // SAFETY：数据帧仍由本探针持有，8 字节对齐。
        Some(v) => unsafe { (v as *const u64).add(i).read_volatile() },
        None => u64::MAX,
    }
}

/// 探针运行结果。
struct Outcome {
    /// 数据页前 6 个 64 位字。
    words: [u64; 6],
    /// 最近一次用户故障记录。
    last_fault: Option<fault::UserFault>,
    /// 本次运行新增的用户故障数。
    faults: u32,
    /// 本次运行新增的正常退出数（`system.task.exit`）。
    exits: u32,
}

/// 运行一个探针：建空间 → 用户任务进入 Ring 3 → 被终止或自行退出 → 回收。
fn run_probe(name: &'static str, probe: UserProbe, arg1: u64, syscalls: SyscallSet) -> Option<Outcome> {
    run_probe_with(name, probe, arg1, syscalls, &[])
}

/// 同 [`run_probe`]，并预先向数据页写入 `prefill`。
fn run_probe_with(
    name: &'static str,
    probe: UserProbe,
    arg1: u64,
    syscalls: SyscallSet,
    prefill: &[(usize, &[u8])],
) -> Option<Outcome> {
    let base = arch::USER_WINDOW.0;
    let p = build(probe, prefill)?;
    *JOB.lock() = Some(Job {
        space: p.space.root(),
        entry: base + CODE_OFF,
        stack: base + STACK_OFF,
        arg0: base + DATA_OFF,
        arg1,
        syscalls,
    });
    let faults_before = fault::count();
    let exits_before = syscall::exit_count();
    if sched::spawn(TaskId(30), name, user_task).is_err() {
        // 失败回滚：撤销待运行的作业；返回时 `p` 被丢弃，地址空间与数据帧随之回收
        *JOB.lock() = None;
        check(false, "无法创建用户任务");
        return None;
    }
    sched::run(); // 用户任务结束（被终止或自行退出）后回到这里
    let faults = fault::count() - faults_before;
    let exits = syscall::exit_count() - exits_before;
    check(faults + exits == 1, "用户任务没有恰好以一种方式结束");
    let mut words = [0u64; 6];
    for (i, w) in words.iter_mut().enumerate() {
        *w = data_word(&p, i);
    }
    let last = fault::last();
    let Probe { space, mut frames } = p;
    drop(space); // 先销毁地址空间（私有页表帧回收），再归还数据帧
    check(frames.release(), "探针数据帧归还失败");
    Some(Outcome { words, last_fault: last, faults, exits })
}

/// 运行 M3.1 演练。
pub fn run() {
    let free_before = frame::free_frames();

    // 1. 上报特权级
    if let Some(Outcome { words: w, last_fault: last, faults, .. }) =
        run_probe("user-cpl", UserProbe::ReportPrivilege, 0, SyscallSet::EMPTY)
    {
        check(faults == 1, "上报探针未经故障路径终止");
        let ring3 = w[0] & 3 == 3 && w[1] == 0x55aa;
        check(ring3, "用户代码未运行在特权级 3");
        check(matches!(last, Some(f) if f.kind == UserFaultKind::InvalidInstruction), "上报探针的终止原因不是无效指令");
        kprintln!("[JSR-USER] probe=report_privilege cs={:#x} cpl={} marker={:#x} ring3={}", w[0], w[0] & 3, w[1], ring3);
    }

    // 2. 读内核地址（一个内核堆对象：内核可读，用户不可读）
    let secret = Box::new(0x5345_4352_4554_u64);
    let secret_addr = &*secret as *const u64 as u64;
    if let Some(Outcome { words: w, last_fault: last, faults, .. }) =
        run_probe("user-read", UserProbe::ReadAddress, secret_addr, SyscallSet::EMPTY)
    {
        check(faults == 1, "读内核探针未经故障路径终止");
        let blocked = w[0] == 0 && w[1] == 0;
        let at_addr = matches!(last, Some(f) if f.kind == UserFaultKind::PageFault && f.addr == secret_addr);
        check(blocked, "用户态读到了内核数据（泄漏）");
        check(at_addr, "读内核地址未在该地址处缺页");
        kprintln!("[JSR-USER] probe=read_kernel addr={:#x} leaked={} fault_at_addr={}", secret_addr, !blocked, at_addr);
    }
    check(*secret == 0x5345_4352_4554, "内核对象被改写");

    // 3. 特权指令
    if let Some(Outcome { words: w, last_fault: last, faults, .. }) =
        run_probe("user-priv", UserProbe::Privileged, 0, SyscallSet::EMPTY)
    {
        check(faults == 1, "特权指令探针未经故障路径终止");
        let stopped = w[1] == 0x7e57 && w[2] == 0;
        check(stopped, "特权指令之后用户代码仍继续执行");
        check(matches!(last, Some(f) if f.kind == UserFaultKind::ProtectionFault), "特权指令未触发保护错误");
        kprintln!("[JSR-USER] probe=privileged marker={:#x} after={:#x} stopped={}", w[1], w[2], stopped);
    }

    let free_after = frame::free_frames();
    check(free_after == free_before, "探针结束后页帧未全部回收");
    kprintln!(
        "[JSR-USER] kernel alive after faults={} free_before={} free_after={} reclaimed={}",
        fault::count(),
        free_before,
        free_after,
        free_after == free_before
    );
    kprintln!("[JSR-USER] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}

/// 运行 M3.2 演练：用户程序经 `syscall` 指令真实陷入内核。
///
/// 授予集合只含 `system.time.now` 与 `system.task.exit`，**不含** `system.task.yield`：
/// * time.now 返回非负 tick 数
/// * 未登记的 ID（0xffff）返回 `-(system.error.unsupported)`
/// * 未授权的 task.yield 返回 `-(system.error.rights_denied)`（统一权限检查生效）
/// * 系统调用前后 rbx / r12 保留不变
/// * 以退出码 42 调用 task.exit：任务**正常退出**（不是故障），其后的指令不得执行
pub fn run_syscall() {
    let free_before = frame::free_frames();
    let base = arch::USER_WINDOW.0;
    let allowed = SyscallSet::of(&[abi::SYSTEM_TIME_NOW, abi::SYSTEM_TASK_EXIT]);
    match syscall::self_check() {
        Ok(n) => kprintln!("[JSR-SYSCALL] self_check ops={} handlers=all", n),
        Err(name) => check(false, name),
    }
    let calls_before = syscall::call_count();
    if let Some(o) = run_probe("user-sys", UserProbe::SyscallSmoke, 0, allowed) {
        let w = o.words;
        let unsupported = syscall::err(abi::SYSTEM_ERROR_UNSUPPORTED) as u64;
        let denied = syscall::err(abi::SYSTEM_ERROR_RIGHTS_DENIED) as u64;
        let now_ok = (w[0] as i64) >= 0;
        let preserved = w[3] == 0x1234_abcd && w[4] == base + DATA_OFF;
        let exited = o.exits == 1 && o.faults == 0 && syscall::last_exit().map(|(_, c)| c) == Some(42);
        let stopped_after_exit = w[5] == 0;
        check(now_ok, "time.now 返回值非法");
        check(w[1] == unsupported, "未登记 ID 未返回 unsupported");
        check(w[2] == denied, "未授权调用未被拒绝");
        check(preserved, "系统调用破坏了应保留的寄存器");
        check(exited, "task.exit 未以退出码 42 正常结束任务");
        check(stopped_after_exit, "task.exit 之后的用户指令仍被执行");
        kprintln!(
            "[JSR-SYSCALL] probe now={} unregistered={} denied={} preserved={} exit_code={} stopped_after_exit={}",
            w[0] as i64,
            w[1] as i64,
            w[2] as i64,
            preserved,
            syscall::last_exit().map(|(_, c)| c).unwrap_or(-1),
            stopped_after_exit
        );
    }
    let calls = syscall::call_count() - calls_before;
    check(calls == 4, "系统调用次数不是 4");
    let reclaimed = frame::free_frames() == free_before;
    check(reclaimed, "系统调用探针结束后页帧未全部回收");
    kprintln!("[JSR-SYSCALL] calls={} reclaimed={} checks={} failed={}", calls, reclaimed, CHECKS.load(Ordering::Relaxed), failed());
}

/// 运行 M3.3 演练：用户指针安全。用 6 种指针调用 `system.console.write`：
/// 1. 合法中文 UTF-8 文本 → 返回字节数，内核整行输出
/// 2. 内核地址（一个内核堆对象）→ `invalid_address`
/// 3. 私有窗口内但未映射的地址 → `invalid_address`
/// 4. 从已映射页跨入未映射页的区间 → `invalid_address`（且不输出任何前半段）
/// 5. 超长长度 → `invalid_argument`
/// 6. 非法 UTF-8 → `invalid_argument`
/// 之后 task.exit(0) 正常退出；内核全程存活、页帧回收。
pub fn run_user_pointers() {
    let free_before = frame::free_frames();
    let text = "你好，jasper-os：用户指针已校验".as_bytes();
    let len = (text.len() as u64).to_le_bytes();
    let bad_utf8: &[u8] = &[0xFF, 0xFE];
    let secret = Box::new(0x5345_4352_4554_u64);
    let kaddr = &*secret as *const u64 as u64;
    let allowed = SyscallSet::of(&[abi::SYSTEM_CONSOLE_WRITE, abi::SYSTEM_TASK_EXIT]);
    let prefill: [(usize, &[u8]); 3] = [(0xF8, &len), (0x100, text), (0x200, bad_utf8)];
    if let Some(o) = run_probe_with("user-ptr", UserProbe::UserPointers, kaddr, allowed, &prefill) {
        let w = o.words;
        let inv_addr = syscall::err(abi::SYSTEM_MEMORY_ERROR_INVALID_ADDRESS);
        let inv_arg = syscall::err(abi::SYSTEM_ERROR_INVALID_ARGUMENT);
        let r: [i64; 6] = [w[0] as i64, w[1] as i64, w[2] as i64, w[3] as i64, w[4] as i64, w[5] as i64];
        check(r[0] == text.len() as i64, "合法文本未完整写出");
        check(r[1] == inv_addr, "内核地址未被拒绝");
        check(r[2] == inv_addr, "未映射地址未被拒绝");
        check(r[3] == inv_addr, "跨入未映射页的区间未被拒绝");
        check(r[4] == inv_arg, "超长长度未被拒绝");
        check(r[5] == inv_arg, "非法 UTF-8 未被拒绝");
        check(o.exits == 1 && o.faults == 0, "用户指针探针未正常退出");
        kprintln!(
            "[JSR-UPTR] valid={} kernel_addr={} unmapped={} crossing={} too_long={} bad_utf8={} exit_ok={}",
            r[0],
            r[1],
            r[2],
            r[3],
            r[4],
            r[5],
            o.exits == 1 && o.faults == 0
        );
    }
    check(*secret == 0x5345_4352_4554, "内核对象被改写");
    drop(secret);
    let reclaimed = frame::free_frames() == free_before;
    check(reclaimed, "用户指针探针结束后页帧未全部回收");
    kprintln!("[JSR-UPTR] reclaimed={} checks={} failed={}", reclaimed, CHECKS.load(Ordering::Relaxed), failed());
}

/// 运行 M3.4 演练：进程与线程对象。
///
/// 建一个进程（地址空间 + 句柄表 + 帧所有权），主线程用 `system.task.spawn` 在**同一进程**里创建工作线程，
/// 二者经共享数据页协作（证明共享地址空间）；主线程拿到线程句柄后关闭两次（第二次必须失败），以退出码 7 退出。
/// 最后一个线程退出时进程进入 Exited；回收后地址空间、全部数据帧与句柄表释放，空闲帧回到基线。
pub fn run_process() {
    use crate::proc::{self, ProcState};
    let free_before = frame::free_frames();
    let base = arch::USER_WINDOW.0;
    let worker_stack_top = base + STACK_OFF + 0x10000;
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_TASK_SPAWN,
        abi::SYSTEM_TASK_YIELD,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ]);
    let Ok(pid) = proc::create("demo-proc", allowed) else {
        check(false, "进程创建失败");
        return;
    };
    let setup = (|| {
        proc::map_new(pid, base + CODE_OFF, MapFlags::USER | MapFlags::EXECUTE)?;
        proc::write(pid, base + CODE_OFF, arch::user_probe(UserProbe::ProcessThreads))?;
        proc::map_new(pid, base + DATA_OFF, MapFlags::USER | MapFlags::WRITE)?;
        proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
        proc::map_new(pid, worker_stack_top - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
        proc::spawn_thread(pid, "proc-main", base + CODE_OFF, base + STACK_OFF, base + DATA_OFF, worker_stack_top)
    })();
    check(setup.is_ok(), "进程装载或主线程创建失败");
    sched::run(); // 两个线程都退出后回到这里

    let st = proc::state(pid);
    check(st == Some(ProcState::Exited { code: 7 }), "进程未以退出码 7 结束");
    let w = |i: u64| proc::read_u64(pid, base + DATA_OFF + i * 8).unwrap_or(u64::MAX);
    let (handle, work, done, main, close1, close2) = (w(0), w(1), w(2), w(3), w(4), w(5));
    let invalid = syscall::err(abi::SYSTEM_HANDLE_ERROR_INVALID);
    check(handle > 0 && (handle as i64) > 0, "task.spawn 未返回有效句柄");
    check(work == 0x574f_524b && done == 1, "工作线程未在共享地址空间里写入");
    check(main == 0x4d41_494e, "主线程未完成");
    check(close1 == 0, "第一次关闭句柄失败");
    check(close2 as i64 == invalid, "第二次关闭句柄未被拒绝");
    kprintln!(
        "[JSR-PROC] threads shared_memory={} handle={:#x} close_first={} close_again={} state={:?}",
        work == 0x574f_524b && done == 1 && main == 0x4d41_494e,
        handle,
        close1 as i64,
        close2 as i64,
        st
    );
    let info = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX); // reap 只释放所有权；销毁由清理过程完成
    check(matches!(info, Some(i) if i.threads == 2 && i.frames == 4 && i.code == 7), "回收信息不符");
    check(proc::state(pid).is_none(), "回收后进程仍存在");
    let free_after = frame::free_frames();
    check(free_after == free_before, "进程回收后页帧未全部归还");
    kprintln!(
        "[JSR-PROC] reaped threads={} frames={} code={} free_before={} free_after={} reclaimed={}",
        info.map(|i| i.threads).unwrap_or(0),
        info.map(|i| i.frames).unwrap_or(0),
        info.map(|i| i.code).unwrap_or(-99),
        free_before,
        free_after,
        free_after == free_before
    );
    kprintln!("[JSR-PROC] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}

/// 内嵌的用户程序 `user-hello`（由 `kernel/build.rs` 构建的独立静态 ELF）。
static USER_HELLO: &[u8] = include_bytes!(env!("JSR_USER_HELLO"));

/// 运行 M5.1-pre 演练：从 ELF 文件装载并运行用户程序。
///
/// 1. 截断的 ELF 被装载器拒绝（返回规范错误名，不做半装载）
/// 2. 合法 ELF：按段权限映射（代码可执行只读、只读数据、两页 BSS），从 ELF 入口进入 Ring 3
/// 3. 程序经 `system.console.write` 输出中文问候与 BSS 检查结果，经 `system.task.exit(0)` 退出
///    （BSS 未清零时程序以退出码 3 退出，验收即失败）
/// 4. 进程回收后空闲帧回到基线
pub fn run_elf() {
    use crate::proc::{self, ProcState};
    let free_before = frame::free_frames();
    let allowed = SyscallSet::of(&[abi::SYSTEM_CONSOLE_WRITE, abi::SYSTEM_TASK_EXIT]);
    let Ok(pid) = proc::create("user-hello", allowed) else {
        check(false, "进程创建失败");
        return;
    };
    let truncated = proc::load_elf(pid, &USER_HELLO[..100]);
    check(truncated.is_err(), "截断的 ELF 未被拒绝");
    let entry = proc::load_elf(pid, USER_HELLO);
    check(entry.is_ok(), "合法 ELF 装载失败");
    let base = arch::USER_WINDOW.0;
    kprintln!(
        "[JSR-PROG] elf bytes={} truncated={} entry={:#x}",
        USER_HELLO.len(),
        truncated.err().map(|e| e.name()).unwrap_or("accepted"),
        entry.unwrap_or(0)
    );
    if let Ok(entry) = entry {
        let stack_ok = proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE).is_ok();
        check(stack_ok, "用户栈映射失败");
        check(proc::spawn_thread(pid, "user-hello", entry, base + STACK_OFF, 0, 0).is_ok(), "主线程创建失败");
        sched::run();
    }
    let st = proc::state(pid);
    check(st == Some(ProcState::Exited { code: 0 }), "user-hello 未以退出码 0 结束（BSS 检查失败时为 3）");
    let info = proc::reap(pid);
    crate::kobj::run_cleanup(usize::MAX); // reap 只释放所有权；销毁由清理过程完成
    let free_after = frame::free_frames();
    check(free_after == free_before, "user-hello 回收后页帧未全部归还");
    kprintln!(
        "[JSR-PROG] exit={:?} frames={} reclaimed={} checks={} failed={}",
        st,
        info.map(|i| i.frames).unwrap_or(0),
        free_after == free_before,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 运行 M4.1 演练：对象生命周期（M4.0 规范 v0.6 第 9 节 M4.1 行）。
///
/// 1. 线程对象由「外部所有权」（模拟句柄）+「内部引用」（执行上下文、进程线程表）共同保活
/// 2. 关闭句柄（释放外部所有权）⇒ closing 而**不销毁**（INV-01）；closing 对象不能再获得所有者
/// 3. 重复关闭被拒（计数下溢）
/// 4. 线程运行并退出 ⇒ 执行上下文的内部引用释放；对象仍由进程线程表保活
/// 5. reap 释放创建者所有权 ⇒ Process 死亡**只入清理队列**，不就地销毁
/// 6. 清理过程每轮 1 个：销毁 Process 时释放线程表引用 ⇒ Task 死亡入队（级联、迭代、不递归）；下一轮销毁 Task
/// 7. 对象数、清理队列、空闲帧全部回到基线
pub fn run_lifecycle() {
    use crate::kobj;
    use crate::proc::{self, ProcState};
    use kernel_core::objtable::{Lifecycle, ObjError};

    let free_before = frame::free_frames();
    let (live0, _, destroyed0) = kobj::stats();
    let allowed = SyscallSet::of(&[abi::SYSTEM_CONSOLE_WRITE, abi::SYSTEM_TASK_EXIT]);
    let Ok(pid) = proc::create("life-proc", allowed) else {
        check(false, "进程创建失败");
        return;
    };
    let base = arch::USER_WINDOW.0;
    let entry = proc::load_elf(pid, USER_HELLO).unwrap_or(0);
    let stack_ok = proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE).is_ok();
    check(entry != 0 && stack_ok, "装载失败");
    let Ok((_, tobj)) = proc::spawn_thread(pid, "life-thread", entry, base + STACK_OFF, 0, 0) else {
        check(false, "线程创建失败");
        return;
    };
    // 模拟一个指向线程对象的句柄（外部所有权）
    check(kobj::acquire_owner(tobj).is_ok(), "取得外部所有权失败");
    let c1 = kobj::with(|t| t.counts(tobj));
    check(c1 == Ok((1, 2, Lifecycle::Live)), "初始计数应为 owners=1 internal=2 Live");
    // 关闭句柄：closing 但不销毁
    let r = kobj::release_owner(tobj);
    let c2 = kobj::with(|t| t.counts(tobj));
    let closing_alive = matches!(r, Ok(x) if x.became_unowned && !x.dead) && c2 == Ok((0, 2, Lifecycle::Closing));
    check(closing_alive, "关闭句柄后对象应 closing 且存活（INV-01）");
    let again = kobj::release_owner(tobj);
    check(again == Err(ObjError::Underflow), "重复关闭未被拒绝");
    let reacquire = kobj::acquire_owner(tobj);
    check(reacquire == Err(ObjError::Invalid), "closing 对象不应再获得所有者");
    kprintln!(
        "[JSR-LIFE] handle closed: became_unowned=true dead=false counts={:?} double_close={} reacquire={}",
        c2,
        again.err().map(|e| e.name()).unwrap_or("ok"),
        reacquire.err().map(|e| e.name()).unwrap_or("ok")
    );

    sched::run(); // 线程运行 user-hello 并退出
    let c3 = kobj::with(|t| t.counts(tobj));
    check(c3 == Ok((0, 1, Lifecycle::Closing)), "线程退出后应只剩线程表的内部引用");
    check(proc::state(pid) == Some(ProcState::Exited { code: 0 }), "进程应已退出");
    kprintln!("[JSR-LIFE] thread exited: task counts={:?} process_state={:?}", c3, proc::state(pid));

    let info = proc::reap(pid);
    let (_, pending1, _) = kobj::stats();
    check(info.is_some() && pending1 == 1, "reap 后应只有 Process 在清理队列中");
    let first = kobj::run_cleanup(1);
    let (_, pending2, _) = kobj::stats();
    check(first == 1 && pending2 == 1, "销毁 Process 应级联使 Task 入队（而不是递归销毁）");
    let second = kobj::run_cleanup(8);
    let (live3, pending3, destroyed3) = kobj::stats();
    check(second == 1 && pending3 == 0, "第二轮应销毁 Task 且清空队列");
    check(live3 == live0 && destroyed3 == destroyed0 + 2, "对象数未回到基线");
    let reclaimed = frame::free_frames() == free_before;
    check(reclaimed, "页帧未回到基线");
    kprintln!(
        "[JSR-LIFE] cascade: after_reap_pending={} round1={} pending={} round2={} pending={} objects_live={}/{} destroyed+={} reclaimed={}",
        pending1,
        first,
        pending2,
        second,
        pending3,
        live3,
        live0,
        destroyed3 - destroyed0,
        reclaimed
    );
    kprintln!("[JSR-LIFE] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}

/// 运行 M4.2 演练：Handle/Rights（M4.0 规范 v0.6 第 9 节 M4.2 行）。
///
/// **用户态（经系统调用）**：复制只能降权；带 TRANSFER 的提权复制被拒；restrict 只减不增；
/// 去掉 DUPLICATE 后不能再复制。
/// **跨进程转移原语（内核层，M4.4 的 send/recv 将建立在它之上）**：两个进程之间：
/// 移动后发送方句柄失效、外部所有权总数不变；无 TRANSFER 被拒；非叶子（Process 句柄）被拒；
/// 接收方句柄表满被拒——三种失败下发送方句柄均原样保留。最后对象与页帧回到基线。
pub fn run_handles() {
    use crate::kobj::{self, KObject};
    use crate::proc::{self, ProcError, ProcState};
    use kernel_core::object::{HandleError, ObjectType, Rights};
    use kernel_core::objtable::ObjId;

    let free_before = frame::free_frames();
    let (live0, _, _) = kobj::stats();
    let base = arch::USER_WINDOW.0;

    // —— 用户态：duplicate / restrict ——
    let allowed = SyscallSet::of(&[
        abi::SYSTEM_TASK_SPAWN,
        abi::SYSTEM_HANDLE_DUPLICATE,
        abi::SYSTEM_HANDLE_RESTRICT,
        abi::SYSTEM_HANDLE_CLOSE,
        abi::SYSTEM_TASK_EXIT,
    ]);
    if let Ok(pid) = proc::create("rights-proc", allowed) {
        let worker_top = base + STACK_OFF + 0x10000;
        let setup = (|| {
            proc::map_new(pid, base + CODE_OFF, MapFlags::USER | MapFlags::EXECUTE)?;
            proc::write(pid, base + CODE_OFF, arch::user_probe(UserProbe::HandleRights))?;
            proc::map_new(pid, base + DATA_OFF, MapFlags::USER | MapFlags::WRITE)?;
            proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
            proc::map_new(pid, worker_top - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)?;
            proc::spawn_thread(pid, "rights-main", base + CODE_OFF, base + STACK_OFF, base + DATA_OFF, worker_top)
        })();
        check(setup.is_ok(), "权限探针进程装载失败");
        sched::run();
        let w = |i: u64| proc::read_u64(pid, base + DATA_OFF + i * 8).unwrap_or(u64::MAX) as i64;
        let denied = syscall::err(abi::SYSTEM_HANDLE_ERROR_RIGHTS_DENIED);
        let (h, h2, esc_dup, restrict_ok, dup_after, esc_restrict) = (w(0), w(1), w(2), w(3), w(4), w(5));
        check(h > 0 && h2 > 0 && h2 != h, "复制句柄失败");
        check(esc_dup == denied, "提权复制未被拒绝");
        check(restrict_ok == 0, "降权失败");
        check(dup_after == denied, "去掉 DUPLICATE 后仍能复制");
        check(esc_restrict == denied, "经 restrict 提权未被拒绝");
        check(proc::state(pid) == Some(ProcState::Exited { code: 0 }), "权限探针进程未正常退出");
        kprintln!(
            "[JSR-HANDLE] user dup={} escalate_dup={} restrict={} dup_without_right={} escalate_restrict={}",
            h2 > 0,
            esc_dup,
            restrict_ok,
            dup_after,
            esc_restrict
        );
        proc::reap(pid);
        kobj::run_cleanup(usize::MAX);
    }

    // —— 内核层：跨进程原子转移 ——
    let (Ok(a), Ok(b)) = (proc::create("xfer-a", SyscallSet::EMPTY), proc::create("xfer-b", SyscallSet::EMPTY)) else {
        check(false, "转移演练进程创建失败");
        return;
    };
    let ev = KObject::Event { signaled: false };
    let h1 = proc::grant_new(a, ev, ObjectType::Event, Rights::WAIT.union(Rights::TRANSFER));
    let h_notr = proc::grant_new(a, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT);
    let h_proc = proc::grant(a, b, ObjectType::Process, Rights::WAIT.union(Rights::TRANSFER));
    let (Ok(h1), Ok(h_notr), Ok(h_proc)) = (h1, h_notr, h_proc) else {
        check(false, "发放句柄失败");
        return;
    };
    let obj_of = |pid: ObjId, h| proc::handle_info(pid, h).and_then(|(r, _)| ObjId::from_raw(r.id.0));
    let ev_id = obj_of(a, h1);
    let moved = proc::transfer(a, h1, b);
    let sender_invalid = proc::handle_info(a, h1).is_none();
    let owners_after = ev_id.and_then(|id| kobj::with(|t| t.counts(id)).ok()).map(|c| c.0);
    let moved_ok = matches!(moved, Ok(nh) if proc::handle_info(b, nh).is_some()) && sender_invalid && owners_after == Some(1);
    check(moved_ok, "移动后发送方句柄应失效、外部所有权总数应不变");
    let no_right = proc::transfer(a, h_notr, b);
    check(no_right == Err(ProcError::Handle(HandleError::RightsDenied)) && proc::handle_info(a, h_notr).is_some(), "无 TRANSFER 应被拒且句柄保留");
    let non_leaf = proc::transfer(a, h_proc, b);
    check(non_leaf == Err(ProcError::NotTransferable) && proc::handle_info(a, h_proc).is_some(), "非叶子对象应被拒且句柄保留");
    // 填满接收方句柄表
    let mut filled = 0;
    while proc::free_handle_slots(b) > 0 {
        if proc::grant_new(b, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT).is_err() {
            break;
        }
        filled += 1;
    }
    let h_last = proc::grant_new(a, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT.union(Rights::TRANSFER));
    let full = h_last.map(|h| (proc::transfer(a, h, b), proc::handle_info(a, h).is_some()));
    let full_ok = matches!(full, Ok((Err(ProcError::Handle(HandleError::TableFull)), true)));
    check(full_ok, "接收方句柄表满应被拒且发送方句柄保留");
    kprintln!(
        "[JSR-HANDLE] transfer moved={} sender_invalid={} owners_after={:?} no_transfer_right={} non_leaf={} receiver_full={} (filled {})",
        moved.is_ok(),
        sender_invalid,
        owners_after,
        if no_right == Err(ProcError::Handle(HandleError::RightsDenied)) { "rights_denied" } else { "WRONG" },
        if non_leaf == Err(ProcError::NotTransferable) { "not_transferable" } else { "WRONG" },
        if full_ok { "table_full" } else { "WRONG" },
        filled
    );
    // 收尾：两个进程无线程 ⇒ 直接进入 exited（关闭句柄表）→ 回收 → 清理
    check(proc::exit_idle(a, 0) && proc::exit_idle(b, 0), "无线程进程未能退出");
    proc::reap(a);
    proc::reap(b);
    kobj::run_cleanup(usize::MAX);
    let (live1, pending1, _) = kobj::stats();
    let reclaimed = frame::free_frames() == free_before;
    check(live1 == live0 && pending1 == 0 && reclaimed, "对象或页帧未回到基线");
    kprintln!(
        "[JSR-HANDLE] objects_live={}/{} pending={} reclaimed={} checks={} failed={}",
        live1,
        live0,
        pending1,
        reclaimed,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
