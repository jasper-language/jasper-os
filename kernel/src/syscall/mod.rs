//! 系统调用分发（M3.2，架构无关）。
//! Architecture-neutral system-call dispatch.
//!
//! # 流程
//! arch 的陷入入口（x86_64 为 `syscall` 指令）把寄存器整理成 [`SyscallArgs`] 后调用 [`on_syscall`]：
//! 1. **查表**：只认登记表中的操作 ID；未登记 ⇒ `system.error.unsupported`
//! 2. **统一权限检查**：当前任务的「可用系统调用集合」必须包含该 ID ⇒ 否则 `system.error.rights_denied`
//!    （集合由创建任务的一方授予；M4 起再叠加针对句柄的 Rights 检查）
//! 3. **执行**：按 ID 分派到真实处理函数
//! 4. **返回约定**：非负 = 成功值；负数 = `-(错误码 ID)`
//!
//! # 不允许占位实现
//! [`self_check`] 在启动时核对：登记表里的**每个**操作都必须有处理函数；缺一个内核就拒绝继续启动。

pub mod table;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use alloc::vec;

use kernel_core::device as devabi;
use kernel_core::frame::FRAME_SIZE;
use kernel_core::object::{HandleError, HandleId, ObjectType, Rights};
use kernel_core::pci::{Bar, Bdf, MAX_BARS};
use kernel_core::sched::Qos;

use crate::kobj::{self, DeviceObj, KObject};
use crate::mm::user::{copy_from_user, copy_to_user, UserPtrError};
use crate::proc::{self, ProcError};
use crate::sync::IrqSpinLock;
use crate::{kprintln, profile, sched};

/// `system.console.write` 单次最多写入的字节数。
pub const CONSOLE_WRITE_MAX: usize = 4096;

/// `system.profile.get` 单次最多写入的字节数（结构化描述足够小，超过即视为调用错误）。
pub const PROFILE_TEXT_MAX: usize = 2048;
use table::*;

/// 一次系统调用的输入（与 ISA 无关）。
#[derive(Debug, Clone, Copy)]
pub struct SyscallArgs {
    /// 操作 ID（登记表中的稳定编号）。
    pub id: u64,
    /// 最多 6 个参数。
    pub args: [u64; 6],
}

/// 把用户传入的 64 位寄存器值解释为句柄：超出 32 位的值一律视为空句柄（永远无效），
/// 不截断——否则 `0x1_0000_0005` 会被当成句柄 5，同一个句柄出现多种写法。
/// Interprets a 64-bit register as a handle value without truncation.
pub(crate) fn handle_arg(v: u64) -> HandleId {
    HandleId::from_raw(v)
}

/// 把用户传入的权限位解释为 [`Rights`]：含未定义的位（或超出 32 位）⇒ `None`（调用方报参数非法），不静默丢弃。
pub(crate) fn rights_arg(v: u64) -> Option<Rights> {
    let bits = u32::try_from(v).ok()?;
    let r = Rights::from_bits_truncate(bits);
    (r.bits() == bits).then_some(r)
}

/// 把错误码 ID 编码成系统调用返回值。
pub const fn err(id: u32) -> i64 {
    -(id as i64)
}

/// 任务可用系统调用集合（位 i = 操作 ID i；目前操作 ID < 64）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyscallSet(pub u64);

impl SyscallSet {
    /// 空集合（内核任务默认：内核任务不经系统调用入口）。
    pub const EMPTY: SyscallSet = SyscallSet(0);

    /// 由若干操作 ID 构造。
    pub const fn of(ids: &[u32]) -> SyscallSet {
        let mut m = 0u64;
        let mut i = 0;
        while i < ids.len() {
            if ids[i] < 64 {
                m |= 1 << ids[i];
            }
            i += 1;
        }
        SyscallSet(m)
    }

    /// 两个集合的并集。
    pub const fn union(self, other: SyscallSet) -> SyscallSet {
        SyscallSet(self.0 | other.0)
    }

    /// 是否包含某个 ID。
    pub const fn contains(self, id: u64) -> bool {
        id < 64 && self.0 & (1 << id) != 0
    }
}

/// 最近一次 `system.task.exit` 的 (任务 ID, 退出码) 与累计次数。
static LAST_EXIT: IrqSpinLock<(Option<(u64, i64)>, u32)> = IrqSpinLock::ranked(crate::lockorder::SYSCALL_LAST_EXIT, (None, 0));
/// 累计系统调用次数（诊断）。
static CALLS: AtomicU32 = AtomicU32::new(0);

/// 最近一次任务正常退出的记录。
pub fn last_exit() -> Option<(u64, i64)> {
    LAST_EXIT.lock().0
}

/// 正常退出的累计次数。
pub fn exit_count() -> u32 {
    LAST_EXIT.lock().1
}

/// 累计系统调用次数。
pub fn call_count() -> u32 {
    CALLS.load(Ordering::Relaxed)
}

/// 是否逐次输出系统调用的进入 / 返回 / 拒绝事件行（默认输出）。
static TRACE: AtomicBool = AtomicBool::new(true);

/// 打开或关闭逐次系统调用事件行，返回原设置。
/// 健壮性测试一次运行数万次调用，逐次打印会淹没串口并拖慢运行；关闭期间调用照常计数（[`call_count`]），
/// 分发、权限检查与执行完全不变——只省略日志。由内核侧的测试驱动在运行前后成对调用。
/// Enables or disables per-call trace lines; returns the previous setting.
pub fn set_trace(on: bool) -> bool {
    TRACE.swap(on, Ordering::Relaxed)
}

fn tracing() -> bool {
    TRACE.load(Ordering::Relaxed)
}

/// 是否为该操作 ID 提供了真实处理函数（与 [`execute`] 的分派表一一对应）。
fn has_handler(id: u32) -> bool {
    matches!(
        id,
        SYSTEM_TASK_EXIT
            | SYSTEM_TASK_YIELD
            | SYSTEM_TIME_NOW
            | SYSTEM_CONSOLE_WRITE
            | SYSTEM_TASK_SPAWN
            | SYSTEM_HANDLE_CLOSE
            | SYSTEM_HANDLE_DUPLICATE
            | SYSTEM_HANDLE_RESTRICT
            | SYSTEM_ASYNC_RING_CREATE
            | SYSTEM_ASYNC_RING_ENTER
            | SYSTEM_ASYNC_CANCEL
            | SYSTEM_TIME_WAIT
            | SYSTEM_CHANNEL_CREATE
            | SYSTEM_CHANNEL_SEND
            | SYSTEM_CHANNEL_RECV
            | SYSTEM_PROCESS_EXIT
            | SYSTEM_TASK_WAIT
            | SYSTEM_PROCESS_WAIT
            | SYSTEM_MEMORY_MAP
            | SYSTEM_MEMORY_UNMAP
            | SYSTEM_MEMORY_PROTECT
            | SYSTEM_TASK_QOS_SET
            | SYSTEM_PROCESS_SPAWN
            | SYSTEM_PROFILE_LIST
            | SYSTEM_PROFILE_GET
            | SYSTEM_DEVICE_LIST
            | SYSTEM_DEVICE_OPEN
            | SYSTEM_DEVICE_GET
            | SYSTEM_DEVICE_MAP
            | SYSTEM_DEVICE_CAPABILITY_LIST
            | SYSTEM_DEVICE_INTERRUPT_CREATE
            | SYSTEM_DEVICE_INTERRUPT_WAIT
    )
}

/// 启动自检：登记表中的每个操作都必须有处理函数。返回已核对的操作数；缺失时返回第一个缺失的名字。
pub fn self_check() -> Result<usize, &'static str> {
    let mut n = 0;
    for e in ENTRIES.iter().filter(|e| e.kind == AbiKind::Op) {
        if !has_handler(e.id) {
            return Err(e.name);
        }
        n += 1;
    }
    Ok(n)
}

/// 错误码 ID 对应的规范名（日志用）。
fn error_name(ret: i64) -> &'static str {
    if ret >= 0 {
        return "OK";
    }
    entry((-ret) as u32).map(|e| e.name).unwrap_or("system.error.unknown")
}

/// 每次系统调用返回前最多销毁的死亡对象数（见 [`on_syscall`] 的出口清理点）。
const CLEANUP_PER_CALL: usize = 16;
/// 创建对象前先回收死亡对象的调用（进程创建在 `spawn_child` 里自带回收）。
const RECLAIM_BEFORE: [u32; 3] = [SYSTEM_TASK_SPAWN, SYSTEM_ASYNC_RING_CREATE, SYSTEM_CHANNEL_CREATE];

/// 系统调用入口（arch 调用；可能不返回——`system.task.exit` 会结束当前任务）。
pub fn on_syscall(a: &SyscallArgs) -> i64 {
    CALLS.fetch_add(1, Ordering::Relaxed);
    // 调度点：所属进程已在 exiting ⇒ 本线程不再执行任何系统调用，直接停止
    if proc::current_exiting() {
        proc::thread_exit(0, "killed");
    }
    let (task_id, task_name) = sched::current();
    let Some(e) = op(a.id) else {
        let ret = err(SYSTEM_ERROR_UNSUPPORTED);
        if tracing() {
            kprintln!("[JSR-SYSCALL] reject id={} task={} ret={}", a.id, task_name, error_name(ret));
        }
        return ret;
    };
    if !sched::current_syscalls().contains(a.id) {
        let ret = err(SYSTEM_ERROR_RIGHTS_DENIED);
        if tracing() {
            kprintln!("[JSR-SYSCALL] deny name={} id={} task={} ret={}", e.name, e.id, task_name, error_name(ret));
        }
        return ret;
    }
    let trace = tracing();
    if trace {
        kprintln!("[JSR-SYSCALL] enter name={} id={} task={} effects={}", e.name, e.id, task_name, e.effects.as_str());
    }
    // WCET 证据：只测真正执行的时间，不含查表与权限检查（那两项是常数级）。
    // 创建对象的调用先回收一轮：死亡对象占着的槽位与配额在新对象申请之前归还，
    // 否则（例如线程句柄先关闭、线程随后才退出——死亡发生在任何系统调用之外）它们会一直堆着直到耗尽
    if RECLAIM_BEFORE.contains(&e.id) {
        crate::kobj::run_cleanup(CLEANUP_PER_CALL);
    }
    let enqueued_before = crate::kobj::enqueued_total();
    let started = crate::arch::cycles();
    let ret = execute(e, a, task_id.0);
    crate::wcet::record_syscall(crate::arch::cycles().wrapping_sub(started));
    if trace {
        kprintln!("[JSR-SYSCALL] exit name={} id={} ret={} status={}", e.name, e.id, ret, error_name(ret));
    }
    // 出口清理点：本次调用让对象死亡（关闭句柄、进程退出……）时，由它自己付清理的代价。死亡对象只进入清理队列；
    // 若没有任何路径执行清理过程，长期运行的进程会把死亡对象一直堆在队列里——配额不归还、槽位不释放，
    // 直到耗尽（HARDEN-1C 的长期运行用例第 9 轮即复现：每进程 8 个环的配额被已关闭的环占满）。
    // 只在「本次调用期间有对象死亡」时清理：别处造成的死亡（例如其他处理器上被终止进程的销毁）不记到
    // 无关任务的延迟里，它们由造成者或下一次创建对象的调用回收。
    // 这里不持对象表锁、不在中断上下文（满足清理过程的执行约束），每次最多处理 CLEANUP_PER_CALL 个，
    // 单次系统调用的额外延迟因此有界；余下的由后续调用继续处理。
    if crate::kobj::enqueued_total() != enqueued_before {
        crate::kobj::run_cleanup(CLEANUP_PER_CALL);
    }
    // 出口调度点：调用期间所属进程进入了 exiting（例如阻塞等待被终止打断）⇒ 不再返回用户态
    if proc::current_exiting() {
        proc::thread_exit(0, "killed");
    }
    ret
}

/// 用户指针错误 → 系统调用错误码。
fn user_ptr_err(e: UserPtrError) -> i64 {
    match e {
        UserPtrError::TooLong => err(SYSTEM_ERROR_INVALID_ARGUMENT),
        UserPtrError::InvalidAddress | UserPtrError::NotUserTask => err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS),
    }
}

/// `system.console.write(ptr, len)`：把用户空间的一段 UTF-8 文本写到控制台，返回写入字节数。
///
/// 先经 [`copy_from_user`] 完整校验并复制到内核缓冲区，再做 UTF-8 校验（非法 UTF-8 拒绝，不做替换），
/// 最后整行输出。内核从不直接解引用用户地址。
fn console_write(ptr: u64, len: u64) -> i64 {
    if len as usize > CONSOLE_WRITE_MAX {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let mut buf = vec![0u8; len as usize];
    if let Err(e) = copy_from_user(&mut buf, ptr, CONSOLE_WRITE_MAX) {
        return user_ptr_err(e);
    }
    match core::str::from_utf8(&buf) {
        Ok(text) => {
            let (_, name) = sched::current();
            kprintln!("[JSR-USERTEXT] task={} bytes={} text={}", name, buf.len(), text);
            buf.len() as i64
        }
        Err(_) => err(SYSTEM_ERROR_INVALID_ARGUMENT),
    }
}

/// 进程层错误 → 系统调用错误码。
pub(crate) fn proc_err(e: ProcError) -> i64 {
    match e {
        ProcError::Handle(HandleError::Invalid) => err(SYSTEM_HANDLE_ERROR_INVALID),
        ProcError::Handle(HandleError::RightsDenied) => err(SYSTEM_HANDLE_ERROR_RIGHTS_DENIED),
        ProcError::Handle(HandleError::TableFull) => err(SYSTEM_HANDLE_ERROR_TABLE_FULL),
        ProcError::NotTransferable => err(SYSTEM_HANDLE_ERROR_NOT_TRANSFERABLE),
        ProcError::NoSuchProcess | ProcError::Exited | ProcError::BadApp => err(SYSTEM_ERROR_RIGHTS_DENIED),
        ProcError::Map(_) => err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS),
        ProcError::OutOfFrames | ProcError::NoTaskSlot => err(SYSTEM_ERROR_INVALID_ARGUMENT),
    }
}

/// `system.task.spawn(entry, stack_top, arg)`：在调用者所在进程里创建线程，
/// 返回指向新线程的句柄（权限 WAIT|CONTROL）。调用者必须属于某个进程。
fn task_spawn(entry: u64, stack: u64, arg: u64) -> i64 {
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    match proc::spawn_thread(pid, "thread", entry, stack, arg, 0) {
        // 线程对象是叶子：句柄带 DUPLICATE 与 TRANSFER，持有者可以复制或（经 Channel）传递它。
        Ok((_, task_obj)) => match proc::put_task_handle(
            task_obj,
            Rights::WAIT.union(Rights::CONTROL).union(Rights::DUPLICATE).union(Rights::TRANSFER),
        ) {
            Ok(h) => h.raw() as i64,
            Err(e) => proc_err(e),
        },
        Err(e) => proc_err(e),
    }
}

/// `system.task.qos.set(qos)`：修改调用线程的服务质量档位（0 = 交互、1 = 用户发起、2 = 工具、3 = 后台），成功返回 0。
/// 降低或不变总是允许；提升需要创建方授予的上限且不超过上限，否则 `rights_denied`（线程不能自升档位）。
/// 未定义的档位数值 ⇒ `invalid_argument`（不截断、不就近取值）。
fn task_qos_set(raw: u64) -> i64 {
    let Some(q) = Qos::from_raw(raw) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    match sched::set_current_qos(q) {
        Ok(()) => 0,
        Err(_) => err(SYSTEM_ERROR_RIGHTS_DENIED),
    }
}

/// `system.process.exit(code)`：发起本进程终止（exiting），然后结束调用线程（不返回）。
/// 其余线程在各自的下一个调度点停止；最后一个线程停止时进程进入 exited，退出码为 `code`。
fn process_exit(code: u64) -> i64 {
    if let Some(pid) = proc::current_process() {
        proc::begin_exit(pid, code as i64);
    }
    proc::thread_exit(code as i64, "process.exit")
}

/// `system.memory.map` / `protect` 的标志位：可写。
pub const MAP_WRITE: u64 = 1 << 0;
/// `system.memory.protect` 的标志位：可执行（不能与 [`MAP_WRITE`] 同时出现；`map` 不接受此位）。
pub const MAP_EXEC: u64 = 1 << 1;

fn mem_err(e: proc::MemError) -> i64 {
    match e {
        proc::MemError::Busy => err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS),
        proc::MemError::InvalidRange => err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS),
        proc::MemError::NotMapped => err(SYSTEM_MEMORY_ERROR_INVALID_ADDRESS),
        proc::MemError::AlreadyMapped => err(SYSTEM_MEMORY_ERROR_ALREADY_MAPPED),
        proc::MemError::Quota => err(SYSTEM_ERROR_QUOTA_EXCEEDED),
        proc::MemError::OutOfMemory => err(SYSTEM_MEMORY_ERROR_OUT_OF_MEMORY),
        proc::MemError::Pressure => err(SYSTEM_MEMORY_ERROR_OUT_OF_MEMORY),
        proc::MemError::NoSuchProcess => err(SYSTEM_ERROR_RIGHTS_DENIED),
    }
}

/// `system.memory.map(va, pages, flags)`：在调用者进程的私有窗口内、从 `va` 起映射 `pages` 个清零的匿名页，成功返回 0。
/// 全有或全无；区间内已有映射 ⇒ `already_mapped`；超出进程帧配额 ⇒ `quota_exceeded`。
fn memory_map(va: u64, pages: u64, flags: u64) -> i64 {
    if flags & !MAP_WRITE != 0 {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    match proc::map_anon(pid, va, pages, flags & MAP_WRITE != 0) {
        Ok(()) => 0,
        Err(e) => mem_err(e),
    }
}

/// `system.memory.unmap(va, pages)`：取消调用者进程中 `[va, va + pages 页)` 的映射，成功返回 0。
/// 全有或全无；区间内有未映射的页 ⇒ `invalid_address`，什么也不改。
fn memory_unmap(va: u64, pages: u64) -> i64 {
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    match proc::unmap_range(pid, va, pages) {
        Ok(()) => 0,
        Err(e) => mem_err(e),
    }
}

/// `system.memory.protect(va, pages, flags)`：修改调用者进程中 `[va, va + pages 页)` 的权限，成功返回 0。
/// `flags` 只能含 [`MAP_WRITE`] 或 [`MAP_EXEC`] 之一（或都不含 = 只读）；两者同时出现 ⇒ `invalid_argument`（W^X）。
/// 全有或全无；区间内有未映射的页 ⇒ `invalid_address`，什么也不改。
fn memory_protect(va: u64, pages: u64, flags: u64) -> i64 {
    if flags & !(MAP_WRITE | MAP_EXEC) != 0 || flags == MAP_WRITE | MAP_EXEC {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let Some(pid) = proc::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    match proc::protect_range(pid, va, pages, flags & MAP_WRITE != 0, flags & MAP_EXEC != 0) {
        Ok(()) => 0,
        Err(e) => mem_err(e),
    }
}

/// `system.time.wait(ticks)` 的同步形式：睡眠直到时钟前进 `ticks` 个 tick（期间不占用处理器），返回 0。
/// 同一操作也可经异步环提交（可被取消）；同步形式没有取消路径，但所属进程终止时以 cancelled 提前返回。
fn time_wait(ticks: u64) -> i64 {
    let Some(deadline) = sched::timer_ticks().checked_add(ticks) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    while sched::timer_ticks() < deadline {
        if proc::block_until(deadline).is_err() {
            return err(SYSTEM_ASYNC_ERROR_CANCELLED);
        }
    }
    0
}

/// 按 ID 分派到真实实现。
fn execute(e: &AbiEntry, a: &SyscallArgs, task_id: u64) -> i64 {
    match e.id {
        SYSTEM_TASK_EXIT => {
            let code = a.args[0] as i64;
            {
                let mut g = LAST_EXIT.lock();
                g.0 = Some((task_id, code));
                g.1 += 1;
            }
            kprintln!("[JSR-SYSCALL] exit name={} id={} code={} action=task_exited", e.name, e.id, code);
            proc::thread_exit(code, "exit")
        }
        SYSTEM_TASK_YIELD => {
            sched::yield_now();
            0
        }
        SYSTEM_TIME_NOW => sched::timer_ticks() as i64,
        SYSTEM_CONSOLE_WRITE => console_write(a.args[0], a.args[1]),
        SYSTEM_TASK_SPAWN => task_spawn(a.args[0], a.args[1], a.args[2]),
        SYSTEM_HANDLE_CLOSE => match proc::close_handle(handle_arg(a.args[0])) {
            Ok(()) => 0,
            Err(e) => proc_err(e),
        },
        SYSTEM_HANDLE_DUPLICATE => {
            let Some(rights) = rights_arg(a.args[1]) else { return err(SYSTEM_ERROR_INVALID_ARGUMENT) };
            match proc::duplicate_current(handle_arg(a.args[0]), rights) {
                Ok(h) => h.raw() as i64,
                Err(e) => proc_err(e),
            }
        }
        SYSTEM_HANDLE_RESTRICT => {
            let Some(rights) = rights_arg(a.args[1]) else { return err(SYSTEM_ERROR_INVALID_ARGUMENT) };
            match proc::restrict_current(handle_arg(a.args[0]), rights) {
                Ok(()) => 0,
                Err(e) => proc_err(e),
            }
        }
        // 登记了却没有实现的操作在启动自检时就会被拦下，运行到这里说明自检被绕过。
        SYSTEM_ASYNC_RING_CREATE => crate::ring::sys_create(a.args[0]),
        SYSTEM_ASYNC_RING_ENTER => crate::ring::sys_enter(a.args[0], a.args[1]),
        SYSTEM_ASYNC_CANCEL => crate::ring::sys_cancel(a.args[0], a.args[1]),
        SYSTEM_TIME_WAIT => time_wait(a.args[0]),
        SYSTEM_CHANNEL_CREATE => crate::ipc::sys_create(a.args[0]),
        SYSTEM_CHANNEL_SEND => crate::ipc::sys_send(a.args[0], a.args[1]),
        SYSTEM_CHANNEL_RECV => crate::ipc::sys_recv(a.args[0], a.args[1]),
        SYSTEM_PROCESS_EXIT => process_exit(a.args[0]),
        SYSTEM_TASK_WAIT => crate::ring::sys_wait(a.args[0], kernel_core::object::ObjectType::Task),
        SYSTEM_PROCESS_WAIT => crate::ring::sys_wait(a.args[0], kernel_core::object::ObjectType::Process),
        SYSTEM_MEMORY_MAP => memory_map(a.args[0], a.args[1], a.args[2]),
        SYSTEM_MEMORY_UNMAP => memory_unmap(a.args[0], a.args[1]),
        SYSTEM_MEMORY_PROTECT => memory_protect(a.args[0], a.args[1], a.args[2]),
        SYSTEM_TASK_QOS_SET => task_qos_set(a.args[0]),
        SYSTEM_PROCESS_SPAWN => crate::proc::spawn::sys_spawn(a.args[0]),
        // 系统调用只能返回标量：`list` 返回内建 Profile 的数量，具体描述用 `get` 按下标取。
        SYSTEM_PROFILE_LIST => profile::count() as i64,
        SYSTEM_PROFILE_GET => profile_get(a.args[0], a.args[1], a.args[2]),
        SYSTEM_DEVICE_LIST => device_list(a.args[0], a.args[1], a.args[2]),
        SYSTEM_DEVICE_OPEN => device_open(a.args[0], a.args[1]),
        SYSTEM_DEVICE_GET => device_get(a.args[0], a.args[1], a.args[2]),
        SYSTEM_DEVICE_MAP => device_map(a.args[0], a.args[1], a.args[2]),
        SYSTEM_DEVICE_CAPABILITY_LIST => device_capability_list(a.args[0], a.args[1], a.args[2]),
        SYSTEM_DEVICE_INTERRUPT_CREATE => crate::interrupt::sys_bind(a.args[0], a.args[1], a.args[2]),
        // 等待中断只有异步形式：结果作为完成记录交付，同步调用没有可以阻塞的语义
        SYSTEM_DEVICE_INTERRUPT_WAIT => err(SYSTEM_ASYNC_ERROR_RING_ONLY),
        _ => err(SYSTEM_ERROR_UNSUPPORTED),
    }
}

/// `system.profile.get(index, buf, cap)`：把第 `index` 个内建 Profile 的键=值描述写入用户缓冲区。
///
/// 失败模式：
/// * 缓冲区为空或超过 [`PROFILE_TEXT_MAX`] ⇒ `invalid_argument`；
/// * 下标越界、Profile 自身不合法或描述装不下用户缓冲区 ⇒ `profile.error.buffer_too_small`
///   （调用方据此扩大缓冲区或换下标，不需要解析自然语言）。
/// English: write the structured description of one profile into a user buffer.
fn profile_get(index: u64, ptr: u64, cap: u64) -> i64 {
    let Ok(capacity) = usize::try_from(cap) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity == 0 || capacity > PROFILE_TEXT_MAX {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    }
    let mut buf = [0u8; PROFILE_TEXT_MAX];
    let Some(len) = profile::render(index as usize, &mut buf) else {
        return err(SYSTEM_PROFILE_ERROR_BUFFER_TOO_SMALL);
    };
    if len > capacity {
        return err(SYSTEM_PROFILE_ERROR_BUFFER_TOO_SMALL);
    }
    if let Err(e) = copy_to_user(ptr, &buf[..len], PROFILE_TEXT_MAX) {
        return user_ptr_err(e);
    }
    len as i64
}

/// 设备句柄允许的最大权限集合：读取配置 / 资源描述、映射寄存器窗口、控制（绑定中断）、复制与传递。
/// 调用者只能申请这个集合的子集；设备访问能力本身由系统调用集合授予。
/// Maximum rights a device handle may carry; callers may request a subset only.
pub const DEVICE_RIGHTS: Rights =
    Rights::READ.union(Rights::MAP).union(Rights::CONTROL).union(Rights::DUPLICATE).union(Rights::TRANSFER);

/// `system.device.list(filter, buf, cap)`：把匹配的启动期 PCI 功能写成定长记录。
///
/// 返回**需要**的字节数。`cap` 足够时全部记录写入用户缓冲区；不足时一个字节也不写，返回值大于 `cap`，
/// 调用者据此扩大缓冲区后重试。过滤字的布局见 [`kernel_core::device::Filter`]。
/// Lists matching devices; returns the required byte count and copies only when the buffer is large enough.
fn device_list(filter: u64, ptr: u64, cap: u64) -> i64 {
    let Ok(word) = u32::try_from(filter) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    let Some(filter) = devabi::Filter::from_word(word) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    let Ok(capacity) = usize::try_from(cap) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    let matching = crate::pci::table().devices().filter(|device| filter.matches(&device.header)).count();
    let required = matching * devabi::RECORD_SIZE;
    if required > capacity {
        return required as i64;
    }
    let mut buf = vec![0u8; required];
    let mut at = 0usize;
    for device in crate::pci::table().devices() {
        if !filter.matches(&device.header) {
            continue;
        }
        let record = devabi::Record::from_parts(device.bdf, &device.header, &device.bars);
        let mut raw = [0u8; devabi::RECORD_SIZE];
        record.encode(&mut raw);
        buf[at..at + devabi::RECORD_SIZE].copy_from_slice(&raw);
        at += devabi::RECORD_SIZE;
    }
    if required > 0 {
        if let Err(e) = copy_to_user(ptr, &buf, required) {
            return user_ptr_err(e);
        }
    }
    required as i64
}

/// `system.device.open(bdf, rights)`：按 BDF 打开已枚举的设备，返回设备句柄。
///
/// 失败路径：BDF 编码非法 ⇒ `invalid_argument`；设备不在启动期设备表中 ⇒ `device.error.not_found`；
/// 申请空权限、未定义权限或超出 [`DEVICE_RIGHTS`] ⇒ `rights_denied`；句柄表满 ⇒ `handle.error.table_full`。
/// Opens an enumerated device by BDF and returns a handle carrying a subset of [`DEVICE_RIGHTS`].
fn device_open(bdf: u64, rights: u64) -> i64 {
    let Ok(raw) = u32::try_from(bdf) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    let Some(bdf) = devabi::unpack_bdf(raw) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    let Some(rights) = rights_arg(rights) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if rights.is_empty() || !DEVICE_RIGHTS.contains(rights) {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    }
    if crate::pci::table().find(bdf).is_none() {
        return err(SYSTEM_DEVICE_ERROR_NOT_FOUND);
    }
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    match proc::grant_new(pid, KObject::Device(DeviceObj { bdf }), ObjectType::Device, rights) {
        Ok(h) => h.raw() as i64,
        Err(e) => proc_err(e),
    }
}

/// `system.device.get(handle, buf, cap)`：经设备句柄读取完整描述，返回写入字节数。
///
/// 句柄必须有效、类型为 Device 且带 `READ`；缓冲区小于 [`kernel_core::device::DESC_SIZE`] ⇒
/// `device.error.buffer_too_small`，不写任何字节。设备表项常驻，句柄关闭后描述仍可由新句柄读取。
/// Reads the full description through a device handle.
fn device_get(handle: u64, ptr: u64, cap: u64) -> i64 {
    let Ok(capacity) = usize::try_from(cap) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    if capacity < devabi::DESC_SIZE {
        return err(SYSTEM_DEVICE_ERROR_BUFFER_TOO_SMALL);
    }
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    let resolved = kobj::with(|t| -> Result<Bdf, ProcError> {
        let id = proc::resolve_in(t, pid, handle_arg(handle), ObjectType::Device, Rights::READ)?;
        match t.get(id) {
            Ok(KObject::Device(device)) => Ok(device.bdf),
            _ => Err(ProcError::Handle(HandleError::Invalid)),
        }
    });
    let bdf = match resolved {
        Ok(bdf) => bdf,
        Err(e) => return proc_err(e),
    };
    let Some(device) = crate::pci::table().find(bdf) else {
        return err(SYSTEM_DEVICE_ERROR_NOT_FOUND);
    };
    let desc = devabi::Desc::from_parts(device.bdf, &device.header, &device.bars);
    let mut raw = [0u8; devabi::DESC_SIZE];
    desc.encode(&mut raw);
    if let Err(e) = copy_to_user(ptr, &raw, devabi::DESC_SIZE) {
        return user_ptr_err(e);
    }
    devabi::DESC_SIZE as i64
}

/// `system.device.capability.list(handle, buf, cap)`：经设备句柄列出厂商专有能力，返回需要的字节数。
///
/// 记录布局见 [`kernel_core::device::CapabilityRecord`]。缓冲区不足时一个字节也不写，返回所需字节数；
/// 能力链在启动期遍历失败 ⇒ `device.error.bad_capability`（不返回不完整的能力表）。
/// Lists vendor-specific capabilities of the device behind a handle (read-only).
fn device_capability_list(handle: u64, ptr: u64, cap: u64) -> i64 {
    let Ok(capacity) = usize::try_from(cap) else {
        return err(SYSTEM_ERROR_INVALID_ARGUMENT);
    };
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    let resolved = kobj::with(|t| -> Result<Bdf, ProcError> {
        let id = proc::resolve_in(t, pid, handle_arg(handle), ObjectType::Device, Rights::READ)?;
        match t.get(id) {
            Ok(KObject::Device(device)) => Ok(device.bdf),
            _ => Err(ProcError::Handle(HandleError::Invalid)),
        }
    });
    let bdf = match resolved {
        Ok(bdf) => bdf,
        Err(e) => return proc_err(e),
    };
    let Some(device) = crate::pci::table().find(bdf) else {
        return err(SYSTEM_DEVICE_ERROR_NOT_FOUND);
    };
    if device.caps_error {
        return err(SYSTEM_DEVICE_ERROR_BAD_CAPABILITY);
    }
    let required = device.cap_count * devabi::CAP_RECORD_SIZE;
    if required > capacity {
        return required as i64;
    }
    if required == 0 {
        return 0;
    }
    let mut buf = vec![0u8; required];
    for (i, record) in device.caps[..device.cap_count].iter().enumerate() {
        let mut raw = [0u8; devabi::CAP_RECORD_SIZE];
        record.encode(&mut raw);
        let at = i * devabi::CAP_RECORD_SIZE;
        buf[at..at + devabi::CAP_RECORD_SIZE].copy_from_slice(&raw);
    }
    if let Err(e) = copy_to_user(ptr, &buf, required) {
        return user_ptr_err(e);
    }
    required as i64
}

/// `system.device.map(handle, bar_index, va)`：把一个内存型 BAR 映射进调用者进程的私有窗口，成功返回 0。
///
/// 句柄必须类型为 Device 且带 `MAP`；`bar_index` 必须指向已实现的内存 BAR（I/O 端口 BAR 被拒，
/// 本步不做端口授权）。映射页固定为 `USER | WRITE | NO_CACHE` 且不可执行；同一进程内同一 BAR 只允许
/// 一个映射（重复请求 ⇒ `memory.error.already_mapped`）。关闭创建映射的句柄或进程退出时映射被撤销，
/// BAR 不是 RAM，因此不进入页帧分配器，也不改变帧计数。
/// Maps one memory BAR of the device behind a handle into the caller's private window.
fn device_map(handle: u64, bar_index: u64, va: u64) -> i64 {
    let Ok(index) = u8::try_from(bar_index) else {
        return err(SYSTEM_DEVICE_ERROR_BAR_OUT_OF_RANGE);
    };
    if index as usize >= MAX_BARS {
        return err(SYSTEM_DEVICE_ERROR_BAR_OUT_OF_RANGE);
    }
    let Some(pid) = proc::current_process() else {
        return err(SYSTEM_ERROR_RIGHTS_DENIED);
    };
    let resolved = kobj::with(|t| -> Result<Bdf, ProcError> {
        let id = proc::resolve_in(t, pid, handle_arg(handle), ObjectType::Device, Rights::MAP)?;
        match t.get(id) {
            Ok(KObject::Device(device)) => Ok(device.bdf),
            _ => Err(ProcError::Handle(HandleError::Invalid)),
        }
    });
    let bdf = match resolved {
        Ok(bdf) => bdf,
        Err(e) => return proc_err(e),
    };
    let Some(device) = crate::pci::table().find(bdf) else {
        return err(SYSTEM_DEVICE_ERROR_NOT_FOUND);
    };
    let (phys, size) = match device.bars[index as usize] {
        Bar::None => return err(SYSTEM_DEVICE_ERROR_BAR_OUT_OF_RANGE),
        Bar::Io { .. } => return err(SYSTEM_DEVICE_ERROR_BAR_NOT_MEMORY),
        Bar::Memory { base, size, .. } => (base, size),
    };
    if phys == 0
        || size == 0
        || !size.is_power_of_two()
        || phys % FRAME_SIZE != 0
        || size % FRAME_SIZE != 0
        || phys.checked_add(size).is_none()
    {
        return err(SYSTEM_DEVICE_ERROR_BAR_INVALID);
    }
    match proc::map_device_bar(pid, handle_arg(handle), index, va, phys, size) {
        Ok(()) => {
            let pages = size / FRAME_SIZE;
            kprintln!(
                "[JSR-DRV1D] map bdf=0x{:06x} bar={} va=0x{:x} pages={} nocache=true exec=false",
                devabi::pack_bdf(bdf),
                index,
                va,
                pages
            );
            0
        }
        Err(e) => mem_err(e),
    }
}
