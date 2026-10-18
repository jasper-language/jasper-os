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

use kernel_core::object::{HandleError, HandleId, Rights};
use kernel_core::sched::Qos;

use crate::mm::user::{copy_from_user, UserPtrError};
use crate::proc::{self, ProcError};
use crate::sync::IrqSpinLock;
use crate::{kprintln, sched};

/// `system.console.write` 单次最多写入的字节数。
pub const CONSOLE_WRITE_MAX: usize = 4096;
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
    u32::try_from(v).map(HandleId::from_raw).unwrap_or(HandleId::NULL)
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
static LAST_EXIT: IrqSpinLock<(Option<(u64, i64)>, u32)> = IrqSpinLock::new((None, 0));
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
    let ret = execute(e, a, task_id.0);
    if trace {
        kprintln!("[JSR-SYSCALL] exit name={} id={} ret={} status={}", e.name, e.id, ret, error_name(ret));
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
        ProcError::NoSuchProcess | ProcError::Exited => err(SYSTEM_ERROR_RIGHTS_DENIED),
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
        _ => err(SYSTEM_ERROR_UNSUPPORTED),
    }
}
