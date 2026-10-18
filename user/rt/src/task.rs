//! 线程与进程：`spawn` / `join`、让出、退出、等待。
//! Threads and processes.
//!
//! # 线程栈
//! 每个线程的栈占栈区间（[`sys::STACKS_BASE`]）中的一个槽位：只映射槽位顶部 [`sys::STACK_PAGES`] 页，
//! 其下未映射，栈溢出会触发页故障（终止本进程）而不是悄悄写坏相邻内存。
//! [`JoinHandle::join`] 等到线程退出后取消栈的映射并归还槽位；不 join 就丢弃 `JoinHandle`
//! 等于让线程脱离——它的栈留到进程退出时由内核回收。

use alloc::boxed::Box;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::error::{check, Error, Result};
use crate::handle::Handle;
use crate::{ids, mem, sys};

/// 结束调用线程（不返回）。本进程最后一个线程结束时，进程以 `code` 退出。
pub fn exit(code: u64) -> ! {
    sys::call(ids::SYSTEM_TASK_EXIT, code, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// 以 `code` 终止整个进程（其余线程在各自下一个调度点停止；不返回）。
pub fn exit_process(code: u64) -> ! {
    sys::call(ids::SYSTEM_PROCESS_EXIT, code, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

/// 让出处理器。
pub fn yield_now() {
    sys::call(ids::SYSTEM_TASK_YIELD, 0, 0, 0);
}

/// 服务质量档位（数值越小越优先）：调度器按档位严格优先，档内按近期 CPU 用量轮转，每档有最低份额。
/// Quality-of-service class of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum Qos {
    /// 交互：直接响应用户操作。
    Interactive = 0,
    /// 用户发起：用户在等结果的工作（新线程的默认档位）。
    UserInitiated = 1,
    /// 工具：用户知道在进行、不急等结果的工作。
    Utility = 2,
    /// 后台：用户看不见的维护工作；有更高档工作时只拿最低份额。
    Background = 3,
}

/// 设置调用线程的服务质量档位（`system.task.qos.set`）。
///
/// 降低或不变总是成功；提升需要创建方授予的上限，否则返回 [`Error::RIGHTS_DENIED`]——
/// 线程降档之后不能自己升回去。新线程继承创建者当时的档位。
pub fn set_qos(q: Qos) -> Result<()> {
    set_qos_raw(q as u64)
}

/// 以原始数值设置档位（未定义的数值返回 [`Error::INVALID_ARGUMENT`]；供健壮性检查使用）。
pub fn set_qos_raw(v: u64) -> Result<()> {
    check(sys::call(ids::SYSTEM_TASK_QOS_SET, v, 0, 0)).map(|_| ())
}

/// 同步等待句柄所指的线程退出，返回其退出码（按 32 位无符号值报告）。
pub fn wait_task(h: &Handle) -> Result<u64> {
    check(sys::call(ids::SYSTEM_TASK_WAIT, h.raw() as u64, 0, 0))
}

/// 同步等待句柄所指的进程退出，返回其退出码（按 32 位无符号值报告）。
pub fn wait_process(h: &Handle) -> Result<u64> {
    check(sys::call(ids::SYSTEM_PROCESS_WAIT, h.raw() as u64, 0, 0))
}

/// 已占用的栈槽位（位图）。
static SLOTS: AtomicU64 = AtomicU64::new(0);

fn take_slot() -> Option<u32> {
    let mut cur = SLOTS.load(Ordering::Relaxed);
    loop {
        let free = (!cur).trailing_zeros();
        if free >= sys::STACK_SLOTS {
            return None;
        }
        match SLOTS.compare_exchange_weak(cur, cur | 1 << free, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return Some(free),
            Err(now) => cur = now,
        }
    }
}

fn put_slot(slot: u32) {
    SLOTS.fetch_and(!(1u64 << slot), Ordering::AcqRel);
}

/// 槽位 `slot` 的栈：返回 (映射起点, 栈顶)。
fn stack_of(slot: u32) -> (u64, u64) {
    let top = sys::STACKS_BASE + (slot as u64 + 1) * sys::STACK_STRIDE;
    (top - sys::STACK_PAGES * sys::PAGE, top)
}

type Job = Box<dyn FnOnce() -> u64 + Send + 'static>;

// 线程入口：内核以 (参数, 0) 进入，此时栈顶按页对齐；先对齐到 16 字节再调用，满足各指令集的调用约定。
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".pushsection .text.jsr_rt_thread_entry,\"ax\"",
    ".global jsr_rt_thread_entry",
    "jsr_rt_thread_entry:",
    "    and rsp, -16",
    "    call {main}",
    "    ud2",
    ".popsection",
    main = sym thread_main,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".pushsection .text.jsr_rt_thread_entry,\"ax\"",
    ".global jsr_rt_thread_entry",
    "jsr_rt_thread_entry:",
    "    mov x9, sp",
    "    and sp, x9, #-16",
    "    bl {main}",
    "    udf #0",
    ".popsection",
    main = sym thread_main,
);

extern "C" {
    fn jsr_rt_thread_entry();
}

extern "C" fn thread_main(arg: u64) -> ! {
    // SAFETY：arg 是 spawn 里 Box::into_raw 得到的指针，只在这里取回一次。
    let job: Box<Job> = unsafe { Box::from_raw(arg as *mut Job) };
    let code = job();
    exit(code)
}

/// 已创建的线程：持有指向它的句柄与它的栈槽位。
pub struct JoinHandle {
    handle: Handle,
    slot: u32,
}

impl JoinHandle {
    /// 指向该线程的句柄（WAIT | CONTROL | DUPLICATE | TRANSFER）。
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// 等待线程退出并返回其退出码；之后取消其栈的映射、归还槽位、关闭句柄。
    pub fn join(self) -> Result<u64> {
        let code = wait_task(&self.handle)?;
        let (base, _) = stack_of(self.slot);
        let r = mem::unmap(base, sys::STACK_PAGES);
        put_slot(self.slot);
        r.map(|_| code)
    }
}

/// 在本进程中创建线程运行 `f`；`f` 的返回值是线程退出码。
///
/// 失败（栈槽位用尽、帧配额不足、调度器槽位已满……）时已分配的栈与闭包都会归还。
pub fn spawn<F>(f: F) -> Result<JoinHandle>
where
    F: FnOnce() -> u64 + Send + 'static,
{
    let slot = take_slot().ok_or(Error::QUOTA_EXCEEDED)?;
    let (base, top) = stack_of(slot);
    if let Err(e) = mem::map(base, sys::STACK_PAGES, mem::WRITE) {
        put_slot(slot);
        return Err(e);
    }
    let job: Box<Job> = Box::new(Box::new(f));
    let arg = Box::into_raw(job) as u64;
    let ret = sys::call(ids::SYSTEM_TASK_SPAWN, jsr_rt_thread_entry as *const () as u64, top, arg);
    match check(ret) {
        Ok(raw) => Ok(JoinHandle {
            // SAFETY：内核刚放入本进程句柄表的新句柄。
            handle: unsafe { Handle::from_raw(raw as u32) },
            slot,
        }),
        Err(e) => {
            // 线程没有创建：闭包与栈都还归我们
            // SAFETY：arg 来自上面的 Box::into_raw，且没有交给任何线程。
            drop(unsafe { Box::from_raw(arg as *mut Job) });
            let _ = mem::unmap(base, sys::STACK_PAGES);
            put_slot(slot);
            Err(e)
        }
    }
}
