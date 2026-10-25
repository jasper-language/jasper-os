//! 用户指针安全（M3.3；HARDEN-1C 改为多核安全）：系统调用参数中的用户地址的校验与复制。
//! User-pointer safety: validation and copying of user addresses passed to system calls (SMP-safe).
//!
//! # 规则（任何一条不满足都返回错误，**绝不**让内核去碰这个地址）
//! 1. 长度不超过调用方给定的上限；`[addr, addr+len)` 不溢出
//! 2. 整个区间位于当前进程地址空间的**私有窗口**内（内核地址、窗口外地址一律拒绝）
//! 3. 区间覆盖的**每一页**都已映射，且带「用户可访问」权限；写入用户时还要求「可写」
//! 4. 全有或全无：任一页不满足 ⇒ 一个字节也不复制
//!
//! # 多核下为什么要先固定再复制
//! 早先的实现「先逐页校验、再逐页复制」，两遍之间不持任何锁，依赖「系统调用期间关中断、单 CPU」。
//! 多核下同一进程的另一个线程可以在别的核上并发取消映射：校验通过的帧被归还、又分给别的进程，
//! 内核随后的复制就会读写别人的内存（跨进程的释放后使用）。
//!
//! 现在的做法复用异步 I/O 与 IPC 已经验证过的路径（[`crate::proc::pin_user_in`]）：
//! * **在对象表锁内**完成「查页表 + 校验 + 固定物理帧」。取消映射也在同一把锁内修改页表，
//!   两者因此互斥：要么固定发生在取消映射之前，要么校验看到的已经是取消之后的页表并拒绝。
//! * 放锁之后经内核的物理内存映射复制。此时即使用户取消映射，被固定的帧也不会被回收或复用
//!   （取消映射只把它记为「孤儿」，最后一次解除固定时才归还，见 [`crate::mm::pin`]）。
//!   结果等价于「复制发生在取消映射之前」——不会触碰别的进程的内存。
//! * 复制结束即解除固定（[`PinnedRange`] 离开作用域）。
//!
//! 同理，并发的改权限（例如改为只读）也只会被线性化为「复制在前、改权限在后」。
//!
//! # 不属于任何进程的用户任务（早期里程碑的探针）
//! M3.x 的探针任务有自己的地址空间，但不属于进程：单线程，且只被允许调用输出与退出。
//! 它们无法修改自己的映射，也没有共享地址空间的其他线程，因此不存在并发取消映射；
//! 对它们沿用「逐页校验、再经物理映射复制」的直接路径。这条路径的前提在运行时检查：
//! 任务的系统调用集合里只要含有任何会改映射或创建线程 / 进程的操作，就拒绝走这条路径。
//!
//! # 已持有对象表锁的调用者
//! 少数路径必须在对象表锁内完成复制（例如异步环「复制成功才消费完成记录」）。它们用
//! [`copy_to_user_in`]，直接使用调用者持有的锁；对象表锁不可重入，在锁内调用 [`copy_to_user`] 会自锁。

use kernel_core::frame::FRAME_SIZE;
use kernel_core::objtable::ObjId;
use kernel_core::paging::{MapError, MapFlags};

use super::{phys_to_virt, space};
use crate::kobj;
use crate::mm::pin::PinnedRange;
use crate::proc::{self, ProcError};
use crate::syscall::table as abi;
use crate::{arch, boot, sched};

/// 测试钩子：在「校验 / 固定」与「复制」之间让当前线程睡眠的 tick 数（0 = 关闭，默认）。
///
/// 只供 HARDEN-1C 的并发演练使用：把原本只有几十纳秒的窗口撑大到一个 tick，并在窗口内**让出处理器**，
/// 让同进程的翻页线程与另一个进程真正有机会在窗口内取消映射、申请帧——修复后的实现先固定后等待，
/// 窗口再大也不会触碰别人的内存；未修复的实现在撑大的窗口下会写坏受害进程（对照实验，见 `uptr_demo`）。
/// 用睡眠而不是自旋：系统调用路径不可被抢占，自旋会一直占着这个核，同核的其他线程排不上，竞态反而不发生。
/// Test hook: ticks to sleep between validation/pinning and the copy (0 = off).
pub static RACE_WINDOW_TICKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// 诊断计数：直接路径上「准备复制时，目标帧已不再映射在原地址」的次数——即内核正要读写一块
/// 已不属于该任务的帧。修复后只有不会被并发修改映射的探针任务走直接路径，这个计数应当恒为 0；
/// 对照实验把进程也放到直接路径上时，它直接证明「先校验、后复制」会触碰已回收的帧。
/// Diagnostic: copies about to touch a frame that is no longer mapped at the address (direct path only).
static STALE_COPIES: crate::sync::IrqU64 = crate::sync::IrqU64::new(0);

/// 累计陈旧复制次数（见 [`STALE_COPIES`]）。
pub fn stale_copies() -> u64 {
    STALE_COPIES.load(core::sync::atomic::Ordering::Relaxed)
}

fn race_window() {
    let n = RACE_WINDOW_TICKS.load(core::sync::atomic::Ordering::Relaxed);
    if n > 0 {
        sched::sleep_until(sched::timer_ticks() + n as u64);
    }
}

/// 用户指针错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPtrError {
    /// 长度超过上限（`system.error.invalid_argument`）。
    TooLong,
    /// Fixed-page reference quota refused; no frames were pinned.
    Quota,
    /// Unable to reserve metadata for an otherwise valid pinned range.
    OutOfMemory,
    /// 地址溢出、不在私有窗口、未映射或权限不足（`system.memory.error.invalid_address`）。
    InvalidAddress,
    /// 当前任务不是用户任务（不属于任何进程）。
    NotUserTask,
}

/// 在对象表锁 `t` 内校验并固定进程 `pid` 的 `[addr, addr+len)`（`write` 时要求可写）。
fn pin_in(t: &mut kobj::Table, pid: ObjId, addr: u64, len: usize, write: bool) -> Result<PinnedRange, UserPtrError> {
    proc::pin_user_in(t, pid, addr, len, write).map_err(|e| match e {
        ProcError::OutOfFrames => UserPtrError::OutOfMemory,
        ProcError::MemoryQuota => UserPtrError::Quota,
        ProcError::NoSuchProcess => UserPtrError::NotUserTask,
        ProcError::Map(MapError::InvalidAddress | MapError::NotMapped | MapError::Busy) => UserPtrError::InvalidAddress,
        _ => UserPtrError::InvalidAddress,
    })
}

/// 当前用户任务的复制路径。
enum Target {
    /// 属于进程：在对象表锁内固定后复制。
    Process(ObjId),
    /// 不属于进程、且无法修改映射的探针任务：直接按页表复制。
    Unshared(arch::SpaceRoot),
}

/// 会改动地址空间映射或产生共享地址空间的执行流的操作：不属于进程的任务若允许其中任何一个，就不能走直接路径。
const MUTATING: [u32; 10] = [
    abi::SYSTEM_EVENT_SOURCE_CREATE,
    abi::SYSTEM_EVENT_SUBSCRIPTION_CREATE,
    abi::SYSTEM_MEMORY_OBJECT_CREATE,
    abi::SYSTEM_MEMORY_OBJECT_MAP,
    abi::SYSTEM_MEMORY_OBJECT_UNMAP,
    abi::SYSTEM_MEMORY_MAP,
    abi::SYSTEM_MEMORY_UNMAP,
    abi::SYSTEM_MEMORY_PROTECT,
    abi::SYSTEM_TASK_SPAWN,
    abi::SYSTEM_PROCESS_SPAWN,
];

fn current() -> Result<Target, UserPtrError> {
    if let Some(pid) = proc::current_process() {
        return Ok(Target::Process(pid));
    }
    let root = sched::current_space().ok_or(UserPtrError::NotUserTask)?;
    let calls = sched::current_syscalls();
    if MUTATING.iter().any(|&id| calls.contains(id as u64)) {
        return Err(UserPtrError::NotUserTask);
    }
    Ok(Target::Unshared(root))
}

/// 直接路径（仅限 [`Target::Unshared`]）：逐页校验 `[addr, addr+len)`，全部通过后逐段调用
/// `f(物理地址对应的内核指针, 段长, 段在缓冲区中的偏移)`。
fn unshared_chunks(
    root: arch::SpaceRoot,
    addr: u64,
    len: usize,
    write: bool,
    mut f: impl FnMut(*mut u8, usize, usize),
) -> Result<(), UserPtrError> {
    if len == 0 {
        return Ok(());
    }
    let end = addr.checked_add(len as u64).ok_or(UserPtrError::InvalidAddress)?;
    if !space::in_private_window(addr) || !space::in_private_window(end - 1) {
        return Err(UserPtrError::InvalidAddress);
    }
    let offset = boot::get().and_then(|b| b.phys_offset).ok_or(UserPtrError::InvalidAddress)?;
    // SAFETY：root 来自当前任务、仍然有效；该任务不能修改自己的映射，也没有共享地址空间的其他执行流（见 `current`）。
    let lookup = |va: u64| unsafe { arch::translate_in(root, offset, va) };
    let mut va = addr - addr % FRAME_SIZE;
    while va < end {
        match lookup(va) {
            Some((_, flags)) if flags.contains(MapFlags::USER) && (!write || flags.contains(MapFlags::WRITE)) => {}
            _ => return Err(UserPtrError::InvalidAddress),
        }
        va += FRAME_SIZE;
    }
    let mut cur = addr;
    let mut done = 0usize;
    while cur < end {
        let page_off = cur % FRAME_SIZE;
        let chunk = ((FRAME_SIZE - page_off) as usize).min(len - done);
        let (frame, _) = lookup(cur - page_off).ok_or(UserPtrError::InvalidAddress)?;
        let kptr = phys_to_virt(frame.start() + page_off).ok_or(UserPtrError::InvalidAddress)?;
        // 测试钩子的位置与固定路径对齐：都在「已确定要读写哪块物理帧」之后、真正复制之前。
        race_window();
        if lookup(cur - page_off).map(|(f, _)| f) != Some(frame) {
            STALE_COPIES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        f(kptr, chunk, done);
        done += chunk;
        cur += chunk as u64;
    }
    Ok(())
}

/// 从用户空间 `src` 复制 `dst.len()` 字节到内核缓冲区（长度上限 `max`）。
/// Copy `dst.len()` bytes from user address `src` (all-or-nothing, SMP-safe).
pub fn copy_from_user(dst: &mut [u8], src: u64, max: usize) -> Result<(), UserPtrError> {
    if dst.len() > max {
        return Err(UserPtrError::TooLong);
    }
    match current()? {
        Target::Process(pid) => {
            let range = kobj::with(|t| pin_in(t, pid, src, dst.len(), false))?;
            race_window();
            if range.read_at(0, dst) {
                Ok(())
            } else {
                Err(UserPtrError::InvalidAddress)
            }
        }
        Target::Unshared(root) => unshared_chunks(root, src, dst.len(), false, |kptr, n, at| {
            // SAFETY：kptr 指向已校验的用户帧（经物理映射），n 不越过页尾；dst[at..at+n] 在界内。
            unsafe { core::ptr::copy_nonoverlapping(kptr, dst[at..at + n].as_mut_ptr(), n) };
        }),
    }
}

/// 把内核缓冲区 `src` 复制到用户空间 `dst`（要求目标页可写；长度上限 `max`）。
/// Copy `src` to user address `dst` (target must be writable; all-or-nothing, SMP-safe).
pub fn copy_to_user(dst: u64, src: &[u8], max: usize) -> Result<(), UserPtrError> {
    if src.len() > max {
        return Err(UserPtrError::TooLong);
    }
    match current()? {
        Target::Process(pid) => {
            let range = kobj::with(|t| pin_in(t, pid, dst, src.len(), true))?;
            race_window();
            if range.write_at(0, src) {
                Ok(())
            } else {
                Err(UserPtrError::InvalidAddress)
            }
        }
        Target::Unshared(root) => unshared_chunks(root, dst, src.len(), true, |kptr, n, at| {
            // SAFETY：同上；目标页已校验为用户可写。
            unsafe { core::ptr::copy_nonoverlapping(src[at..at + n].as_ptr(), kptr, n) };
        }),
    }
}

/// 同 [`copy_to_user`]，供**已经持有对象表锁**的调用者使用：在 `t` 内校验、固定并复制，进程由调用者给出。
/// Same as [`copy_to_user`] for callers that already hold the object-table lock.
pub fn copy_to_user_in(t: &mut kobj::Table, pid: ObjId, dst: u64, src: &[u8], max: usize) -> Result<(), UserPtrError> {
    if src.len() > max {
        return Err(UserPtrError::TooLong);
    }
    let range = pin_in(t, pid, dst, src.len(), true)?;
    if range.write_at(0, src) {
        Ok(())
    } else {
        Err(UserPtrError::InvalidAddress)
    }
}
