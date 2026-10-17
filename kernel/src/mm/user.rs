//! 用户指针安全（M3.3）：系统调用参数中的用户地址的校验与复制。
//! User-pointer safety: validation and copying of user addresses passed to system calls.
//!
//! # 规则（任何一条不满足都返回错误，**绝不**让内核去碰这个地址）
//! 1. 长度不超过调用方给定的上限；`[addr, addr+len)` 不溢出
//! 2. 整个区间位于当前任务地址空间的**私有窗口**内（内核地址、窗口外地址一律拒绝）
//! 3. 区间覆盖的**每一页**都已映射，且带「用户可访问」权限；写入用户时还要求「可写」
//!
//! # 为什么经物理内存映射复制，而不直接解引用用户地址
//! 校验通过后按页查出物理帧，经内核的全物理内存映射读写。这样即使用户映射了奇怪的东西
//! （设备内存、与内核共享的帧……），内核也只触碰「刚验证过、属于该任务私有窗口」的那些帧；
//! 并且系统调用期间关中断、单 CPU，校验与复制之间不存在映射被并发改动的窗口（TOCTOU）。
//! SMP 时需改为在地址空间锁内完成「校验 + 复制」。

use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::{MapFlags, PageMapper, VirtPage};

use super::{phys_to_virt, space};
use crate::{arch, boot, sched};

/// 用户指针错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPtrError {
    /// 长度超过上限（`system.error.invalid_argument`）。
    TooLong,
    /// 地址溢出、不在私有窗口、未映射或权限不足（`system.memory.error.invalid_address`）。
    InvalidAddress,
    /// 当前任务不是用户任务（没有自己的地址空间）。
    NotUserTask,
}

/// 逐页校验 `[addr, addr+len)` 并对每段调用 `f(物理地址对应的内核指针, 段长, 段在缓冲区中的偏移)`。
fn for_each_chunk(
    addr: u64,
    len: usize,
    need: MapFlags,
    mut f: impl FnMut(*mut u8, usize, usize),
) -> Result<(), UserPtrError> {
    if len == 0 {
        return Ok(());
    }
    let end = addr.checked_add(len as u64).ok_or(UserPtrError::InvalidAddress)?;
    if !space::in_private_window(addr) || !space::in_private_window(end - 1) {
        return Err(UserPtrError::InvalidAddress);
    }
    let root = sched::current_space().ok_or(UserPtrError::NotUserTask)?;
    let offset = boot::get().and_then(|b| b.phys_offset).ok_or(UserPtrError::InvalidAddress)?;
    // SAFETY：只用于只读查询（translate），不修改页表；调用发生在关中断的系统调用路径上。
    let mapper = unsafe { arch::space_mapper(root, offset) };

    // 第一遍：完整校验，不复制任何字节（要么全部成功，要么什么都不做）
    let mut va = addr - addr % FRAME_SIZE;
    while va < end {
        match mapper.translate(VirtPage::containing(va)) {
            Some((_, flags)) if flags.contains(MapFlags::USER) && flags.contains(need) => {}
            _ => return Err(UserPtrError::InvalidAddress),
        }
        va += FRAME_SIZE;
    }
    // 第二遍：逐页经物理映射复制
    let mut cur = addr;
    let mut done = 0usize;
    while cur < end {
        let page_off = cur % FRAME_SIZE;
        let chunk = ((FRAME_SIZE - page_off) as usize).min(len - done);
        let (frame, _) = mapper.translate(VirtPage::containing(cur)).ok_or(UserPtrError::InvalidAddress)?;
        let kptr = phys_to_virt(frame.start() + page_off).ok_or(UserPtrError::InvalidAddress)?;
        f(kptr, chunk, done);
        done += chunk;
        cur += chunk as u64;
    }
    Ok(())
}

/// 从用户空间 `src` 复制 `dst.len()` 字节到内核缓冲区（长度上限 `max`）。
pub fn copy_from_user(dst: &mut [u8], src: u64, max: usize) -> Result<(), UserPtrError> {
    if dst.len() > max {
        return Err(UserPtrError::TooLong);
    }
    for_each_chunk(src, dst.len(), MapFlags::READ_ONLY, |kptr, n, at| {
        // SAFETY：kptr 指向已校验的用户帧（经物理映射），n 不越过页尾；dst[at..at+n] 在界内。
        unsafe { core::ptr::copy_nonoverlapping(kptr, dst[at..at + n].as_mut_ptr(), n) };
    })
}

/// 把内核缓冲区 `src` 复制到用户空间 `dst`（要求目标页可写；长度上限 `max`）。
pub fn copy_to_user(dst: u64, src: &[u8], max: usize) -> Result<(), UserPtrError> {
    if src.len() > max {
        return Err(UserPtrError::TooLong);
    }
    for_each_chunk(dst, src.len(), MapFlags::WRITE, |kptr, n, at| {
        // SAFETY：同上；目标页已校验为用户可写。
        unsafe { core::ptr::copy_nonoverlapping(src[at..at + n].as_ptr(), kptr, n) };
    })
}
