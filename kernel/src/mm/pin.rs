//! 物理页固定（INV-05）：异步请求在后端不再访问之前，阻止其缓冲区所在的物理帧被释放或复用。
//! Physical frame pinning: keeps frames used by in-flight requests from being freed or reused.
//!
//! # 模型
//! * 每个被固定的帧有一个**固定计数**：每个使用它的请求 +1，请求销毁（X）时 −1。
//!   同一缓冲区被多个请求使用时计数叠加——单个请求结束只减自己的一份。
//! * 帧的**所有者**（进程的数据帧表）放弃它时调用 [`release`]：未被固定 ⇒ 立即归还；
//!   仍被固定 ⇒ 记为「孤儿」，等最后一次 [`unpin`] 时才真正归还。因此用户在请求进行中取消映射缓冲区，
//!   映射消失，帧却不会在请求结束前被复用。
//!
//! # 边界
//! 只管物理帧的生命周期；设备映射（IOMMU）与托管对象固定是另外两个层次，不在这里，也不与这里合并计数。
//!
//! # 锁
//! 一把关中断自旋锁，位于全局锁顺序的最底层（页帧 / 映射一层）；持锁期间只调用页帧服务。

use alloc::vec::Vec;

use kernel_core::frame::PhysFrame;

use super::frame;
use crate::sync::IrqSpinLock;

/// 一个被固定的帧。
struct Pin {
    frame: PhysFrame,
    count: u32,
    /// 所有者已放弃：最后一次解除固定时归还给页帧服务。
    orphaned: bool,
}

static PINS: IrqSpinLock<Vec<Pin>> = IrqSpinLock::ranked(crate::lockorder::MEMORY_PINS, Vec::new());

/// 累计：所有者放弃时帧仍被固定（因而延后归还）的次数。验收用它证明「固定期间确实发生了取消映射」，
/// 也就是并发竞态真的出现过、并且被固定挡住了。
/// Cumulative count of frames released by their owner while still pinned.
///（32 位目标没有 64 位原子指令，用内核的关中断 64 位计数器。）
static ORPHANED_TOTAL: crate::sync::IrqU64 = crate::sync::IrqU64::new(0);

/// 固定一个帧（计数 +1）。
pub fn pin(f: PhysFrame) {
    let mut pins = PINS.lock();
    match pins.iter_mut().find(|p| p.frame == f) {
        Some(p) => p.count += 1,
        None => pins.push(Pin { frame: f, count: 1, orphaned: false }),
    }
}

/// 解除一次固定（计数 −1）。计数归零且所有者已放弃 ⇒ 归还帧。返回帧是否因此被归还。
pub fn unpin(f: PhysFrame) -> bool {
    let mut pins = PINS.lock();
    let Some(i) = pins.iter().position(|p| p.frame == f) else {
        return false;
    };
    pins[i].count -= 1;
    if pins[i].count > 0 {
        return false;
    }
    let p = pins.swap_remove(i);
    if p.orphaned {
        let _ = frame::deallocate(p.frame);
        return true;
    }
    false
}

/// 所有者放弃一个帧：未被固定 ⇒ 立即归还；仍被固定 ⇒ 延后到最后一次解除固定时归还。
pub fn release(f: PhysFrame) {
    let mut pins = PINS.lock();
    match pins.iter_mut().find(|p| p.frame == f) {
        Some(p) => {
            p.orphaned = true;
            ORPHANED_TOTAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        }
        None => {
            drop(pins);
            let _ = frame::deallocate(f);
        }
    }
}

/// 累计「所有者放弃时帧仍被固定」的次数（见 [`ORPHANED_TOTAL`]）。
pub fn orphaned_total() -> u64 {
    ORPHANED_TOTAL.load(core::sync::atomic::Ordering::Relaxed)
}

/// `(被固定的帧数, 其中所有者已放弃、等待最后解除固定的帧数)`（诊断与验收用）。
pub fn stats() -> (usize, usize) {
    let pins = PINS.lock();
    (pins.len(), pins.iter().filter(|p| p.orphaned).count())
}

/// 一段被固定的用户内存（RAII）：由若干「帧 + 帧内偏移 + 长度」组成，丢弃时逐帧解除固定。
/// 之后对它的读写只经内核的物理内存映射进行，**不经用户虚拟地址**——用户取消映射也不影响它。
/// A pinned user range; written through the kernel's physical mapping, unpinned on drop.
pub struct PinnedRange {
    segs: Vec<(PhysFrame, u32, u32)>,
    len: usize,
}

impl PinnedRange {
    /// 由已校验的段建立并逐帧固定（段由调用者从进程页表查得）。
    pub fn new(segs: Vec<(PhysFrame, u32, u32)>) -> Self {
        for (f, _, _) in &segs {
            pin(*f);
        }
        let len = segs.iter().map(|s| s.2 as usize).sum();
        PinnedRange { segs, len }
    }

    /// 总字节数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 从偏移 `at` 起读出 `out.len()` 字节到 `out`；越界返回 `false` 且不读任何字节。
    /// Read `out.len()` bytes starting at `at`; out of range ⇒ `false`, nothing read.
    pub fn read_at(&self, at: usize, out: &mut [u8]) -> bool {
        match at.checked_add(out.len()) {
            Some(end) if end <= self.len => {}
            _ => return false,
        }
        let mut pos = 0usize; // 当前段在整个范围中的起点
        let mut done = 0usize;
        for &(f, off, n) in &self.segs {
            let n = n as usize;
            let seg_end = pos + n;
            let want_start = at + done;
            if done < out.len() && want_start < seg_end && want_start >= pos {
                let in_seg = want_start - pos;
                let k = (n - in_seg).min(out.len() - done);
                // 没有物理内存映射时如实失败，不跳过这一段却报告成功
                let Some(p) = super::phys_to_virt(f.start() + off as u64 + in_seg as u64) else { return false };
                // SAFETY：帧被本范围固定，[off+in_seg, off+in_seg+k) 位于帧内且属于该用户缓冲区。
                unsafe { core::ptr::copy_nonoverlapping(p as *const u8, out[done..].as_mut_ptr(), k) };
                done += k;
            }
            pos = seg_end;
        }
        done == out.len()
    }

    /// 从偏移 `at` 起写入 `bytes`；越界返回 `false` 且不写任何字节。
    pub fn write_at(&self, at: usize, bytes: &[u8]) -> bool {
        match at.checked_add(bytes.len()) {
            Some(end) if end <= self.len => {}
            _ => return false,
        }
        let mut pos = 0usize; // 当前段在整个范围中的起点
        let mut done = 0usize;
        for &(f, off, n) in &self.segs {
            let n = n as usize;
            let seg_end = pos + n;
            let want_start = at + done;
            if done < bytes.len() && want_start < seg_end && want_start >= pos {
                let in_seg = want_start - pos;
                let k = (n - in_seg).min(bytes.len() - done);
                // 没有物理内存映射时如实失败，不跳过这一段却报告成功
                let Some(p) = super::phys_to_virt(f.start() + off as u64 + in_seg as u64) else { return false };
                // SAFETY：帧被本范围固定，[off+in_seg, off+in_seg+k) 位于帧内且属于该用户缓冲区。
                unsafe { core::ptr::copy_nonoverlapping(bytes[done..].as_ptr(), p, k) };
                done += k;
            }
            pos = seg_end;
        }
        done == bytes.len()
    }
}

impl Drop for PinnedRange {
    fn drop(&mut self) {
        for (f, _, _) in &self.segs {
            unpin(*f);
        }
    }
}
