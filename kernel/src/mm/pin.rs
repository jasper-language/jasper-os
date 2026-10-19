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
        Some(p) => p.orphaned = true,
        None => {
            drop(pins);
            let _ = frame::deallocate(f);
        }
    }
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
                if let Some(p) = super::phys_to_virt(f.start() + off as u64 + in_seg as u64) {
                    // SAFETY：帧被本范围固定，[off+in_seg, off+in_seg+k) 位于帧内且属于该用户缓冲区。
                    unsafe { core::ptr::copy_nonoverlapping(bytes[done..].as_ptr(), p, k) };
                }
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
