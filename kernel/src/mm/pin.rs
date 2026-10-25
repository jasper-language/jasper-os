//! User buffer page references (INV-05 / SHM-1). Author: chatgpt.
//! Every RAM segment retains an Arc<Memory Page>; only the final Page drop may return its frame.
//! Virtual unmap/creator exit cannot revoke an already accepted buffer's physical reference.
//! Physical counts below are diagnostic: they preserve the existing "unmapped while pinned" witness.
//! Device BAR segments are borrowed non-RAM addresses and are never returned to the RAM allocator.
//! Pin construction reserves all diagnostic metadata before publication; failure leaves no pin counts.

use alloc::{sync::Arc, vec::Vec};

use kernel_core::frame::PhysFrame;

use crate::sync::IrqSpinLock;

/// 一个被固定的帧。
struct Pin {
    frame: PhysFrame,
    count: usize,
    /// A private mapping was removed while pinned; RAM Page references control actual reclamation.
    orphaned: bool,
}

static PINS: IrqSpinLock<Vec<Pin>> = IrqSpinLock::ranked(crate::lockorder::MEMORY_PINS, Vec::new());

/// 累计：所有者放弃时帧仍被固定（因而延后归还）的次数。验收用它证明「固定期间确实发生了取消映射」，
/// 也就是并发竞态真的出现过、并且被固定挡住了。
/// Cumulative count of frames released by their owner while still pinned.
///（32 位目标没有 64 位原子指令，用内核的关中断 64 位计数器。）
static ORPHANED_TOTAL: crate::sync::IrqU64 = crate::sync::IrqU64::new(0);

/// Diagnostic removal only: Page references are the sole owners of RAM allocations.
fn unpin(f: PhysFrame) {
    let mut pins=PINS.lock();
    let Some(i)=pins.iter().position(|p|p.frame==f) else { return; };
    pins[i].count-=1;
    if pins[i].count==0 { pins.swap_remove(i); }
}

/// Records the existing "unmapped while pinned" observation without transferring frame ownership.
/// A managed Page reference, not this diagnostic counter, prevents physical reuse.
pub fn mapping_released(f: PhysFrame) {
    let mut pins=PINS.lock();
    if let Some(p)=pins.iter_mut().find(|p| p.frame==f) {
        if !p.orphaned { p.orphaned=true; ORPHANED_TOTAL.fetch_add(1,core::sync::atomic::Ordering::Relaxed); }
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
    /// Every RAM segment retains its canonical Memory page, including anonymous/image/stack pages.
    _page_refs: Vec<Option<Arc<super::memory_object::Page>>>,
    _charge: super::memory_quota::Charge,
}

impl PinnedRange {
    /// 由已校验的段建立并逐帧固定（段由调用者从进程页表查得）。
    pub fn new(segs: Vec<(PhysFrame, u32, u32)>, page_refs: Vec<Option<Arc<super::memory_object::Page>>>, charge: super::memory_quota::Charge) -> Option<Self> {
        assert!(segs.len()==page_refs.len(),"pin segments and backing references differ");
        let mut pins=PINS.lock();
        if pins.try_reserve(segs.len()).is_err() { drop(pins); return None; }
        for (f,_,_) in &segs {
            match pins.iter_mut().find(|p|p.frame==*f) {
                Some(p)=>p.count=p.count.checked_add(1).expect("physical pin diagnostic count overflow"),
                None=>pins.push(Pin {frame:*f,count:1,orphaned:false}),
            }
        }
        drop(pins);
        let len = segs.iter().map(|s| s.2 as usize).sum();
        Some(PinnedRange { segs, len, _page_refs: page_refs, _charge: charge })
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

/// Opt-in fault fixture: ensure the next non-empty diagnostic registry needs allocation.
#[cfg(feature="shm1-verify")]
pub fn reset_empty_diagnostics() {
    let mut pins=PINS.lock();
    assert!(pins.is_empty(),"cannot reset live pin observations");
    *pins=Vec::new();
}
