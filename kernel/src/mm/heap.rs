//! 内核堆（M2.3）：把 `kernel-core` 的链表堆算法接到「页帧 + 映射」之上，作为 Rust 的全局分配器。
//!
//! # 职责
//! * 在固定的虚拟区间 [`HEAP_START`, `HEAP_START + HEAP_MAX`) 上按需增长：分配失败时映射更多页再重试
//! * 实现 `GlobalAlloc`，使内核可以使用 `alloc`（`Box` / `Vec` / `String` …）
//!
//! # 为什么按需增长、不预先映射全部
//! 物理内存按实际使用量消耗；区间上限只是虚拟地址预留。增长以 [`GROW_STEP`] 为最小单位，
//! 大对象一次增长到够用为止。目前只增不缩（页不归还）——收缩需要「整页空闲」的判定，留待需要时实现。
//!
//! # 锁顺序（避免死锁）
//! 堆锁 → 映射器锁 → 页帧锁。映射与页帧服务本身不使用堆，因此不存在反向依赖。

use core::alloc::{GlobalAlloc, Layout};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::heap::LinkedListHeap;
use kernel_core::paging::{MapFlags, VirtPage};

use super::{frame, map};
use crate::sync::IrqSpinLock;

/// 堆虚拟区间起点（低半区，与映射演练地址、内核镜像、物理内存映射均不重叠）。
pub const HEAP_START: u64 = 0x0000_4444_4444_0000;
/// 堆虚拟区间上限（只是预留，实际按需映射）。
pub const HEAP_MAX: u64 = 64 * 1024 * 1024;
/// 每次至少增长的字节数。
pub const GROW_STEP: u64 = 64 * 1024;

/// 堆状态：算法本体 + 已映射到的位置。
struct HeapState {
    heap: LinkedListHeap,
    /// 已映射区间的末尾（下一次增长从这里开始）。
    mapped_end: u64,
}

static HEAP: IrqSpinLock<HeapState> =
    IrqSpinLock::new(HeapState { heap: LinkedListHeap::empty(), mapped_end: HEAP_START });

/// 增长失败的原因（诊断用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrowError {
    /// 超出预留的虚拟区间。
    LimitReached,
    /// 没有空闲物理帧。
    OutOfFrames,
    /// 映射失败。
    MapFailed,
}

/// 至少增长 `bytes` 字节（向上取整到页与 [`GROW_STEP`]）。调用者已持有堆锁。
fn grow(state: &mut HeapState, bytes: u64) -> Result<(), GrowError> {
    let want = bytes.max(GROW_STEP).div_ceil(FRAME_SIZE) * FRAME_SIZE;
    let start = state.mapped_end;
    if start + want > HEAP_START + HEAP_MAX {
        return Err(GrowError::LimitReached);
    }
    let mut va = start;
    while va < start + want {
        let f = frame::allocate().map_err(|_| GrowError::OutOfFrames)?;
        let page = VirtPage::containing(va);
        if map::map(page, f, MapFlags::WRITE | MapFlags::GLOBAL).is_err() {
            let _ = frame::deallocate(f);
            return Err(GrowError::MapFailed);
        }
        va += FRAME_SIZE;
        state.mapped_end = va;
    }
    // SAFETY：[start, mapped_end) 刚映射为可写、仅由堆使用，且与已有区间首尾相接（会被合并）。
    unsafe { state.heap.extend(start as usize, (state.mapped_end - start) as usize) };
    Ok(())
}

/// 初始化堆：映射首批页。需在页帧与映射服务就绪之后调用。
pub fn init() -> Result<(), GrowError> {
    let mut s = HEAP.lock();
    if s.heap.total_bytes() == 0 {
        grow(&mut s, GROW_STEP)?;
    }
    Ok(())
}

/// 堆统计：(总字节, 空闲字节, 空闲块数, 已映射字节)。
pub fn stats() -> (usize, usize, usize, u64) {
    let s = HEAP.lock();
    (s.heap.total_bytes(), s.heap.free_bytes(), s.heap.free_blocks(), s.mapped_end - HEAP_START)
}

/// 内核全局分配器。
pub struct KernelHeap;

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut s = HEAP.lock();
        let p = s.heap.allocate(layout.size(), layout.align());
        if !p.is_null() {
            return p;
        }
        // 不够：增长「大小 + 对齐余量」后重试一次
        let need = (layout.size() + layout.align()) as u64;
        if grow(&mut s, need).is_err() {
            return core::ptr::null_mut();
        }
        s.heap.allocate(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HEAP.lock().heap.deallocate(ptr, layout.size());
    }
}

#[global_allocator]
static GLOBAL: KernelHeap = KernelHeap;
