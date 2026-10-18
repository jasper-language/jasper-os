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

use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::heap::LinkedListHeap;
use kernel_core::paging::{MapFlags, VirtPage};

use super::{frame, map};
use crate::sync::IrqSpinLock;

/// 堆虚拟区间起点（低半区，与映射演练地址、内核镜像、物理内存映射均不重叠）。
pub const HEAP_START: u64 = 0x0000_4444_4444_0000;
/// 堆虚拟区间上限（只是预留，实际按需映射）。
pub const HEAP_MAX: u64 = crate::config::ACTIVE.memory.heap_max;
/// 每次至少增长的字节数。
pub const GROW_STEP: u64 = crate::config::ACTIVE.memory.heap_grow_step;

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
    /// 超出预留的虚拟区间，或容量计算溢出。
    LimitReached,
    /// 没有空闲物理帧。
    OutOfFrames,
    /// 映射失败。
    MapFailed,
}

/// 扩容所需的页帧与映射操作（Strategy）：真实路径用全局页帧服务 + 内核映射；
/// 验收用例可包一层，在第 k 页注入分配或映射失败，以验证回滚。
/// Frame and mapping operations used while growing; tests wrap it to inject failures.
pub trait GrowEnv {
    /// 分配一个物理帧。
    fn alloc(&mut self) -> Result<PhysFrame, GrowError>;
    /// 把 `page` 映射到 `frame`（内核可写）。
    fn map(&mut self, page: VirtPage, frame: PhysFrame) -> Result<(), GrowError>;
    /// 取消映射并返回原帧。
    fn unmap(&mut self, page: VirtPage) -> Option<PhysFrame>;
    /// 归还物理帧。
    fn free(&mut self, frame: PhysFrame);
}

/// 真实环境：全局页帧服务 + 内核地址空间映射。
pub struct KernelGrowEnv;

impl GrowEnv for KernelGrowEnv {
    fn alloc(&mut self) -> Result<PhysFrame, GrowError> {
        frame::allocate().map_err(|_| GrowError::OutOfFrames)
    }
    fn map(&mut self, page: VirtPage, f: PhysFrame) -> Result<(), GrowError> {
        map::map(page, f, MapFlags::WRITE | MapFlags::GLOBAL).map_err(|_| GrowError::MapFailed)
    }
    fn unmap(&mut self, page: VirtPage) -> Option<PhysFrame> {
        map::unmap(page).ok()
    }
    fn free(&mut self, f: PhysFrame) {
        let _ = frame::deallocate(f);
    }
}

/// 事务式扩容：在 `[*mapped_end, window_end)` 内至少增长 `bytes` 字节（向上取整到页与 [`GROW_STEP`]）。
///
/// 资源所有权：本次映射的页在**全部成功之前**归本函数所有（记在 `done` 计数里）；
/// 任一页分配或映射失败 ⇒ 按相反顺序取消映射、归还帧，`*mapped_end` 与 `heap` 都保持调用前的样子。
/// 全部成功后才一次性推进 `*mapped_end` 并把整段交给 `heap`——不存在「已映射但无人管理」的页。
/// 所有容量与地址计算都用检查式算术，溢出视为 [`GrowError::LimitReached`]。
/// Transactional growth: either the whole range is mapped and handed to the heap, or nothing changes.
pub fn grow_in(
    heap: &mut LinkedListHeap,
    mapped_end: &mut u64,
    window_end: u64,
    bytes: u64,
    env: &mut dyn GrowEnv,
) -> Result<u64, GrowError> {
    let want = bytes.max(GROW_STEP).checked_next_multiple_of(FRAME_SIZE).ok_or(GrowError::LimitReached)?;
    let start = *mapped_end;
    let end = start.checked_add(want).ok_or(GrowError::LimitReached)?;
    if end > window_end {
        return Err(GrowError::LimitReached);
    }
    let mut va = start;
    let mut failure = None;
    while va < end {
        let page = VirtPage::containing(va);
        match env.alloc() {
            Ok(f) => {
                if let Err(e) = env.map(page, f) {
                    env.free(f);
                    failure = Some(e);
                    break;
                }
            }
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
        va += FRAME_SIZE;
    }
    if let Some(e) = failure {
        // 回滚：逆序取消本次已映射的页并归还其帧（中间页表帧保留在页表结构中，供后续复用）
        while va > start {
            va -= FRAME_SIZE;
            if let Some(f) = env.unmap(VirtPage::containing(va)) {
                env.free(f);
            }
        }
        return Err(e);
    }
    *mapped_end = end;
    // SAFETY：[start, end) 刚映射为可写、仅由堆使用，且与已有区间首尾相接（会被合并）。
    unsafe { heap.extend(start as usize, (end - start) as usize) };
    Ok(want)
}

/// 至少增长 `bytes` 字节（调用者已持有堆锁）。
fn grow(state: &mut HeapState, bytes: u64) -> Result<(), GrowError> {
    grow_in(&mut state.heap, &mut state.mapped_end, HEAP_START + HEAP_MAX, bytes, &mut KernelGrowEnv).map(|_| ())
}

/// 初始化堆：映射首批页。需在页帧与映射服务就绪之后调用。
pub fn init() -> Result<(), GrowError> {
    let mut s = HEAP.lock();
    if s.heap.total_bytes() == 0 {
        grow(&mut s, GROW_STEP)?;
    }
    Ok(())
}

/// 保证堆里至少有 `bytes` 字节空闲（不足时一次增长补齐）。
///
/// 用途：启动期一次性的大块常驻分配（例如调度器的内核栈）会吃掉堆里原有的空闲余量；
/// 之后若某个演练的小分配触发增长，增长出来的页帧不会再还给页帧分配器，该演练的「页帧回到基线」就会失败。
/// 常驻分配之后调用本函数把余量补回原值，后续行为与没有这次分配时一致。
pub fn ensure_free(bytes: usize) -> Result<(), GrowError> {
    let mut s = HEAP.lock();
    let free = s.heap.free_bytes();
    if free < bytes {
        grow(&mut s, (bytes - free) as u64)?;
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
