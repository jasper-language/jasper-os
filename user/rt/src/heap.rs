//! 全局分配器：在私有窗口的固定区间 [`sys::HEAP_BASE`] 上，经 `system.memory.map` 按需增长。
//! Global allocator growing on demand through `system.memory.map`.
//!
//! 切分与合并复用 kernel-core 的链表堆算法（与内核堆同一份、已在宿主上测试）；本模块只负责「内存从哪来」：
//! 分配失败时把区间顶端再映射一段（至少 [`GROW_PAGES`] 页），交给算法后重试。
//! 堆只增不缩：释放的内存回到空闲链表供后续分配使用，页在进程退出时由内核统一回收。

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use kernel_core::heap::LinkedListHeap;

use crate::sync::Mutex;
use crate::{mem, sys};

/// 每次增长的最少页数（64 KiB）。
pub const GROW_PAGES: u64 = 16;

struct State {
    heap: LinkedListHeap,
    /// 已映射区间的末端（下一次增长的起点）。
    top: u64,
}

static STATE: Mutex<State> = Mutex::new(State { heap: LinkedListHeap::empty(), top: sys::HEAP_BASE });

/// 堆统计：(已映射字节, 空闲字节, 空闲块数)。
pub fn stats() -> (usize, usize, usize) {
    let s = STATE.lock();
    (s.heap.total_bytes(), s.heap.free_bytes(), s.heap.free_blocks())
}

/// 单次 `system.memory.map` 的页数上限（与内核一致）。
const MAP_CHUNK: u64 = 1024;

/// 把区间顶端扩大到至少容纳 `size` 字节、按 `align` 对齐的一块；成功返回 true。
///
/// 大请求拆成多次映射（每次不超过 [`MAP_CHUNK`] 页）；中途失败则取消本次已映射的部分，堆保持原样。
fn grow(s: &mut State, size: usize, align: usize) -> bool {
    let need = (size as u64).saturating_add(align as u64).saturating_add(64);
    let pages = need.div_ceil(sys::PAGE).max(GROW_PAGES);
    let Some(end) = pages.checked_mul(sys::PAGE).and_then(|len| s.top.checked_add(len)) else { return false };
    if end > sys::HEAP_BASE + sys::HEAP_LIMIT {
        return false;
    }
    let mut done = 0u64;
    while done < pages {
        let n = (pages - done).min(MAP_CHUNK);
        if mem::map(s.top + done * sys::PAGE, n, mem::WRITE).is_err() {
            let mut undo = 0u64;
            while undo < done {
                let m = (done - undo).min(MAP_CHUNK);
                let _ = mem::unmap(s.top + undo * sys::PAGE, m);
                undo += m;
            }
            return false;
        }
        done += n;
    }
    // SAFETY：[top, end) 刚由内核映射为本进程可写的清零页，此后只归本堆使用，且与已交给堆的区间首尾相接、不重叠。
    unsafe { s.heap.extend(s.top as usize, (end - s.top) as usize) };
    s.top = end;
    true
}

/// 运行时的全局分配器。
pub struct RtAlloc;

// SAFETY：所有状态都在互斥锁内修改；算法保证返回的块互不重叠、满足对齐，且只在相同 size 下回收。
unsafe impl GlobalAlloc for RtAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut s = STATE.lock();
        let p = s.heap.allocate(layout.size(), layout.align());
        if !p.is_null() {
            return p;
        }
        if !grow(&mut s, layout.size(), layout.align()) {
            return null_mut();
        }
        s.heap.allocate(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        STATE.lock().heap.deallocate(ptr, layout.size());
    }
}

#[global_allocator]
static ALLOC: RtAlloc = RtAlloc;
