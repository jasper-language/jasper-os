//! 堆分配算法（M2.3）：在一段原始内存上做「按地址排序的空闲链表 + 首次适配 + 释放时合并」。
//!
//! # 职责
//! 只管「这段内存里哪些字节空闲、怎么切、怎么合」。内存从哪来（页帧 + 映射）、何时扩容、
//! 怎样接到 Rust 的 `GlobalAlloc` 上，是内核的事（`kernel/src/mm/heap.rs`）。
//! 因此本算法可在宿主上用一块普通数组完整测试。
//!
//! # 数据结构
//! 每个空闲块的头部就地存放一个 [`Node`]（大小 + 下一个空闲块地址），链表按地址递增排序：
//! * 分配：首次适配；块头部因对齐产生的前缀、尾部剩余的后缀若不小于最小块就放回链表
//! * 释放：按地址插回，并与前后相邻空闲块合并——碎片不会无限累积
//! * 最小块 = `size_of::<Node>()`、对齐 = [`MIN_ALIGN`]：保证任何空闲块都放得下节点头
//!
//! # 为什么不用更复杂的算法
//! 内核早期分配量小、生命周期短，首次适配 + 合并足够且容易证明正确。
//! 将来可换成 slab / 伙伴系统：它们只需提供同样的 `allocate` / `deallocate` / `extend`。

use core::mem::{align_of, size_of};
use core::ptr::null_mut;

/// 空闲块头（就地存放在空闲内存里）。
#[repr(C)]
struct Node {
    size: usize,
    next: *mut Node,
}

/// 最小对齐与最小块大小（16 字节，容纳 [`Node`] 且满足常见 SIMD/ABI 对齐）。
pub const MIN_ALIGN: usize = 16;
const MIN_BLOCK: usize = if size_of::<Node>() > MIN_ALIGN { size_of::<Node>() } else { MIN_ALIGN };

const fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

/// 链表堆。
pub struct LinkedListHeap {
    head: *mut Node,
    total: usize,
    free: usize,
}

// SAFETY：堆只通过 `&mut self` 修改，内部裸指针指向调用者交给它独占管理的内存；
// 跨线程/中断共享时由调用者加锁（内核用 IrqSpinLock）。
unsafe impl Send for LinkedListHeap {}

impl LinkedListHeap {
    /// 空堆（`const`，可放进 `static`）。
    pub const fn empty() -> Self {
        LinkedListHeap { head: null_mut(), total: 0, free: 0 }
    }

    /// 管理的总字节数。
    pub fn total_bytes(&self) -> usize {
        self.total
    }

    /// 当前空闲字节数。
    pub fn free_bytes(&self) -> usize {
        self.free
    }

    /// 空闲块个数（碎片度诊断）。
    pub fn free_blocks(&self) -> usize {
        let mut n = 0;
        let mut p = self.head;
        while !p.is_null() {
            n += 1;
            // SAFETY：链表中的节点都位于本堆管理的内存内。
            p = unsafe { (*p).next };
        }
        n
    }

    /// 把一段新内存交给堆管理（初始化与扩容都用它）。
    ///
    /// # Safety
    /// `[start, start+size)` 必须可读写、未被其他人使用、此后由本堆独占，且不与已有区域重叠。
    pub unsafe fn extend(&mut self, start: usize, size: usize) {
        let s = align_up(start, MIN_ALIGN);
        let end = start + size;
        if end <= s || end - s < MIN_BLOCK {
            return;
        }
        let len = (end - s) & !(MIN_ALIGN - 1);
        self.total += len;
        self.insert_free(s, len);
    }

    /// 分配；失败返回空指针（由调用者决定是否扩容后重试）。
    ///
    /// # Safety
    /// 返回的内存未初始化；必须以相同的 `size`/`align` 调用 [`deallocate`](Self::deallocate) 归还。
    pub unsafe fn allocate(&mut self, size: usize, align: usize) -> *mut u8 {
        let size = align_up(size.max(MIN_BLOCK), MIN_ALIGN);
        let align = align.max(MIN_ALIGN);
        let mut prev: *mut Node = null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let region_start = cur as usize;
            let region_end = region_start + (*cur).size;
            let alloc_start = align_up(region_start, align);
            let alloc_end = alloc_start.checked_add(size);
            if let Some(alloc_end) = alloc_end {
                let front = alloc_start - region_start;
                let back = region_end.saturating_sub(alloc_end);
                let fits = alloc_end <= region_end
                    && (front == 0 || front >= MIN_BLOCK)
                    && (back == 0 || back >= MIN_BLOCK);
                if fits {
                    // 摘下当前块，再把前后剩余放回（insert_free 会保持排序并尝试合并）
                    let next = (*cur).next;
                    if prev.is_null() {
                        self.head = next;
                    } else {
                        (*prev).next = next;
                    }
                    self.free -= (*cur).size;
                    if front > 0 {
                        self.insert_free(region_start, front);
                    }
                    if back > 0 {
                        self.insert_free(alloc_end, back);
                    }
                    return alloc_start as *mut u8;
                }
            }
            prev = cur;
            cur = (*cur).next;
        }
        null_mut()
    }

    /// 归还。
    ///
    /// # Safety
    /// `ptr` 必须来自本堆的 [`allocate`](Self::allocate)，且 `size` 与分配时一致、未被重复归还。
    pub unsafe fn deallocate(&mut self, ptr: *mut u8, size: usize) {
        let size = align_up(size.max(MIN_BLOCK), MIN_ALIGN);
        self.insert_free(ptr as usize, size);
    }

    /// 按地址顺序插入一个空闲块，并与前后相邻块合并。
    unsafe fn insert_free(&mut self, addr: usize, size: usize) {
        debug_assert!(addr % align_of::<Node>() == 0 && size >= MIN_BLOCK);
        self.free += size;
        // 找到插入位置：prev < addr < cur
        let mut prev: *mut Node = null_mut();
        let mut cur = self.head;
        while !cur.is_null() && (cur as usize) < addr {
            prev = cur;
            cur = (*cur).next;
        }
        let node = addr as *mut Node;
        node.write(Node { size, next: cur });
        if prev.is_null() {
            self.head = node;
        } else {
            (*prev).next = node;
        }
        // 与后继合并
        if !cur.is_null() && addr + (*node).size == cur as usize {
            (*node).size += (*cur).size;
            (*node).next = (*cur).next;
        }
        // 与前驱合并
        if !prev.is_null() && prev as usize + (*prev).size == addr {
            (*prev).size += (*node).size;
            (*prev).next = (*node).next;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4096))]
    struct Arena([u8; 64 * 1024]);

    fn heap(arena: &mut Arena) -> LinkedListHeap {
        let mut h = LinkedListHeap::empty();
        unsafe { h.extend(arena.0.as_mut_ptr() as usize, arena.0.len()) };
        h
    }

    #[test]
    fn alloc_free_returns_to_baseline_and_coalesces() {
        let mut arena = Box::new(Arena([0; 64 * 1024]));
        let mut h = heap(&mut arena);
        let total = h.free_bytes();
        assert_eq!(total, 64 * 1024);
        let mut ptrs = Vec::new();
        for i in 1..200usize {
            let sz = (i * 37) % 300 + 1;
            let p = unsafe { h.allocate(sz, 8) };
            assert!(!p.is_null());
            ptrs.push((p, sz));
        }
        // 无重叠
        let mut ranges: Vec<(usize, usize)> =
            ptrs.iter().map(|&(p, s)| (p as usize, p as usize + align_up(s.max(MIN_BLOCK), MIN_ALIGN))).collect();
        ranges.sort();
        for w in ranges.windows(2) {
            assert!(w[0].1 <= w[1].0, "分配区间重叠");
        }
        // 交错释放（先奇后偶），最终必须完全合并成一个块
        for (i, &(p, s)) in ptrs.iter().enumerate() {
            if i % 2 == 1 {
                unsafe { h.deallocate(p, s) };
            }
        }
        for (i, &(p, s)) in ptrs.iter().enumerate() {
            if i % 2 == 0 {
                unsafe { h.deallocate(p, s) };
            }
        }
        assert_eq!(h.free_bytes(), total);
        assert_eq!(h.free_blocks(), 1, "释放后没有合并成一个块");
        // 合并后整块可再次分出
        let all = unsafe { h.allocate(total, 16) };
        assert!(!all.is_null());
    }

    #[test]
    fn honors_alignment_and_reports_exhaustion() {
        let mut arena = Box::new(Arena([0; 64 * 1024]));
        let mut h = heap(&mut arena);
        let p = unsafe { h.allocate(100, 4096) };
        assert_eq!(p as usize % 4096, 0);
        let q = unsafe { h.allocate(1 << 20, 16) };
        assert!(q.is_null(), "超出容量必须返回空指针");
        unsafe { h.deallocate(p, 100) };
        assert_eq!(h.free_bytes(), h.total_bytes());
    }

    #[test]
    fn extend_adds_capacity() {
        // 同一块内存切成两段、中间留 4 KiB 空隙，保证两段确定不相邻
        let mut arena = Box::new(Arena([0; 64 * 1024]));
        let base = arena.0.as_mut_ptr() as usize;
        let mut h = LinkedListHeap::empty();
        unsafe {
            h.extend(base, 30 * 1024);
            h.extend(base + 34 * 1024, 30 * 1024);
        }
        assert_eq!(h.total_bytes(), 60 * 1024);
        let p = unsafe { h.allocate(40 * 1024, 16) };
        assert!(p.is_null(), "两段不相邻，不能拼成 40 KiB");
        let q = unsafe { h.allocate(28 * 1024, 16) };
        assert!(!q.is_null());
        // 相邻扩容会与已有空闲块合并
        unsafe { h.extend(base + 30 * 1024, 4 * 1024) };
        assert_eq!(h.total_bytes(), 64 * 1024);
    }
}
