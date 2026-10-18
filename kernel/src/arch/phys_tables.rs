//! 经全物理内存映射访问页表内存：通用页表遍历器的 [`TableMemory`] 实现，供自行建表的指令集共用。
//! Page-table memory reached through the linear physical map, shared by ports that walk their own tables.
//!
//! 职责：只把「物理地址 + 表项下标」换算成全物理内存映射里的虚拟地址并做 8 字节的易失读写；
//! 表项位格式、TLB 维护都不在这里（分别属于各指令集的表项格式与映射器）。
//! 边界：不含任何指令集专有的指令或寄存器，因此放在 `arch/` 顶层而不是某个 `arch/<isa>/` 下；
//! x86_64 的页表经第三方封装访问，不使用本模块。

use kernel_core::pagetable::{TableMemory, ENTRIES};

/// 经全物理内存映射读写页表。
/// Page-table memory reached through the linear physical map.
#[derive(Clone, Copy)]
pub struct PhysTables {
    offset: u64,
}

impl PhysTables {
    /// `offset` 为全物理内存映射偏移。
    /// Creates an accessor for the linear map at `offset`.
    ///
    /// # Safety
    /// 之后交给遍历器的表地址都必须是有效页表所在的物理帧。
    pub unsafe fn new(offset: u64) -> Self {
        PhysTables { offset }
    }

    /// 全物理内存映射偏移（物理地址加上它即得可访问的虚拟地址）。
    /// The linear-map offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    fn slot(&self, table: u64, index: usize) -> *mut u64 {
        debug_assert!(index < ENTRIES);
        (self.offset + table + index as u64 * 8) as *mut u64
    }
}

impl TableMemory for PhysTables {
    fn read(&self, table: u64, index: usize) -> u64 {
        // SAFETY：构造者保证 `table` 是有效页表；下标由遍历器限制在 512 以内。
        unsafe { self.slot(table, index).read_volatile() }
    }

    fn write(&mut self, table: u64, index: usize, raw: u64) {
        // SAFETY：同上。
        unsafe { self.slot(table, index).write_volatile(raw) }
    }

    fn zero(&mut self, table: u64) {
        for i in 0..ENTRIES {
            self.write(table, i, 0);
        }
    }
}
