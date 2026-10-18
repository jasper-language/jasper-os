//! 经全物理内存映射访问页表内存：通用页表遍历器的 [`TableMemory`] 实现，供自行建表的指令集共用。
//! Page-table memory reached through the linear physical map, shared by ports that walk their own tables.
//!
//! 职责：只把「物理地址 + 表项下标」换算成全物理内存映射里的虚拟地址并做易失读写；表项宽度 `W`（8 或 4 字节，
//! 后者如 RISC-V Sv32）是类型参数，4 字节表项零扩展读出、只写低 32 位；
//! 表项位格式、TLB 维护都不在这里（分别属于各指令集的表项格式与映射器）。
//! 边界：不含任何指令集专有的指令或寄存器，因此放在 `arch/` 顶层而不是某个 `arch/<isa>/` 下；
//! x86_64 的页表经第三方封装访问，不使用本模块。

use kernel_core::pagetable::{entries_per_table, TableMemory};

/// 经全物理内存映射读写页表；`W` 为表项宽度（字节，8 或 4）。
/// Page-table memory reached through the linear physical map; `W` is the entry width.
#[derive(Clone, Copy)]
pub struct PhysTables<const W: usize = 8> {
    offset: u64,
}

impl<const W: usize> PhysTables<W> {
    /// `offset` 为全物理内存映射偏移。
    /// Creates an accessor for the linear map at `offset`.
    ///
    /// # Safety
    /// 之后交给遍历器的表地址都必须是有效页表所在的物理帧。
    pub unsafe fn new(offset: u64) -> Self {
        const { assert!(W == 8 || W == 4, "表项宽度只能是 8 或 4 字节") };
        PhysTables { offset }
    }

    /// 全物理内存映射偏移（物理地址加上它即得可访问的虚拟地址）。
    /// The linear-map offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    fn slot(&self, table: u64, index: usize) -> usize {
        debug_assert!(index < entries_per_table(W));
        (self.offset + table + (index * W) as u64) as usize
    }
}

impl<const W: usize> TableMemory for PhysTables<W> {
    const ENTRY_BYTES: usize = W;

    fn read(&self, table: u64, index: usize) -> u64 {
        let p = self.slot(table, index);
        // SAFETY：构造者保证 `table` 是有效页表；下标由遍历器限制在一张表以内，地址按表项宽度对齐。
        unsafe {
            if W == 8 {
                (p as *const u64).read_volatile()
            } else {
                u64::from((p as *const u32).read_volatile())
            }
        }
    }

    fn write(&mut self, table: u64, index: usize, raw: u64) {
        let p = self.slot(table, index);
        // SAFETY：同上；4 字节表项的高位由遍历器保证为 0。
        unsafe {
            if W == 8 {
                (p as *mut u64).write_volatile(raw)
            } else {
                debug_assert!(raw >> 32 == 0);
                (p as *mut u32).write_volatile(raw as u32)
            }
        }
    }

    fn zero(&mut self, table: u64) {
        for i in 0..entries_per_table(W) {
            self.write(table, i, 0);
        }
    }
}
