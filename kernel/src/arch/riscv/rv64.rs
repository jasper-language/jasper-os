//! RV64 专有部分：Sv39 地址布局与早期页表、寄存器宽度相关的汇编宏、系统调用返回值的寄存器约定。
//! RV64 specifics: Sv39 layout and early tables, XLEN assembler macros, the syscall return convention.
//!
//! 本文件与 `rv32.rs` 导出同一组名字（布局常量、页表形状、早期建表、汇编宏），由 `mod.rs` 按目标选择其一，
//! 其余模块只经 `mode::` 使用它们——两种寄存器宽度共用同一套陷入、上下文切换、地址空间与引导代码。
//!
//! # 地址布局（Sv39 低半区，顶级表 256 项、每项 1 GiB）
//! * 内核映像所在的那一项：**恒等映射**（虚拟地址 = 物理地址），按段设置权限的 4 KiB 页；
//! * 顶级第 64..128 项：**全物理内存映射**，偏移 [`PHYS_OFFSET`]，每项一个 1 GiB 大页（可读写、不可执行、全局）；
//!   早期覆盖 0..4 GiB（含设备区与内存起点），之后随设备树报告的内存扩展，至多 64 GiB；
//! * 顶级第 32..64 项：每个地址空间私有的用户窗口（见 `space.rs`）；
//! * 顶级第 128..256 项：之后新增的内核虚拟区（堆等），启动时一次性预分配、所有地址空间共享。
//!
//! 与 x86_64 / AArch64 的布局按「顶级表项」一一对应（下标相同，只是每项覆盖 1 GiB 而不是 512 GiB）：
//! Core 只通过平台常量（私有窗口、堆起点、演练地址）使用这些区域，因此在各平台上含义相同。
//!
//! # 为什么在地址转换关闭时用 Rust 建表
//! 此时处于裸地址模式（satp = 0）：访存直达物理内存，没有属性限制；这里只做 8 字节对齐的 `write_volatile`。

use core::ptr::addr_of_mut;

use super::cpu;
use super::paging::pte;

/// 架构名（横幅与诊断输出用）。
pub const NAME: &str = "riscv64";

/// 页表级数。
pub const LEVELS: usize = 3;
/// 本内核使用的虚拟地址位数：Sv39 的低半区 `[0, 2^38)`（高半区要求高位符号扩展，本内核不使用）。
pub const VA_BITS: u32 = 38;
/// 每级下标位数。
pub const INDEX_BITS: u32 = 9;
/// 表项宽度（字节）。
pub const ENTRY_BYTES: usize = 8;
/// 表项中物理页号字段的位数（位 10 起）。
pub const PPN_BITS: u32 = 44;

/// 全物理内存映射的偏移（顶级第 64 项的起点）。
pub const PHYS_OFFSET: u64 = 64 << 30;
/// 全物理内存映射偏移下**不可**访问的物理区间（Sv39 没有空洞）。
pub const PHYS_HOLE: (u64, u64) = (0, 0);

/// 私有窗口的第一个顶级下标（含）：`0x8_0000_0000`。
pub const USER_FIRST: usize = 32;
/// 私有窗口的最后一个顶级下标（不含）：`0x10_0000_0000`。
pub const USER_LAST: usize = 64;
/// 每个顶级表项覆盖的地址位数（1 GiB）。
pub const TOP_SHIFT: u32 = 30;
/// 内核共享部分的第一个顶级下标（含）。
pub const KERNEL_FIRST: usize = 128;
/// 内核共享部分的最后一个顶级下标（不含）= 低半区的顶级表项数。
pub const KERNEL_LAST: usize = 256;
/// 用户态运行时与用户程序的链接地址按同一数值布局：两边必须一致。
const _: () = assert!((USER_FIRST as u64) << TOP_SHIFT == kernel_core::user_layout::WINDOW_BASE_RISCV64);

/// 内核共享部分顶级第 136 项内（与 x86_64 / AArch64 的堆位于同一下标的顶级表项）。
pub const KERNEL_HEAP_BASE: u64 = 0x22_2222_0000;
/// 内核共享部分的第一个顶级表项（第 128 项）的起点。
pub const KERNEL_PROBE_VA: u64 = 0x20_0000_0000;
/// Sv39 低半区之外。
pub const INVALID_VA: u64 = 0x40_0000_0000;

/// satp.MODE = Sv39。
pub const SATP_MODE: u64 = 8 << 60;
/// satp 中物理页号字段的位数。
pub const SATP_PPN_BITS: u32 = 44;

/// 全物理内存映射的顶级表项范围。
const PHYS_FIRST: usize = 64;
const PHYS_LAST: usize = 128;
/// 内核映像的恒等映射必须落在私有窗口之下的顶级表项内（与其余区域不重叠）。
const IDENTITY_LIMIT: usize = USER_FIRST;
/// 早期就映射的物理地址范围（GiB）：覆盖设备区与内存起点，设备树读出前即可访问。
const EARLY_PHYS_GIB: usize = 4;
/// 内核映像恒等映射可用的末级表数（每张 2 MiB；与链接脚本中的映像大小上限一致）。
const IMAGE_L2_TABLES: usize = 16;
const GIB: u64 = 1 << 30;
const MIB2: u64 = 1 << 21;
const PAGE: u64 = 4096;

/// 一张 4 KiB 对齐的页表。
#[repr(C, align(4096))]
struct Table([u64; 512]);

const EMPTY: Table = Table([0; 512]);
static mut ROOT: Table = EMPTY;
static mut ID_L1: Table = EMPTY;
static mut ID_L2: [Table; IMAGE_L2_TABLES] = [EMPTY; IMAGE_L2_TABLES];

/// 启动时的顶级表（内核地址空间）的物理地址。
pub fn root_phys() -> u64 {
    // 只取地址。恒等映射下虚拟地址即物理地址。
    addr_of_mut!(ROOT) as u64
}

fn table_entry(phys: u64) -> u64 {
    pte::ppn(phys) | pte::V
}

fn phys_gigapage(g: usize) -> u64 {
    pte::ppn(g as u64 * GIB) | pte::V | pte::R | pte::W | pte::G | pte::A | pte::D
}

/// 建立早期页表（地址转换关闭、单执行流时调用一次）。映像 `[start, end)` 未按 2 MiB 对齐、跨越 1 GiB 边界、
/// 超过上限或不在恒等映射允许的范围内时返回 `false`，不写任何表。`page_entry` 给出映像内每页的叶表项（按段权限）。
///
/// # Safety
/// 只能在启用地址转换之前、没有其他执行流时调用一次。
pub unsafe fn build_boot_tables(start: u64, end: u64, page_entry: impl Fn(u64) -> u64) -> bool {
    if start % MIB2 != 0
        || end <= start
        || (start / GIB) != ((end - 1) / GIB)
        || end - start > IMAGE_L2_TABLES as u64 * MIB2
        || (start / GIB) as usize >= IDENTITY_LIMIT
    {
        return false;
    }
    let root = addr_of_mut!(ROOT) as *mut u64;
    let id_l1 = addr_of_mut!(ID_L1) as *mut u64;
    let id_l2 = addr_of_mut!(ID_L2) as *mut Table;

    // 恒等映射：按 4 KiB 页、按段权限
    let mut page = start;
    while page < end {
        let k = ((page - start) / MIB2) as usize;
        let l2 = id_l2.add(k) as *mut u64;
        l2.add(((page >> 12) & 511) as usize).write_volatile(page_entry(page));
        page += PAGE;
    }
    let first_l1 = ((start >> 21) & 511) as usize;
    let mut k = 0;
    while (k as u64) * MIB2 < end - start {
        id_l1.add(first_l1 + k).write_volatile(table_entry(id_l2.add(k) as u64));
        k += 1;
    }
    root.add((start >> 30) as usize).write_volatile(table_entry(id_l1 as u64));

    // 全物理内存映射：早期范围
    let mut g = 0;
    while g < EARLY_PHYS_GIB {
        root.add(PHYS_FIRST + g).write_volatile(phys_gigapage(g));
        g += 1;
    }
    true
}

/// 让全物理内存映射覆盖到物理地址 `end`（不含）；已覆盖的部分不变。返回实际覆盖到的地址：
/// 至少是早期映射的范围，至多 64 GiB（超出部分不映射）。
/// Extend the linear physical map to cover `[0, end)`; returns the covered end.
pub fn cover_phys(end: u64) -> u64 {
    let gib = end.div_ceil(GIB).clamp(EARLY_PHYS_GIB as u64, (PHYS_LAST - PHYS_FIRST) as u64) as usize;
    let root = addr_of_mut!(ROOT) as *mut u64;
    for g in 0..gib {
        // SAFETY：ROOT 是本模块的启动顶级表，经恒等映射访问；只写全物理内存映射范围内的空项。
        unsafe {
            let slot = root.add(PHYS_FIRST + g);
            if slot.read_volatile() & pte::V == 0 {
                slot.write_volatile(phys_gigapage(g));
            }
        }
    }
    cpu::tlb_flush_all();
    gib as u64 * GIB
}

/// 把系统调用的 64 位返回值写回用户寄存器：RV64 只用 `a0`，其余寄存器保持不变。
/// Write a syscall result back: RV64 returns it in `a0` alone.
pub fn set_syscall_return(x: &mut [usize; 32], value: i64) {
    x[10] = value as usize;
}

/// 本文件内汇编使用的寄存器宽度宏（在每段汇编开头展开、结尾以 [`xlen_asm_end`] 撤销，各段自成一体）：
/// * `SX r, off, base` / `LX r, off, base`：存 / 取一个寄存器宽度的字；
/// * `SD64 r, off, base`：把寄存器作为 64 位值存入 8 字节槽（RV64 即 `sd`）；
/// * `SRET off, base`：把系统调用返回值（RV64 为 `a0`）存入 8 字节槽。
macro_rules! xlen_asm_begin {
    () => {
        ".macro SX r, off, base\n sd \\r, \\off(\\base)\n.endm\n\
         .macro LX r, off, base\n ld \\r, \\off(\\base)\n.endm\n\
         .macro SD64 r, off, base\n sd \\r, \\off(\\base)\n.endm\n\
         .macro SRET off, base\n sd a0, \\off(\\base)\n.endm\n"
    };
}

/// 撤销 [`xlen_asm_begin`] 定义的宏。
macro_rules! xlen_asm_end {
    () => {
        ".purgem SX\n.purgem LX\n.purgem SD64\n.purgem SRET\n"
    };
}

pub(super) use {xlen_asm_begin, xlen_asm_end};
