//! RV32 专有部分：Sv32 地址布局与早期页表、寄存器宽度相关的汇编宏、系统调用返回值的寄存器约定。
//! RV32 specifics: Sv32 layout and early tables, XLEN assembler macros, the syscall return convention.
//!
//! 与 `rv64.rs` 导出同一组名字，由 `mod.rs` 按目标选择其一。
//!
//! # Sv32 的形状
//! 2 级页表，每张 4 KiB = 1024 个 4 字节表项；顶级每项覆盖 4 MiB（可以是 4 MiB 大页），末级每项 4 KiB。
//! 表项的物理页号有 22 位，因此物理地址为 **34 位**（可超过 4 GiB），而虚拟地址只有 32 位：
//! 全物理内存映射不可能覆盖全部物理地址，只映射设备区与内存所在的两段（见下）。
//!
//! # 地址布局（虚拟 4 GiB，顶级 1024 项）
//! * 第 0 项：不映射（空指针附近一律缺页）；
//! * 第 1..256 项：每个地址空间私有的用户窗口 `[0x0040_0000, 0x4000_0000)`；
//! * 第 256..512 项：物理 `[0, 1 GiB)`（设备区）的线性映射，偏移 [`PHYS_OFFSET`]，4 MiB 大页；
//! * 第 512..576 项：内核映像的恒等映射（QEMU `virt` 的内存从物理 2 GiB 开始，映像在其中），按段权限的 4 KiB 页；
//! * 第 576..704 项：内核共享部分（堆等），启动时一次性预分配、所有地址空间共享；
//! * 第 768..1024 项：物理 `[2 GiB, 3 GiB)`（内存）的线性映射，与设备区**同一偏移**，4 MiB 大页。
//!
//! 两段线性映射用同一个偏移，Core 看到的仍是「物理地址 + 偏移 = 可访问的虚拟地址」这一条规则；
//! 偏移下落在内核区的物理 `[1 GiB, 2 GiB)` 是空洞（[`PHYS_HOLE`]），3 GiB 以上的物理内存不被映射——
//! 引导时这两部分都标为保留，不交给页帧分配器。

use core::ptr::addr_of_mut;

use super::paging::pte;
use crate::syscall::SyscallArgs;

/// 架构名（横幅与诊断输出用）。
pub const NAME: &str = "riscv32";

/// 用户程序的 ELF 类别（32 位用户 ABI）。
pub const ELF_CLASS: kernel_core::elf::ElfClass = kernel_core::elf::ElfClass::Elf32;

/// 页表级数。
pub const LEVELS: usize = 2;
/// 虚拟地址位数（全部 32 位）。
pub const VA_BITS: u32 = 32;
/// 每级下标位数。
pub const INDEX_BITS: u32 = 10;
/// 表项宽度（字节）。
pub const ENTRY_BYTES: usize = 4;
/// 表项中物理页号字段的位数（位 10..32）：可寻址 34 位物理地址。
pub const PPN_BITS: u32 = 22;

/// 线性映射偏移：物理地址加上它即得可访问的虚拟地址（设备区与内存两段共用）。
pub const PHYS_OFFSET: u64 = 1 << 30;
/// 线性映射偏移下**不可**访问的物理区间 `[start, end)`（落在内核区，见模块文档）。
pub const PHYS_HOLE: (u64, u64) = (1 << 30, 2 << 30);

/// 私有窗口的第一个顶级下标（含）：`0x0040_0000`。
pub const USER_FIRST: usize = 1;
/// 私有窗口的最后一个顶级下标（不含）：`0x4000_0000`。
pub const USER_LAST: usize = 256;
/// 每个顶级表项覆盖的地址位数（4 MiB）。
pub const TOP_SHIFT: u32 = 22;
/// 内核共享部分的第一个顶级下标（含）：`0x9000_0000`。
pub const KERNEL_FIRST: usize = 576;
/// 内核共享部分的最后一个顶级下标（不含）：`0xB000_0000`（共 128 项，与其他平台的共享部分项数相同）。
pub const KERNEL_LAST: usize = 704;

/// 内核共享部分第 584 项内（距共享部分起点 8 项，与其他平台的堆位置对应），其后留有堆上限所需的空间。
pub const KERNEL_HEAP_BASE: u64 = 0x9222_0000;
/// 内核共享部分的第一个顶级表项（第 576 项）的起点。
pub const KERNEL_PROBE_VA: u64 = 0x9000_0000;
/// 32 位虚拟地址空间之外。
pub const INVALID_VA: u64 = 1 << 32;

/// satp.MODE = Sv32（位 31）。
pub const SATP_MODE: u64 = 1 << 31;
/// satp 中物理页号字段的位数。
pub const SATP_PPN_BITS: u32 = 22;

/// 设备区线性映射的第一个顶级下标与项数。
const DEV_FIRST: usize = 256;
/// 内存线性映射的第一个顶级下标与项数。
const RAM_FIRST: usize = 768;
/// 每段线性映射的项数（各 1 GiB）。
const LINEAR_ENTRIES: usize = 256;
/// 内存线性映射覆盖的物理起点（2 GiB）。
const RAM_PHYS: u64 = 2 << 30;
/// 线性映射覆盖到的物理地址上限（3 GiB，不含）。
const COVERED_END: u64 = 3 << 30;
/// 恒等映射允许的顶级下标范围（映像必须完整落在其中）。
const IDENTITY_FIRST: usize = 512;
const IDENTITY_LAST: usize = KERNEL_FIRST;
/// 内核映像恒等映射可用的末级表数（每张 4 MiB；与链接脚本中的映像大小上限一致）。
const IMAGE_L1_TABLES: usize = 8;
const MIB4: u64 = 1 << 22;
const PAGE: u64 = 4096;

// 布局自洽：各区互不重叠，且线性映射与恒等映射、共享部分的位置与偏移一致。
const _: () = assert!(USER_LAST <= DEV_FIRST && DEV_FIRST + LINEAR_ENTRIES <= IDENTITY_FIRST);
const _: () = assert!(IDENTITY_FIRST + IMAGE_L1_TABLES <= IDENTITY_LAST && KERNEL_LAST <= RAM_FIRST);
const _: () = assert!(((DEV_FIRST as u64) << TOP_SHIFT) == PHYS_OFFSET);
const _: () = assert!(((RAM_FIRST as u64) << TOP_SHIFT) == RAM_PHYS + PHYS_OFFSET);
const _: () = assert!(PHYS_HOLE.1 == RAM_PHYS && PHYS_HOLE.0 == (LINEAR_ENTRIES as u64) << TOP_SHIFT);
const _: () = assert!(KERNEL_PROBE_VA == (KERNEL_FIRST as u64) << TOP_SHIFT);
const _: () = assert!((KERNEL_HEAP_BASE >> TOP_SHIFT) as usize == KERNEL_FIRST + 8);
const _: () = assert!((USER_FIRST as u64) << TOP_SHIFT == kernel_core::user_layout::WINDOW_BASE_RISCV32);
const _: () = assert!((USER_LAST as u64) << TOP_SHIFT == kernel_core::user_layout::WINDOW_END_RISCV32);

/// 一张 4 KiB 对齐的 Sv32 页表。
#[repr(C, align(4096))]
struct Table([u32; 1024]);

const EMPTY: Table = Table([0; 1024]);
static mut ROOT: Table = EMPTY;
static mut ID_L1: [Table; IMAGE_L1_TABLES] = [EMPTY; IMAGE_L1_TABLES];

/// 启动时的顶级表（内核地址空间）的物理地址。
pub fn root_phys() -> u64 {
    // 只取地址。恒等映射下虚拟地址即物理地址。
    addr_of_mut!(ROOT) as usize as u64
}

fn table_entry(phys: u64) -> u32 {
    (pte::ppn(phys) | pte::V) as u32
}

fn megapage(phys: u64) -> u32 {
    (pte::ppn(phys) | pte::V | pte::R | pte::W | pte::G | pte::A | pte::D) as u32
}

/// 建立早期页表（地址转换关闭、单执行流时调用一次）。映像 `[start, end)` 未按 4 MiB 对齐、超过上限
/// 或不在恒等映射允许的顶级范围内时返回 `false`，不写任何表。`page_entry` 给出映像内每页的叶表项（按段权限）。
/// 两段线性映射（设备区、内存）在这里一次建好：都是顶级大页，不消耗额外的表。
///
/// # Safety
/// 只能在启用地址转换之前、没有其他执行流时调用一次。
pub unsafe fn build_boot_tables(start: u64, end: u64, page_entry: impl Fn(u64) -> u64) -> bool {
    if start % MIB4 != 0
        || end <= start
        || end - start > IMAGE_L1_TABLES as u64 * MIB4
        || ((start >> TOP_SHIFT) as usize) < IDENTITY_FIRST
        || (((end - 1) >> TOP_SHIFT) as usize) >= IDENTITY_LAST
    {
        return false;
    }
    let root = addr_of_mut!(ROOT) as *mut u32;
    let id_l1 = addr_of_mut!(ID_L1) as *mut Table;

    // 恒等映射：按 4 KiB 页、按段权限
    let mut page = start;
    while page < end {
        let k = ((page - start) / MIB4) as usize;
        let l1 = id_l1.add(k) as *mut u32;
        l1.add(((page >> 12) & 1023) as usize).write_volatile(page_entry(page) as u32);
        page += PAGE;
    }
    let first = (start >> TOP_SHIFT) as usize;
    let mut k = 0;
    while (k as u64) * MIB4 < end - start {
        root.add(first + k).write_volatile(table_entry(id_l1.add(k) as usize as u64));
        k += 1;
    }

    // 线性映射：设备区与内存两段
    for i in 0..LINEAR_ENTRIES {
        root.add(DEV_FIRST + i).write_volatile(megapage((i as u64) << TOP_SHIFT));
        root.add(RAM_FIRST + i).write_volatile(megapage(RAM_PHYS + ((i as u64) << TOP_SHIFT)));
    }
    true
}

/// 线性映射覆盖到的物理地址上限（不含）。Sv32 下两段线性映射在建表时已全部建好，与 `end` 无关：
/// 恒为 3 GiB；其中 [`PHYS_HOLE`] 不可访问，调用者须把它与上限之外的内存一并标为保留。
/// Covered end of the linear map; fixed at 3 GiB on Sv32 (minus [`PHYS_HOLE`]).
pub fn cover_phys(_end: u64) -> u64 {
    COVERED_END
}

/// 把系统调用的 64 位返回值写回用户寄存器：RV32 的 32 位用户 ABI 以 `a0` = 低 32 位、`a1` = 高 32 位返回
/// （小值的高位即符号扩展，错误码 `-(ID)` 在两个寄存器里组合后仍是同一个负数）；其余寄存器保持不变。
/// Write a syscall result back: the 32-bit user ABI returns it in `a0` (low) and `a1` (high).
pub fn set_syscall_return(x: &mut [usize; 32], value: i64) {
    x[10] = value as u32 as usize;
    x[11] = ((value as u64) >> 32) as usize;
}

/// 从用户寄存器取出系统调用的操作 ID 与参数（32 位用户 ABI 的 64 位参数约定）：
/// `a7` = ID；最多 3 个 64 位参数，低 32 位依次在 `a0`–`a2`（与 RV64 的参数位置相同），高 32 位依次在 `a3`–`a5`。
/// 因此只用到低半的调用（指针、长度、句柄）与 RV64 写法一致，而时长、请求标识等需要完整 64 位的参数也不会被截断；
/// 用户态必须显式给出高半（不需要时为 0），否则残留的高半会让参数变成另一个值并被 Core 按原值校验。
/// Collect the syscall id and arguments: up to three 64-bit arguments, low halves in `a0`–`a2`,
/// high halves in `a3`–`a5`.
pub fn syscall_args(x: &[usize; 32]) -> SyscallArgs {
    let pair = |lo: usize, hi: usize| (x[lo] as u32 as u64) | ((x[hi] as u32 as u64) << 32);
    SyscallArgs { id: x[17] as u32 as u64, args: [pair(10, 13), pair(11, 14), pair(12, 15), 0, 0, 0] }
}

/// 本文件内汇编使用的寄存器宽度宏（在每段汇编开头展开、结尾以 [`xlen_asm_end`] 撤销，各段自成一体）：
/// * `SX r, off, base` / `LX r, off, base`：存 / 取一个寄存器宽度的字（RV32 为 `sw` / `lw`）；
/// * `SD64 r, off, base`：把寄存器零扩展为 64 位存入 8 字节槽（低字 = 寄存器，高字 = 0；小端序）；
/// * `SRET off, base`：把系统调用返回值（`a0` 低、`a1` 高）存入 8 字节槽。
macro_rules! xlen_asm_begin {
    () => {
        ".macro SX r, off, base\n sw \\r, \\off(\\base)\n.endm\n\
         .macro LX r, off, base\n lw \\r, \\off(\\base)\n.endm\n\
         .macro SD64 r, off, base\n sw \\r, \\off(\\base)\n sw zero, \\off+4(\\base)\n.endm\n\
         .macro SRET off, base\n sw a0, \\off(\\base)\n sw a1, \\off+4(\\base)\n.endm\n"
    };
}

/// 撤销 [`xlen_asm_begin`] 定义的宏。
macro_rules! xlen_asm_end {
    () => {
        ".purgem SX\n.purgem LX\n.purgem SD64\n.purgem SRET\n"
    };
}

pub(super) use {xlen_asm_begin, xlen_asm_end};
