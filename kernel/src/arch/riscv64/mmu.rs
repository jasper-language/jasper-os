//! RISC-V 早期页表（Sv39）与地址转换启用。
//! Early Sv39 page tables and enabling translation.
//!
//! # 地址布局（Sv39 低半区，顶级表 256 项、每项 1 GiB）
//! * 内核映像所在的那一项：**恒等映射**（虚拟地址 = 物理地址），按段设置权限的 4 KiB 页；
//! * 顶级第 64..128 项：**全物理内存映射**，偏移 [`PHYS_OFFSET`]，每项一个 1 GiB 大页（可读写、不可执行、全局）；
//!   早期覆盖 0..4 GiB（含设备区与内存起点），之后随设备树报告的内存扩展，至多 64 GiB；
//! * 顶级第 32..64 项：每个地址空间私有的用户窗口（见 `space.rs`）；
//! * 顶级第 128..256 项：之后新增的内核虚拟区（堆等），启动时一次性预分配、所有地址空间共享。
//!
//! 与 x86_64 / AArch64 的布局按「顶级表项」一一对应（下标相同，只是每项覆盖 1 GiB 而不是 512 GiB）：
//! Core 只通过平台常量（私有窗口、堆起点、演练地址）使用这些区域，因此在三个平台上含义相同。
//!
//! # 为什么在地址转换关闭时用 Rust 建表
//! 此时处于裸地址模式（satp = 0）：访存直达物理内存，没有属性限制；这里只做 8 字节对齐的 `write_volatile`。

use core::ptr::addr_of_mut;

use super::cpu::{self, write_csr};
use super::paging::pte;

/// 全物理内存映射的偏移（顶级第 64 项的起点）。
pub const PHYS_OFFSET: u64 = 64 << 30;
/// 全物理内存映射的顶级表项范围。
const PHYS_FIRST: usize = 64;
const PHYS_LAST: usize = 128;
/// 内核映像的恒等映射必须落在私有窗口之下的顶级表项内（与其余区域不重叠）。
const IDENTITY_LIMIT: usize = 32;
/// 早期就映射的物理地址范围（GiB）：覆盖设备区与内存起点，设备树读出前即可访问。
const EARLY_PHYS_GIB: usize = 4;
/// 内核映像恒等映射可用的末级表数（每张 2 MiB；与链接脚本中的映像大小上限一致）。
const IMAGE_L2_TABLES: usize = 16;
const GIB: u64 = 1 << 30;
const MIB2: u64 = 1 << 21;
const PAGE: u64 = 4096;
/// satp.MODE = Sv39。
const SATP_SV39: u64 = 8 << 60;

/// 一张 4 KiB 对齐的页表。
#[repr(C, align(4096))]
struct Table([u64; 512]);

const EMPTY: Table = Table([0; 512]);
static mut ROOT: Table = EMPTY;
static mut ID_L1: Table = EMPTY;
static mut ID_L2: [Table; IMAGE_L2_TABLES] = [EMPTY; IMAGE_L2_TABLES];

extern "C" {
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
}

/// 内核映像的物理地址范围 `[start, end)`（恒等映射，虚拟地址相同）。
pub fn image_range() -> (u64, u64) {
    // 只取链接脚本定义的符号地址，不读其内容。
    (core::ptr::addr_of!(__kernel_start) as u64, core::ptr::addr_of!(__kernel_end) as u64)
}

/// 启动时的顶级表（内核地址空间）的物理地址。
pub fn root_phys() -> u64 {
    // 只取地址。恒等映射下虚拟地址即物理地址。
    addr_of_mut!(ROOT) as u64
}

/// 由页表物理地址构造 satp 值。
pub fn satp_for(root: u64) -> u64 {
    SATP_SV39 | (root >> 12)
}

fn table_entry(phys: u64) -> u64 {
    pte::ppn(phys) | pte::V
}

fn kernel_page(phys: u64, text_end: u64, rodata_end: u64) -> u64 {
    let base = pte::ppn(phys) | pte::V | pte::R | pte::G | pte::A;
    if phys < text_end {
        base | pte::X
    } else if phys < rodata_end {
        base
    } else {
        base | pte::W | pte::D
    }
}

fn phys_gigapage(g: usize) -> u64 {
    pte::ppn(g as u64 * GIB) | pte::V | pte::R | pte::W | pte::G | pte::A | pte::D
}

/// 建立早期页表（地址转换关闭、单执行流时调用一次）。映像未按 2 MiB 对齐、跨越 1 GiB 边界、
/// 超过上限或不在恒等映射允许的范围内时返回 `false`，不写任何表。
///
/// # Safety
/// 只能在启用地址转换之前、没有其他执行流时调用一次。
pub unsafe fn build_boot_tables() -> bool {
    let (start, end) = image_range();
    let text_end = core::ptr::addr_of!(__text_end) as u64;
    let rodata_end = core::ptr::addr_of!(__rodata_end) as u64;
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
        l2.add(((page >> 12) & 511) as usize).write_volatile(kernel_page(page, text_end, rodata_end));
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

/// 装入早期页表并启用 Sv39；返回后代码与栈继续在恒等映射下运行。
/// 同时：关闭浮点单元（内核与用户程序都不得使用浮点寄存器）、禁止监管态访问用户页（SUM = 0）、
/// 用户态只可读 `time` 计数器。
///
/// # Safety
/// 必须在 [`build_boot_tables`] 成功之后、从恒等映射覆盖的代码与栈上调用一次。
pub unsafe fn enable() {
    core::arch::asm!(
        "csrc sstatus, {bits}",
        bits = in(reg) cpu::SSTATUS_FS | cpu::SSTATUS_SUM | cpu::SSTATUS_SIE,
        options(nostack, preserves_flags)
    );
    write_csr!("scounteren", 1u64 << 1);
    cpu::tlb_flush_all();
    write_csr!("satp", satp_for(root_phys()));
    cpu::tlb_flush_all();
}
