//! AArch64 早期页表与 MMU 启用。
//! Early page tables and MMU enable for AArch64.
//!
//! # 地址布局（只用 TTBR0，47 位，顶级表 256 项；TTBR1 的遍历被关闭）
//! * 顶级第 0 项：内核映像的**恒等映射**（虚拟地址 = 物理地址），按段设置权限的 4 KiB 页；
//! * 顶级第 1 项：**全物理内存映射**，偏移 [`PHYS_OFFSET`]；第 0 GiB 为设备内存（串口、中断控制器），
//!   其后各 GiB 为普通内存块（不可执行），覆盖范围随设备树报告的内存扩展；
//! * 顶级第 32..64 项：每个地址空间私有的用户窗口（见 `space.rs`）；
//! * 顶级第 128..256 项：之后新增的内核虚拟区（堆等），启动时一次性预分配、所有地址空间共享。
//!
//! 与 x86_64 的低半区布局一一对应，因此 Core 中的地址常量在两个平台上含义相同。
//!
//! # 为什么在 MMU 关闭时用 Rust 建表
//! 此时所有数据访问都按设备内存处理（不允许非对齐访问）：这里只做 8 字节对齐的 `write_volatile`，
//! 不调用任何库函数、不使用原子操作，因而是安全的。

use core::ptr::addr_of_mut;

use super::cpu::{self, read_sysreg, write_sysreg};
use super::paging::desc;

/// 全物理内存映射的偏移（顶级第 1 项的起点）。
pub const PHYS_OFFSET: u64 = 1 << 39;
/// 早期就映射的物理地址范围（GiB）：覆盖 QEMU `virt` 的设备区与内存起点，设备树读出前即可访问。
const EARLY_PHYS_GIB: usize = 4;
/// 内核映像恒等映射可用的第 3 级表数（每张 2 MiB；与链接脚本中的映像大小上限一致）。
const IMAGE_L3_TABLES: usize = 16;
const GIB: u64 = 1 << 30;
const MIB2: u64 = 1 << 21;
const PAGE: u64 = 4096;

/// 一张 4 KiB 对齐的转换表。
#[repr(C, align(4096))]
struct Table([u64; 512]);

const EMPTY: Table = Table([0; 512]);
static mut ROOT: Table = EMPTY;
static mut ID_L1: Table = EMPTY;
static mut ID_L2: Table = EMPTY;
static mut ID_L3: [Table; IMAGE_L3_TABLES] = [EMPTY; IMAGE_L3_TABLES];
static mut PHYS_L1: Table = EMPTY;

extern "C" {
    static __image_start: u8;
    static __image_end: u8;
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
}

/// 原始 `Image` 的范围 `[start, end)`（含 64 字节头；恒等映射，虚拟地址相同）。
pub fn image_span() -> (u64, u64) {
    (core::ptr::addr_of!(__image_start) as u64, core::ptr::addr_of!(__image_end) as u64)
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

fn table_desc(phys: u64) -> u64 {
    phys | desc::VALID | desc::TABLE_OR_PAGE
}

fn kernel_page(phys: u64, text_end: u64, rodata_end: u64) -> u64 {
    let base = phys | desc::VALID | desc::TABLE_OR_PAGE | desc::ATTR_NORMAL | desc::SH_INNER | desc::AF;
    if phys < text_end {
        base | desc::AP_RO | desc::UXN
    } else if phys < rodata_end {
        base | desc::AP_RO | desc::UXN | desc::PXN
    } else {
        base | desc::UXN | desc::PXN
    }
}

fn normal_block(phys: u64) -> u64 {
    phys | desc::VALID | desc::ATTR_NORMAL | desc::SH_INNER | desc::AF | desc::UXN | desc::PXN
}

fn device_block(phys: u64) -> u64 {
    phys | desc::VALID | desc::ATTR_DEVICE | desc::AF | desc::UXN | desc::PXN
}

/// 建立早期页表（MMU 关闭、单执行流时调用一次）。映像跨越 1 GiB 边界或超过上限时返回 `false`，不写任何表。
///
/// # Safety
/// 只能在 MMU 打开之前、没有其他执行流时调用一次。
pub unsafe fn build_boot_tables() -> bool {
    let (start, end) = image_range();
    let text_end = core::ptr::addr_of!(__text_end) as u64;
    let rodata_end = core::ptr::addr_of!(__rodata_end) as u64;
    if start % MIB2 != 0 || end <= start || (start / GIB) != ((end - 1) / GIB) || end - start > IMAGE_L3_TABLES as u64 * MIB2 {
        return false;
    }
    let root = addr_of_mut!(ROOT) as *mut u64;
    let id_l1 = addr_of_mut!(ID_L1) as *mut u64;
    let id_l2 = addr_of_mut!(ID_L2) as *mut u64;
    let id_l3 = addr_of_mut!(ID_L3) as *mut Table;
    let phys_l1 = addr_of_mut!(PHYS_L1) as *mut u64;

    // 恒等映射：按 4 KiB 页、按段权限
    let mut page = start;
    while page < end {
        let k = ((page - start) / MIB2) as usize;
        let l3 = id_l3.add(k) as *mut u64;
        l3.add(((page >> 12) & 511) as usize).write_volatile(kernel_page(page, text_end, rodata_end));
        page += PAGE;
    }
    let first_l2 = ((start >> 21) & 511) as usize;
    let mut k = 0;
    while (k as u64) * MIB2 < end - start {
        id_l2.add(first_l2 + k).write_volatile(table_desc(id_l3.add(k) as u64));
        k += 1;
    }
    id_l1.add(((start >> 30) & 511) as usize).write_volatile(table_desc(id_l2 as u64));
    root.write_volatile(table_desc(id_l1 as u64));

    // 全物理内存映射：第 0 GiB 设备内存，其后为普通内存
    phys_l1.write_volatile(device_block(0));
    let mut g = 1;
    while g < EARLY_PHYS_GIB {
        phys_l1.add(g).write_volatile(normal_block(g as u64 * GIB));
        g += 1;
    }
    root.add(1).write_volatile(table_desc(phys_l1 as u64));
    true
}

/// 让全物理内存映射覆盖到物理地址 `end`（不含）；已覆盖的部分不变。返回实际覆盖到的地址：
/// 至少是早期映射的范围，至多 512 GiB（超出部分不映射）。
/// Extend the linear physical map to cover `[0, end)`; returns the covered end.
pub fn cover_phys(end: u64) -> u64 {
    let gib = end.div_ceil(GIB).clamp(EARLY_PHYS_GIB as u64, 512) as usize;
    let phys_l1 = addr_of_mut!(PHYS_L1) as *mut u64;
    for g in 1..gib {
        // SAFETY：PHYS_L1 是本模块独占的早期表，经恒等映射访问；无效 → 有效的写入无需作废 TLB。
        unsafe {
            let slot = phys_l1.add(g);
            if slot.read_volatile() & desc::VALID == 0 {
                slot.write_volatile(normal_block(g as u64 * GIB));
            }
        }
    }
    cpu::table_write_barrier();
    gib as u64 * GIB
}

/// MAIR：属性 0 = 普通内存写回读写分配，属性 1 = 设备内存 nGnRE。
const MAIR: u64 = 0xff | (0x04 << 8);
/// SCTLR_EL1：MMU、数据与指令缓存、EL1/EL0 栈对齐检查；其余为保留位 1。
/// 未置 nTWI / nTWE（EL0 的 WFI / WFE 被捕获）、UMA（EL0 不能改中断屏蔽）、UCT / DZE / UCI（EL0 不能做缓存维护）。
const SCTLR: u64 = 0x30d0_0800 | (1 << 0) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);

/// 装入早期页表并打开 MMU 与缓存；返回后代码与栈继续在恒等映射下运行。
///
/// # Safety
/// 必须在 [`build_boot_tables`] 成功之后、从恒等映射覆盖的代码与栈上调用一次。
pub unsafe fn enable() {
    let pa_range = read_sysreg!("id_aa64mmfr0_el1") & 0xf;
    let ips = pa_range.min(5);
    // T0SZ=17（47 位）、内部 / 外部写回、内部共享、4 KiB 粒度；关闭 TTBR1 遍历（EPD1）且其粒度字段设为合法的 4 KiB。
    let tcr = 17 | (1 << 8) | (1 << 10) | (3 << 12) | (17 << 16) | (1 << 23) | (2 << 30) | (ips << 32);
    write_sysreg!("cpacr_el1", 0u64); // 浮点 / SIMD 访问一律陷入：内核与用户程序都不得使用
    write_sysreg!("mair_el1", MAIR);
    write_sysreg!("tcr_el1", tcr);
    write_sysreg!("ttbr0_el1", root_phys());
    write_sysreg!("ttbr1_el1", 0u64);
    cpu::isb();
    cpu::tlb_flush_all();
    write_sysreg!("sctlr_el1", SCTLR);
    cpu::isb();
}
