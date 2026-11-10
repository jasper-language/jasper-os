//! LoongArch64 早期分页与直接映射窗口。
//!
//! * DMW0：`0x8000_...` 强序非缓存物理窗口，用于 UART/中断控制器；
//! * DMW1：`0x9000_...` 一致性缓存物理窗口，用于页表与设备无关的内存访问；
//! * PGDL/PGDH：同一个 48 位软件页表根，低地址内核映像保持恒等映射。
//!
//! QEMU 直接以物理地址进入 `_start`；本模块在串口已经可用后开启分页。

use core::ptr::addr_of_mut;

use super::cpu::{self, write_csr};
use super::paging::{pte, La64Mapper};
use super::tlb_refill;

/// Coherent direct-map offset.
pub const PHYS_OFFSET: u64 = 0x9000_0000_0000_0000;
/// Strongly ordered direct-map offset.
pub const UNCACHED_OFFSET: u64 = 0x8000_0000_0000_0000;

const PAGE: u64 = 4096;
const IMAGE_L3_TABLES: usize = 16;
const DMW_PLV0: u64 = 1;
const DMW_MAT_CC: u64 = 1 << 4;
const DMW0: u64 = 0x8000_0000_0000_0000 | DMW_PLV0;
const DMW1: u64 = 0x9000_0000_0000_0000 | DMW_MAT_CC | DMW_PLV0;

#[repr(C, align(4096))]
struct Table([u64; 512]);

const EMPTY: Table = Table([0; 512]);
static mut ROOT: Table = EMPTY;
static mut L1: Table = EMPTY;
static mut L2: Table = EMPTY;
static mut L3: [Table; IMAGE_L3_TABLES] = [EMPTY; IMAGE_L3_TABLES];

extern "C" {
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
}

/// Kernel image physical range.
pub fn image_range() -> (u64, u64) {
    (
        core::ptr::addr_of!(__kernel_start) as u64,
        core::ptr::addr_of!(__kernel_end) as u64,
    )
}

/// Physical root-table address.
pub fn root_phys() -> u64 {
    addr_of_mut!(ROOT) as u64
}

fn leaf(phys: u64, text_end: u64, rodata_end: u64) -> u64 {
    let mut entry = (phys & pte::ADDR_MASK) | pte::PRESENT | pte::VALID | pte::CACHE_CC | pte::GLOBAL;
    if phys < text_end {
        // executable, read-only
    } else if phys < rodata_end {
        entry |= pte::NO_EXEC;
    } else {
        entry |= pte::NO_EXEC | pte::WRITE | pte::DIRTY | pte::MODIFIED;
    }
    entry
}

/// Build a low-half identity map for the kernel image.
///
/// # Safety
/// Call once before paging is enabled and while all image addresses are accessible physically.
pub unsafe fn build_boot_tables() -> bool {
    let (start, end) = image_range();
    let text_end = core::ptr::addr_of!(__text_end) as u64;
    let rodata_end = core::ptr::addr_of!(__rodata_end) as u64;
    if start % PAGE != 0 || end <= start || end - start > (IMAGE_L3_TABLES as u64) * 2 * 1024 * 1024 {
        return false;
    }
    let root = addr_of_mut!(ROOT) as *mut u64;
    let l1 = addr_of_mut!(L1) as *mut u64;
    let l2 = addr_of_mut!(L2) as *mut u64;
    let l3s = addr_of_mut!(L3) as *mut Table;

    // The image starts at 0x0020_0000, so its level-2 index is 1 rather
    // than 0. Install the lower levels at their actual VA indices and keep
    // every L3 table tied to the matching L2 slot.
    let root_index = ((start >> 39) & 511) as usize;
    let l1_index = ((start >> 30) & 511) as usize;
    let first_l2_index = ((start >> 21) & 511) as usize;
    root.add(root_index).write_volatile(l1 as u64);
    l1.add(l1_index).write_volatile(l2 as u64);
    for i in 0..IMAGE_L3_TABLES {
        l2.add(first_l2_index + i)
            .write_volatile(l3s.add(i) as u64);
    }

    let mut page = start;
    while page < end {
        let block = ((page >> 21) as usize) - first_l2_index;
        let leaf_index = ((page >> 12) & 511) as usize;
        let table = l3s.add(block) as *mut u64;
        table.add(leaf_index).write_volatile(leaf(page, text_end, rodata_end));
        page += PAGE;
    }
    true
}

fn pwctl0() -> u64 {
    // PTBASE=12, PTWIDTH=9, DIRECTORY0/1 base/width = (21,9)/(30,9).
    12 | (9 << 5) | (21 << 10) | (9 << 15) | (30 << 20) | (9 << 25)
}

fn pwctl1() -> u64 {
    // DIRECTORY2/3 base/width = (39,9)/(48,9).
    39 | (9 << 6) | (48 << 12) | (9 << 18)
}

/// Install direct-map windows and enable paged translation.
///
/// # Safety
/// Must follow a successful [`build_boot_tables`] and run on the boot stack inside the identity map.
pub unsafe fn enable() {
    write_csr!("0x180", DMW0);
    write_csr!("0x181", DMW1);
    write_csr!("0x19", root_phys());
    write_csr!("0x1a", root_phys());
    write_csr!("0x1c", pwctl0());
    write_csr!("0x1d", pwctl1());
    tlb_refill::init();
    let mut crmd = cpu::read_csr!("0x0");
    crmd &= !cpu::CRMD_DA;
    crmd |= cpu::CRMD_PG;
    write_csr!("0x0", crmd);
    cpu::data_barrier();
    cpu::tlb_flush_all();
}

/// Build a mapper for the active root.
///
/// # Safety
/// `phys_offset` must select the coherent physical direct map.
pub unsafe fn active_mapper(phys_offset: u64) -> La64Mapper {
    La64Mapper::for_root(cpu::read_csr!("0x19") & pte::ADDR_MASK, phys_offset)
}
