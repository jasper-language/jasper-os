//! RISC-V 早期地址转换：内核映像范围、按段权限的映像页表项、satp 值与启用分页（RV32 / RV64 共用）。
//! Early RISC-V translation shared by RV32 and RV64: image range, per-section image entries, satp, enabling paging.
//!
//! 页表的形状与布局（Sv39 / Sv32）由 `mode`（`rv64.rs` / `rv32.rs`）给出；本文件只做两者相同的部分：
//! 由链接脚本符号得到内核映像与各段边界、按段生成恒等映射的叶表项、组装 satp、关浮点与 SUM 后打开地址转换。

use super::cpu::{self, write_csr};
use super::mode;
use super::paging::pte;

pub use super::mode::{cover_phys, root_phys, PHYS_HOLE, PHYS_OFFSET};

extern "C" {
    static __kernel_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
    static __kernel_end: u8;
}

/// 内核映像的物理地址范围 `[start, end)`（恒等映射，虚拟地址相同）。
pub fn image_range() -> (u64, u64) {
    // 只取链接脚本定义的符号地址，不读其内容。
    (core::ptr::addr_of!(__kernel_start) as usize as u64, core::ptr::addr_of!(__kernel_end) as usize as u64)
}

/// 由页表物理地址构造 satp 值（不使用地址空间标识，ASID = 0）。
pub fn satp_for(root: u64) -> u64 {
    mode::SATP_MODE | (root >> 12)
}

/// 映像内物理页 `phys` 的叶表项：代码只读可执行、只读数据只读、其余可写不可执行；全部全局、预置访问 / 脏位。
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

/// 建立早期页表（映像恒等映射 + 全物理内存映射）；映像布局不满足本模式的要求时返回 `false`，不写任何表。
///
/// # Safety
/// 只能在启用地址转换之前、没有其他执行流时调用一次。
pub unsafe fn build_boot_tables() -> bool {
    let (start, end) = image_range();
    let text_end = core::ptr::addr_of!(__text_end) as usize as u64;
    let rodata_end = core::ptr::addr_of!(__rodata_end) as usize as u64;
    mode::build_boot_tables(start, end, |page| kernel_page(page, text_end, rodata_end))
}

/// 设置本处理器的监管态状态位：关中断、关闭浮点单元、禁止监管态访问用户页（SUM = 0）、用户态只可读 `time` 计数器。
/// 每个处理器启动时调用一次（引导处理器在 [`enable`] 里，其他处理器在其启动入口里）。
///
/// # Safety
/// 只改本处理器的 sstatus 与 scounteren；调用者保证此后不再依赖浮点单元或监管态访问用户页。
pub unsafe fn configure_hart() {
    core::arch::asm!(
        "csrc sstatus, {bits}",
        bits = in(reg) (cpu::SSTATUS_FS | cpu::SSTATUS_SUM | cpu::SSTATUS_SIE) as usize,
        options(nostack, preserves_flags)
    );
    write_csr!("scounteren", 1u64 << 1);
}

/// 装入早期页表并启用地址转换；返回后代码与栈继续在恒等映射下运行。
/// 同时：关闭浮点单元（内核与用户程序都不得使用浮点寄存器）、禁止监管态访问用户页（SUM = 0）、
/// 用户态只可读 `time` 计数器。
///
/// # Safety
/// 必须在 [`build_boot_tables`] 成功之后、从恒等映射覆盖的代码与栈上调用一次。
pub unsafe fn enable() {
    configure_hart();
    cpu::tlb_flush_all();
    write_csr!("satp", satp_for(root_phys()));
    cpu::tlb_flush_all();
}
