//! LoongArch64 CSR、稳定计数器、TLB 与屏障的最小封装。
//!
//! 寄存器号与位域来自 LoongArch 架构手册及 Linux LoongArch 的公开定义。
//! 这里只负责单条硬件操作；中断分发、页表语义由相邻模块负责。

/// Current Mode（CRMD）。
pub const CSR_CRMD: u64 = 0x00;
/// Previous Mode（PRMD）。
pub const CSR_PRMD: u64 = 0x01;
/// Extended Unit Enable（EUEN）。
pub const CSR_EUEN: u64 = 0x02;
/// Exception Configuration（ECFG）。
pub const CSR_ECFG: u64 = 0x04;
/// Exception Status（ESTAT）。
pub const CSR_ESTAT: u64 = 0x05;
/// Exception Return Address（ERA）。
pub const CSR_ERA: u64 = 0x06;
/// Bad Virtual Address（BADV）。
pub const CSR_BADV: u64 = 0x07;
/// Exception Entry（EENTRY）。
pub const CSR_EENTRY: u64 = 0x0c;
/// Page-table base for the low virtual-address half（PGDL）。
pub const CSR_PGDL: u64 = 0x19;
/// Page-table base for the high virtual-address half（PGDH）。
pub const CSR_PGDH: u64 = 0x1a;
/// Page-walk control 0（PWCTL0）。
pub const CSR_PWCTL0: u64 = 0x1c;
/// Page-walk control 1（PWCTL1）。
pub const CSR_PWCTL1: u64 = 0x1d;
/// Current processor identifier（CPUID）。
pub const CSR_CPUID: u64 = 0x20;
/// Kernel scratch 0；从用户态陷入时保存内核栈顶。
pub const CSR_KS0: u64 = 0x30;
/// Local timer identifier.
pub const CSR_TMID: u64 = 0x40;
/// Local timer configuration.
pub const CSR_TCFG: u64 = 0x41;
/// Local timer countdown value.
pub const CSR_TVAL: u64 = 0x42;
/// Local timer interrupt clear.
pub const CSR_TINTCLR: u64 = 0x44;
/// Direct-map window 0（uncached, kernel）。
pub const CSR_DMWIN0: u64 = 0x180;
/// Direct-map window 1（coherent cached, kernel）。
pub const CSR_DMWIN1: u64 = 0x181;

/// CRMD.PLV mask.
pub const CRMD_PLV: u64 = 0x3;
/// CRMD privilege level 0（kernel）。
pub const PLV_KERNEL: u64 = 0;
/// CRMD privilege level 3（user）。
pub const PLV_USER: u64 = 3;
/// CRMD interrupt enable.
pub const CRMD_IE: u64 = 1 << 2;
/// CRMD direct-address mode.
pub const CRMD_DA: u64 = 1 << 3;
/// CRMD paged-address mode.
pub const CRMD_PG: u64 = 1 << 4;

/// PRMD previous interrupt enable.
pub const PRMD_PIE: u64 = 1 << 2;

/// ECFG local timer interrupt mask（ESTAT.IS bit 11）。
pub const ECFG_TIMER: u64 = 1 << 11;
/// ESTAT.I[11]: local timer pending.
pub const ESTAT_TIMER: u64 = 1 << 11;
/// ESTAT.ExcCode field shift.
pub const ESTAT_EXC_SHIFT: u64 = 16;
/// ESTAT.ExcCode field width.
pub const ESTAT_EXC_MASK: u64 = 0x3f;

/// TCFG enable.
pub const TCFG_EN: u64 = 1;
/// TCFG periodic.
pub const TCFG_PERIOD: u64 = 1 << 1;
/// TCFG value shift.
pub const TCFG_VAL_SHIFT: u64 = 2;

/// Exception: breakpoint.
pub const EXC_BREAKPOINT: u64 = 12;
/// Exception: system call.
pub const EXC_SYSCALL: u64 = 11;
/// Exception class: address error.
pub const EXC_ADDRESS_ERROR: u64 = 8;
/// Exception classes for TLB load/store/instruction misses.
pub const EXC_TLB_LOAD: u64 = 1;
pub const EXC_TLB_STORE: u64 = 2;
pub const EXC_TLB_INSTRUCTION: u64 = 3;
/// TLB privilege error: a valid translation exists but does not allow the
/// current privilege level.
pub const EXC_TLB_PRIVILEGE: u64 = 7;
/// Instruction non-existent.
pub const EXC_INVALID_INSTRUCTION: u64 = 13;

macro_rules! read_csr {
    ($csr:literal) => {{
        let value: u64;
        // SAFETY: the caller only uses CSR numbers described by the architecture contract.
        unsafe {
            core::arch::asm!(
                concat!("csrrd {0}, ", $csr),
                out(reg) value,
                options(nostack, preserves_flags)
            )
        };
        value
    }};
}

macro_rules! write_csr {
    ($csr:literal, $value:expr) => {{
        let mut value = $value as u64;
        // csrwr writes the old value back to the source register.
        unsafe {
            core::arch::asm!(
                concat!("csrwr {0}, ", $csr),
                inout(reg) value,
                options(nostack, preserves_flags)
            )
        };
    }};
}

pub(super) use {read_csr, write_csr};

/// Atomically clear `mask` in a CSR.
#[inline(always)]
pub unsafe fn clear_csr_bits(csr: u64, mask: u64) {
    match csr {
        CSR_CRMD => core::arch::asm!(
            "csrxchg $zero, {mask}, 0x0",
            mask = in(reg) mask,
            options(nostack, preserves_flags)
        ),
        CSR_ECFG => core::arch::asm!(
            "csrxchg $zero, {mask}, 0x4",
            mask = in(reg) mask,
            options(nostack, preserves_flags)
        ),
        _ => core::hint::unreachable_unchecked(),
    }
}

/// Atomically set `mask` in a CSR.
#[inline(always)]
pub unsafe fn set_csr_bits(csr: u64, mask: u64) {
    match csr {
        CSR_CRMD => core::arch::asm!(
            "csrxchg {value}, {mask}, 0x0",
            value = inout(reg) mask => _,
            mask = in(reg) mask,
            options(nostack, preserves_flags)
        ),
        CSR_ECFG => core::arch::asm!(
            "csrxchg {value}, {mask}, 0x4",
            value = inout(reg) mask => _,
            mask = in(reg) mask,
            options(nostack, preserves_flags)
        ),
        _ => core::hint::unreachable_unchecked(),
    }
}

/// Whether the current processor accepts interrupts.
#[inline(always)]
pub fn irq_enabled() -> bool {
    read_csr!("0x0") & CRMD_IE != 0
}

/// Mask interrupts on the current processor.
#[inline(always)]
pub fn irq_mask() {
    // SAFETY: changes only CRMD.IE; it also acts as a compiler barrier.
    unsafe { clear_csr_bits(CSR_CRMD, CRMD_IE) };
}

/// Unmask interrupts on the current processor.
#[inline(always)]
pub fn irq_unmask() {
    // SAFETY: changes only CRMD.IE.
    unsafe { set_csr_bits(CSR_CRMD, CRMD_IE) };
}

/// Read CPUCFG register `index`.
#[inline(always)]
pub fn cpucfg(index: u64) -> u64 {
    let mut value = index;
    // SAFETY: CPUCFG is a read-only processor identification space.
    unsafe {
        core::arch::asm!(
            "cpucfg {value}, {value}",
            value = inout(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Stable architecture timer count.
#[inline(always)]
pub fn read_time() -> u64 {
    let value: u64;
    // SAFETY: rdtime.d has no side effects.
    unsafe {
        core::arch::asm!(
            "rdtime.d {value}, $zero",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Timer frequency: CPUCFG4.CCFREQ * CPUCFG5.CCMUL / CPUCFG5.CCDIV.
pub fn timer_frequency() -> u64 {
    let base = cpucfg(4) & 0xffff_ffff;
    let ratio = cpucfg(5);
    let mul = (ratio & 0xffff).max(1);
    let div = ((ratio >> 16) & 0xffff).max(1);
    base.saturating_mul(mul) / div
}

/// Data barrier.
#[inline(always)]
pub fn data_barrier() {
    // SAFETY: dbar only orders memory operations.
    unsafe { core::arch::asm!("dbar 0", options(nostack, preserves_flags)) };
}

/// Invalidate every non-global TLB entry matching the current ASID.
#[inline(always)]
pub fn tlb_flush_all() {
    // SAFETY: invtlb only invalidates address translation caches.
    unsafe {
        core::arch::asm!(
            "invtlb 0x4, $zero, $zero",
            options(nostack, preserves_flags)
        )
    };
}

/// Invalidate both global and current-ASID translations containing `va`.
///
/// Heap mappings are global. A refill can cache a two-page TLB pair while only
/// one page of that pair is mapped, so the later map of its sibling must
/// invalidate global entries too.
#[inline(always)]
pub fn tlb_flush_page(va: u64) {
    // SAFETY: operation 6 matches a global entry or an ASID-matching entry at `va`.
    unsafe {
        core::arch::asm!(
            "invtlb 0x6, $zero, {va}",
            va = in(reg) va,
            options(nostack, preserves_flags)
        )
    };
}

/// Synchronize instruction fetch with preceding stores.
#[inline(always)]
pub fn sync_icache() {
    // SAFETY: ibar 0 orders instruction-fetch state.
    unsafe { core::arch::asm!("ibar 0", options(nostack, preserves_flags)) };
}

/// Current processor identifier.
#[inline(always)]
pub fn cpuid() -> usize {
    read_csr!("0x20") as usize
}
