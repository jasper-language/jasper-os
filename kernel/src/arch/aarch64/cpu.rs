//! AArch64 处理器状态的最小封装：系统寄存器读写、中断屏蔽位、屏障。
//! Minimal wrappers for AArch64 system registers, the IRQ mask and barriers.
//!
//! 只被本目录内的其它模块使用；每个封装只做一条指令，语义与风险写在调用处。

/// 读一个系统寄存器（`mrs`）。
macro_rules! read_sysreg {
    ($name:literal) => {{
        let v: u64;
        // SAFETY：读取系统寄存器没有副作用；调用处只读本特权级可访问的寄存器。
        unsafe { core::arch::asm!(concat!("mrs {}, ", $name), out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }};
}

/// 写一个系统寄存器（`msr`）。调用者负责随后的同步（`isb`）与写入值的正确性，因此在 `unsafe` 块中使用。
macro_rules! write_sysreg {
    ($name:literal, $v:expr) => {
        core::arch::asm!(concat!("msr ", $name, ", {}"), in(reg) $v as u64, options(nostack, preserves_flags))
    };
}

pub(super) use {read_sysreg, write_sysreg};

/// PSTATE.DAIF 中的 IRQ 屏蔽位（bit 7）。
const DAIF_I: u64 = 1 << 7;

/// 当前是否允许 IRQ。
#[inline(always)]
pub fn irq_enabled() -> bool {
    read_sysreg!("daif") & DAIF_I == 0
}

/// 屏蔽 IRQ。
#[inline(always)]
pub fn irq_mask() {
    // SAFETY：只改变本处理器的 IRQ 屏蔽位；作为编译器屏障防止临界区内的访存被移出。
    unsafe { core::arch::asm!("msr daifset, #2", options(nostack, preserves_flags)) };
}

/// 解除 IRQ 屏蔽。
#[inline(always)]
pub fn irq_unmask() {
    // SAFETY：同上；作为编译器屏障防止临界区内的访存被移出。
    unsafe { core::arch::asm!("msr daifclr, #2", options(nostack, preserves_flags)) };
}

/// 指令同步屏障。
#[inline(always)]
pub fn isb() {
    // SAFETY：屏障没有副作用。
    unsafe { core::arch::asm!("isb", options(nostack, preserves_flags)) };
}

/// 页表写入对页表遍历可见（内部共享域的存储屏障 + 指令同步）。
#[inline(always)]
pub fn table_write_barrier() {
    // SAFETY：屏障没有副作用。
    unsafe { core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags)) };
}

/// 作废所有地址空间中虚拟地址 `va` 所在页的 TLB 项（广播到内部共享域）并等待完成。
#[inline(always)]
pub fn tlb_flush_page(va: u64) {
    // SAFETY：只作废 TLB 缓存项；之后的访问会重新遍历页表。
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {}",
            "dsb ish",
            "isb",
            in(reg) (va >> 12) & 0x0000_0fff_ffff_ffff,
            options(nostack, preserves_flags)
        )
    };
}

/// 作废本处理器 EL1&0 转换机制的全部 TLB 项并等待完成。
#[inline(always)]
pub fn tlb_flush_all() {
    // SAFETY：只作废 TLB 缓存项。
    unsafe { core::arch::asm!("dsb ishst", "tlbi vmalle1", "dsb ish", "isb", options(nostack, preserves_flags)) };
}

/// 让 `[va, va + len)` 中刚写入的指令对取指可见：逐缓存行把数据缓存清到统一点（`dc cvau`），
/// 再作废全部指令缓存（广播到内部共享域）。`va` 可以是该内存的任意别名（例如全物理内存映射）：
/// 数据缓存按物理地址维护，指令缓存整体作废，因此与用户态看到的虚拟地址无关。
/// Makes freshly written instructions in `[va, va + len)` visible to instruction fetch.
#[inline]
pub fn sync_icache(va: u64, len: u64) {
    // CTR_EL0.DminLine（位 19:16）= log2(数据缓存最小行的字数)
    let line = 4u64 << ((read_sysreg!("ctr_el0") >> 16) & 0xf);
    let mut p = va & !(line - 1);
    while p < va + len {
        // SAFETY：只把缓存行写回统一点，不改变内存内容。
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) p, options(nostack, preserves_flags)) };
        p += line;
    }
    // SAFETY：屏障与指令缓存作废没有副作用（之后取指重新从统一点读取）。
    unsafe { core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack, preserves_flags)) };
}

/// 本处理器的亲和性标识（MPIDR_EL1 的 Aff0–Aff2，作为处理器拓扑中的硬件标识）。
pub fn boot_affinity() -> u32 {
    let v: u64;
    // SAFETY：只读系统寄存器，无副作用。
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) v, options(nomem, nostack, preserves_flags)) };
    (v & 0x00FF_FFFF) as u32
}
