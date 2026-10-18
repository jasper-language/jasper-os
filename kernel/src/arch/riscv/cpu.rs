//! RISC-V 处理器状态的最小封装：控制状态寄存器（CSR）读写、监管态中断使能位、地址转换与指令同步屏障。
//! Minimal wrappers for RISC-V CSRs, the supervisor interrupt-enable bit and fences.
//!
//! 只被本目录内的其它模块使用；每个封装只做一条（或一组不可分的）指令，语义与风险写在调用处。
//! CSR 与寄存器同宽（RV32 为 32 位、RV64 为 64 位）：读出的值零扩展为 `u64` 交给调用者，写入时截到寄存器宽度，
//! 因此两种寄存器宽度共用同一套调用代码；各位的位置在两种宽度下相同（本内核只用低 32 位内的状态位）。

/// 读一个 CSR（`csrr`），零扩展为 `u64`。
macro_rules! read_csr {
    ($name:literal) => {{
        let v: usize;
        // SAFETY：读取 CSR 没有副作用；调用处只读监管态可访问的寄存器。
        unsafe { core::arch::asm!(concat!("csrr {}, ", $name), out(reg) v, options(nomem, nostack, preserves_flags)) };
        v as u64
    }};
}

/// 写一个 CSR（`csrw`），值截到寄存器宽度。调用者负责写入值的正确性与随后的同步，因此在 `unsafe` 块中使用。
macro_rules! write_csr {
    ($name:literal, $v:expr) => {
        core::arch::asm!(concat!("csrw ", $name, ", {}"), in(reg) ($v) as usize, options(nostack, preserves_flags))
    };
}

pub(super) use {read_csr, write_csr};

/// sstatus.SIE：监管态全局中断使能。
pub const SSTATUS_SIE: u64 = 1 << 1;
/// sstatus.SPIE：陷入前的 SIE（`sret` 时恢复到 SIE）。
pub const SSTATUS_SPIE: u64 = 1 << 5;
/// sstatus.SPP：陷入前的特权级（1 = 监管态，0 = 用户态）。
pub const SSTATUS_SPP: u64 = 1 << 8;
/// sstatus.FS：浮点单元状态（0 = 关闭，访问浮点寄存器即陷入）。
pub const SSTATUS_FS: u64 = 3 << 13;
/// sstatus.SUM：允许监管态访问用户页。本内核始终保持为 0。
pub const SSTATUS_SUM: u64 = 1 << 18;

/// sie.STIE：监管态定时器中断使能。
pub const SIE_STIE: u64 = 1 << 5;
/// sie.SEIE：监管态外部中断使能。
pub const SIE_SEIE: u64 = 1 << 9;

/// 当前是否允许中断。
#[inline(always)]
pub fn irq_enabled() -> bool {
    read_csr!("sstatus") & SSTATUS_SIE != 0
}

/// 关中断。
#[inline(always)]
pub fn irq_mask() {
    // SAFETY：只清除本处理器的全局中断使能位；作为编译器屏障防止临界区内的访存被移出。
    unsafe { core::arch::asm!("csrci sstatus, {}", const SSTATUS_SIE, options(nostack, preserves_flags)) };
}

/// 开中断。
#[inline(always)]
pub fn irq_unmask() {
    // SAFETY：同上。
    unsafe { core::arch::asm!("csrsi sstatus, {}", const SSTATUS_SIE, options(nostack, preserves_flags)) };
}

/// 在 sie 中打开给定的中断源位。
pub fn enable_sources(bits: u64) {
    // SAFETY：只置位本处理器的监管态中断使能寄存器。
    unsafe { core::arch::asm!("csrs sie, {}", in(reg) bits as usize, options(nostack, preserves_flags)) };
}

/// 页表写入后作废本处理器上 `va` 所在页的地址转换缓存（全部地址空间）。
/// RISC-V 允许缓存「无效」表项，因此新增映射之后同样需要调用。
#[inline(always)]
pub fn tlb_flush_page(va: u64) {
    // SAFETY：只作废地址转换缓存；之后的访问会重新遍历页表。
    unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) va as usize, options(nostack, preserves_flags)) };
}

/// 作废本处理器的全部地址转换缓存，并对随后的页表遍历排序之前的页表写入。
#[inline(always)]
pub fn tlb_flush_all() {
    // SAFETY：只作废地址转换缓存。
    unsafe { core::arch::asm!("sfence.vma zero, zero", options(nostack, preserves_flags)) };
}

/// 让之前写入内存的指令对本处理器的取指可见（`fence.i`）。
#[inline(always)]
pub fn sync_icache() {
    // SAFETY：只同步本处理器的指令流，没有其他副作用。
    unsafe { core::arch::asm!("fence.i", options(nostack, preserves_flags)) };
}

/// 读 64 位 `time` 计数器（单调递增；频率见设备树 `timebase-frequency`）。
/// Read the 64-bit `time` counter.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn read_time() -> u64 {
    let v: u64;
    // SAFETY：读计数器没有副作用。
    unsafe { core::arch::asm!("rdtime {}", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// 读 64 位 `time` 计数器（RV32：高、低 32 位分两条指令读出）。
/// Read the 64-bit `time` counter on RV32 (high/low halves, retried across a carry).
///
/// 先读高位、再读低位、再读一次高位：两次高位相同说明读低位期间没有发生向高位的进位，组合结果一致；
/// 否则重读。不需要关中断或加锁（计数器由硬件推进，读者之间互不影响），因此中断处理程序里也能安全调用。
#[cfg(target_arch = "riscv32")]
#[inline(always)]
pub fn read_time() -> u64 {
    loop {
        let (hi, lo, hi2): (u32, u32, u32);
        // SAFETY：读计数器没有副作用。
        unsafe {
            core::arch::asm!(
                "rdtimeh {0}",
                "rdtime {1}",
                "rdtimeh {2}",
                out(reg) hi,
                out(reg) lo,
                out(reg) hi2,
                options(nomem, nostack, preserves_flags)
            )
        };
        if hi == hi2 {
            return (u64::from(hi) << 32) | u64::from(lo);
        }
    }
}
