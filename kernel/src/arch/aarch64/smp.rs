//! AArch64 多处理器启动：设备树处理器节点发现、PSCI `CPU_ON` 唤醒、其他处理器的入口、逻辑下标与核间中断。
//! AArch64 multiprocessor bring-up: CPU discovery from the device tree, PSCI CPU_ON, secondary entry, IPIs.
//!
//! # 启动流程
//! 1. 引导适配层解析设备树时调用 [`configure`]：记下处理器拓扑（`device_type = "cpu"` 节点的亲和性值）
//!    与 PSCI 调用途径（`method`）。此时不发出任何固件调用。
//! 2. 引导处理器 [`init_boot`]：查询 PSCI 版本（低于 0.2 则只用引导处理器）、登记自己的 GIC 接口位。
//! 3. [`start`]：把内核地址空间根、MMU 配置（取自引导处理器，保证属性与粒度一致）、栈与逻辑下标写入启动块，
//!    把启动块清到一致点（被启动的处理器在 MMU 关闭时读它，不经缓存），然后 `CPU_ON(亲和性, 入口, 启动块)`。
//! 4. 被启动的处理器从 `jsr_a64_secondary` 开始（MMU 关闭，可能在 EL2）：降到 EL1、按启动块打开 MMU、
//!    把逻辑下标写入 `TPIDR_EL1`、换到给定的栈，进入 [`secondary_main`]：装向量表、初始化本处理器的 GIC 分组寄存器、
//!    登记接口位、启动本地虚拟定时器，然后交给 Core。
//!
//! # 边界
//! 入口代码与启动块都在内核映像内，映像恒等映射（虚拟地址 = 物理地址），所以把它们的地址直接交给固件即可，
//! 不需要低端启动帧。逻辑下标放在 `TPIDR_EL1`（只有特权级可访问），读取只需一条指令、不查表。

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use kernel_core::fdt::Fdt;
use kernel_core::psci::{self, Conduit, PsciError};
use kernel_core::smp::{IpiKind, SmpError, Topology, MAX_CPUS};
use spin::Once;

use super::cpu::{self, read_sysreg};
use super::{gic, mmu, space, timer, vectors};
use crate::arch::{CpuDiscovery, CpuStart};

/// 设备树给出的拓扑与来源（引导适配层写入一次）。
static FIRMWARE: Once<(Topology, &'static str)> = Once::new();
/// PSCI 调用途径：0 = 没有，1 = hvc，2 = smc。
static CONDUIT: AtomicU8 = AtomicU8::new(0);
/// 其他处理器本地定时器的频率（启动前写入）。
static AP_TIMER_HZ: AtomicU32 = AtomicU32::new(0);

/// 启动块：被启动的处理器在 MMU 关闭时按物理地址读取（布局与下方汇编的偏移一致）。
/// 独占一个缓存行，便于整体清到一致点；同一时刻只启动一个处理器，所以只需一份。
#[repr(C, align(64))]
struct StartBlock {
    /// [0] 地址空间根、[1] MAIR、[2] TCR、[3] SCTLR、[4] 栈顶、[5] 逻辑下标。
    words: [AtomicU64; 6],
}

static START_BLOCK: StartBlock = StartBlock { words: [const { AtomicU64::new(0) }; 6] };

// 其他处理器的入口（PSCI CPU_ON 的入口地址；x0 = 启动块物理地址）。MMU 关闭期间只读启动块、不写内存。
global_asm!(
    r#"
    .section .text.jsr_a64_secondary, "ax"
    .balign 4
    .global jsr_a64_secondary
jsr_a64_secondary:
    mov x19, x0
    mrs x9, CurrentEL
    lsr x9, x9, #2
    cmp x9, #2
    b.ne 1f
    // EL2 → EL1（与引导处理器相同的设置）：EL1 为 AArch64、可访问计数器与定时器、虚拟计数器偏移为 0
    mov x9, #(1 << 31)
    msr hcr_el2, x9
    mov x9, #3
    msr cnthctl_el2, x9
    msr cntvoff_el2, xzr
    mov x9, #0x3c5
    msr spsr_el2, x9
    adr x9, 1f
    msr elr_el2, x9
    eret
1:
    mrs x9, CurrentEL
    lsr x9, x9, #2
    cmp x9, #1
    b.ne 9f
    ldr x10, [x19, #0]
    ldr x11, [x19, #8]
    ldr x12, [x19, #16]
    ldr x13, [x19, #24]
    ldr x14, [x19, #32]
    ldr x15, [x19, #40]
    msr cpacr_el1, xzr
    msr mair_el1, x11
    msr tcr_el1, x12
    msr ttbr0_el1, x10
    msr ttbr1_el1, xzr
    isb
    tlbi vmalle1
    ic iallu
    dsb nsh
    isb
    msr sctlr_el1, x13
    isb
    msr tpidr_el1, x15
    msr spsel, #1
    mov sp, x14
    mov x0, x15
    bl jsr_a64_secondary_main
9:
    wfe
    b 9b
    .previous
    "#
);

extern "C" {
    fn jsr_a64_secondary();
}

/// 亲和性值 → 硬件标识：只接受 Aff0–Aff2（与 [`cpu::boot_affinity`] 一致），带 Aff3 的处理器不纳入。
fn affinity_id(reg: u64) -> Option<u32> {
    (reg & !0x00FF_FFFF == 0).then_some(reg as u32)
}

/// 由设备树记录处理器拓扑与 PSCI 调用途径（引导适配层调用一次；不发出固件调用）。
/// 设备树与本机不符或没有可用的调用途径时，只记录引导处理器并写明原因。
pub fn configure(fdt: &Fdt<'_>) {
    let boot = cpu::boot_affinity();
    let psci_node = match fdt.find_compatible("arm,psci-0.2").ok().flatten() {
        Some(n) => Some(n),
        None => fdt.find_compatible("arm,psci-1.0").ok().flatten(),
    };
    let conduit = psci_node.and_then(|n| n.string("method")).and_then(Conduit::from_method);
    CONDUIT.store(
        match conduit {
            None => 0,
            Some(Conduit::Hvc) => 1,
            Some(Conduit::Smc) => 2,
        },
        Ordering::Relaxed,
    );
    let found = match fdt.cpu_topology(boot, affinity_id) {
        Err(e) => (Topology::boot_only(boot), e.name()),
        Ok(c) if !c.boot_listed => (Topology::boot_only(boot), "system.firmware.error.boot_cpu_unlisted"),
        Ok(c) if c.topology.count() > 1 && conduit.is_none() => {
            (Topology::boot_only(boot), "system.firmware.psci.error.no_conduit")
        }
        Ok(c) if c.topology.count() > 1 => (c.topology, "fdt.cpus"),
        Ok(c) => (c.topology, "boot_only"),
    };
    FIRMWARE.call_once(|| found);
}

/// 发出一次 PSCI 调用，返回 x0（按有符号数解释）。
fn call(conduit: Conduit, function: u32, a1: u64, a2: u64, a3: u64) -> i64 {
    let mut x0 = u64::from(function);
    // SAFETY：调用途径来自设备树 `method`（固件声明它处理该途径的调用）；按 SMC 调用约定 x0–x17 可能被改写。
    unsafe {
        match conduit {
            Conduit::Hvc => core::arch::asm!(
                "hvc #0",
                inout("x0") x0, inout("x1") a1 => _, inout("x2") a2 => _, inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack)
            ),
            Conduit::Smc => core::arch::asm!(
                "smc #0",
                inout("x0") x0, inout("x1") a1 => _, inout("x2") a2 => _, inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack)
            ),
        }
    }
    x0 as i64
}

/// 当前记录的调用途径。
fn conduit() -> Option<Conduit> {
    match CONDUIT.load(Ordering::Relaxed) {
        1 => Some(Conduit::Hvc),
        2 => Some(Conduit::Smc),
        _ => None,
    }
}

/// 引导处理器：确认 PSCI 版本、登记自己的 GIC 接口位，返回拓扑。版本不支持时只报告引导处理器。
pub fn init_boot() -> CpuDiscovery {
    let boot = cpu::boot_affinity();
    gic::record_interface(0);
    let (topology, source) = FIRMWARE.get().copied().unwrap_or((Topology::boot_only(boot), "boot_only"));
    if topology.count() > 1 {
        let supported = conduit().is_some_and(|c| psci::version_supported(call(c, psci::FN_VERSION, 0, 0, 0)));
        if !supported {
            return CpuDiscovery { topology: Topology::boot_only(boot), source: PsciError::NotSupported.name() };
        }
    }
    CpuDiscovery { topology, source }
}

/// 把 `[va, va + len)` 的数据缓存清到一致点并作废（被启动的处理器在 MMU 关闭时不经缓存读取）。
fn clean_to_poc(va: u64, len: u64) {
    // CTR_EL0.DminLine（位 19:16）= log2(数据缓存最小行的字数)
    let line = 4u64 << ((read_sysreg!("ctr_el0") >> 16) & 0xf);
    let mut p = va & !(line - 1);
    while p < va + len {
        // SAFETY：只把缓存行写回一致点并作废，不改变内存内容。
        unsafe { core::arch::asm!("dc civac, {}", in(reg) p, options(nostack, preserves_flags)) };
        p += line;
    }
    // SAFETY：屏障无副作用。
    unsafe { core::arch::asm!("dsb sy", options(nostack, preserves_flags)) };
}

/// 启动一个处理器（见模块文档）。参数非法时不写启动块、不发出固件调用。
///
/// # Safety
/// 同 `Platform::cpu_start`。
pub unsafe fn start(req: &CpuStart<space::SpaceRoot>) -> Result<(), SmpError> {
    if req.index == 0 || req.index >= MAX_CPUS || affinity_id(u64::from(req.hw_id)).is_none() {
        return Err(SmpError::NoSuchCpu);
    }
    let conduit = conduit().ok_or(SmpError::StartFailed)?;
    let entry = jsr_a64_secondary as *const () as u64;
    let block = core::ptr::addr_of!(START_BLOCK) as u64;
    let (img_start, img_end) = mmu::image_range();
    // 入口与启动块必须在恒等映射的内核映像内（固件按物理地址使用它们）
    if !(img_start..img_end).contains(&entry) || !(img_start..img_end).contains(&block) || req.stack_top % 16 != 0 {
        return Err(SmpError::StartFailed);
    }
    let values = [
        req.space.0,
        read_sysreg!("mair_el1"),
        read_sysreg!("tcr_el1"),
        read_sysreg!("sctlr_el1"),
        req.stack_top,
        req.index as u64,
    ];
    for (w, v) in START_BLOCK.words.iter().zip(values) {
        w.store(v, Ordering::Relaxed);
    }
    AP_TIMER_HZ.store(req.timer_hz, Ordering::Relaxed);
    clean_to_poc(block, core::mem::size_of::<StartBlock>() as u64);
    psci::decode(call(conduit, psci::FN_CPU_ON_64, u64::from(req.hw_id), entry, block)).map_err(PsciError::to_smp)
}

/// 其他处理器进入 Rust 的第一站（MMU 已开、栈已换、`TPIDR_EL1` 已设）。
#[no_mangle]
extern "C" fn jsr_a64_secondary_main(index: u64) -> ! {
    let index = index as usize;
    vectors::init();
    let ready = timer::interrupt().is_some_and(gic::init_cpu) && gic::record_interface(index) != 0;
    if !ready {
        // 本处理器收不到中断：不报到，发起方等待超时后判失败
        crate::arch::halt_forever();
    }
    timer::init(AP_TIMER_HZ.load(Ordering::Relaxed));
    crate::smp::secondary_main(index)
}

/// 当前处理器的逻辑下标（`TPIDR_EL1`；引导处理器在入口处置 0）。
#[inline(always)]
pub fn cpu_index() -> usize {
    read_sysreg!("tpidr_el1") as usize
}

/// 向逻辑下标 `cpu` 发送核间中断。
pub fn send_ipi(target: usize, kind: IpiKind) -> Result<(), SmpError> {
    if target >= MAX_CPUS {
        return Err(SmpError::NoSuchCpu);
    }
    if target == cpu_index() {
        return Err(SmpError::SelfTarget);
    }
    if gic::send_sgi(target, kind) {
        Ok(())
    } else {
        Err(SmpError::NoSuchCpu)
    }
}

/// 只作废本处理器上一段页的 TLB 项（所有地址空间；不广播）。
pub fn tlb_flush_local(va: u64, pages: u64) {
    // SAFETY：屏障与 TLB 作废没有副作用（之后的访问重新遍历页表）。
    unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)) };
    for i in 0..pages {
        let page = (va.wrapping_add(i * 4096) >> 12) & 0x0000_0fff_ffff_ffff;
        // SAFETY：同上。
        unsafe { core::arch::asm!("tlbi vaae1, {}", in(reg) page, options(nostack, preserves_flags)) };
    }
    // SAFETY：同上。
    unsafe { core::arch::asm!("dsb nsh", "isb", options(nostack, preserves_flags)) };
}
