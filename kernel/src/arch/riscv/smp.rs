//! RISC-V 多处理器启动：设备树处理器节点发现、SBI HSM `hart_start` 唤醒、其他处理器的入口、逻辑下标与核间中断（RV32 / RV64 共用）。
//! RISC-V multiprocessor bring-up: CPU discovery from the device tree, SBI HSM hart_start, secondary entry, IPIs.
//!
//! # 启动流程
//! 1. 引导适配层解析设备树时调用 [`configure`]：记下处理器拓扑（`device_type = "cpu"` 节点的 `reg` = hart 号）。此时不发出固件调用。
//! 2. 引导处理器 [`init_boot`]：确认固件实现了 HSM 与 IPI 扩展（缺任一则只用引导处理器并写明原因），打开本处理器的软件中断。
//! 3. [`start`]：先经 HSM 查询目标状态，只有「已停止」才继续；把 satp 值（内核地址空间）、栈顶与逻辑下标写入启动块，
//!    然后 `hart_start(hart, 入口, 启动块)`。
//! 4. 被启动的处理器从 `jsr_rv_secondary` 开始（地址转换关闭、监管态、`a1` = 启动块物理地址）：关中断、按启动块装入 satp、
//!    把逻辑下标放进 `tp`、换到给定的栈，进入 [`jsr_rv_secondary_main`]：设置监管态状态位、装陷入入口、打开软件中断与本地定时器，
//!    然后交给 Core。
//!
//! # 核间中断
//! SBI 只提供一条核间中断线（监管态软件中断）。种类放在每个处理器一格的 [`IpiMailbox`] 里：发送方先置位再经 SBI 触发，
//! 接收方先撤下 sip.SSIP 再一次取走全部种类——两步之间到达的请求会再次触发中断，不会丢失。
//!
//! # 边界
//! 入口代码与启动块都在内核映像内，映像恒等映射（虚拟地址 = 物理地址），所以把它们的地址直接交给固件即可，不需要低端启动帧。
//! 逻辑下标放在 `tp`（内核不使用线程局部存储），读取只需一条指令；陷入入口负责在用户态与内核态之间切换它（见 `trap.rs`）。

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use kernel_core::fdt::Fdt;
use kernel_core::sbi::{self, HartState, SbiError};
use kernel_core::smp::{IpiKind, IpiMailbox, SmpError, Topology, MAX_CPUS};
use spin::Once;

use super::mode::{xlen_asm_begin, xlen_asm_end};
use super::trap::WB;
use super::{cpu, mmu, sbi as fw, space, timer, trap};
use crate::arch::{CpuDiscovery, CpuStart};
use crate::irq::{self, IrqLine};

/// 设备树给出的拓扑与来源（引导适配层写入一次）。
static FIRMWARE: Once<(Topology, &'static str)> = Once::new();
/// 其他处理器本地定时器的频率（启动前写入）。
static AP_TIMER_HZ: AtomicU32 = AtomicU32::new(0);
/// 每个处理器一格的核间中断信箱（下标 = 逻辑下标）。
static MAILBOX: [IpiMailbox; MAX_CPUS] = [const { IpiMailbox::new() }; MAX_CPUS];

/// 启动块：被启动的处理器在地址转换关闭时按物理地址读取（布局与下方汇编的偏移一致）。
/// 同一时刻只启动一个处理器，所以只需一份。
#[repr(C, align(64))]
struct StartBlock {
    /// [0] satp 值、[1] 栈顶、[2] 逻辑下标。
    words: [AtomicUsize; 3],
}

static START_BLOCK: StartBlock = StartBlock { words: [const { AtomicUsize::new(0) }; 3] };

// 其他处理器的入口（HSM hart_start 的入口地址；a0 = hart 号，a1 = 启动块物理地址）。地址转换打开前只读启动块、不写内存。
global_asm!(
    xlen_asm_begin!(),
    r#"
    .section .text.jsr_rv_secondary, "ax"
    .option push
    .option norelax
    .balign 4
    .global jsr_rv_secondary
jsr_rv_secondary:
    csrw sie, zero
    csrci sstatus, 2
    LX t0, 0, a1
    LX t1, {wb}, a1
    LX tp, 2*{wb}, a1
    sfence.vma zero, zero
    csrw satp, t0
    sfence.vma zero, zero
    mv sp, t1
    mv a0, tp
    call jsr_rv_secondary_main
1:
    wfi
    j 1b
    .option pop
    .previous
    "#,
    xlen_asm_end!(),
    wb = const WB,
);

extern "C" {
    fn jsr_rv_secondary();
}

/// hart 号 → 硬件标识：超出 32 位的 hart 号不纳入（拓扑以 32 位记录硬件标识）。
fn hart_id(reg: u64) -> Option<u32> {
    u32::try_from(reg).ok()
}

/// 由设备树记录处理器拓扑（引导适配层调用一次；不发出固件调用）。设备树与本机不符时只记录引导处理器并写明原因。
pub fn configure(fdt: &Fdt<'_>, boot_hart: u32) {
    let found = match fdt.cpu_topology(boot_hart, hart_id) {
        Err(e) => (Topology::boot_only(boot_hart), e.name()),
        Ok(c) if !c.boot_listed => (Topology::boot_only(boot_hart), "system.firmware.error.boot_cpu_unlisted"),
        Ok(c) if c.topology.count() > 1 => (c.topology, "fdt.cpus"),
        Ok(c) => (c.topology, "boot_only"),
    };
    FIRMWARE.call_once(|| found);
}

/// 引导处理器：确认固件实现了 HSM 与 IPI 扩展、打开本处理器的软件中断，返回拓扑。缺少扩展时只报告引导处理器。
pub fn init_boot(boot_hart: u32) -> CpuDiscovery {
    cpu::enable_sources(cpu::SIE_SSIE);
    let (topology, source) = FIRMWARE.get().copied().unwrap_or((Topology::boot_only(boot_hart), "boot_only"));
    if topology.count() > 1 {
        if !fw::has_extension(sbi::EID_HSM) {
            return CpuDiscovery { topology: Topology::boot_only(boot_hart), source: "system.firmware.sbi.error.no_hsm" };
        }
        if !fw::has_extension(sbi::EID_IPI) {
            return CpuDiscovery { topology: Topology::boot_only(boot_hart), source: "system.firmware.sbi.error.no_ipi" };
        }
    }
    CpuDiscovery { topology, source }
}

/// 启动一个处理器（见模块文档）。参数非法或目标不处于「已停止」时不写启动块、不发出启动调用。
///
/// # Safety
/// 同 `Platform::cpu_start`。
pub unsafe fn start(req: &CpuStart<space::SpaceRoot>) -> Result<(), SmpError> {
    if req.index == 0 || req.index >= MAX_CPUS {
        return Err(SmpError::NoSuchCpu);
    }
    let hart = req.hw_id as usize;
    match fw::hart_status(hart) {
        Err(e) => return Err(sbi::decode(e).err().unwrap_or(SbiError::Failed).to_smp()),
        Ok(v) => match HartState::decode(v) {
            Some(s) if s.startable() => {}
            Some(_) => return Err(SmpError::BadState),
            None => return Err(SmpError::StartFailed),
        },
    }
    let entry = jsr_rv_secondary as *const () as usize as u64;
    let block = core::ptr::addr_of!(START_BLOCK) as usize as u64;
    let (img_start, img_end) = mmu::image_range();
    // 入口与启动块必须在恒等映射的内核映像内（固件按物理地址使用它们）
    if !(img_start..img_end).contains(&entry) || !(img_start..img_end).contains(&block) || req.stack_top % 16 != 0 {
        return Err(SmpError::StartFailed);
    }
    let values = [mmu::satp_for(req.space.0) as usize, req.stack_top as usize, req.index];
    for (w, v) in START_BLOCK.words.iter().zip(values) {
        w.store(v, Ordering::Relaxed);
    }
    AP_TIMER_HZ.store(req.timer_hz, Ordering::Relaxed);
    // 启动块的写入先于固件启动目标处理器（目标处理器在地址转换关闭时读它；处理器之间缓存一致）
    core::sync::atomic::fence(Ordering::SeqCst);
    sbi::decode(fw::hart_start(hart, entry as usize, block as usize)).map_err(SbiError::to_smp)
}

/// 其他处理器进入 Rust 的第一站（地址转换已开、栈已换、`tp` 已设）。
#[no_mangle]
extern "C" fn jsr_rv_secondary_main(index: usize) -> ! {
    // SAFETY：本处理器刚以内核地址空间打开地址转换，此处只设置本处理器的状态位。
    unsafe { mmu::configure_hart() };
    trap::init();
    cpu::enable_sources(cpu::SIE_SSIE);
    timer::init(AP_TIMER_HZ.load(Ordering::Relaxed));
    crate::smp::secondary_main(index)
}

/// 当前处理器的逻辑下标（`tp`；引导处理器在入口处置 0）。
#[inline(always)]
pub fn cpu_index() -> usize {
    cpu::tp()
}

/// 向逻辑下标 `target` 发送核间中断：先在其信箱置位，该种类原本未待处理时再经 SBI 触发软件中断。
pub fn send_ipi(target: usize, kind: IpiKind) -> Result<(), SmpError> {
    let topology = FIRMWARE.get().map(|f| f.0);
    let Some(hart) = topology.and_then(|t| t.hw_id(target)).filter(|_| target < MAX_CPUS) else {
        return Err(SmpError::NoSuchCpu);
    };
    if target == cpu_index() {
        return Err(SmpError::SelfTarget);
    }
    if MAILBOX[target].post(kind) {
        // 已待处理：先前的发送方已经（或即将）触发中断，接收方会一并取走
        return Ok(());
    }
    sbi::decode(fw::send_ipi(hart as usize)).map_err(|_| SmpError::NoSuchCpu)
}

/// 监管态软件中断的处理（中断上下文）：先撤下挂起位，再取走本处理器信箱中的全部种类逐一交给 Core。
pub fn on_soft_interrupt(from_user: bool) {
    cpu::clear_soft_pending();
    MAILBOX[cpu_index()].take(|kind| irq::on_hardware_irq(IrqLine::Ipi(kind), from_user));
}
