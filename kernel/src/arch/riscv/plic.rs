//! 平台级中断控制器（PLIC）：外部设备中断的优先级、使能、阈值与「认领 → 完成」。
//! Platform-Level Interrupt Controller: priorities, enables, threshold and claim/complete.
//!
//! 寄存器基地址来自设备树（`riscv,plic0` / `sifive,plic-1.0.0`）；本处理器监管态所对应的「上下文」编号
//! 由 PLIC 节点的 `interrupts-extended` 与本处理器中断控制器的 phandle 解析得到，不按机型写死。
//! 每个处理器的监管态各有一个上下文（逻辑下标 → 上下文编号由引导适配层登记）：认领 / 完成总是用执行者自己的上下文，
//! 中断源的路由 = 只在目标处理器的上下文里使能它。使能位图的读改写经一把关中断的自旋锁串行（多个处理器会同时改同一个字）。
//! 中断源编号只在本目录内出现；Core 只看到逻辑中断线。

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use kernel_core::smp::MAX_CPUS;
use spin::Mutex;

use super::{cpu, smp, uart};

/// 每个中断源的优先级寄存器（4 字节 / 源）。
const PRIORITY: usize = 0x0000;
/// 各上下文的使能位图起点与步长。
const ENABLE: usize = 0x2000;
const ENABLE_STRIDE: usize = 0x80;
/// 各上下文的阈值 / 认领寄存器起点与步长。
const CONTEXT: usize = 0x20_0000;
const CONTEXT_STRIDE: usize = 0x1000;
/// 上下文内：阈值、认领 / 完成。
const THRESHOLD: usize = 0;
const CLAIM: usize = 4;
/// 自检时等待中断挂起的最多轮数（设备在写使能寄存器后立刻挂起中断，正常只需一轮）。
const SELF_TEST_SPINS: u32 = 100_000;

/// 寄存器块的虚拟地址（0 = 未知）。
static BASE: AtomicUsize = AtomicUsize::new(0);
/// 各处理器（逻辑下标）监管态的上下文编号（`u32::MAX` = 未知）。
static CONTEXT_OF: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];
/// 使能位图读改写的串行化。
static ENABLE_LOCK: Mutex<()> = Mutex::new(());

/// 设置寄存器块的虚拟地址与启动处理器的上下文编号（引导适配层解析设备树后调用）。
pub fn set_base(va: u64, context: u32) {
    BASE.store(va as usize, Ordering::Relaxed);
    CONTEXT_OF[0].store(context, Ordering::Relaxed);
}

/// 登记逻辑下标 `index` 的处理器的上下文编号（引导适配层按设备树为其他处理器调用）。
pub fn set_cpu_context(index: usize, context: u32) {
    if let Some(c) = CONTEXT_OF.get(index) {
        c.store(context, Ordering::Relaxed);
    }
}

/// 处理器 `index` 的上下文编号。
fn context_of(index: usize) -> Option<u32> {
    CONTEXT_OF.get(index).map(|c| c.load(Ordering::Relaxed)).filter(|&c| c != u32::MAX)
}

/// 处理器 `index` 是否有已知的上下文（可作为中断的目标）。
pub fn has_context(index: usize) -> bool {
    BASE.load(Ordering::Relaxed) != 0 && context_of(index).is_some()
}

fn reg(off: usize) -> *mut u32 {
    (BASE.load(Ordering::Relaxed) + off) as *mut u32
}

fn context_reg(context: u32, off: usize) -> *mut u32 {
    reg(CONTEXT + context as usize * CONTEXT_STRIDE + off)
}

/// 设置中断源的优先级（0 = 永不送达）。
pub fn set_priority(source: u32, prio: u32) {
    // SAFETY：基地址来自设备树；优先级寄存器按源编号排列。
    unsafe { reg(PRIORITY + source as usize * 4).write_volatile(prio) };
}

/// 在处理器 `index` 的上下文里使能 / 关闭一个中断源；该处理器没有已知上下文时返回 `false`，不写寄存器。
pub fn set_enabled_on(index: usize, source: u32, on: bool) -> bool {
    let Some(ctx) = context_of(index) else {
        return false;
    };
    if BASE.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let word = reg(ENABLE + ctx as usize * ENABLE_STRIDE + (source / 32) as usize * 4);
    let bit = 1u32 << (source % 32);
    crate::arch::without_irq(|| {
        let _g = ENABLE_LOCK.lock();
        // SAFETY：读改写该上下文的使能位图中的一个字；锁保证不与其他处理器的读改写交错。
        unsafe {
            let v = word.read_volatile();
            word.write_volatile(if on { v | bit } else { v & !bit });
        }
    });
    true
}

/// 为执行者自己的上下文使能 / 关闭一个中断源。
fn set_enabled(source: u32, on: bool) {
    set_enabled_on(smp::cpu_index(), source, on);
}

/// 认领执行者上下文中当前最高优先级的挂起中断；没有时（或上下文未知时）返回 0。
pub fn claim() -> u32 {
    match context_of(smp::cpu_index()) {
        // SAFETY：读认领寄存器即认领一个中断（PLIC 的规定语义）。
        Some(ctx) if BASE.load(Ordering::Relaxed) != 0 => unsafe { context_reg(ctx, CLAIM).read_volatile() },
        _ => 0,
    }
}

/// 通知处理完成（之后该源才能再次送达）；必须在认领它的处理器上调用。
pub fn complete(source: u32) {
    if let Some(ctx) = context_of(smp::cpu_index()) {
        // SAFETY：写回认领到的源编号即完成。
        unsafe { context_reg(ctx, CLAIM).write_volatile(source) };
    }
}

/// 其他处理器：本上下文阈值置 0、打开监管态外部中断。上下文未知时返回 `false`，什么都不改。
pub fn init_cpu() -> bool {
    let Some(ctx) = context_of(smp::cpu_index()) else {
        return false;
    };
    if BASE.load(Ordering::Relaxed) == 0 {
        return false;
    }
    // SAFETY：阈值寄存器属于本处理器的上下文。
    unsafe { context_reg(ctx, THRESHOLD).write_volatile(0) };
    cpu::enable_sources(cpu::SIE_SEIE);
    true
}

/// 自检结果。
pub struct SelfTest {
    /// 参与自检的中断源。
    pub source: u32,
    /// 认领到的源编号。
    pub claimed: u32,
    /// 完成之后是否已无挂起中断。
    pub drained: bool,
}

/// 初始化本上下文（阈值 0），并用串口的「发送保持寄存器空」中断做一次真实的「挂起 → 认领 → 完成」自检；
/// 自检后关闭串口中断，打开监管态外部中断。基地址、上下文或串口中断号未知时返回 `None`，什么都不改。
pub fn init() -> Option<SelfTest> {
    let source = uart::interrupt()?;
    let ctx = context_of(0)?;
    if BASE.load(Ordering::Relaxed) == 0 {
        return None;
    }
    // SAFETY：阈值寄存器属于本上下文；0 表示放行所有优先级 > 0 的源。
    unsafe { context_reg(ctx, THRESHOLD).write_volatile(0) };
    set_priority(source, 1);
    set_enabled(source, true);
    uart::set_tx_interrupt(true);
    let mut claimed = 0;
    for _ in 0..SELF_TEST_SPINS {
        claimed = claim();
        if claimed != 0 {
            break;
        }
    }
    uart::set_tx_interrupt(false);
    if claimed != 0 {
        complete(claimed);
    }
    // 自检之后不得再有挂起的中断；若意外认领到别的源，也要完成它，不留下卡住的源
    let extra = claim();
    if extra != 0 {
        complete(extra);
    }
    let drained = extra == 0;
    // 自检用过的源交还：之后由设备中断线的路由决定在哪个上下文使能
    set_enabled(source, false);
    cpu::enable_sources(cpu::SIE_SEIE);
    Some(SelfTest { source, claimed, drained })
}
