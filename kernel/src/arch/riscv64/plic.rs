//! 平台级中断控制器（PLIC）：外部设备中断的优先级、使能、阈值与「认领 → 完成」。
//! Platform-Level Interrupt Controller: priorities, enables, threshold and claim/complete.
//!
//! 寄存器基地址来自设备树（`riscv,plic0` / `sifive,plic-1.0.0`）；本处理器监管态所对应的「上下文」编号
//! 由 PLIC 节点的 `interrupts-extended` 与本处理器中断控制器的 phandle 解析得到，不按机型写死。
//! 单处理器：只为启动处理器的监管态上下文使能中断源。中断源编号只在本目录内出现；Core 只看到逻辑中断线。

use core::sync::atomic::{AtomicU64, Ordering};

use super::{cpu, uart};

/// 每个中断源的优先级寄存器（4 字节 / 源）。
const PRIORITY: u64 = 0x0000;
/// 各上下文的使能位图起点与步长。
const ENABLE: u64 = 0x2000;
const ENABLE_STRIDE: u64 = 0x80;
/// 各上下文的阈值 / 认领寄存器起点与步长。
const CONTEXT: u64 = 0x20_0000;
const CONTEXT_STRIDE: u64 = 0x1000;
/// 上下文内：阈值、认领 / 完成。
const THRESHOLD: u64 = 0;
const CLAIM: u64 = 4;
/// 自检时等待中断挂起的最多轮数（设备在写使能寄存器后立刻挂起中断，正常只需一轮）。
const SELF_TEST_SPINS: u32 = 100_000;

/// 寄存器块的虚拟地址（0 = 未知）。
static BASE: AtomicU64 = AtomicU64::new(0);
/// 启动处理器监管态的上下文编号（`u64::MAX` = 未知）。
static CONTEXT_ID: AtomicU64 = AtomicU64::new(u64::MAX);

/// 设置寄存器块的虚拟地址与上下文编号（引导适配层解析设备树后调用）。
pub fn set_base(va: u64, context: u32) {
    BASE.store(va, Ordering::Relaxed);
    CONTEXT_ID.store(u64::from(context), Ordering::Relaxed);
}

fn reg(off: u64) -> *mut u32 {
    (BASE.load(Ordering::Relaxed) + off) as *mut u32
}

fn context_reg(off: u64) -> *mut u32 {
    reg(CONTEXT + CONTEXT_ID.load(Ordering::Relaxed) * CONTEXT_STRIDE + off)
}

/// 设置中断源的优先级（0 = 永不送达）。
fn set_priority(source: u32, prio: u32) {
    // SAFETY：基地址来自设备树；优先级寄存器按源编号排列。
    unsafe { reg(PRIORITY + u64::from(source) * 4).write_volatile(prio) };
}

/// 为本上下文使能 / 关闭一个中断源。
fn set_enabled(source: u32, on: bool) {
    let ctx = CONTEXT_ID.load(Ordering::Relaxed);
    let word = reg(ENABLE + ctx * ENABLE_STRIDE + u64::from(source / 32) * 4);
    let bit = 1u32 << (source % 32);
    // SAFETY：读改写本上下文的使能位图中的一个字。
    unsafe {
        let v = word.read_volatile();
        word.write_volatile(if on { v | bit } else { v & !bit });
    }
}

/// 认领当前最高优先级的挂起中断；没有时返回 0。
pub fn claim() -> u32 {
    // SAFETY：读认领寄存器即认领一个中断（PLIC 的规定语义）。
    unsafe { context_reg(CLAIM).read_volatile() }
}

/// 通知处理完成（之后该源才能再次送达）。
pub fn complete(source: u32) {
    // SAFETY：写回认领到的源编号即完成。
    unsafe { context_reg(CLAIM).write_volatile(source) };
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
    if BASE.load(Ordering::Relaxed) == 0 || CONTEXT_ID.load(Ordering::Relaxed) == u64::MAX {
        return None;
    }
    // SAFETY：阈值寄存器属于本上下文；0 表示放行所有优先级 > 0 的源。
    unsafe { context_reg(THRESHOLD).write_volatile(0) };
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
    cpu::enable_sources(cpu::SIE_SEIE);
    Some(SelfTest { source, claimed, drained })
}
