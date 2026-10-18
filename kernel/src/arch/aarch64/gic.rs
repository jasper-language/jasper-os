//! GICv2 中断控制器：分发器（Distributor）与 CPU 接口的初始化、应答与结束。
//! GICv2 distributor and CPU interface: init, acknowledge, end-of-interrupt.
//!
//! 寄存器基地址来自设备树（`arm,cortex-a15-gic` / `arm,gic-400` 的 `reg` 第 0、1 项）。
//! 单处理器：只使能本处理器的私有中断（PPI，编号 < 32）；共享外设中断（SPI）留给以后的设备驱动。
//! 中断号只在本目录内出现；Core 只看到逻辑中断线。

use core::sync::atomic::{AtomicU64, Ordering};

/// 分发器：控制寄存器。
const GICD_CTLR: u64 = 0x000;
/// 分发器：使能置位寄存器组。
const GICD_ISENABLER: u64 = 0x100;
/// 分发器：使能清除寄存器组。
const GICD_ICENABLER: u64 = 0x180;
/// 分发器：优先级寄存器组（每个中断 1 字节）。
const GICD_IPRIORITYR: u64 = 0x400;
/// CPU 接口：控制寄存器。
const GICC_CTLR: u64 = 0x000;
/// CPU 接口：优先级屏蔽寄存器。
const GICC_PMR: u64 = 0x004;
/// CPU 接口：分组点寄存器。
const GICC_BPR: u64 = 0x008;
/// CPU 接口：应答寄存器。
const GICC_IAR: u64 = 0x00c;
/// CPU 接口：中断结束寄存器。
const GICC_EOIR: u64 = 0x010;
/// 应答值中的中断号字段。
const IAR_ID_MASK: u32 = 0x3ff;
/// 伪中断号（没有待处理的中断）。
pub const SPURIOUS: u32 = 1023;
/// 使能的中断所用的优先级（数值越小越优先）。
const PRIORITY: u8 = 0xa0;

/// 分发器与 CPU 接口的虚拟地址（0 = 尚未从设备树得到）。
static DIST: AtomicU64 = AtomicU64::new(0);
static CPU: AtomicU64 = AtomicU64::new(0);

/// 设置两组寄存器的虚拟地址（引导适配层解析设备树后调用）。
pub fn set_bases(dist_va: u64, cpu_va: u64) {
    DIST.store(dist_va, Ordering::Relaxed);
    CPU.store(cpu_va, Ordering::Relaxed);
}

/// 写 32 位寄存器。
///
/// # Safety
/// `base` 必须是已映射为设备内存的 GIC 寄存器块。
unsafe fn w32(base: u64, off: u64, v: u32) {
    ((base + off) as *mut u32).write_volatile(v)
}

/// 读 32 位寄存器。
///
/// # Safety
/// 同 [`w32`]。
unsafe fn r32(base: u64, off: u64) -> u32 {
    ((base + off) as *const u32).read_volatile()
}

/// 初始化并只使能私有中断 `ppi`（< 32）。基地址未知或中断号不是私有中断时返回 `false`，不做任何写入。
/// Initialise the GIC and enable only private interrupt `ppi`.
pub fn init(ppi: u32) -> bool {
    let (d, c) = (DIST.load(Ordering::Relaxed), CPU.load(Ordering::Relaxed));
    if d == 0 || c == 0 || ppi >= 32 {
        return false;
    }
    // SAFETY：基地址来自设备树中的 GIC 节点并以设备内存属性映射；按 GICv2 规定的顺序：
    // 先关分发器 → 清掉本处理器全部私有中断的使能 → 设优先级 → 只使能目标中断 → 开分发器 → 开 CPU 接口。
    unsafe {
        w32(d, GICD_CTLR, 0);
        w32(d, GICD_ICENABLER, u32::MAX);
        ((d + GICD_IPRIORITYR + u64::from(ppi)) as *mut u8).write_volatile(PRIORITY);
        w32(d, GICD_ISENABLER, 1 << ppi);
        w32(d, GICD_CTLR, 1);
        w32(c, GICC_PMR, 0xff);
        w32(c, GICC_BPR, 0);
        w32(c, GICC_CTLR, 1);
    }
    true
}

/// 应答当前最高优先级的待处理中断，返回原始应答值（结束时原样交回 [`end`]）。
pub fn acknowledge() -> u32 {
    // SAFETY：只在 IRQ 入口调用；读 IAR 是 GIC 规定的应答方式。
    unsafe { r32(CPU.load(Ordering::Relaxed), GICC_IAR) }
}

/// 应答值中的中断号。
pub fn interrupt_id(iar: u32) -> u32 {
    iar & IAR_ID_MASK
}

/// 结束一个已应答的中断（降优先级并失活）。
pub fn end(iar: u32) {
    // SAFETY：`iar` 来自 [`acknowledge`]；写 EOIR 是 GIC 规定的结束方式。
    unsafe { w32(CPU.load(Ordering::Relaxed), GICC_EOIR, iar) }
}
