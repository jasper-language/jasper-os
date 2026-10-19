//! GICv2 中断控制器：分发器（Distributor）与 CPU 接口的初始化、应答与结束，以及核间中断（软件生成中断）。
//! GICv2 distributor and CPU interface: init, acknowledge, end-of-interrupt, and SGIs used as IPIs.
//!
//! 寄存器基地址来自设备树（`arm,cortex-a15-gic` / `arm,gic-400` 的 `reg` 第 0、1 项）。
//! 每个处理器只使能自己的私有中断（PPI，编号 < 32）与用作核间中断的软件生成中断（SGI 0–2）；
//! 共享外设中断（SPI）留给以后的设备驱动。分发器的全局开关只由引导处理器打开一次，
//! 私有中断与软件生成中断的使能、优先级寄存器以及 CPU 接口都是按处理器分组（banked）的，各处理器自己初始化。
//! 中断号只在本目录内出现；Core 只看到逻辑中断线。

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use kernel_core::smp::{IpiKind, MAX_CPUS};

/// 分发器：控制寄存器。
const GICD_CTLR: u64 = 0x000;
/// 分发器：使能置位寄存器组。
const GICD_ISENABLER: u64 = 0x100;
/// 分发器：使能清除寄存器组。
const GICD_ICENABLER: u64 = 0x180;
/// 分发器：优先级寄存器组（每个中断 1 字节）。
const GICD_IPRIORITYR: u64 = 0x400;
/// 分发器：目标寄存器组；第 0 组的低字节读出「本处理器的 CPU 接口位」（按处理器分组）。
const GICD_ITARGETSR: u64 = 0x800;
/// 分发器：软件生成中断寄存器（写入目标接口位与中断号即发出）。
const GICD_SGIR: u64 = 0xf00;
/// 用作核间中断的软件生成中断号（与 [`IpiKind`] 一一对应）。
const SGI_RESCHEDULE: u32 = 0;
const SGI_SHOOTDOWN: u32 = 1;
const SGI_CALL: u32 = 2;
/// 上面三个软件生成中断的使能位。
const SGI_MASK: u32 = (1 << SGI_RESCHEDULE) | (1 << SGI_SHOOTDOWN) | (1 << SGI_CALL);
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
/// 逻辑下标 → CPU 接口位（GICv2 至多 8 个接口；0 = 未登记或单处理器实现）。
static INTERFACE: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(0) }; MAX_CPUS];

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

/// 引导处理器：初始化分发器与本处理器，只使能私有中断 `ppi`（< 32）与核间中断用的软件生成中断。
/// 基地址未知或中断号不是私有中断时返回 `false`，不做任何写入。
/// Initialise the distributor and the boot processor's interface.
pub fn init(ppi: u32) -> bool {
    let (d, c) = (DIST.load(Ordering::Relaxed), CPU.load(Ordering::Relaxed));
    if d == 0 || c == 0 || ppi >= 32 {
        return false;
    }
    // SAFETY：基地址来自设备树中的 GIC 节点并以设备内存属性映射；按 GICv2 规定的顺序：先关分发器 → 本处理器初始化 → 开分发器。
    unsafe {
        w32(d, GICD_CTLR, 0);
        init_banked(d, c, ppi);
        w32(d, GICD_CTLR, 1);
    }
    true
}

/// 其他处理器：只初始化本处理器按处理器分组的部分（分发器的全局开关已由引导处理器打开）。
/// 条件同 [`init`]；失败时不做任何写入。
/// Initialise the executing secondary processor's banked state.
pub fn init_cpu(ppi: u32) -> bool {
    let (d, c) = (DIST.load(Ordering::Relaxed), CPU.load(Ordering::Relaxed));
    if d == 0 || c == 0 || ppi >= 32 {
        return false;
    }
    // SAFETY：同 [`init`]；只写按处理器分组的寄存器。
    unsafe { init_banked(d, c, ppi) };
    true
}

/// 本处理器的分组寄存器：清掉全部私有中断的使能 → 设优先级 → 只使能目标中断 → 开 CPU 接口。
///
/// # Safety
/// `d`、`c` 是已映射的分发器与 CPU 接口；`ppi < 32`。
unsafe fn init_banked(d: u64, c: u64, ppi: u32) {
    w32(d, GICD_ICENABLER, u32::MAX);
    for id in [ppi, SGI_RESCHEDULE, SGI_SHOOTDOWN, SGI_CALL] {
        ((d + GICD_IPRIORITYR + u64::from(id)) as *mut u8).write_volatile(PRIORITY);
    }
    w32(d, GICD_ISENABLER, (1 << ppi) | SGI_MASK);
    w32(c, GICC_PMR, 0xff);
    w32(c, GICC_BPR, 0);
    w32(c, GICC_CTLR, 1);
}

/// 登记执行者（逻辑下标 `index`）的 CPU 接口位，供之后向它发送软件生成中断。返回登记到的接口位（0 = 不可寻址）。
/// Record the executing processor's CPU interface bit.
pub fn record_interface(index: usize) -> u8 {
    let d = DIST.load(Ordering::Relaxed);
    if d == 0 || index >= MAX_CPUS {
        return 0;
    }
    // SAFETY：目标寄存器第 0 组按处理器分组且只读，读出的低字节就是本处理器的接口位。
    let bit = unsafe { r32(d, GICD_ITARGETSR) } as u8;
    INTERFACE[index].store(bit, Ordering::Release);
    bit
}

/// 向逻辑下标 `index` 的处理器发送与 `kind` 对应的软件生成中断。目标未登记接口位时返回 `false`，不写寄存器。
/// Send the SGI for `kind` to processor `index`.
pub fn send_sgi(index: usize, kind: IpiKind) -> bool {
    let d = DIST.load(Ordering::Relaxed);
    let bit = INTERFACE.get(index).map(|b| b.load(Ordering::Acquire)).unwrap_or(0);
    if d == 0 || bit == 0 {
        return false;
    }
    let id = match kind {
        IpiKind::Reschedule => SGI_RESCHEDULE,
        IpiKind::TlbShootdown => SGI_SHOOTDOWN,
        IpiKind::Call => SGI_CALL,
    };
    // 先让之前的普通内存写入（请求内容）对目标可见，再发中断
    // SAFETY：屏障无副作用；写 SGIR 只产生一个软件生成中断（过滤字段 0 = 按目标列表）。
    unsafe {
        core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
        w32(d, GICD_SGIR, (u32::from(bit) << 16) | id);
    }
    true
}

/// 中断号若是核间中断，返回其种类。
/// IPI kind of interrupt `id`, if it is one.
pub fn ipi_kind(id: u32) -> Option<IpiKind> {
    match id {
        SGI_RESCHEDULE => Some(IpiKind::Reschedule),
        SGI_SHOOTDOWN => Some(IpiKind::TlbShootdown),
        SGI_CALL => Some(IpiKind::Call),
        _ => None,
    }
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
