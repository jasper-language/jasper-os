//! 本地 APIC（xAPIC 寄存器窗口）：每个处理器一个，负责核间中断、本地定时器与中断结束确认。
//! Local APIC (xAPIC MMIO): inter-processor interrupts, local timer and end-of-interrupt.
//!
//! # 职责
//! * 经 IA32_APIC_BASE 取得寄存器物理地址，经全物理内存映射访问（引导器至少映射低 4 GiB；
//!   该区间由固件的内存类型范围寄存器设为不可缓存，因此寄存器访问不经缓存）
//! * 启用本处理器的本地 APIC、发送 INIT / 启动 / 固定向量核间中断、EOI
//! * 本地定时器：以 PIT 为基准校准一次，之后各处理器按同一计数周期运行
//!
//! # 边界
//! 引导处理器的设备中断仍经 8259（虚拟线连接到本地 APIC 的 LINT0，不改动）；
//! 其他处理器屏蔽 LINT0/LINT1，只接收核间中断与自己的本地定时器。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use x86_64::registers::model_specific::Msr;

use super::pit;

/// 本地定时器向量。
pub const LOCAL_TIMER_VECTOR: u8 = 0xEC;
/// 「重新调度」核间中断向量。
pub const IPI_RESCHEDULE_VECTOR: u8 = 0xF0;
/// 「TLB 击落」核间中断向量。
pub const IPI_SHOOTDOWN_VECTOR: u8 = 0xF1;
/// 「跨核调用」核间中断向量。
pub const IPI_CALL_VECTOR: u8 = 0xF2;
/// 伪中断向量（低 4 位必须全 1）。
pub const SPURIOUS_VECTOR: u8 = 0xFF;

const MSR_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;

const REG_ID: u64 = 0x20;
const REG_TPR: u64 = 0x80;
const REG_EOI: u64 = 0xB0;
const REG_SVR: u64 = 0xF0;
const REG_ICR_LOW: u64 = 0x300;
const REG_ICR_HIGH: u64 = 0x310;
const REG_LVT_TIMER: u64 = 0x320;
const REG_LVT_LINT0: u64 = 0x350;
const REG_LVT_LINT1: u64 = 0x360;
const REG_LVT_ERROR: u64 = 0x370;
const REG_TIMER_INIT: u64 = 0x380;
const REG_TIMER_CURRENT: u64 = 0x390;
const REG_TIMER_DIVIDE: u64 = 0x3E0;

const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;
const LVT_EXTINT: u32 = 0b111 << 8;
const LVT_NMI: u32 = 0b100 << 8;
const ICR_PENDING: u32 = 1 << 12;
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
const ICR_INIT: u32 = 0b101 << 8;
const ICR_STARTUP: u32 = 0b110 << 8;
/// 定时器分频 16。
const DIVIDE_BY_16: u32 = 0b0011;
/// 校准窗口（毫秒）。
const CALIBRATE_MS: u32 = 10;

/// 寄存器窗口的虚拟地址（0 = 尚未初始化）。
static BASE: AtomicU64 = AtomicU64::new(0);
/// 校准结果：本地定时器每毫秒的计数（分频 16 之后）。
static COUNTS_PER_MS: AtomicU32 = AtomicU32::new(0);

fn read(reg: u64) -> u32 {
    // SAFETY：BASE 指向本地 APIC 寄存器窗口（调用前已初始化），寄存器 32 位对齐。
    unsafe { ((BASE.load(Ordering::Relaxed) + reg) as *const u32).read_volatile() }
}

fn write(reg: u64, value: u32) {
    // SAFETY：同上；写入是标准寄存器编程。
    unsafe { ((BASE.load(Ordering::Relaxed) + reg) as *mut u32).write_volatile(value) }
}

/// 寄存器窗口是否已就绪。
pub fn ready() -> bool {
    BASE.load(Ordering::Relaxed) != 0
}

/// 记录寄存器窗口位置（引导处理器上调用一次）；返回其物理地址。地址超出已映射的低 4 GiB 时返回 `None`。
pub fn init_base(phys_offset: u64) -> Option<u64> {
    // SAFETY：IA32_APIC_BASE 在所有 64 位处理器上存在；只读。
    let raw = unsafe { Msr::new(MSR_APIC_BASE).read() };
    let phys = raw & 0x000F_FFFF_FFFF_F000;
    if phys >= 1 << 32 {
        return None;
    }
    if raw & APIC_BASE_ENABLE == 0 {
        // SAFETY：只置全局启用位，基址不变。
        unsafe { Msr::new(MSR_APIC_BASE).write(raw | APIC_BASE_ENABLE) };
    }
    BASE.store(phys_offset + phys, Ordering::Release);
    Some(phys)
}

/// 启用本处理器的本地 APIC；非引导处理器同时屏蔽 LINT0/LINT1（外部中断只交给引导处理器）。
pub fn enable_local(boot_processor: bool) {
    if !boot_processor {
        // SAFETY：其他处理器的 IA32_APIC_BASE 与引导处理器同址；只置全局启用位。
        unsafe {
            let raw = Msr::new(MSR_APIC_BASE).read();
            Msr::new(MSR_APIC_BASE).write(raw | APIC_BASE_ENABLE);
        }
        write(REG_LVT_LINT0, LVT_MASKED);
        write(REG_LVT_LINT1, LVT_MASKED);
    } else {
        // 引导处理器：虚拟线模式（LINT0 = 外部中断，接 8259；LINT1 = NMI），设备中断照旧经 8259 投递
        write(REG_LVT_LINT0, LVT_EXTINT);
        write(REG_LVT_LINT1, LVT_NMI);
    }
    write(REG_LVT_ERROR, LVT_MASKED);
    write(REG_TPR, 0);
    write(REG_SVR, 0x100 | SPURIOUS_VECTOR as u32);
}

/// 本处理器的 APIC 标识。
pub fn id() -> u32 {
    read(REG_ID) >> 24
}

/// 中断结束确认。
pub fn eoi() {
    write(REG_EOI, 0);
}

/// 写中断命令寄存器并等待投递完成（有界：硬件异常时不永远自旋）。
fn send(dest: u32, low: u32) -> bool {
    write(REG_ICR_HIGH, dest << 24);
    write(REG_ICR_LOW, low);
    for _ in 0..1_000_000 {
        if read(REG_ICR_LOW) & ICR_PENDING == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// 发送固定向量核间中断。
pub fn send_fixed(dest: u32, vector: u8) -> bool {
    send(dest, ICR_LEVEL_ASSERT | vector as u32)
}

/// INIT → 10 ms → 启动（两次，间隔 200 µs）：处理器从 `start_page × 4 KiB` 处以实模式开始执行。
pub fn send_init_startup(dest: u32, start_page: u8) -> bool {
    if !send(dest, ICR_INIT | ICR_LEVEL_ASSERT) {
        return false;
    }
    pit::delay_us(10_000);
    for _ in 0..2 {
        if !send(dest, ICR_STARTUP | ICR_LEVEL_ASSERT | start_page as u32) {
            return false;
        }
        pit::delay_us(200);
    }
    true
}

/// 以 PIT 为基准校准本地定时器（引导处理器上调用一次）；返回每毫秒计数。
pub fn calibrate_timer() -> u32 {
    write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_TIMER_INIT, u32::MAX);
    pit::delay_us(CALIBRATE_MS * 1000);
    let elapsed = u32::MAX - read(REG_TIMER_CURRENT);
    write(REG_TIMER_INIT, 0);
    let per_ms = (elapsed / CALIBRATE_MS).max(1);
    COUNTS_PER_MS.store(per_ms, Ordering::Relaxed);
    per_ms
}

/// 让本处理器的本地定时器以 `hz` 周期中断（使用校准结果）；未校准时返回 `false`。
pub fn start_periodic(hz: u32) -> bool {
    let per_ms = COUNTS_PER_MS.load(Ordering::Relaxed);
    if per_ms == 0 || hz == 0 {
        return false;
    }
    let count = (per_ms as u64 * 1000 / hz as u64).clamp(1, u32::MAX as u64) as u32;
    write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
    write(REG_LVT_TIMER, LOCAL_TIMER_VECTOR as u32 | LVT_PERIODIC);
    write(REG_TIMER_INIT, count);
    true
}
