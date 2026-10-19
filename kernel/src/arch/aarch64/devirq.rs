//! AArch64 平台的可路由设备中断线：PL011 串口与 PL031 实时时钟的共享外设中断，经 GICv2 分发器投递到任意处理器。
//! Routable device interrupt lines on AArch64: the PL011 UART and PL031 RTC shared peripheral interrupts via the GICv2.
//!
//! # 职责
//! * 线 0 = 串口的共享外设中断，线 1 = 实时时钟的共享外设中断（中断号来自设备树，设备树里有才存在）。
//! * 路由 = 改写分发器目标寄存器中该中断的接口位；屏蔽 = 分发器的使能位（关闭期间挂起状态保留，不会丢失）。
//! * 持续自触发由分发器的「置挂起」产生：处理窗口内（结束中断之前）再次置挂起，结束后立即再次送达。
//!
//! # 边界与原因
//! * 两个设备自身的中断源保持关闭：控制台发送不受影响，实时时钟也不必改时间；设备侧没有需要清除的中断条件，
//!   因此确认只在持续自触发时重新置挂起。演练与自检因此不依赖某一款设备的中断时序。
//! * 处理器的接口位由多处理器启动时登记；未登记的处理器拒绝作为目标。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use kernel_core::irq::IrqError;

use super::gic;

/// 线的规范名。
const NAMES: [&str; 2] = ["uart", "rtc"];

/// 各线的中断号（0 = 不可用）。
static IDS: [AtomicU32; 2] = [const { AtomicU32::new(0) }; 2];
/// 可用线数。
static COUNT: AtomicUsize = AtomicUsize::new(0);
/// 各线的持续自触发开关。
static STORM: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];

/// 登记设备树给出的两个共享外设中断号（`None` = 设备树里没有该设备）。
pub fn set_ids(uart: Option<u32>, rtc: Option<u32>) {
    IDS[0].store(uart.unwrap_or(0), Ordering::Relaxed);
    IDS[1].store(rtc.unwrap_or(0), Ordering::Relaxed);
}

/// 引导处理器上配置（分发器初始化、引导处理器接口位登记之后调用一次）：关闭、清挂起、目标为引导处理器。返回可用线数。
pub fn configure() -> usize {
    let mut n = 0;
    for (i, id) in IDS.iter().enumerate() {
        let id = id.load(Ordering::Relaxed);
        if id == 0 || !gic::spi_configure(id) {
            break;
        }
        n = i + 1;
    }
    COUNT.store(n, Ordering::Release);
    n
}

/// 可用线数。
pub fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}

/// 线的规范名。
pub fn name(line: usize) -> &'static str {
    NAMES.get(line).copied().unwrap_or("none")
}

/// 中断号对应的线（中断入口用）。
pub fn line_of_id(id: u32) -> Option<usize> {
    (0..count()).find(|&i| IDS[i].load(Ordering::Relaxed) == id)
}

fn id_of(line: usize) -> Option<u32> {
    if line < count() {
        Some(IDS[line].load(Ordering::Relaxed))
    } else {
        None
    }
}

/// 路由到处理器 `cpu`（屏蔽状态不变）。
pub fn route(line: usize, cpu: usize) -> Result<(), IrqError> {
    let id = id_of(line).ok_or(IrqError::NoLine)?;
    if gic::spi_set_target(id, cpu) {
        Ok(())
    } else {
        Err(IrqError::RouteFailed)
    }
}

/// 屏蔽 / 解除屏蔽；解除时持续自触发的线重新置挂起（幂等）。
pub fn set_masked(line: usize, masked: bool) {
    let Some(id) = id_of(line) else {
        return;
    };
    gic::spi_set_enabled(id, !masked);
    if !masked && STORM[line].load(Ordering::Relaxed) {
        gic::spi_set_pending(id, true);
    }
}

/// 确认：设备侧没有中断条件要清除；持续自触发时再次置挂起。
pub fn ack(line: usize) {
    if let Some(id) = id_of(line) {
        if STORM[line].load(Ordering::Relaxed) {
            gic::spi_set_pending(id, true);
        }
    }
}

/// 打开 / 关闭持续自触发；关闭时清掉残留的挂起。
pub fn self_trigger(line: usize, on: bool) -> Result<(), IrqError> {
    let id = id_of(line).ok_or(IrqError::NoLine)?;
    STORM[line].store(on, Ordering::Relaxed);
    gic::spi_set_pending(id, on);
    Ok(())
}
