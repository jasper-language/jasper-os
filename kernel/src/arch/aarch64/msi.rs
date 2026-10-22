//! AArch64 的 MSI：GICv2m 帧、向量范围、消息与投递。
//! AArch64 MSI through the GICv2m frame: vector range, message composition and delivery.
//!
//! # 模型
//! GICv2m 在设备树里以 `arm,gic-v2m-frame` 给出一个 4 KiB 的寄存器帧。帧内的 SPI 号范围不是
//! 设备树的固定属性，而是由帧的 TYPER 寄存器在运行期报告（高 16 位 = 第一个共享外设中断号，
//! 低 16 位 = 可用个数）。内核只取其中前 [`VECTOR_COUNT`] 个作为设备 MSI 向量，编号就是 GIC
//! 的中断号，因此中断入口可以按中断号直接找回向量。
//!
//! 投递分两步：先把该中断号在分发器里的目标改成逻辑处理器 `cpu`，再向帧的 SETSPI 寄存器写入
//! 中断号。地址本身不编码目标处理器（GICv2m 的目标由分发器决定），所以平台把
//! [`super::super::Platform::MSI_ADDRESS_ENCODES_TARGET`] 保持为假，演练据此核对实际送达的处理器。
//!
//! # 边界
//! * 只处理 GICv2m 的共享外设中断帧；不含 ITS / GICv3 的 LPI 路径。
//! * 向帧写入的值与寄存器偏移只在本文件出现；Core 只看到向量号与消息。
//! * SPI 线在第一次使用时配置并解除屏蔽；之后每次投递只改目标与写帧。

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use kernel_core::fdt::Fdt;
use kernel_core::msi::MsiError;

use super::{cpu, gic, mmu};
use crate::arch::{MsiMessage, MsiRange};

/// GICv2m 帧内报告 SPI 范围的 TYPER 寄存器偏移。
const V2M_MSI_TYPER: u64 = 0x008;
/// GICv2m 帧内触发一条 SPI 的 SETSPI_NS 寄存器偏移。
const V2M_MSI_SETSPI_NS: u64 = 0x040;
/// 本平台交给 Core 的每核向量数；与 x86_64 相同，便于上层用同一套分配语义。
pub const VECTOR_COUNT: u8 = 16;

/// 帧的虚拟地址（0 = 设备树没有 GICv2m）。
static FRAME: AtomicU64 = AtomicU64::new(0);
/// 帧的物理地址：写进设备消息，设备按总线地址访问。
static FRAME_PHYS: AtomicU64 = AtomicU64::new(0);
/// 第一个可用 SPI（来自 TYPER）。
static FIRST: AtomicU8 = AtomicU8::new(0);
/// 可用 SPI 个数（已截到 [`VECTOR_COUNT`]）。
static COUNT: AtomicU8 = AtomicU8::new(0);
/// SPI 是否已在分发器里配置并解除屏蔽。
static READY: AtomicU8 = AtomicU8::new(0);

/// 从设备树记录 GICv2m 帧并读出 SPI 范围；没有该节点或范围不可用时返回 `false`。
/// 只记录参数，不配置分发器：此时 GIC 与处理器接口尚未初始化。
pub fn configure(fdt: &Fdt<'_>) -> bool {
    let Ok(Some(node)) = fdt.find_compatible("arm,gic-v2m-frame") else {
        return false;
    };
    let Some((base, size)) = node.reg(0) else {
        return false;
    };
    if base == 0 || size < 0x1000 || base % 8 != 0 {
        return false;
    }
    let frame = mmu::PHYS_OFFSET + base;
    // SAFETY：帧落在第 0 GiB 的设备内存映射内，TYPER 是 32 位只读寄存器。
    let typer = unsafe { ((frame + V2M_MSI_TYPER) as *const u32).read_volatile() };
    let first = ((typer >> 16) & 0x3ff) as u8;
    let reported = (typer & 0xffff).min(u32::from(u8::MAX)) as u8;
    // 向量号是 u8；first + count 不得回绕，且至少要有两个向量（改绑 / 释放路径需要）。
    let available = u16::from(u8::MAX) - u16::from(first);
    let count = reported.min(VECTOR_COUNT).min(available as u8);
    if count < 2 {
        return false;
    }
    FRAME.store(frame, Ordering::Release);
    FRAME_PHYS.store(base, Ordering::Release);
    FIRST.store(first, Ordering::Release);
    COUNT.store(count, Ordering::Release);
    true
}

/// 可用的 MSI 向量范围；没有 GICv2m 时返回 `None`。
pub fn range() -> Option<MsiRange> {
    if FRAME.load(Ordering::Acquire) == 0 {
        return None;
    }
    let count = COUNT.load(Ordering::Acquire);
    (count >= 2).then_some(MsiRange { first: FIRST.load(Ordering::Acquire), count })
}

/// 中断号是否属于本平台的 MSI 向量。
pub fn owns(id: u32) -> bool {
    let first = u32::from(FIRST.load(Ordering::Acquire));
    let count = u32::from(COUNT.load(Ordering::Acquire));
    id >= first && id < first + count
}

/// 中断号对应的向量号。
pub fn vector_of(id: u32) -> u8 {
    id as u8
}

/// 向量是否在本平台范围内。
fn in_range(vector: u8) -> bool {
    let first = FIRST.load(Ordering::Acquire);
    let count = COUNT.load(Ordering::Acquire);
    vector >= first && u16::from(vector) < u16::from(first) + u16::from(count)
}

/// 第一次使用时在分发器里配置并解除屏蔽全部 MSI 线；之后不再重复写配置。
/// 每条线同时配成边沿触发：帧的写入只产生一个脉冲，电平语义会在应答前撤销它。
fn ensure_ready() -> bool {
    if FRAME.load(Ordering::Acquire) == 0 {
        return false;
    }
    if READY.load(Ordering::Acquire) != 0 {
        return true;
    }
    let first = FIRST.load(Ordering::Acquire);
    let count = COUNT.load(Ordering::Acquire);
    for index in 0..count {
        let id = u32::from(first) + u32::from(index);
        if !gic::spi_configure(id) || !gic::spi_set_edge(id, true) {
            return false;
        }
        gic::spi_set_enabled(id, true);
    }
    // 配置写入必须对中断分发可见后才允许投递。
    cpu::table_write_barrier();
    READY.store(1, Ordering::Release);
    true
}

/// 组合发往逻辑处理器 `cpu`、向量为 `vector` 的 MSI 消息。
///
/// 地址是帧的 SETSPI 寄存器（所有处理器相同），数据是 SPI 号；同时把该 SPI 的目标改到 `cpu`，
/// 因为 GICv2m 的目标不编码在消息地址里。地址取物理地址：消息由设备按总线地址写出，
/// 不能使用内核的偏移映射虚拟地址。处理器不可寻址或向量越界时返回 `None`，且不改目标。
pub fn message(cpu_index: usize, vector: u8) -> Option<MsiMessage> {
    if !in_range(vector) || !ensure_ready() {
        return None;
    }
    if !gic::spi_set_target(u32::from(vector), cpu_index) {
        return None;
    }
    Some(MsiMessage {
        address: FRAME_PHYS.load(Ordering::Acquire) + V2M_MSI_SETSPI_NS,
        data: u32::from(vector),
    })
}

/// 向处理器 `cpu` 的 `vector` 投递一条真实 MSI。
pub fn trigger(cpu_index: usize, vector: u8) -> Result<(), MsiError> {
    if !in_range(vector) {
        return Err(MsiError::OutOfRange);
    }
    if !ensure_ready() {
        return Err(MsiError::Unsupported);
    }
    if !gic::spi_set_target(u32::from(vector), cpu_index) {
        return Err(MsiError::NoSuchCpu);
    }
    let frame = FRAME.load(Ordering::Acquire);
    // SAFETY：`frame` 是设备树给出的 GICv2m 帧，已按设备内存映射；SETSPI 是 32 位写寄存器。
    unsafe { ((frame + V2M_MSI_SETSPI_NS) as *mut u32).write_volatile(u32::from(vector)) };
    // 让设备写先于后续对中断计数的读取可见。
    cpu::table_write_barrier();
    Ok(())
}
