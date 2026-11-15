//! x86_64 的设备 MSI 向量：范围选择、IDT 入口、消息编码与投递。
//! x86_64 device MSI vectors: range selection, IDT entries, message encoding and delivery.
//!
//! # 职责
//! * 为设备 MSI 使用架构允许的完整外部设备向量窗口：`0x60..=0xEF`。
//!   已占用：`0x00–0x1F` 处理器异常、`0x20–0x2F` 8259、`0x50/0x51` I/O APIC 设备线、
//!   `0xEC` 本地定时器、`0xF0–0xF2` 核间中断、`0xFF` 伪中断。
//! * 为这段向量各装一个 IDT 入口。入口只做两件事：把向量交给 Core 的 `irq::on_msi`
//!   （按当前处理器查表、计数、调用处理函数），然后向本地 APIC 发 EOI。
//! * 组合 MSI 消息（目的地 = 目标处理器的 APIC 标识）并投递固定向量中断。
//!
//! # 边界
//! 所有 x86 专有数值与 APIC 访问都在本文件；Core 只经 `arch::Platform` 的
//! `msi_vector_range` / `msi_message` / `msi_trigger` 使用。MSI-X 表的写入与设备使能属于后续步骤，
//! 本文件不触碰设备配置空间。

use x86_64::structures::idt::InterruptStackFrame;

use super::apic;
use super::smp;
use crate::arch::{MsiMessage, MsiRange};

/// 设备 MSI 向量范围的第一个向量。
pub const FIRST_VECTOR: u8 = 0x60;
/// 外部设备向量窗口终点（不含）。
pub const END_VECTOR: u8 = 0xF0;
/// 本地 APIC 定时器在该窗口中的保留向量。
const LOCAL_TIMER_VECTOR: u8 = 0xEC;
/// 设备 MSI 向量个数。
pub const VECTOR_COUNT: u8 = END_VECTOR - FIRST_VECTOR - 1;

/// 固定投递的 MSI 消息地址基址（本地 APIC 消息地址）。
const MSI_ADDRESS_BASE: u64 = 0xFEE0_0000;

/// 向量是否落在本平台的设备 MSI 范围内。
fn in_range(vector: u8) -> bool {
    (FIRST_VECTOR..END_VECTOR).contains(&vector) && vector != LOCAL_TIMER_VECTOR
}

/// 可用的向量范围。
pub fn range() -> MsiRange {
    MsiRange { first: FIRST_VECTOR, count: VECTOR_COUNT }
}

/// 组合发往逻辑处理器 `cpu`、向量为 `vector` 的 MSI 消息。
///
/// 地址 = 本地 APIC 消息地址 | (目标 APIC 标识 << 12)；数据 = 向量号（固定投递、边沿触发）。
/// 处理器不存在、APIC 标识不可寻址或向量不在范围内时返回 `None`。
pub fn message(cpu: usize, vector: u8) -> Option<MsiMessage> {
    if !in_range(vector) {
        return None;
    }
    let apic_id = smp::hw_id_of(cpu).filter(|&id| id < 256)?;
    Some(MsiMessage {
        address: MSI_ADDRESS_BASE | (apic_id as u64) << 12,
        data: vector as u32,
    })
}

/// 向处理器 `cpu` 的 `vector` 投递一条真实 MSI（自测用）。
pub fn trigger(cpu: usize, vector: u8) -> Result<(), kernel_core::msi::MsiError> {
    use kernel_core::msi::MsiError;
    if !in_range(vector) {
        return Err(MsiError::OutOfRange);
    }
    let apic_id = smp::hw_id_of(cpu).filter(|&id| id < 256).ok_or(MsiError::NoSuchCpu)?;
    if apic::send_fixed(apic_id, vector) {
        Ok(())
    } else {
        Err(MsiError::Timeout)
    }
}

mod generated {
    use super::*;
    include!(concat!(env!("OUT_DIR"), "/x86_msi_entries.rs"));
}

/// 向量号与对应入口（供 IDT 初始化逐项安装）。
pub(super) use generated::ENTRIES;
