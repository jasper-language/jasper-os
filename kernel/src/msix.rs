//! MSI-X 表与 PBA 的内核侧操作：不可缓存映射、表项编程、屏蔽 / 解除屏蔽、待决位与功能使能。
//! Kernel-side MSI-X table/PBA operations: uncached mapping, entry programming, masking and pending bits.
//!
//! # 职责
//! * 用 [`crate::mmio`] 把 MSI-X 表与 PBA 所在的 BAR 子区间映射为不可缓存内核窗口；不另造映射器。
//! * 用 `kernel_core::pci` 的表项布局与 PBA 位解释，组合 [`crate::arch::msi_message`] 给出的消息并写入表项。
//! * 编程顺序固定为「先屏蔽该项 → 写地址 / 数据 → 按调用者意愿解除屏蔽」；非法输入在写任何寄存器之前拒绝。
//!
//! # 边界
//! * 不解析能力链（启动期已完成）、不分配向量池、不注册处理函数；向量与目标处理器由调用者给出。
//! * 所有 MMIO 访问都经 [`mmio::Mapping`] 的 volatile 读写；本文件不含指令集专有值。
//! * 写入表项期间不修改全局使能位；[`MsixDevice::enable`] / [`MsixDevice::disable`] 单独控制功能位。

use kernel_core::pci::{
    self as core_pci, msix_control_disable, msix_control_enable, msix_control_function_masked,
    msix_control_set_function_masked, Bdf, MsixCapability, MsixEntry,
};

use crate::mmio::{Mapping, MmioError};
use crate::{arch, pci, sched};

/// MSI-X 操作错误。
/// MSI-X operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsixError {
    /// 设备没有解析到 MSI-X 能力。
    /// The device has no parsed MSI-X capability.
    NoCapability,
    /// 表项下标超出该功能的表大小。
    /// The table index is outside the function's table.
    EntryOutOfRange,
    /// 处理器下标越界或不在线。
    /// The processor index is out of range or offline.
    CpuOffline,
    /// 向量不在平台给出的 MSI 向量范围内。
    /// The vector is outside the platform's MSI vector range.
    VectorOutOfRange,
    /// 平台无法为请求的目标组合 MSI 消息。
    /// The platform cannot compose a message for the requested destination.
    MessageUnavailable,
    /// 配置空间不可达（能力控制字段读写失败）。
    /// The configuration space is unreachable.
    Unreachable,
    /// 表或 PBA 无法映射到内核窗口。
    /// The table or PBA cannot be mapped into the kernel window.
    MapFailed(MmioError),
}

impl MsixError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            MsixError::NoCapability => "system.device.error.msix_no_capability",
            MsixError::EntryOutOfRange => "system.device.error.msix_entry_out_of_range",
            MsixError::CpuOffline => "system.cpu.error.not_online",
            MsixError::VectorOutOfRange => "system.irq.error.msi_vector_out_of_range",
            MsixError::MessageUnavailable => "system.irq.error.msi_unsupported",
            MsixError::Unreachable => "system.device.error.config_unreachable",
            MsixError::MapFailed(reason) => reason.name(),
        }
    }
}

impl From<MmioError> for MsixError {
    fn from(reason: MmioError) -> MsixError {
        MsixError::MapFailed(reason)
    }
}

/// 一个功能的 MSI-X 表操作句柄；丢弃时取消映射并关闭功能使能。
/// A handle over one function's MSI-X table; unmapped and disabled on drop.
pub struct MsixDevice {
    bdf: Bdf,
    capability: MsixCapability,
    table: Mapping,
    pba: Mapping,
    saved_control: u16,
}

impl MsixDevice {
    /// 为已解析 MSI-X 能力的设备映射表与 PBA，并保存原始控制字段。
    ///
    /// 没有能力、BAR 不是内存 BAR、区间越界或映射失败时返回结构化错误，不产生句柄。
    /// Maps the table and PBA of a device with a parsed MSI-X capability.
    pub fn new(device: &pci::Device) -> Result<MsixDevice, MsixError> {
        let capability = device.msix.ok_or(MsixError::NoCapability)?;
        let table = capability.table();
        let table_bytes = table.table_size() as u32 * core_pci::MSIX_TABLE_ENTRY as u32;
        let pba_bytes = table.pba_bytes() as u32;
        let table_bar = *device.bars.get(table.table_bir() as usize).ok_or(MsixError::MapFailed(MmioError::BadBar))?;
        let pba_bar = *device.bars.get(table.pba_bir() as usize).ok_or(MsixError::MapFailed(MmioError::BadBar))?;
        let table_map = Mapping::map(&table_bar, table.table_offset(), table_bytes)?;
        let pba_map = match Mapping::map(&pba_bar, table.pba_offset(), pba_bytes) {
            Ok(map) => map,
            Err(e) => return Err(MsixError::MapFailed(e)),
        };
        let saved_control = read_control(device.bdf, capability)?;
        Ok(MsixDevice {
            bdf: device.bdf,
            capability,
            table: table_map,
            pba: pba_map,
            saved_control,
        })
    }

    /// 设备地址。
    /// Device address.
    pub const fn bdf(&self) -> Bdf {
        self.bdf
    }

    /// 表项数。
    /// Number of table entries.
    pub const fn table_size(&self) -> u16 {
        self.capability.table().table_size()
    }

    /// 建立句柄时读到的能力控制字段。
    /// Capability control word observed when the handle was built.
    pub const fn saved_control(&self) -> u16 {
        self.saved_control
    }

    /// 当前能力控制字段（配置空间读失败时返回 [`MsixError::Unreachable`]）。
    /// Reads the current capability control word.
    pub fn control(&self) -> Result<u16, MsixError> {
        read_control(self.bdf, self.capability)
    }

    /// 使能 MSI-X 并清除功能屏蔽位（表项自身的屏蔽位不变）。
    /// Enables MSI-X and clears the function-mask bit, leaving per-vector masks untouched.
    pub fn enable(&mut self) -> Result<(), MsixError> {
        let control = self.control()?;
        let next = msix_control_enable(control);
        self.write_control(msix_control_set_function_masked(next, false))
    }

    /// 清除 MSI-X 全局使能位（保留功能屏蔽位与表项屏蔽位）。
    /// Clears the MSI-X global-enable bit.
    pub fn disable(&mut self) -> Result<(), MsixError> {
        let control = self.control()?;
        self.write_control(msix_control_disable(control))
    }

    /// 功能屏蔽位当前状态。
    /// Current function-mask state.
    pub fn function_masked(&self) -> Result<bool, MsixError> {
        Ok(msix_control_function_masked(self.control()?))
    }

    /// 读取一个表项；下标越界返回 [`MsixError::EntryOutOfRange`]。
    /// Reads one table entry, rejecting out-of-range indices.
    pub fn entry(&self, index: u16) -> Result<MsixEntry, MsixError> {
        let offset = self.entry_offset(index)?;
        let low = self.read_table_word(offset);
        let high = self.read_table_word(offset + 4);
        let data = self.read_table_word(offset + 8);
        let control = self.read_table_word(offset + 12);
        Ok(MsixEntry::from_words([low, high, data, control]))
    }

    /// 把表项 `index` 编程为发往处理器 `cpu`、向量 `vector` 的消息。
    ///
    /// 先置该表项的屏蔽位并写入地址 / 数据，最后按 `unmask` 决定是否解除屏蔽。
    /// 表项越界、处理器越界 / 不在线、向量越界或消息无法组合时返回结构化错误，且不写任何寄存器。
    /// Programs one entry for `(cpu, vector)`, masking it first and optionally unmasking it last.
    pub fn program(&mut self, index: u16, cpu: usize, vector: u8, unmask: bool) -> Result<(), MsixError> {
        let offset = self.entry_offset(index)?;
        if !sched::online_cpus().contains(cpu) {
            return Err(MsixError::CpuOffline);
        }
        let range = arch::msi_vector_range().ok_or(MsixError::VectorOutOfRange)?;
        let in_range = vector as u16 >= range.first as u16
            && (vector as u16) < range.first as u16 + range.count as u16;
        if !in_range {
            return Err(MsixError::VectorOutOfRange);
        }
        let message = arch::msi_message(cpu, vector).ok_or(MsixError::MessageUnavailable)?;

        let current = self.entry(index)?;
        let addressed = current.with_message(message.address, message.data).ok_or(MsixError::MessageUnavailable)?;
        let masked = addressed.with_mask(true);
        let final_entry = addressed.with_mask(!unmask);
        let words = masked.words();
        self.write_table_word(offset, words[core_pci::MSIX_ENTRY_ADDR_LOW]);
        self.write_table_word(offset + 4, words[core_pci::MSIX_ENTRY_ADDR_HIGH]);
        self.write_table_word(offset + 8, words[core_pci::MSIX_ENTRY_DATA]);
        self.write_table_word(offset + 12, words[core_pci::MSIX_ENTRY_CONTROL]);
        self.write_table_word(offset + 12, final_entry.words()[core_pci::MSIX_ENTRY_CONTROL]);
        Ok(())
    }

    /// 屏蔽一个表项（保留消息字段）。
    /// Masks one entry.
    pub fn mask(&mut self, index: u16) -> Result<(), MsixError> {
        let offset = self.entry_offset(index)?;
        let current = self.entry(index)?;
        self.write_table_word(offset + 12, current.with_mask(true).words()[core_pci::MSIX_ENTRY_CONTROL]);
        Ok(())
    }

    /// 解除一个表项的屏蔽（保留消息字段）。
    /// Unmasks one entry.
    pub fn unmask(&mut self, index: u16) -> Result<(), MsixError> {
        let offset = self.entry_offset(index)?;
        let current = self.entry(index)?;
        self.write_table_word(offset + 12, current.with_mask(false).words()[core_pci::MSIX_ENTRY_CONTROL]);
        Ok(())
    }

    /// 读取一个表项的 PBA 待决位；下标越界返回 [`MsixError::EntryOutOfRange`]。
    /// Reads the pending bit of one entry.
    pub fn pending(&self, index: u16) -> Result<bool, MsixError> {
        let table = self.capability.table();
        // 能力给出的是 BAR 内绝对偏移，而 PBA 映射已指向 PBA 起点：换算为映射内偏移。
        let word_index = table.pba_word_offset(index).ok_or(MsixError::EntryOutOfRange)? - table.pba_offset() as u64;
        let low = unsafe { self.pba.read32(word_index) } as u64;
        let high = unsafe { self.pba.read32(word_index + 4) } as u64;
        let word = low | high << 32;
        let bit = index % 64;
        core_pci::msix_pba_pending(&[word], bit + 1, bit).ok_or(MsixError::EntryOutOfRange)
    }

    fn entry_offset(&self, index: u16) -> Result<u64, MsixError> {
        let table = self.capability.table();
        // 能力给出的是 BAR 内绝对偏移，而表映射已指向表起点：换算为映射内偏移。
        table
            .entry_offset(index)
            .map(|offset| offset - table.table_offset() as u64)
            .ok_or(MsixError::EntryOutOfRange)
    }

    fn read_table_word(&self, offset: u64) -> u32 {
        // SAFETY：`offset` 已按表项布局限制在已映射的表区间内。
        unsafe { self.table.read32(offset) }
    }

    fn write_table_word(&mut self, offset: u64, value: u32) {
        // SAFETY：同 `read_table_word`；写入的是表项的一个 32 位字。
        unsafe { self.table.write32(offset, value) };
    }

    fn write_control(&mut self, value: u16) -> Result<(), MsixError> {
        let at = self.capability.offset() as u16;
        let word = pci::read_config32(self.bdf, at).ok_or(MsixError::Unreachable)?;
        if pci::write_config32(self.bdf, at, (value as u32) << 16 | (word & 0xFFFF)) {
            Ok(())
        } else {
            Err(MsixError::Unreachable)
        }
    }
}

impl Drop for MsixDevice {
    fn drop(&mut self) {
        // 清理路径尽力关闭全局使能；失败不掩盖已经报告的错误。
        let _ = self.disable();
    }
}

/// 读取 MSI-X 能力控制字段（能力头双字的高 16 位）。
fn read_control(bdf: Bdf, capability: MsixCapability) -> Result<u16, MsixError> {
    let word = pci::read_config32(bdf, capability.offset() as u16).ok_or(MsixError::Unreachable)?;
    Ok((word >> 16) as u16)
}
