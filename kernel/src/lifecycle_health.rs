//! P0 A/B 最小生产健康门。
//! Minimum production health gate for P0 A/B boots.
//!
//! 只有全部启动阶段、设备装配、首个用户程序、P0 GPT 校验和真实 virtio-blk 控制记录
//! 读写均通过后，本模块才把当前试启动槽确认为健康。它不挂载 System A/B 根映像，也不
//! 代表完整系统服务健康。
//! This module confirms the current trial slot only after all boot stages, device assembly,
//! the first user program, P0 GPT validation and real virtio-blk control I/O pass. It does
//! not mount the System A/B root images or represent full-service health.

use alloc::sync::Arc;

use crc::{Crc, CRC_32_ISO_HDLC};
use jasper_lifecycle_boot::{
    recover, BootControlError, ControlIo, ControlIoError, CONTROL_RECORD_BYTES, P0_CONTROL_A_LBA,
    P0_CONTROL_A_PARTITION_GUID, P0_CONTROL_A_TYPE_GUID, P0_CONTROL_B_LBA,
    P0_CONTROL_B_PARTITION_GUID, P0_CONTROL_B_TYPE_GUID, P0_DISK_GUID,
};
#[cfg(not(feature = "lifecycle-health-fail-verify"))]
use jasper_lifecycle_boot::commit;
use jasper_lifecycle_boot::CommitError;
use kernel_core::block::{self, Request, Terminal};

use crate::blk::BlockDevice;
use crate::sync::IrqSpinLock;
#[cfg(not(feature = "lifecycle-health-fail-verify"))]
use crate::kprintln;
use crate::{mmio, pci, virtio};

const HEALTH_PAGES: u64 = 5;
const GPT_HEADER_LBA: u64 = 1;
const GPT_ENTRY_LBA: u64 = 2;
const GPT_HEADER_BYTES: usize = 92;
const GPT_ENTRY_BYTES: usize = 128;
const GPT_REVISION: u32 = 0x0001_0000;

/// 健康门失败原因。
/// Health-gate failure reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthError {
    /// 当前平台没有可验证的 Jasper P0 磁盘。No verifiable Jasper P0 disk is present.
    Unsupported,
    /// virtio-blk 初始化或 I/O 失败。virtio-blk initialization or I/O failed.
    Block,
    /// GPT 保护性 MBR 不符。The protective MBR does not match.
    GptMbr,
    /// GPT 头字段、磁盘 GUID 或位置不符。The GPT header fields, disk GUID or locations do not match.
    GptHeader,
    /// GPT 头 CRC 不符。The GPT header CRC does not match.
    GptCrc,
    /// Control 分区项不符。A Control partition entry does not match.
    GptPartition,
    /// 两份控制记录不能恢复。The two control records cannot be recovered.
    Recovery(BootControlError),
    /// 健康状态机拒绝当前槽。The health state machine rejected the current slot.
    State(BootControlError),
    /// 控制记录提交失败。Control-record commit failed.
    Commit(CommitError),
    /// 专用负向构建在健康门注入失败。The dedicated negative build injected a health failure.
    InjectedFailure,
}

impl HealthError {
    /// 稳定失败名。Stable failure name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Block => "block",
            Self::GptMbr => "gpt_mbr",
            Self::GptHeader => "gpt_header",
            Self::GptCrc => "gpt_crc",
            Self::GptPartition => "gpt_partition",
            Self::Recovery(_) => "recovery",
            Self::State(_) => "state",
            Self::Commit(_) => "commit",
            Self::InjectedFailure => "injected_failure",
        }
    }
}

struct KernelControlIo {
    device: Arc<IrqSpinLock<BlockDevice>>,
}

impl KernelControlIo {
    fn read_page(&self, lba: u64) -> Result<[u8; block::IO_ALIGNMENT as usize], HealthError> {
        if !lba.is_multiple_of(block::SECTORS_PER_IO_UNIT) {
            return Err(HealthError::Block);
        }
        let mut device = self.device.lock();
        if !matches!(
            device.execute(Request::read(lba, 1), false),
            Ok(Terminal::Completed)
        ) {
            return Err(HealthError::Block);
        }
        let mut page = [0u8; block::IO_ALIGNMENT as usize];
        device
            .copy_prefix(&mut page)
            .map_err(|_| HealthError::Block)?;
        Ok(page)
    }

    fn read_gpt(&self) -> Result<alloc::vec::Vec<u8>, HealthError> {
        let mut device = self.device.lock();
        if !matches!(
            device.execute(Request::read(0, HEALTH_PAGES), false),
            Ok(Terminal::Completed)
        ) {
            return Err(HealthError::Block);
        }
        let mut bytes = alloc::vec![0u8; HEALTH_PAGES as usize * block::IO_ALIGNMENT as usize];
        device
            .copy_prefix(&mut bytes)
            .map_err(|_| HealthError::Block)?;
        Ok(bytes)
    }

    fn write_page(
        &self,
        lba: u64,
        page: &[u8; block::IO_ALIGNMENT as usize],
    ) -> Result<(), HealthError> {
        if !lba.is_multiple_of(block::SECTORS_PER_IO_UNIT) {
            return Err(HealthError::Block);
        }
        let mut device = self.device.lock();
        device
            .fill_pattern(0, page)
            .map_err(|_| HealthError::Block)?;
        if matches!(
            device.execute(Request::write(lba, 1, true), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(HealthError::Block)
        }
    }

    fn copy_lba(copy: usize) -> Result<u64, ControlIoError> {
        match copy {
            0 => Ok(P0_CONTROL_A_LBA),
            1 => Ok(P0_CONTROL_B_LBA),
            _ => Err(ControlIoError::Failed),
        }
    }
}

impl ControlIo for KernelControlIo {
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let mut page = self
            .read_page(Self::copy_lba(copy)?)
            .map_err(|_| ControlIoError::Failed)?;
        page[..CONTROL_RECORD_BYTES].copy_from_slice(bytes);
        self.write_page(Self::copy_lba(copy)?, &page)
            .map_err(|_| ControlIoError::Failed)
    }

    fn flush(&mut self) -> Result<(), ControlIoError> {
        if matches!(
            self.device.lock().execute(Request::flush(), false),
            Ok(Terminal::Completed)
        ) {
            Ok(())
        } else {
            Err(ControlIoError::Failed)
        }
    }

    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let page = self
            .read_page(Self::copy_lba(copy)?)
            .map_err(|_| ControlIoError::Failed)?;
        out.copy_from_slice(&page[..CONTROL_RECORD_BYTES]);
        Ok(())
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().expect("fixed u32 field"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes[..8].try_into().expect("fixed u64 field"))
}

fn validate_gpt(
    page: &[u8],
    capacity: u64,
) -> Result<(), HealthError> {
    let mbr = &page[..block::SECTOR_BYTES as usize];
    if mbr[510..512] != [0x55, 0xaa]
        || mbr[446 + 4] != 0xee
        || read_u32(&mbr[446 + 8..446 + 12]) != 1
    {
        return Err(HealthError::GptMbr);
    }
    let header =
        &page[block::SECTOR_BYTES as usize..block::SECTOR_BYTES as usize + GPT_HEADER_BYTES];
    if &header[..8] != b"EFI PART"
        || read_u32(&header[8..12]) != GPT_REVISION
        || read_u32(&header[12..16]) as usize != GPT_HEADER_BYTES
        || read_u64(&header[24..32]) != GPT_HEADER_LBA
        || read_u64(&header[72..80]) != GPT_ENTRY_LBA
        || read_u32(&header[80..84]) != 128
        || read_u32(&header[84..88]) as usize != GPT_ENTRY_BYTES
        || header[56..72] != P0_DISK_GUID
    {
        return Err(HealthError::GptHeader);
    }
    let backup_lba = read_u64(&header[32..40]);
    if backup_lba.checked_add(1).is_none_or(|end| end > capacity) {
        return Err(HealthError::GptHeader);
    }
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let stored_crc = read_u32(&header[16..20]);
    let mut crc_header = [0u8; GPT_HEADER_BYTES];
    crc_header.copy_from_slice(header);
    crc_header[16..20].fill(0);
    if crc.checksum(&crc_header) != stored_crc {
        return Err(HealthError::GptCrc);
    }
    let entries_start = GPT_ENTRY_LBA as usize * block::SECTOR_BYTES as usize;
    let entries_end = entries_start + 128 * GPT_ENTRY_BYTES;
    let entries = page
        .get(entries_start..entries_end)
        .ok_or(HealthError::GptHeader)?;
    if crc.checksum(entries) != read_u32(&header[88..92]) {
        return Err(HealthError::GptCrc);
    }
    validate_partition_entry(
        &entries[3 * GPT_ENTRY_BYTES..4 * GPT_ENTRY_BYTES],
        P0_CONTROL_A_TYPE_GUID,
        P0_CONTROL_A_PARTITION_GUID,
        P0_CONTROL_A_LBA,
    )?;
    validate_partition_entry(
        &entries[4 * GPT_ENTRY_BYTES..5 * GPT_ENTRY_BYTES],
        P0_CONTROL_B_TYPE_GUID,
        P0_CONTROL_B_PARTITION_GUID,
        P0_CONTROL_B_LBA,
    )
}

fn validate_partition_entry(
    entry: &[u8],
    expected_type: [u8; 16],
    expected_unique: [u8; 16],
    expected_start: u64,
) -> Result<(), HealthError> {
    let first = read_u64(&entry[32..40]);
    let last = read_u64(&entry[40..48]);
    let sectors = last
        .checked_sub(first)
        .and_then(|value| value.checked_add(1))
        .ok_or(HealthError::GptPartition)?;
    if entry[..16] != expected_type
        || entry[16..32] != expected_unique
        || first != expected_start
        || sectors < (64 * 1024 * 1024 / block::SECTOR_BYTES)
    {
        return Err(HealthError::GptPartition);
    }
    Ok(())
}

/// 确认当前 A/B 槽的最小健康集合并持久提交。
/// Confirms the minimum health set for the current A/B slot and commits it durably.
pub fn confirm_minimum_health() -> Result<(), HealthError> {
    mmio::prepare_window().map_err(|_| HealthError::Block)?;
    let device = pci::table()
        .devices()
        .find(|device| {
            device.header.vendor == virtio::VIRTIO_VENDOR
                && virtio::is_blk_device(device.header.device)
        })
        .ok_or(HealthError::Unsupported)?;
    let blockdev = BlockDevice::new(device, HEALTH_PAGES).map_err(|_| HealthError::Block)?;
    let capacity = blockdev.geometry().capacity_sectors;
    let device = Arc::new(IrqSpinLock::new(blockdev));
    let mut io = KernelControlIo {
        device: Arc::clone(&device),
    };
    let gpt = io.read_gpt()?;
    validate_gpt(&gpt, capacity)?;

    let mut first = [0u8; CONTROL_RECORD_BYTES];
    let mut second = [0u8; CONTROL_RECORD_BYTES];
    io.read_copy(0, &mut first)
        .map_err(|_| HealthError::Block)?;
    io.read_copy(1, &mut second)
        .map_err(|_| HealthError::Block)?;
    let current = recover(Some(&first), Some(&second)).map_err(HealthError::Recovery)?;

#[cfg(feature = "lifecycle-health-fail-verify")]
    {
        let _ = current;
        Err(HealthError::InjectedFailure)
    }
#[cfg(not(feature = "lifecycle-health-fail-verify"))]
    {
        let slot = current
            .candidate()
            .map(|(slot, _)| slot)
            .unwrap_or_else(|| current.active_slot());
        let mut next = current;
        next.report_health(slot, true).map_err(HealthError::State)?;
        let mut published = current;
        commit(&mut io, &mut published, next).map_err(HealthError::Commit)?;
        kprintln!(
            "[JSR-LIFE-HEALTH] result=confirmed slot={:?} generation={} release={} attempts=0 storage=virtio-blk",
            slot,
            published.generation(),
            published.slot(slot).release()
        );
        drop(io);
        drop(device);
        Ok(())
    }
}
