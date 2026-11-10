//! LC-3 P0 GPT 映像创建与回读。
//! LC-3 P0 GPT image creation and readback.
//!
//! 使用成熟 `gpt` 库写保护性 MBR、主/备份 GPT 头与分区表。本模块只创建空分区
//! 容器，不格式化文件系统、不复制系统映像，也不表示映像可启动。
//! Uses the mature `gpt` crate for the protective MBR, primary/backup headers and entry
//! arrays. This module creates empty partition containers only; it formats no filesystem,
//! copies no system image and does not claim bootability.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use gpt::disk::LogicalBlockSize;
use gpt::partition_types::{OperatingSystem, Type};
use gpt::{GptConfig, GptError};
use jasper_lifecycle_model::layout::{LayoutError, P0Layout, PartitionRole, SECTOR_BYTES};
use uuid::Uuid;

const DISK_GUID: Uuid = uuid::uuid!("4a617370-6572-4f53-9000-000000000000");

/// GPT 映像创建、验证或几何错误。
/// GPT image creation, validation or geometry error.
#[derive(Debug)]
pub enum GptImageError {
    /// 布局拒绝。Layout rejected.
    Layout(LayoutError),
    /// 总字节数不是 512 字节扇区的整数倍。Size is not a multiple of the 512-byte sector.
    UnalignedSize(u64),
    /// GPT 库或底层 I/O 失败。GPT library or underlying I/O failed.
    Gpt(GptError),
    /// FAT 文件系统操作失败。FAT filesystem operation failed.
    Fat(io::Error),
    /// 回读的分区表与 P0 布局绑定不符。Readback partition table differs from the P0 binding.
    CorruptTable(&'static str),
}

impl std::fmt::Display for GptImageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Layout(error) => write!(formatter, "P0 layout rejected: {error:?}"),
            Self::UnalignedSize(bytes) => {
                write!(formatter, "disk size {bytes} is not sector-aligned")
            }
            Self::Gpt(error) => write!(formatter, "GPT operation failed: {error}"),
            Self::Fat(error) => write!(formatter, "FAT operation failed: {error}"),
            Self::CorruptTable(reason) => write!(formatter, "GPT readback mismatch: {reason}"),
        }
    }
}

impl std::error::Error for GptImageError {}

impl From<LayoutError> for GptImageError {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}

impl From<GptError> for GptImageError {
    fn from(value: GptError) -> Self {
        Self::Gpt(value)
    }
}

impl From<io::Error> for GptImageError {
    fn from(value: io::Error) -> Self {
        Self::Fat(value)
    }
}

/// 已完成回读验证的 P0 GPT 映像。
/// P0 GPT image that passed readback verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GptImageReceipt {
    /// 总扇区数。Total sector count.
    pub total_sectors: u64,
    /// 分区数量。Partition count.
    pub partitions: usize,
    /// 磁盘 GUID。Disk GUID.
    pub disk_guid: Uuid,
}

/// 已格式化并回读验证的 ESP。
/// ESP that was formatted and verified by reopening.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EspReceipt {
    /// ESP 首扇区。ESP first LBA.
    pub start_lba: u64,
    /// ESP 扇区数。ESP sector count.
    pub sectors: u64,
    /// FAT 类型。FAT type.
    pub fat_type: fatfs::FatType,
    /// 卷标。Volume label.
    pub volume_label: String,
}

/// 在不存在的新路径上创建稀疏 P0 GPT 映像并立即回读验证。
/// Creates a sparse P0 GPT image at a fresh path and verifies it by reopening.
pub fn create_p0_gpt(path: &Path, total_bytes: u64) -> Result<GptImageReceipt, GptImageError> {
    if !total_bytes.is_multiple_of(SECTOR_BYTES) {
        return Err(GptImageError::UnalignedSize(total_bytes));
    }
    let layout = P0Layout::new(total_bytes / SECTOR_BYTES)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| GptImageError::Gpt(GptError::Io(error)))?;
    file.set_len(total_bytes)
        .map_err(|error| GptImageError::Gpt(GptError::Io(error)))?;
    let protective_size = u32::try_from(layout.total_sectors() - 1).unwrap_or(u32::MAX);
    file.write_all(&gpt::mbr::ProtectiveMBR::with_lb_size(protective_size).to_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| GptImageError::Gpt(GptError::Io(error)))?;
    drop(file);
    let result = write_layout(path, layout).and_then(|()| verify_layout(path, layout));
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

/// 回读已有 GPT 并验证它仍是绑定的 P0 布局。
/// Reopens an existing GPT and verifies that it still matches the bound P0 layout.
pub fn verify_p0_gpt(path: &Path, total_bytes: u64) -> Result<GptImageReceipt, GptImageError> {
    if !total_bytes.is_multiple_of(SECTOR_BYTES) {
        return Err(GptImageError::UnalignedSize(total_bytes));
    }
    let layout = P0Layout::new(total_bytes / SECTOR_BYTES)?;
    verify_layout(path, layout)
}

/// 在 P0 ESP 分区范围内创建 FAT32，并重新验证 GPT 与卷结构。
/// Creates FAT32 within the P0 ESP range and reopens both the GPT and volume.
pub fn format_esp_fat32(path: &Path, total_bytes: u64) -> Result<EspReceipt, GptImageError> {
    let gpt = verify_p0_gpt(path, total_bytes)?;
    let layout = P0Layout::new(gpt.total_sectors)?;
    let esp = layout.partition(PartitionRole::Esp);
    let file = open_image_rw(path)?;
    let slice = PartitionSlice::new(
        file,
        esp.start_lba * SECTOR_BYTES,
        esp.sectors * SECTOR_BYTES,
    )?;
    fatfs::format_volume(
        slice,
        fatfs::FormatVolumeOptions::new()
            .bytes_per_sector(SECTOR_BYTES as u16)
            .total_sectors(u32::try_from(esp.sectors).map_err(|_| {
                GptImageError::Fat(io::Error::new(io::ErrorKind::InvalidInput, "ESP too large"))
            })?)
            .fat_type(fatfs::FatType::Fat32)
            .fats(2)
            .volume_label(*b"JASPER ESP "),
    )?;
    let file = open_image_rw(path)?;
    file.sync_all()?;
    drop(file);
    verify_p0_gpt(path, total_bytes)?;

    let file = open_image_rw(path)?;
    let slice = PartitionSlice::new(
        file,
        esp.start_lba * SECTOR_BYTES,
        esp.sectors * SECTOR_BYTES,
    )?;
    let filesystem = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())?;
    let receipt = EspReceipt {
        start_lba: esp.start_lba,
        sectors: esp.sectors,
        fat_type: filesystem.fat_type(),
        volume_label: filesystem.volume_label().trim().into(),
    };
    if receipt.fat_type != fatfs::FatType::Fat32 || receipt.volume_label != "JASPER ESP" {
        return Err(GptImageError::Fat(io::Error::new(
            io::ErrorKind::InvalidData,
            "ESP readback does not match FAT32 volume",
        )));
    }
    filesystem.stats()?;
    filesystem.unmount()?;
    Ok(receipt)
}

fn write_layout(path: &Path, layout: P0Layout) -> Result<(), GptImageError> {
    let mut disk = GptConfig::new()
        .writable(true)
        .logical_block_size(LogicalBlockSize::Lb512)
        .only_valid_headers(true)
        .change_partition_count(true)
        .create(path)?;
    disk.update_guid(Some(DISK_GUID));
    for role in PartitionRole::ALL {
        let partition = layout.partition(role);
        disk.add_partition_at(
            role_name(role),
            role as u32 + 1,
            partition.start_lba,
            partition.sectors,
            role_type(role),
            0,
        )?;
    }
    let mut partitions = disk.take_partitions();
    for (id, partition) in &mut partitions {
        let role = role_for_id(*id).ok_or(GptImageError::CorruptTable("unknown partition id"))?;
        partition.part_guid = partition_guid(role);
        partition.name = role_name(role).into();
    }
    disk.update_partitions(partitions)?;
    let file = disk.write()?;
    file.sync_all()
        .map_err(|error| GptImageError::Gpt(GptError::Io(error)))
}

fn verify_layout(path: &Path, layout: P0Layout) -> Result<GptImageReceipt, GptImageError> {
    verify_protective_mbr(path, layout)?;
    let disk = GptConfig::new()
        .writable(false)
        .logical_block_size(LogicalBlockSize::Lb512)
        .only_valid_headers(true)
        .open(path)?;
    let primary = disk
        .primary_header()
        .map_err(|_| GptImageError::CorruptTable("invalid primary header"))?;
    let backup = disk
        .backup_header()
        .map_err(|_| GptImageError::CorruptTable("invalid backup header"))?;
    if primary.disk_guid != DISK_GUID || backup.disk_guid != DISK_GUID || disk.guid() != &DISK_GUID
    {
        return Err(GptImageError::CorruptTable("disk GUID mismatch"));
    }
    if primary.current_lba != 1
        || backup.current_lba != layout.total_sectors() - 1
        || primary.backup_lba != layout.total_sectors() - 1
    {
        return Err(GptImageError::CorruptTable(
            "primary/backup header location",
        ));
    }
    let expected: BTreeMap<u32, PartitionRole> = PartitionRole::ALL
        .into_iter()
        .map(|role| (role as u32 + 1, role))
        .collect();
    if disk.partitions().len() != expected.len() {
        return Err(GptImageError::CorruptTable("partition count"));
    }
    for (id, role) in expected {
        let partition = disk
            .partitions()
            .get(&id)
            .ok_or(GptImageError::CorruptTable("missing partition id"))?;
        let bound = layout.partition(role);
        if partition.first_lba != bound.start_lba
            || partition.last_lba != bound.end_lba() - 1
            || partition.part_type_guid.guid != role_type(role).guid
            || partition.part_guid != partition_guid(role)
            || partition.name != role_name(role)
        {
            return Err(GptImageError::CorruptTable("partition role mismatch"));
        }
    }
    Ok(GptImageReceipt {
        total_sectors: layout.total_sectors(),
        partitions: disk.partitions().len(),
        disk_guid: DISK_GUID,
    })
}

fn verify_protective_mbr(path: &Path, layout: P0Layout) -> Result<(), GptImageError> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| GptImageError::Gpt(GptError::Io(error)))?;
    let mut sector = [0u8; 512];
    file.read_exact(&mut sector)
        .map_err(|error| GptImageError::Gpt(GptError::Io(error)))?;
    let expected_size = u32::try_from(layout.total_sectors() - 1).unwrap_or(u32::MAX);
    if sector[446] != 0
        || sector[450] != 0xEE
        || u32::from_le_bytes(sector[454..458].try_into().unwrap()) != 1
        || u32::from_le_bytes(sector[458..462].try_into().unwrap()) != expected_size
        || sector[510..512] != [0x55, 0xAA]
    {
        return Err(GptImageError::CorruptTable("protective MBR"));
    }
    Ok(())
}

fn open_image_rw(path: &Path) -> Result<fs::File, GptImageError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(GptImageError::Fat)
}

struct PartitionSlice {
    file: fs::File,
    offset: u64,
    length: u64,
    position: u64,
}

impl PartitionSlice {
    fn new(mut file: fs::File, offset: u64, length: u64) -> io::Result<Self> {
        file.seek(SeekFrom::Start(offset))?;
        Ok(Self {
            file,
            offset,
            length,
            position: 0,
        })
    }

    fn remaining(&self) -> u64 {
        self.length.saturating_sub(self.position)
    }
}

impl Read for PartitionSlice {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let allowed = usize::try_from(self.remaining())
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        if allowed == 0 {
            return Ok(0);
        }
        let count = self.file.read(&mut buffer[..allowed])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Write for PartitionSlice {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let allowed = usize::try_from(self.remaining())
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        if allowed != buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write crosses ESP partition boundary",
            ));
        }
        let count = self.file.write(buffer)?;
        self.position += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for PartitionSlice {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
        };
        if target < 0 || target > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek crosses ESP partition boundary",
            ));
        }
        let target = target as u64;
        self.file.seek(SeekFrom::Start(
            self.offset.checked_add(target).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "ESP offset overflow")
            })?,
        ))?;
        self.position = target;
        Ok(target)
    }
}

fn role_for_id(id: u32) -> Option<PartitionRole> {
    PartitionRole::ALL.get(id.checked_sub(1)? as usize).copied()
}

const fn role_name(role: PartitionRole) -> &'static str {
    match role {
        PartitionRole::Esp => "Jasper ESP",
        PartitionRole::SystemA => "Jasper System A",
        PartitionRole::SystemB => "Jasper System B",
        PartitionRole::ControlA => "Jasper Control A",
        PartitionRole::ControlB => "Jasper Control B",
        PartitionRole::Rescue => "Jasper Rescue",
        PartitionRole::Data => "Jasper Data",
    }
}

const fn partition_guid(role: PartitionRole) -> Uuid {
    match role {
        PartitionRole::Esp => uuid::uuid!("4a617370-6572-4f53-a001-000000000001"),
        PartitionRole::SystemA => uuid::uuid!("4a617370-6572-4f53-a002-000000000002"),
        PartitionRole::SystemB => uuid::uuid!("4a617370-6572-4f53-a003-000000000003"),
        PartitionRole::ControlA => uuid::uuid!("4a617370-6572-4f53-a004-000000000004"),
        PartitionRole::ControlB => uuid::uuid!("4a617370-6572-4f53-a005-000000000005"),
        PartitionRole::Rescue => uuid::uuid!("4a617370-6572-4f53-a006-000000000006"),
        PartitionRole::Data => uuid::uuid!("4a617370-6572-4f53-a007-000000000007"),
    }
}

fn role_type(role: PartitionRole) -> Type {
    if role == PartitionRole::Esp {
        return gpt::partition_types::EFI;
    }
    Type {
        guid: match role {
            PartitionRole::Esp => unreachable!(),
            PartitionRole::SystemA => {
                uuid::uuid!("4a617370-6572-4f53-8001-000000000001")
            }
            PartitionRole::SystemB => {
                uuid::uuid!("4a617370-6572-4f53-8001-000000000002")
            }
            PartitionRole::ControlA => {
                uuid::uuid!("4a617370-6572-4f53-8001-000000000003")
            }
            PartitionRole::ControlB => {
                uuid::uuid!("4a617370-6572-4f53-8001-000000000004")
            }
            PartitionRole::Rescue => {
                uuid::uuid!("4a617370-6572-4f53-8001-000000000005")
            }
            PartitionRole::Data => {
                uuid::uuid!("4a617370-6572-4f53-8001-000000000006")
            }
        },
        os: OperatingSystem::Custom("Jasper".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "jasper-gpt-{tag}-{}-{nanos}.img",
            std::process::id()
        ))
    }

    #[test]
    fn creates_sparse_p0_gpt_with_bound_roles_and_backup_header() {
        let path = temp_path("p0");
        let bytes = 36 * 1024 * 1024 * 1024u64;
        let receipt = create_p0_gpt(&path, bytes).unwrap();
        assert_eq!(receipt.total_sectors, bytes / SECTOR_BYTES);
        assert_eq!(receipt.partitions, 7);
        assert_eq!(verify_p0_gpt(&path, bytes).unwrap(), receipt);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn formats_only_esp_as_fat32_and_preserves_gpt() {
        let path = temp_path("esp");
        let bytes = 36 * 1024 * 1024 * 1024u64;
        let gpt = create_p0_gpt(&path, bytes).unwrap();
        let esp = format_esp_fat32(&path, bytes).unwrap();
        assert_eq!(esp.start_lba, 2048);
        assert_eq!(esp.sectors, 512 * 2048);
        assert_eq!(esp.fat_type, fatfs::FatType::Fat32);
        assert_eq!(esp.volume_label, "JASPER ESP");
        assert_eq!(verify_p0_gpt(&path, bytes).unwrap(), gpt);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn refuses_existing_or_unaligned_output() {
        let path = temp_path("existing");
        fs::write(&path, b"keep").unwrap();
        assert!(matches!(
            create_p0_gpt(&path, 36 * 1024 * 1024 * 1024u64),
            Err(GptImageError::Gpt(GptError::Io(_)))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        let _ = fs::remove_file(path);

        let missing = temp_path("unaligned");
        assert!(matches!(
            create_p0_gpt(&missing, SECTOR_BYTES - 1),
            Err(GptImageError::UnalignedSize(_))
        ));
        assert!(!missing.exists());
    }

    #[test]
    fn rejects_disk_below_layout_minimum_without_creating_a_file() {
        let path = temp_path("small");
        assert!(matches!(
            create_p0_gpt(&path, 34 * 1024 * 1024 * 1024u64),
            Err(GptImageError::Layout(LayoutError::TooSmall))
        ));
        assert!(!path.exists());
    }
}
