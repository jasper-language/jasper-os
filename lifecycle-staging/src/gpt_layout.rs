//! LC-3 P0 GPT 映像创建与回读。
//! LC-3 P0 GPT image creation and readback.
//!
//! 使用成熟 `gpt`、`fatfs` 与 e2fsprogs 写保护性 MBR、GPT、ESP 和 ext4 文件系统。
//! 本模块不复制系统映像，也不表示映像可启动。
//! Uses mature `gpt`, `fatfs` and e2fsprogs for the protective MBR, GPT, ESP and ext4
//! filesystems. This module copies no system image and does not claim bootability.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

use gpt::disk::LogicalBlockSize;
use gpt::partition_types::{OperatingSystem, Type};
use gpt::{GptConfig, GptError};
use jasper_lifecycle_model::layout::{LayoutError, P0Layout, PartitionRole, SECTOR_BYTES};
use rustix::fs::{seek as sparse_seek, SeekFrom as SparseSeekFrom};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
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
    /// 外部成熟格式化工具失败。External mature formatting tool failed.
    Tool(String),
    /// 待格式化分区不是全零，拒绝覆盖潜在数据。Target partition is not all zero.
    NonEmptyPartition(PartitionRole),
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
            Self::Tool(error) => write!(formatter, "filesystem tool failed: {error}"),
            Self::NonEmptyPartition(role) => {
                write!(formatter, "partition {role:?} contains non-zero data")
            }
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

/// 已由 ext4 工具格式化的角色分区。
/// Role partition formatted by the ext4 tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ext4Receipt {
    /// 分区角色。Partition role.
    pub role: PartitionRole,
    /// 首扇区。First LBA.
    pub start_lba: u64,
    /// 扇区数。Sector count.
    pub sectors: u64,
    /// 文件系统块数。Filesystem block count.
    pub blocks: u64,
    /// 文件系统 UUID。Filesystem UUID.
    pub uuid: Uuid,
    /// 卷标。Volume label.
    pub volume_label: String,
}

/// 已安装 UEFI 启动文件的 ESP。
/// ESP containing installed UEFI boot files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EspInstallReceipt {
    /// UEFI 启动器字节数。UEFI bootloader byte count.
    pub bootloader_bytes: u64,
    /// 内核字节数。Kernel byte count.
    pub kernel_bytes: u64,
    /// 复制的文件数。Copied file count.
    pub files: usize,
    /// 复制的目录数。Copied directory count.
    pub directories: usize,
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

/// 把成熟 bootloader 生成的 FAT 分区文件递归安装到 P0 ESP，并逐文件复核摘要。
/// Recursively installs files from a mature bootloader-generated FAT partition into the P0 ESP
/// and verifies every copied file by digest.
pub fn install_uefi_esp(
    path: &Path,
    total_bytes: u64,
    source_fat: &Path,
) -> Result<EspInstallReceipt, GptImageError> {
    let gpt = verify_p0_gpt(path, total_bytes)?;
    let layout = P0Layout::new(gpt.total_sectors)?;
    let esp = layout.partition(PartitionRole::Esp);
    let source_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source_fat)
        .map_err(GptImageError::Fat)?;
    let source_fs = fatfs::FileSystem::new(source_file, fatfs::FsOptions::new())?;
    let target_file = open_image_rw(path)?;
    let target_slice = PartitionSlice::new(
        target_file,
        esp.start_lba * SECTOR_BYTES,
        esp.sectors * SECTOR_BYTES,
    )?;
    let target_fs = fatfs::FileSystem::new(target_slice, fatfs::FsOptions::new())?;
    if target_fs.root_dir().iter().next().is_some() {
        return Err(GptImageError::Tool(
            "target ESP is not empty; refusing to merge boot files".into(),
        ));
    }
    let mut stats = CopyStats::default();
    copy_fat_tree(&source_fs.root_dir(), &target_fs.root_dir(), &mut stats)?;
    target_fs.unmount()?;
    normalize_fat32_partition(path, esp)?;
    verify_uefi_esp_contents(path, total_bytes, &source_fs.root_dir(), esp)?;
    let source_root = source_fs.root_dir();
    let bootloader_bytes = if source_root.open_file("efi/boot/jasper-loader.efi").is_ok() {
        file_size(&source_root, "efi/boot/jasper-loader.efi")?
    } else {
        file_size(&source_root, "efi/boot/bootx64.efi")?
    };
    let kernel_bytes = if source_root.open_file("kernel-x86_64").is_ok() {
        file_size(&source_root, "kernel-x86_64")?
    } else {
        file_size(&source_root, "slots/a/kernel-x86_64")?
            .checked_add(file_size(&source_root, "slots/b/kernel-x86_64")?)
            .ok_or_else(|| GptImageError::Tool("slot kernel size overflow".into()))?
    };
    Ok(EspInstallReceipt {
        bootloader_bytes,
        kernel_bytes,
        files: stats.files,
        directories: stats.directories,
    })
}

/// 使用 e2fsprogs `mkfs.ext4` 创建 A/B 系统槽和共享 Data 文件系统。
///
/// 每个目标分区必须先全零；函数不覆盖已有文件系统或用户数据。
/// Creates A/B system and shared-data ext4 filesystems with e2fsprogs `mkfs.ext4`.
/// Every target partition must be entirely zero, preventing silent data overwrite.
pub fn format_p0_ext4(path: &Path, total_bytes: u64) -> Result<Vec<Ext4Receipt>, GptImageError> {
    let gpt = verify_p0_gpt(path, total_bytes)?;
    let layout = P0Layout::new(gpt.total_sectors)?;
    let mut receipts = Vec::new();
    for (role, uuid, label) in [
        (
            PartitionRole::SystemA,
            uuid::uuid!("4a617370-6572-4f53-b001-000000000001"),
            "JASPER-SYS-A",
        ),
        (
            PartitionRole::SystemB,
            uuid::uuid!("4a617370-6572-4f53-b001-000000000002"),
            "JASPER-SYS-B",
        ),
        (
            PartitionRole::Data,
            uuid::uuid!("4a617370-6572-4f53-b001-000000000003"),
            "JASPER-DATA",
        ),
    ] {
        let partition = layout.partition(role);
        ensure_partition_range_zero(path, partition)?;
        let offset = partition
            .start_lba
            .checked_mul(SECTOR_BYTES)
            .ok_or_else(|| GptImageError::Tool("ext4 partition offset overflow".into()))?;
        let byte_length = partition
            .sectors
            .checked_mul(SECTOR_BYTES)
            .ok_or_else(|| GptImageError::Tool("ext4 partition length overflow".into()))?;
        if !byte_length.is_multiple_of(4096) {
            return Err(GptImageError::Tool(
                "ext4 partition is not 4 KiB aligned".into(),
            ));
        }
        let blocks = byte_length / 4096;
        let offset_option = format!("offset={offset},nodiscard");
        let uuid_text = uuid.to_string();
        let output = Command::new("mkfs.ext4")
            .args([
                "-F",
                "-q",
                "-t",
                "ext4",
                "-b",
                "4096",
                "-m",
                "1",
                "-L",
                label,
                "-U",
                &uuid_text,
                "-E",
                &offset_option,
            ])
            .arg(path)
            .arg(blocks.to_string())
            .output()
            .map_err(|error| GptImageError::Tool(error.to_string()))?;
        if !output.status.success() {
            return Err(GptImageError::Tool(format!(
                "mkfs.ext4 {role:?} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        verify_ext4_magic(path, partition)?;
        receipts.push(Ext4Receipt {
            role,
            start_lba: partition.start_lba,
            sectors: partition.sectors,
            blocks,
            uuid,
            volume_label: label.into(),
        });
    }
    verify_p0_gpt(path, total_bytes)?;
    Ok(receipts)
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

fn verify_uefi_esp_contents(
    image: &Path,
    total_bytes: u64,
    expected_root: &fatfs::Dir<fs::File>,
    esp: jasper_lifecycle_model::layout::Partition,
) -> Result<(), GptImageError> {
    verify_p0_gpt(image, total_bytes)?;
    let file = open_image_rw(image)?;
    let slice = PartitionSlice::new(
        file,
        esp.start_lba * SECTOR_BYTES,
        esp.sectors * SECTOR_BYTES,
    )?;
    let filesystem = fatfs::FileSystem::new(slice, fatfs::FsOptions::new())?;
    let root = filesystem.root_dir();
    let mut expected = BTreeMap::new();
    collect_fat_tree(expected_root, "", &mut expected)?;
    let mut installed = BTreeMap::new();
    collect_fat_tree(&root, "", &mut installed)?;
    if expected != installed {
        return Err(GptImageError::Tool(
            "installed ESP tree differs from mature bootloader output".into(),
        ));
    }
    drop(root);
    filesystem.unmount()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FatFingerprint {
    Directory,
    File { bytes: u64, digest: [u8; 32] },
}

fn collect_fat_tree<T: Read + Seek + Write>(
    directory: &fatfs::Dir<T>,
    prefix: &str,
    entries: &mut BTreeMap<String, FatFingerprint>,
) -> Result<(), GptImageError> {
    for entry in directory.iter() {
        let entry = entry?;
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let fingerprint = if entry.is_dir() {
            FatFingerprint::Directory
        } else if entry.is_file() {
            let mut file = directory.open_file(&name)?;
            let (bytes, digest) = digest_file(&mut file)?;
            FatFingerprint::File { bytes, digest }
        } else {
            return Err(GptImageError::Tool(format!(
                "unsupported FAT entry type in verification: {path}"
            )));
        };
        if entries.insert(path.clone(), fingerprint).is_some() {
            return Err(GptImageError::Tool(format!(
                "duplicate FAT path in verification: {path}"
            )));
        }
        if entry.is_dir() {
            let child = directory.open_dir(&name)?;
            collect_fat_tree(&child, &path, entries)?;
        }
    }
    Ok(())
}

fn normalize_fat32_partition(
    image: &Path,
    esp: jasper_lifecycle_model::layout::Partition,
) -> Result<(), GptImageError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = std::env::temp_dir().join(format!(
        "jasper-esp-normalize-{}-{nanos}.img",
        std::process::id()
    ));
    let extract = Command::new("dd")
        .args([
            format!("if={}", image.display()),
            format!("of={}", temporary.display()),
            "bs=512".into(),
            format!("skip={}", esp.start_lba),
            format!("count={}", esp.sectors),
            "conv=sparse".into(),
            "status=none".into(),
        ])
        .output()
        .map_err(|error| {
            let _ = fs::remove_file(&temporary);
            GptImageError::Tool(format!("dd extraction failed: {error}"))
        })?;
    if !extract.status.success() {
        let _ = fs::remove_file(&temporary);
        return Err(GptImageError::Tool(format!(
            "dd extraction failed: {}",
            String::from_utf8_lossy(&extract.stderr).trim()
        )));
    }
    let result = (|| {
        let mut clean = false;
        for _ in 0..3 {
            let repair = Command::new("fsck.fat")
                .args(["-a", "-w"])
                .arg(&temporary)
                .output()
                .map_err(|error| GptImageError::Tool(format!("fsck.fat repair failed: {error}")))?;
            if repair.status.code().is_none() {
                return Err(GptImageError::Tool(
                    "fsck.fat repair terminated by signal".into(),
                ));
            }
            let check = Command::new("fsck.fat")
                .args(["-n", "-v", "-l"])
                .arg(&temporary)
                .output()
                .map_err(|error| GptImageError::Tool(format!("fsck.fat check failed: {error}")))?;
            let text = String::from_utf8_lossy(&check.stdout);
            clean = ![
                "Expected a valid",
                "Bad short file name",
                "Renamed to",
                "share clusters",
                "Start does point",
                "Deleting ",
            ]
            .iter()
            .any(|marker| text.contains(marker));
            if clean {
                break;
            }
        }
        if !clean {
            return Err(GptImageError::Tool("fsck.fat did not normalize ESP".into()));
        }
        let restore = Command::new("dd")
            .args([
                format!("if={}", temporary.display()),
                format!("of={}", image.display()),
                "bs=512".into(),
                format!("seek={}", esp.start_lba),
                "conv=notrunc,sparse".into(),
                "status=none".into(),
            ])
            .output()
            .map_err(|error| GptImageError::Tool(format!("dd restore failed: {error}")))?;
        if !restore.status.success() {
            return Err(GptImageError::Tool(format!(
                "dd restore failed: {}",
                String::from_utf8_lossy(&restore.stderr).trim()
            )));
        }
        let file = open_image_rw(image)?;
        file.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temporary);
    result
}

fn file_size(root: &fatfs::Dir<fs::File>, path: &str) -> Result<u64, GptImageError> {
    let mut file = root.open_file(path)?;
    Ok(io::copy(&mut file, &mut io::sink())?)
}

fn digest_file<T: Read + Seek + Write>(
    file: &mut fatfs::File<'_, T>,
) -> io::Result<(u64, [u8; 32])> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        hasher.update(&buffer[..count]);
    }
    Ok((bytes, hasher.finalize().into()))
}

#[derive(Default)]
struct CopyStats {
    files: usize,
    directories: usize,
}

fn copy_fat_tree(
    source: &fatfs::Dir<fs::File>,
    target: &fatfs::Dir<PartitionSlice>,
    stats: &mut CopyStats,
) -> Result<(), GptImageError> {
    for entry in source.iter() {
        let entry = entry?;
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let path = name;
        if entry.is_dir() {
            target
                .create_dir(&path)
                .map_err(|error| GptImageError::Tool(format!("create ESP dir {path}: {error}")))?;
            stats.directories += 1;
            let source_dir = source.open_dir(&path).map_err(|error| {
                GptImageError::Tool(format!("open source FAT dir {path}: {error}"))
            })?;
            let target_dir = target.open_dir(&path).map_err(|error| {
                GptImageError::Tool(format!("open target ESP dir {path}: {error}"))
            })?;
            copy_fat_tree(&source_dir, &target_dir, stats)?;
        } else if entry.is_file() {
            let mut source_file = source.open_file(&path).map_err(|error| {
                GptImageError::Tool(format!("open source FAT file {path}: {error}"))
            })?;
            let mut target_file = target.create_file(&path).map_err(|error| {
                GptImageError::Tool(format!("create target ESP file {path}: {error}"))
            })?;
            target_file.truncate()?;
            io::copy(&mut source_file, &mut target_file)?;
            target_file.flush()?;
            stats.files += 1;
        } else {
            return Err(GptImageError::Tool(format!(
                "unsupported FAT entry type: {path}"
            )));
        }
    }
    Ok(())
}

fn open_image_ro(path: &Path) -> Result<fs::File, GptImageError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(GptImageError::Fat)
}

pub(crate) fn ensure_partition_range_zero(
    path: &Path,
    partition: jasper_lifecycle_model::layout::Partition,
) -> Result<(), GptImageError> {
    let mut file = open_image_ro(path)?;
    let offset = partition
        .start_lba
        .checked_mul(SECTOR_BYTES)
        .ok_or_else(|| GptImageError::Tool("partition offset overflow".into()))?;
    let length = partition
        .sectors
        .checked_mul(SECTOR_BYTES)
        .ok_or_else(|| GptImageError::Tool("partition length overflow".into()))?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| GptImageError::Tool("partition end overflow".into()))?;
    let mut cursor = 0u64;
    loop {
        let data = match sparse_seek(&file, SparseSeekFrom::Data(cursor)) {
            Ok(position) => position,
            Err(Errno::NXIO) => return Ok(()),
            Err(Errno::NOTSUP) => {
                return ensure_byte_range_zero(&mut file, offset, length, partition.role)
            }
            Err(error) => return Err(GptImageError::Tool(format!("SEEK_DATA failed: {error:?}"))),
        };
        if data >= end {
            return Ok(());
        }
        let hole = sparse_seek(&file, SparseSeekFrom::Hole(data)).unwrap_or(end);
        let start = data.max(offset);
        let stop = hole.min(end);
        if start < stop {
            ensure_byte_range_zero(&mut file, start, stop - start, partition.role)?;
        }
        cursor = hole.max(data.saturating_add(1));
    }
}

fn ensure_byte_range_zero(
    file: &mut fs::File,
    offset: u64,
    length: u64,
    role: PartitionRole,
) -> Result<(), GptImageError> {
    file.seek(SeekFrom::Start(offset))?;
    let mut remaining = length;
    let mut buffer = vec![0u8; 4 * 1024 * 1024];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        file.read_exact(&mut buffer[..count])?;
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(GptImageError::NonEmptyPartition(role));
        }
        remaining -= count as u64;
    }
    Ok(())
}

fn verify_ext4_magic(
    path: &Path,
    partition: jasper_lifecycle_model::layout::Partition,
) -> Result<(), GptImageError> {
    let mut file = open_image_ro(path)?;
    let superblock = partition
        .start_lba
        .checked_mul(SECTOR_BYTES)
        .and_then(|offset| offset.checked_add(1024 + 56))
        .ok_or_else(|| GptImageError::Tool("ext4 superblock offset overflow".into()))?;
    file.seek(SeekFrom::Start(superblock))?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic)?;
    if magic != [0x53, 0xef] {
        return Err(GptImageError::Tool(format!(
            "ext4 superblock missing for {:?}",
            partition.role
        )));
    }
    Ok(())
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
    fn formats_system_and_data_ext4_without_overwriting_existing_filesystems() {
        let path = temp_path("ext4");
        let bytes = 36 * 1024 * 1024 * 1024u64;
        let gpt = create_p0_gpt(&path, bytes).unwrap();
        let receipts = format_p0_ext4(&path, bytes).unwrap();
        assert_eq!(receipts.len(), 3);
        assert_eq!(receipts[0].role, PartitionRole::SystemA);
        assert_eq!(receipts[1].role, PartitionRole::SystemB);
        assert_eq!(receipts[2].role, PartitionRole::Data);
        assert_eq!(receipts[0].blocks, 2_097_152);
        assert_eq!(receipts[0].volume_label, "JASPER-SYS-A");
        assert_eq!(receipts[1].volume_label, "JASPER-SYS-B");
        assert_eq!(receipts[2].volume_label, "JASPER-DATA");
        assert_eq!(verify_p0_gpt(&path, bytes).unwrap(), gpt);
        assert!(matches!(
            format_p0_ext4(&path, bytes),
            Err(GptImageError::NonEmptyPartition(PartitionRole::SystemA))
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn installs_bootloader_fat_tree_into_empty_esp() {
        let source_path = temp_path("esp-source");
        let image_path = temp_path("esp-image");
        let bytes = 36 * 1024 * 1024 * 1024u64;
        create_p0_gpt(&image_path, bytes).unwrap();
        format_esp_fat32(&image_path, bytes).unwrap();

        let source_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        source_file.set_len(64 * 1024 * 1024).unwrap();
        fatfs::format_volume(
            source_file,
            fatfs::FormatVolumeOptions::new().fat_type(fatfs::FatType::Fat32),
        )
        .unwrap();
        let source_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source_path)
            .unwrap();
        let source = fatfs::FileSystem::new(source_file, fatfs::FsOptions::new()).unwrap();
        source.root_dir().create_dir("efi").unwrap();
        source.root_dir().create_dir("efi/boot").unwrap();
        source
            .root_dir()
            .create_file("efi/boot/bootx64.efi")
            .unwrap()
            .write_all(b"uefi-bootloader")
            .unwrap();
        source
            .root_dir()
            .create_file("kernel-x86_64")
            .unwrap()
            .write_all(b"kernel-image")
            .unwrap();
        source.unmount().unwrap();

        let receipt = install_uefi_esp(&image_path, bytes, &source_path).unwrap();
        assert_eq!(receipt.bootloader_bytes, 15);
        assert_eq!(receipt.kernel_bytes, 12);
        assert_eq!(receipt.files, 2);
        assert_eq!(receipt.directories, 2);
        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(image_path);
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
