//! 绑定 P0 Control A/B 分区的启动控制记录后端。
//! Boot-control record backend bound to the P0 Control A/B partitions.
//!
//! 两条记录直接存储在独立 GPT 分区内。每代只写非活动副本，随后刷盘并读回；
//! 本模块不复制系统映像、不选择可启动槽，也不把控制记录成功当作启动成功。
//! The two records live directly in separate GPT partitions. Each generation writes only
//! the inactive copy, flushes and reads it back. This module copies no system image,
//! selects no bootable slot, and never treats a control commit as a successful boot.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use jasper_lifecycle_model::boot::{
    commit, recover, BootControlError, CommitError, ControlBlock, ControlIo, ControlIoError,
};
use jasper_lifecycle_model::layout::{LayoutError, P0Layout, PartitionRole, SECTOR_BYTES};
use jasper_lifecycle_model::CONTROL_RECORD_BYTES;

use crate::gpt_layout::{ensure_partition_range_zero, verify_p0_gpt, GptImageError};

const CONTROL_ROLES: [PartitionRole; 2] = [PartitionRole::ControlA, PartitionRole::ControlB];

/// 控制记录或 P0 分区后端错误。
/// Control-record or P0-partition backend failure.
#[derive(Debug)]
pub enum P0ControlError {
    /// P0 GPT 验证失败。P0 GPT verification failed.
    Gpt(GptImageError),
    /// 布局计算失败。Layout calculation failed.
    Layout(LayoutError),
    /// 底层 I/O 失败。Underlying I/O failed.
    Io(io::Error),
    /// 初始化目标控制分区不是全零，拒绝覆盖。The target control partition is not all zero.
    NonEmptyControl(PartitionRole),
    /// 两副本不能恢复出一个有效控制记录。The two copies cannot recover a valid record.
    Recovery(BootControlError),
    /// 下一世代提交失败。Next-generation commit failed.
    Commit(CommitError),
}

impl std::fmt::Display for P0ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gpt(error) => write!(formatter, "P0 GPT failed: {error}"),
            Self::Layout(error) => write!(formatter, "P0 layout failed: {error:?}"),
            Self::Io(error) => write!(formatter, "control partition I/O failed: {error}"),
            Self::NonEmptyControl(role) => {
                write!(formatter, "control partition {role:?} is not all zero")
            }
            Self::Recovery(error) => {
                write!(formatter, "control-record recovery failed: {error:?}")
            }
            Self::Commit(error) => write!(formatter, "control-record commit failed: {error:?}"),
        }
    }
}

impl std::error::Error for P0ControlError {}

impl From<GptImageError> for P0ControlError {
    fn from(value: GptImageError) -> Self {
        Self::Gpt(value)
    }
}

impl From<LayoutError> for P0ControlError {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}

impl From<io::Error> for P0ControlError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// 直接访问 P0 Control A/B 分区的控制记录 I/O。
/// Control-record I/O that directly accesses the P0 Control A/B partitions.
pub struct PartitionControlIo {
    file: File,
    total_bytes: u64,
    layout: P0Layout,
}

impl PartitionControlIo {
    fn new(path: &Path, total_bytes: u64) -> Result<Self, P0ControlError> {
        let receipt = verify_p0_gpt(path, total_bytes)?;
        let layout = P0Layout::new(receipt.total_sectors)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        Ok(Self {
            file,
            total_bytes,
            layout,
        })
    }

    fn role(copy: usize) -> Result<PartitionRole, ControlIoError> {
        CONTROL_ROLES
            .get(copy)
            .copied()
            .ok_or(ControlIoError::Failed)
    }

    fn offset(&self, role: PartitionRole) -> Result<u64, ControlIoError> {
        let partition = self.layout.partition(role);
        if partition.role != role
            || partition.start_lba < 1
            || partition.sectors < CONTROL_RECORD_BYTES.div_ceil(SECTOR_BYTES as usize) as u64
        {
            return Err(ControlIoError::Failed);
        }
        partition
            .start_lba
            .checked_mul(SECTOR_BYTES)
            .filter(|offset| {
                offset
                    .checked_add(CONTROL_RECORD_BYTES as u64)
                    .is_some_and(|end| end <= self.total_bytes)
            })
            .ok_or(ControlIoError::Failed)
    }
}

impl ControlIo for PartitionControlIo {
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let offset = self.offset(Self::role(copy)?)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.write_all(bytes))
            .map_err(|_| ControlIoError::Failed)
    }

    fn flush(&mut self) -> Result<(), ControlIoError> {
        self.file.sync_all().map_err(|_| ControlIoError::Failed)
    }

    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let offset = self.offset(Self::role(copy)?)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.read_exact(out))
            .map_err(|_| ControlIoError::Failed)
    }
}

/// 绑定到 P0 GPT 的控制记录存储。
/// Control-record store bound to the P0 GPT.
pub struct P0ControlStore {
    io: PartitionControlIo,
    current: ControlBlock,
}

impl P0ControlStore {
    /// 从 P0 Control A/B 分区恢复最高有效世代。
    /// Recovers the highest valid generation from the P0 Control A/B partitions.
    pub fn open(path: &Path, total_bytes: u64) -> Result<Self, P0ControlError> {
        let mut io = PartitionControlIo::new(path, total_bytes)?;
        let mut first = [0u8; CONTROL_RECORD_BYTES];
        let mut second = [0u8; CONTROL_RECORD_BYTES];
        io.read_copy(0, &mut first)
            .map_err(|_| P0ControlError::Io(io::Error::other("read Control A failed")))?;
        io.read_copy(1, &mut second)
            .map_err(|_| P0ControlError::Io(io::Error::other("read Control B failed")))?;
        let current = recover(Some(&first), Some(&second)).map_err(P0ControlError::Recovery)?;
        Ok(Self { io, current })
    }

    /// 在确认两个 Control 分区全零后初始化两份相同记录。
    ///
    /// 分区中存在任何非零字节都会失败关闭；初始化不覆盖未知数据。
    /// Initializes two identical records only after both Control partitions are entirely zero.
    /// Any non-zero byte fails closed, so initialization cannot overwrite unknown data.
    pub fn initialize(
        path: &Path,
        total_bytes: u64,
        block: ControlBlock,
    ) -> Result<Self, P0ControlError> {
        let receipt = verify_p0_gpt(path, total_bytes)?;
        let layout = P0Layout::new(receipt.total_sectors)?;
        for role in CONTROL_ROLES {
            ensure_partition_range_zero(path, layout.partition(role)).map_err(
                |error| match error {
                    GptImageError::NonEmptyPartition(role) => P0ControlError::NonEmptyControl(role),
                    other => P0ControlError::Gpt(other),
                },
            )?;
        }
        let mut io = PartitionControlIo::new(path, total_bytes)?;
        let bytes = block.encode();
        io.write_copy(0, &bytes)
            .map_err(|_| P0ControlError::Io(io::Error::other("write Control A failed")))?;
        io.write_copy(1, &bytes)
            .map_err(|_| P0ControlError::Io(io::Error::other("write Control B failed")))?;
        io.flush()
            .map_err(|_| P0ControlError::Io(io::Error::other("flush control partitions failed")))?;
        let mut readback = [0u8; CONTROL_RECORD_BYTES];
        for copy in 0..CONTROL_ROLES.len() {
            io.read_copy(copy, &mut readback)
                .map_err(|_| P0ControlError::Io(io::Error::other("read control failed")))?;
            if readback != bytes {
                return Err(P0ControlError::Io(io::Error::other(
                    "control-partition readback mismatch",
                )));
            }
        }
        Ok(Self { io, current: block })
    }

    /// 当前控制记录快照。Current control-record snapshot.
    pub const fn current(&self) -> ControlBlock {
        self.current
    }

    /// 提交严格的下一世代，仅写入非活动 Control 分区。
    /// Commits exactly the next generation into only the inactive Control partition.
    pub fn commit_next(&mut self, next: ControlBlock) -> Result<(), P0ControlError> {
        commit(&mut self.io, &mut self.current, next).map_err(P0ControlError::Commit)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use jasper_lifecycle_model::boot::{Candidate, Slot};

    use super::*;
    use crate::gpt_layout::create_p0_gpt;

    const IMAGE_BYTES: u64 = 36 * 1024 * 1024 * 1024;

    struct TestImage(PathBuf);

    impl TestImage {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "jasper-p0-control-{tag}-{}-{nanos}.img",
                std::process::id()
            ));
            create_p0_gpt(&path, IMAGE_BYTES).unwrap();
            Self(path)
        }
    }

    impl Drop for TestImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn initial() -> ControlBlock {
        ControlBlock::initialize(Slot::A, 1, [1; 32], 1, 1, 1, 1).unwrap()
    }

    fn staged(block: ControlBlock) -> ControlBlock {
        let mut next = block;
        next.stage_candidate(
            Slot::B,
            Candidate {
                release: 2,
                digest: [2; 32],
                transaction_id: 2,
                security_epoch: 2,
                data_schema_min: 1,
                data_schema_max: 1,
            },
        )
        .unwrap();
        next
    }

    #[test]
    fn initializes_and_recovers_records_inside_control_partitions() {
        let image = TestImage::new("recover");
        let store = P0ControlStore::initialize(&image.0, IMAGE_BYTES, initial()).unwrap();
        drop(store);
        assert_eq!(
            P0ControlStore::open(&image.0, IMAGE_BYTES)
                .unwrap()
                .current(),
            initial()
        );
    }

    #[test]
    fn torn_active_copy_recovers_the_previous_generation() {
        let image = TestImage::new("torn");
        let mut store = P0ControlStore::initialize(&image.0, IMAGE_BYTES, initial()).unwrap();
        store.commit_next(staged(initial())).unwrap();
        let newest = store.current();
        assert_eq!(newest.generation(), 2);
        drop(store);

        let layout = P0Layout::new(IMAGE_BYTES / SECTOR_BYTES).unwrap();
        let offset = layout.partition(PartitionRole::ControlA).start_lba * SECTOR_BYTES;
        let mut file = OpenOptions::new().write(true).open(&image.0).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&[0]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let recovered = P0ControlStore::open(&image.0, IMAGE_BYTES)
            .unwrap()
            .current();
        assert_eq!(recovered, initial());
        assert!(recovered.candidate().is_none());
    }

    #[test]
    fn initialization_refuses_nonzero_control_data() {
        let image = TestImage::new("nonempty");
        let layout = P0Layout::new(IMAGE_BYTES / SECTOR_BYTES).unwrap();
        let offset = layout.partition(PartitionRole::ControlB).start_lba * SECTOR_BYTES;
        let mut file = OpenOptions::new().write(true).open(&image.0).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(b"do-not-overwrite").unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert!(matches!(
            P0ControlStore::initialize(&image.0, IMAGE_BYTES, initial()),
            Err(P0ControlError::NonEmptyControl(PartitionRole::ControlB))
        ));
    }
}
