//! LC-2/LC-3 启动控制记录的本地文件后端。
//! Local file backend for LC-2/LC-3 boot-control records.
//!
//! 后端只持久化固定控制记录，不创建 GPT、不复制系统映像，也不代表候选槽已经可启动。
//! This backend persists fixed control records only. It does not create GPT, copy a system
//! image or claim that a candidate slot is bootable.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use jasper_lifecycle_model::boot::{
    commit, recover, BootControlError, CommitError, ControlBlock, ControlIo, ControlIoError,
};
use jasper_lifecycle_model::CONTROL_RECORD_BYTES;

const CONTROL_COPIES: [&str; 2] = ["control.0", "control.1"];

/// 两份控制记录的文件目录。
/// Directory containing the two control-record copies.
pub struct FileControlIo {
    root: PathBuf,
}

impl FileControlIo {
    /// 使用调用方现有目录建立文件后端。
    /// Creates a file backend over an existing caller-owned directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl ControlIo for FileControlIo {
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let target = self
            .root
            .join(*CONTROL_COPIES.get(copy).ok_or(ControlIoError::Failed)?);
        let temporary = self.root.join(format!(
            ".control-{copy}-{}-{}.tmp",
            std::process::id(),
            now_nanos()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| ControlIoError::Failed)?;
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(ControlIoError::Failed);
        }
        drop(file);
        if fs::rename(&temporary, target).is_err() {
            let _ = fs::remove_file(temporary);
            return Err(ControlIoError::Failed);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ControlIoError> {
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ControlIoError::Failed)
    }

    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; CONTROL_RECORD_BYTES],
    ) -> Result<(), ControlIoError> {
        let path = self
            .root
            .join(*CONTROL_COPIES.get(copy).ok_or(ControlIoError::Failed)?);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| ControlIoError::Failed)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|_| ControlIoError::Failed)?;
        if bytes.len() != CONTROL_RECORD_BYTES {
            return Err(ControlIoError::Failed);
        }
        out.copy_from_slice(&bytes);
        Ok(())
    }
}

/// 当前控制记录及可重开的两副本文件后端。
/// Current control record and a reopenable dual-copy file backend.
pub struct FileControlStore {
    io: FileControlIo,
    current: ControlBlock,
}

/// 控制存储打开、初始化或提交失败。
/// Control-store open, initialization or commit failure.
#[derive(Debug)]
pub enum ControlStoreError {
    /// 文件系统操作失败。Filesystem operation failed.
    Io(io::Error),
    /// 两份记录均无效。Both records are invalid.
    Corrupt,
    /// 两份记录恢复失败。Dual-copy recovery failed.
    Recovery(BootControlError),
    /// 下一世代提交失败。Next-generation commit failed.
    Commit(CommitError),
}

impl std::fmt::Display for ControlStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "control-store I/O failed: {error}"),
            Self::Corrupt => write!(formatter, "both control records are invalid"),
            Self::Recovery(error) => write!(formatter, "control recovery failed: {error:?}"),
            Self::Commit(error) => write!(formatter, "control commit failed: {error:?}"),
        }
    }
}

impl std::error::Error for ControlStoreError {}

impl FileControlStore {
    /// 从现有目录恢复最高有效控制记录。
    /// Recovers the highest valid control record from an existing directory.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ControlStoreError> {
        let root = root.into();
        let first = read_optional(&root.join(CONTROL_COPIES[0]))?;
        let second = read_optional(&root.join(CONTROL_COPIES[1]))?;
        let current =
            recover(first.as_deref(), second.as_deref()).map_err(ControlStoreError::recovery)?;
        Ok(Self {
            io: FileControlIo::new(root),
            current,
        })
    }

    /// 初始化一个空目录并写入两份相同控制记录。
    /// Initializes an empty directory and writes two identical control records.
    pub fn initialize(
        root: impl Into<PathBuf>,
        block: ControlBlock,
    ) -> Result<Self, ControlStoreError> {
        let root = root.into();
        fs::create_dir(&root)?;
        let mut io = FileControlIo::new(root.clone());
        let bytes = block.encode();
        io.write_copy(0, &bytes)
            .and_then(|_| io.write_copy(1, &bytes))
            .and_then(|_| io.flush())
            .map_err(|_| {
                let _ = fs::remove_file(root.join(CONTROL_COPIES[0]));
                let _ = fs::remove_file(root.join(CONTROL_COPIES[1]));
                ControlStoreError::Io(io::Error::other("control initialization failed"))
            })?;
        Ok(Self { io, current: block })
    }

    /// 当前控制记录快照。Current control-record snapshot.
    pub const fn current(&self) -> ControlBlock {
        self.current
    }

    /// 提交严格的下一世代；只有 flush 和读回均成功后才发布本地镜像。
    /// Commits exactly the next generation and publishes the local mirror only after flush/readback.
    pub fn commit_next(&mut self, next: ControlBlock) -> Result<(), ControlStoreError> {
        commit(&mut self.io, &mut self.current, next).map_err(ControlStoreError::Commit)
    }
}

impl From<io::Error> for ControlStoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl ControlStoreError {
    fn recovery(error: BootControlError) -> Self {
        if error == BootControlError::CorruptRecord {
            Self::Corrupt
        } else {
            Self::Recovery(error)
        }
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, ControlStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ControlStoreError::Io(error)),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ControlStoreError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "control copy is not a regular file",
        )));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use jasper_lifecycle_model::boot::{Candidate, Slot};

    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("jasper-control-store-{tag}-{}", now_nanos()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn initial() -> ControlBlock {
        ControlBlock::initialize(Slot::A, 1, [1; 32], 1, 0, 1, 1).unwrap()
    }

    fn candidate() -> ControlBlock {
        let mut block = initial();
        block
            .stage_candidate(
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
        block
    }

    #[test]
    fn initialize_and_reopen_keep_the_same_control_generation() {
        let temp = TestDir::new("reopen");
        let root = temp.0.join("control");
        let store = FileControlStore::initialize(&root, initial()).unwrap();
        drop(store);
        assert_eq!(FileControlStore::open(&root).unwrap().current(), initial());
    }

    #[test]
    fn candidate_commit_is_reopened_from_the_inactive_copy() {
        let temp = TestDir::new("candidate");
        let root = temp.0.join("control");
        let mut store = FileControlStore::initialize(&root, initial()).unwrap();
        store.commit_next(candidate()).unwrap();
        drop(store);
        assert_eq!(
            FileControlStore::open(&root).unwrap().current().candidate(),
            candidate().candidate()
        );
    }

    #[test]
    fn torn_new_copy_recovers_the_previous_generation() {
        let temp = TestDir::new("torn");
        let root = temp.0.join("control");
        let mut store = FileControlStore::initialize(&root, initial()).unwrap();
        store.commit_next(candidate()).unwrap();
        drop(store);
        let newest = (candidate().generation() & 1) as usize;
        fs::write(root.join(CONTROL_COPIES[newest]), b"torn").unwrap();
        assert_eq!(FileControlStore::open(&root).unwrap().current(), initial());
    }
}
