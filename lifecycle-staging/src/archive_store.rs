//! LC-2 归档收据的本地双副本持久后端。
//! Local dual-copy persistence backend for LC-2 archive receipts.
//!
//! 本后端固定使用两个不可由调用者指定的文件名，写入顺序为
//! `write_copy -> flush -> readback`。它可以发现单副本撕裂、同代冲突和前序链断开，
//! 但本地区块若被整体回滚到一份旧的有效双副本，仍需 TPM/安全单调计数器证明。
//! The backend owns two fixed filenames and commits with
//! `write_copy -> flush -> readback`. It detects torn single copies, equal-sequence
//! conflicts and broken chains; a coherent rollback of both local files still requires
//! an external TPM or secure monotonic anchor.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use jasper_lifecycle_model::archive::{
    commit, recover, repair, ArchiveError, ArchiveIo, ArchiveReceipt, ARCHIVE_RECEIPT_BYTES,
};
use jasper_lifecycle_model::update::UpdateStage;

const RECEIPT_COPIES: [&str; 2] = ["archive-receipt.0", "archive-receipt.1"];

/// 固定双副本归档收据存储。
/// Fixed dual-copy archive-receipt store.
#[derive(Debug)]
pub struct FileArchiveStore {
    root: PathBuf,
    io: FileArchiveIo,
}

/// 打开本地归档收据后端。
/// Opens the local archive-receipt backend.
impl FileArchiveStore {
    /// 打开一个已存在目录；失败关闭，不把任意文件路径扩展成调用者权限。
    /// Opens an existing directory and fails closed; caller paths never become authority.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, ArchiveError> {
        let root = root.into();
        let metadata = fs::symlink_metadata(&root).map_err(|_| ArchiveError::Readback)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ArchiveError::Readback);
        }
        Ok(Self {
            io: FileArchiveIo { root: root.clone() },
            root,
        })
    }

    /// 返回当前最高有效收据；空目录返回 `None`。
    /// Returns the highest valid receipt; an empty directory returns `None`.
    pub fn load(&self) -> Result<Option<ArchiveReceipt>, ArchiveError> {
        let first = read_optional(&self.root.join(RECEIPT_COPIES[0]))?;
        let second = read_optional(&self.root.join(RECEIPT_COPIES[1]))?;
        match (first.as_ref(), second.as_ref()) {
            (None, None) => Ok(None),
            (Some(first), second) => recover(Some(first), second).map(Some),
            (None, Some(second)) => recover(None, Some(second)).map(Some),
        }
    }

    /// 修复单个损坏或过期副本，并返回最高有效收据。
    /// Repairs one damaged or stale copy and returns the highest valid receipt.
    pub fn repair(&mut self) -> Result<Option<ArchiveReceipt>, ArchiveError> {
        let first = read_optional(&self.root.join(RECEIPT_COPIES[0]))?;
        let second = read_optional(&self.root.join(RECEIPT_COPIES[1]))?;
        match (first, second) {
            (None, None) => Ok(None),
            (Some(first), Some(second)) => repair(&mut self.io, &first, &second).map(Some),
            (Some(first), None) => {
                repair(&mut self.io, &first, &[0u8; ARCHIVE_RECEIPT_BYTES]).map(Some)
            }
            (None, Some(second)) => {
                repair(&mut self.io, &[0u8; ARCHIVE_RECEIPT_BYTES], &second).map(Some)
            }
        }
    }

    /// 提交下一份终态收据，只接受精确 sequence 后继和前序摘要。
    /// Commits the next terminal receipt with exact sequence and previous-digest checks.
    pub fn commit_next(
        &mut self,
        transaction_id: u64,
        manifest_sha256: [u8; 32],
        terminal_stage: UpdateStage,
    ) -> Result<ArchiveReceipt, ArchiveError> {
        let current = self.load()?;
        if let Some(receipt) = current {
            if receipt.transaction_id() == transaction_id
                && receipt.manifest_sha256() == manifest_sha256
                && receipt.terminal_stage() == terminal_stage
            {
                return Ok(receipt);
            }
        }
        let archive_sequence = match current {
            Some(receipt) => receipt
                .archive_sequence()
                .checked_add(1)
                .ok_or(ArchiveError::Sequence)?,
            None => 1,
        };
        let previous_sha256 = current.map_or([0; 32], ArchiveReceipt::chain_sha256);
        let next = ArchiveReceipt::new(
            archive_sequence,
            transaction_id,
            manifest_sha256,
            previous_sha256,
            terminal_stage,
        )?;
        commit(&mut self.io, current, next)
    }
}

#[derive(Debug)]
struct FileArchiveIo {
    root: PathBuf,
}

impl ArchiveIo for FileArchiveIo {
    fn write_copy(
        &mut self,
        copy: usize,
        bytes: &[u8; ARCHIVE_RECEIPT_BYTES],
    ) -> Result<(), ArchiveError> {
        let name = RECEIPT_COPIES.get(copy).ok_or(ArchiveError::Write)?;
        let target = self.root.join(name);
        let temporary = self.root.join(format!(".{name}.tmp-{}", now_nanos()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| ArchiveError::Write)?;
        if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(ArchiveError::Write);
        }
        drop(file);
        if fs::rename(&temporary, &target).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(ArchiveError::Write);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ArchiveError> {
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ArchiveError::Flush)
    }

    fn read_copy(
        &mut self,
        copy: usize,
        out: &mut [u8; ARCHIVE_RECEIPT_BYTES],
    ) -> Result<(), ArchiveError> {
        let name = RECEIPT_COPIES.get(copy).ok_or(ArchiveError::Readback)?;
        read_exact_regular(&self.root.join(name), out)
    }
}

fn read_optional(path: &Path) -> Result<Option<[u8; ARCHIVE_RECEIPT_BYTES]>, ArchiveError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let mut bytes = [0u8; ARCHIVE_RECEIPT_BYTES];
            read_exact_regular(path, &mut bytes)?;
            Ok(Some(bytes))
        }
        Ok(_) => Err(ArchiveError::Readback),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ArchiveError::Readback),
    }
}

fn read_exact_regular(
    path: &Path,
    out: &mut [u8; ARCHIVE_RECEIPT_BYTES],
) -> Result<(), ArchiveError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ArchiveError::Readback)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != ARCHIVE_RECEIPT_BYTES as u64
    {
        return Err(ArchiveError::Readback);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ArchiveError::Readback)?;
    file.read_exact(out).map_err(|_| ArchiveError::Readback)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "jasper-archive-store-{tag}-{}-{}",
                std::process::id(),
                now_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn commits_real_files_and_reopens_the_exact_chain() {
        let temp = TestDir::new("chain");
        let mut store = FileArchiveStore::open(&temp.0).unwrap();
        assert_eq!(store.load().unwrap(), None);
        let first = store
            .commit_next(7, [1; 32], UpdateStage::Complete)
            .unwrap();
        let second = store
            .commit_next(8, [2; 32], UpdateStage::RolledBack)
            .unwrap();
        assert_eq!(second.archive_sequence(), 2);
        assert_eq!(second.previous_sha256(), first.chain_sha256());
        assert!(temp.0.join(RECEIPT_COPIES[0]).is_file());
        assert!(temp.0.join(RECEIPT_COPIES[1]).is_file());
        assert_eq!(
            FileArchiveStore::open(&temp.0).unwrap().load(),
            Ok(Some(second))
        );
    }

    #[test]
    fn identical_terminal_transaction_is_idempotent() {
        let temp = TestDir::new("idempotent");
        let mut store = FileArchiveStore::open(&temp.0).unwrap();
        let first = store
            .commit_next(7, [1; 32], UpdateStage::Complete)
            .unwrap();
        assert_eq!(
            store.commit_next(7, [1; 32], UpdateStage::Complete),
            Ok(first)
        );
        assert_eq!(store.load(), Ok(Some(first)));
    }

    #[test]
    fn one_torn_copy_recovers_and_is_rewritten() {
        let temp = TestDir::new("repair");
        let mut store = FileArchiveStore::open(&temp.0).unwrap();
        let first = store
            .commit_next(7, [1; 32], UpdateStage::Complete)
            .unwrap();
        let second = store
            .commit_next(8, [2; 32], UpdateStage::Complete)
            .unwrap();
        fs::write(
            temp.0.join(RECEIPT_COPIES[0]),
            [0x5a; ARCHIVE_RECEIPT_BYTES],
        )
        .unwrap();
        assert_eq!(store.load(), Ok(Some(second)));
        assert_eq!(store.repair(), Ok(Some(second)));
        let first_copy = fs::read(temp.0.join(RECEIPT_COPIES[0])).unwrap();
        let second_copy = fs::read(temp.0.join(RECEIPT_COPIES[1])).unwrap();
        assert_eq!(first_copy, second_copy);
        assert_ne!(first_copy, first.encode());
    }

    #[test]
    fn equal_sequence_conflict_fails_without_rewriting_either_copy() {
        let temp = TestDir::new("conflict");
        let store = FileArchiveStore::open(&temp.0).unwrap();
        let first = ArchiveReceipt::new(1, 7, [1; 32], [0; 32], UpdateStage::Complete).unwrap();
        let conflict = ArchiveReceipt::new(1, 8, [2; 32], [0; 32], UpdateStage::Complete).unwrap();
        fs::write(temp.0.join(RECEIPT_COPIES[0]), first.encode()).unwrap();
        fs::write(temp.0.join(RECEIPT_COPIES[1]), conflict.encode()).unwrap();
        assert_eq!(store.load(), Err(ArchiveError::EqualSequenceMismatch));
        assert_eq!(
            fs::read(temp.0.join(RECEIPT_COPIES[0])).unwrap(),
            first.encode()
        );
        assert_eq!(
            fs::read(temp.0.join(RECEIPT_COPIES[1])).unwrap(),
            conflict.encode()
        );
    }

    #[test]
    fn nonterminal_or_disconnected_sequences_do_not_create_files() {
        let temp = TestDir::new("invalid");
        let mut store = FileArchiveStore::open(&temp.0).unwrap();
        assert_eq!(
            store.commit_next(7, [1; 32], UpdateStage::Trial),
            Err(ArchiveError::NonTerminal)
        );
        assert!(!temp.0.join(RECEIPT_COPIES[0]).exists());

        let first = ArchiveReceipt::new(1, 7, [1; 32], [0; 32], UpdateStage::Complete).unwrap();
        let disconnected =
            ArchiveReceipt::new(3, 8, [2; 32], [9; 32], UpdateStage::Complete).unwrap();
        fs::write(temp.0.join(RECEIPT_COPIES[0]), first.encode()).unwrap();
        fs::write(temp.0.join(RECEIPT_COPIES[1]), disconnected.encode()).unwrap();
        assert_eq!(store.load(), Err(ArchiveError::PreviousDigest));
        assert_eq!(
            store.commit_next(9, [3; 32], UpdateStage::Complete),
            Err(ArchiveError::PreviousDigest)
        );
    }
}
