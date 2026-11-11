//! Bounded, read-only ext4 access with JBD2 recovery overlay.
//!
//! Storage is injected through [`Ext4ByteSource`]. The backing implementation
//! must return exactly the requested byte range or an error; partial reads are
//! never converted into zero-filled success.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt::{self, Display, Formatter};

use ext4_view::{Ext4, Ext4Read, FileType};

/// Block source error. The source is responsible for bounds and I/O checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ext4SourceError;

impl Display for Ext4SourceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("ext4 source read failed")
    }
}

impl Error for Ext4SourceError {}

/// Random-access byte source used by the ext4 reader.
pub trait Ext4ByteSource {
    /// Fill `dst` with exactly `dst.len()` bytes beginning at `offset`.
    fn read_exact(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Ext4SourceError>;
}

struct SourceReader<S>(S);

impl<S: Ext4ByteSource> Ext4Read for SourceReader<S> {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        self.0
            .read_exact(start_byte, dst)
            .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
    }
}

/// Structured failure from ext4 loading or VFS operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ext4FsError {
    Io,
    NotFound,
    NotDirectory,
    IsDirectory,
    SpecialFile,
    Corrupt,
    Incompatible,
    InvalidPath,
    TooLarge,
}

impl Ext4FsError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Io => "system.fs.error.ext4_io",
            Self::NotFound => "system.fs.error.not_found",
            Self::NotDirectory => "system.fs.error.not_directory",
            Self::IsDirectory => "system.fs.error.is_directory",
            Self::SpecialFile => "system.fs.error.special_file",
            Self::Corrupt => "system.fs.error.ext4_corrupt",
            Self::Incompatible => "system.fs.error.ext4_incompatible",
            Self::InvalidPath => "system.fs.error.invalid_path",
            Self::TooLarge => "system.fs.error.too_large",
        }
    }

    fn from_view(error: ext4_view::Ext4Error) -> Self {
        match error {
            ext4_view::Ext4Error::Io(_) => Self::Io,
            ext4_view::Ext4Error::NotFound => Self::NotFound,
            ext4_view::Ext4Error::NotADirectory => Self::NotDirectory,
            ext4_view::Ext4Error::IsADirectory => Self::IsDirectory,
            ext4_view::Ext4Error::IsASpecialFile => Self::SpecialFile,
            ext4_view::Ext4Error::Corrupt(_) => Self::Corrupt,
            ext4_view::Ext4Error::Incompatible(_) => Self::Incompatible,
            ext4_view::Ext4Error::NotAbsolute
            | ext4_view::Ext4Error::MalformedPath
            | ext4_view::Ext4Error::PathTooLong => Self::InvalidPath,
            ext4_view::Ext4Error::FileTooLarge => Self::TooLarge,
            _ => Self::Corrupt,
        }
    }
}

impl Display for Ext4FsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Error for Ext4FsError {}

/// Metadata copied out of the ext4 read view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ext4Metadata {
    pub len: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Stable file type for a directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ext4EntryType {
    Regular,
    Directory,
    Symlink,
    Other,
}

/// One bounded directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ext4DirEntry {
    pub name: Vec<u8>,
    pub entry_type: Ext4EntryType,
}

/// Read-only ext4 filesystem. Journal transactions are consulted through the
/// ext4-view recovery view; this type never writes to the backing source.
pub struct Ext4Reader {
    fs: Ext4,
}

impl Ext4Reader {
    /// Open an ext4 image from an injected byte source.
    pub fn open<S: Ext4ByteSource + 'static>(source: S) -> Result<Self, Ext4FsError> {
        Ext4::load(Box::new(SourceReader(source)))
            .map(|fs| Self { fs })
            .map_err(Ext4FsError::from_view)
    }

    /// Open an in-memory ext4 image.
    pub fn open_bytes(bytes: Vec<u8>) -> Result<Self, Ext4FsError> {
        Self::open(MemorySource(bytes))
    }

    /// Filesystem label as UTF-8 bytes.
    pub fn label(&self) -> &[u8] {
        self.fs.label().as_bytes()
    }

    pub fn metadata(&self, path: &str) -> Result<Ext4Metadata, Ext4FsError> {
        let metadata = self.fs.metadata(path).map_err(Ext4FsError::from_view)?;
        Ok(Ext4Metadata {
            len: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            is_dir: metadata.is_dir(),
            is_symlink: metadata.is_symlink(),
        })
    }

    /// Read a file only after proving its declared size fits `max_bytes`.
    pub fn read_file(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>, Ext4FsError> {
        let metadata = self.fs.metadata(path).map_err(Ext4FsError::from_view)?;
        if metadata.len() > max_bytes as u64 {
            return Err(Ext4FsError::TooLarge);
        }
        self.fs.read(path).map_err(Ext4FsError::from_view)
    }

    /// Read at most `dst.len()` leading bytes without allocating the entire file.
    /// 最多读取文件开头的 `dst.len()` 字节，避免为大型用户态文件分配整块内存。
    pub fn read_file_prefix(&self, path: &str, dst: &mut [u8]) -> Result<usize, Ext4FsError> {
        let mut file = self.fs.open(path).map_err(Ext4FsError::from_view)?;
        file.read_bytes(dst).map_err(Ext4FsError::from_view)
    }

    /// Read a directory up to `max_entries`, failing atomically if the bound is
    /// exceeded.
    pub fn read_dir(
        &self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<Ext4DirEntry>, Ext4FsError> {
        let iter = self.fs.read_dir(path).map_err(Ext4FsError::from_view)?;
        let mut entries = Vec::new();
        for entry in iter {
            if entries.len() == max_entries {
                return Err(Ext4FsError::TooLarge);
            }
            let entry = entry.map_err(Ext4FsError::from_view)?;
            let file_type = entry.file_type().map_err(Ext4FsError::from_view)?;
            entries.push(Ext4DirEntry {
                name: entry.file_name().as_ref().to_vec(),
                entry_type: entry_type(file_type),
            });
        }
        Ok(entries)
    }
}

fn entry_type(file_type: FileType) -> Ext4EntryType {
    if file_type.is_regular_file() {
        Ext4EntryType::Regular
    } else if file_type.is_dir() {
        Ext4EntryType::Directory
    } else if file_type.is_symlink() {
        Ext4EntryType::Symlink
    } else {
        Ext4EntryType::Other
    }
}

struct MemorySource(Vec<u8>);

impl Ext4ByteSource for MemorySource {
    fn read_exact(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Ext4SourceError> {
        let start = usize::try_from(offset).map_err(|_| Ext4SourceError)?;
        let end = start.checked_add(dst.len()).ok_or(Ext4SourceError)?;
        let source = self.0.get(start..end).ok_or(Ext4SourceError)?;
        dst.copy_from_slice(source);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::process::Command;

    fn command_available(program: &str) -> bool {
        Command::new(program)
            .arg("-V")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[test]
    fn malformed_sources_fail_without_panicking() {
        for size in 0..4096 {
            let mut bytes = alloc::vec![0u8; size];
            if let Some(last) = bytes.last_mut() {
                *last = 0xff;
            }
            let _ = Ext4Reader::open_bytes(bytes);
        }

        let mut seed = 0x4653_3145_5854_3401u64;
        let original = alloc::vec![0u8; 64 * 1024];
        for _ in 0..20_000 {
            let mut image = original.clone();
            for _ in 0..(seed as usize % 7 + 1) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = seed as usize % image.len();
                image[at] ^= (seed >> 32) as u8;
            }
            let _ = Ext4Reader::open_bytes(image);
        }
    }

    #[test]
    fn memory_source_is_exact_and_bounded() {
        let mut source = MemorySource(alloc::vec![1, 2, 3, 4]);
        let mut out = [0u8; 2];
        source.read_exact(1, &mut out).unwrap();
        assert_eq!(out, [2, 3]);
        assert_eq!(source.read_exact(3, &mut out), Err(Ext4SourceError));
    }

    #[test]
    fn reads_a_real_linux_created_ext4_image() {
        if !command_available("mke2fs")
            || !command_available("debugfs")
            || !command_available("e2fsck")
        {
            eprintln!("ext4 tooling unavailable; real image test skipped");
            return;
        }

        let dir = std::env::temp_dir().join(format!("jasper-ext4-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("volume.img");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();

        let status = Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-b", "4096", "-F", "-L", "JASPER_FS1"])
            .arg(&image)
            .status()
            .unwrap();
        assert!(status.success(), "mke2fs failed");

        let status = Command::new("debugfs")
            .args(["-w", "-R", "mkdir /dir"])
            .arg(&image)
            .status()
            .unwrap();
        assert!(status.success(), "debugfs mkdir failed");

        let source_file = dir.join("hello.txt");
        std::fs::write(&source_file, b"hello from Linux ext4\n").unwrap();
        let status = Command::new("debugfs")
            .args(["-w", "-R"])
            .arg(format!("write {} /dir/hello.txt", source_file.display()))
            .arg(&image)
            .status()
            .unwrap();
        assert!(status.success(), "debugfs write failed");

        let status = Command::new("e2fsck")
            .args(["-fy"])
            .arg(&image)
            .status()
            .unwrap();
        assert!(
            status.success() || status.code() == Some(1),
            "e2fsck rejected the fixture"
        );

        let bytes = std::fs::read(&image).unwrap();
        let fs = Ext4Reader::open_bytes(bytes).unwrap();
        assert_eq!(
            fs.read_file("/dir/hello.txt", 4096).unwrap(),
            b"hello from Linux ext4\n"
        );
        let mut prefix = [0u8; 5];
        assert_eq!(fs.read_file_prefix("/dir/hello.txt", &mut prefix).unwrap(), 5);
        assert_eq!(&prefix, b"hello");
        let metadata = fs.metadata("/dir/hello.txt").unwrap();
        assert_eq!(metadata.len, 22);
        assert!(!metadata.is_dir);
        let entries = fs.read_dir("/dir", 16).unwrap();
        assert!(entries.iter().any(|entry| {
            entry.name == b"hello.txt" && entry.entry_type == Ext4EntryType::Regular
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn debugfs_blocks(image: &std::path::Path, path: &str) -> Vec<u64> {
        let output = Command::new("debugfs")
            .args(["-R", &format!("blocks {path}")])
            .arg(image)
            .output()
            .unwrap();
        assert!(output.status.success(), "debugfs blocks failed");
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect()
    }

    fn write_at(path: &std::path::Path, offset: u64, bytes: &[u8]) {
        let mut file = OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    fn read_at(path: &std::path::Path, offset: u64, bytes: &mut [u8]) {
        let mut file = OpenOptions::new().read(true).open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(bytes).unwrap();
    }

    fn jbd_checksum(parts: &[&[u8]]) -> u32 {
        const CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
        let mut digest = CRC32C.digest_with_initial(crc::CRC_32_ISCSI.init.reverse_bits());
        for part in parts {
            digest.update(part);
        }
        digest.finalize() ^ (!0)
    }

    #[test]
    fn committed_dirty_journal_overlays_the_old_file_data() {
        assert_eq!(jbd_checksum(&[&[1, 0, 0, 0], &[2, 0, 0, 0]]), 0x858c_13d3);
        if !command_available("mke2fs")
            || !command_available("debugfs")
            || !command_available("e2fsck")
        {
            eprintln!("ext4 tooling unavailable; journal test skipped");
            return;
        }

        const BLOCK: usize = 4096;
        const JBD2_MAGIC: u32 = 0xC03B_3998;
        const DESCRIPTOR: u32 = 1;
        const COMMIT: u32 = 2;
        const SAME_UUID: u32 = 0x2;
        const LAST: u32 = 0x8;

        let dir = std::env::temp_dir().join(format!("jasper-ext4-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let image = dir.join("journal.img");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let status = Command::new("mke2fs")
            .args([
                "-q",
                "-t",
                "ext4",
                "-b",
                "4096",
                "-F",
                "-O",
                "^metadata_csum,^metadata_csum_seed,^64bit",
            ])
            .arg(&image)
            .status()
            .unwrap();
        assert!(status.success(), "mke2fs failed");

        let old_file = dir.join("old.txt");
        std::fs::write(&old_file, b"OLD-VIEW-0000000").unwrap();
        let status = Command::new("debugfs")
            .args(["-w", "-R"])
            .arg(format!("write {} /victim", old_file.display()))
            .arg(&image)
            .status()
            .unwrap();
        assert!(status.success(), "debugfs write failed");

        let victim_blocks = debugfs_blocks(&image, "/victim");
        let journal_blocks = debugfs_blocks(&image, "<8>");
        assert_eq!(victim_blocks.len(), 1);
        assert!(journal_blocks.len() >= 4);

        let mut replacement = [0u8; BLOCK];
        read_at(&image, victim_blocks[0] * BLOCK as u64, &mut replacement);
        replacement[..16].copy_from_slice(b"JOURNALED-VIEW!!");
        replacement[16..].fill(0);

        let mut descriptor = [0u8; BLOCK];
        descriptor[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        descriptor[4..8].copy_from_slice(&DESCRIPTOR.to_be_bytes());
        descriptor[8..12].copy_from_slice(&1u32.to_be_bytes());
        let mut journal_super = [0u8; BLOCK];
        read_at(&image, journal_blocks[0] * BLOCK as u64, &mut journal_super);
        assert_eq!(
            u32::from_be_bytes(journal_super[0..4].try_into().unwrap()),
            JBD2_MAGIC
        );
        journal_super[0x28..0x2c].copy_from_slice(&0x12u32.to_be_bytes());
        journal_super[0x50] = 4;
        journal_super[0x1c..0x20].copy_from_slice(&1u32.to_be_bytes());
        journal_super[0xfc..0x100].fill(0);
        let journal_uuid: [u8; 16] = journal_super[0x30..0x40].try_into().unwrap();
        let super_checksum =
            jbd_checksum(&[&journal_super[..0xfc], &[0; 4], &journal_super[0x100..1024]]);
        journal_super[0xfc..0x100].copy_from_slice(&super_checksum.to_be_bytes());

        let tag_checksum = jbd_checksum(&[&journal_uuid, &1u32.to_be_bytes(), &replacement]);
        descriptor[12..16].copy_from_slice(&(victim_blocks[0] as u32).to_be_bytes());
        descriptor[16..20].copy_from_slice(&(SAME_UUID | LAST).to_be_bytes());
        descriptor[24..28].copy_from_slice(&tag_checksum.to_be_bytes());
        let descriptor_checksum = jbd_checksum(&[&journal_uuid, &descriptor[..BLOCK - 4], &[0; 4]]);
        descriptor[BLOCK - 4..].copy_from_slice(&descriptor_checksum.to_be_bytes());

        let mut commit = [0u8; BLOCK];
        commit[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        commit[4..8].copy_from_slice(&COMMIT.to_be_bytes());
        commit[8..12].copy_from_slice(&1u32.to_be_bytes());
        let commit_checksum = jbd_checksum(&[&journal_uuid, &commit[..16], &[0; 4], &commit[20..]]);
        commit[16..20].copy_from_slice(&commit_checksum.to_be_bytes());

        write_at(&image, journal_blocks[1] * BLOCK as u64, &descriptor);
        write_at(&image, journal_blocks[2] * BLOCK as u64, &replacement);
        write_at(&image, journal_blocks[3] * BLOCK as u64, &commit);
        write_at(&image, journal_blocks[0] * BLOCK as u64, &journal_super);

        let mut incompat = [0u8; 4];
        read_at(&image, 1024 + 0x60, &mut incompat);
        let incompat = u32::from_le_bytes(incompat) | 0x4;
        write_at(&image, 1024 + 0x60, &incompat.to_le_bytes());

        let bytes = std::fs::read(&image).unwrap();
        let mut incomplete = bytes.clone();
        let commit_offset = journal_blocks[3] as usize * BLOCK + 16;
        incomplete[commit_offset..commit_offset + 4].fill(0);
        let uncommitted = Ext4Reader::open_bytes(incomplete).unwrap();
        assert_eq!(
            uncommitted.read_file("/victim", 4096).unwrap(),
            b"OLD-VIEW-0000000"
        );
        drop(uncommitted);

        let fs = Ext4Reader::open_bytes(bytes).unwrap();
        let recovered = fs.read_file("/victim", 4096).unwrap();
        assert_eq!(&recovered[..16], b"JOURNALED-VIEW!!");

        drop(fs);
        let status = Command::new("e2fsck")
            .args(["-fy"])
            .arg(&image)
            .status()
            .unwrap();
        assert!(
            status.success() || status.code() == Some(1),
            "Linux e2fsck rejected the committed transaction"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
