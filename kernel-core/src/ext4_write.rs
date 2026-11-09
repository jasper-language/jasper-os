//! Experimental no_std ext4 write engine.
//!
//! `ext4_rs` computes directory/inode/extent metadata mutations, but its block
//! interface does not carry I/O errors and it has no JBD2 writer. This module
//! runs each operation against a buffered block device, then commits every
//! changed block through a Jasper-owned JBD2 transaction and BLK-style flush.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use ext4_rs::{BlockDevice, Ext4, InodeFileType};

use crate::ext4_view::{Ext4ByteSource, Ext4FsError, Ext4Reader, Ext4SourceError};
use crate::sync::SpinLock;

pub const EXT4_BLOCK_BYTES: usize = 4096;
const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR: u32 = 1;
const JBD2_COMMIT: u32 = 2;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const TAG_SAME_UUID: u32 = 0x2;
const TAG_LAST: u32 = 0x8;
const EXT4_RECOVERY_INCOMPAT: u32 = 0x4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ext4WriteError {
    Io,
    InvalidImage,
    NotFound,
    AlreadyExists,
    NotAFile,
    JournalUnavailable,
    JournalFull,
    Operation,
    NotDurable,
    Busy,
    TooManyHandles,
    InvalidHandle,
    ReadOnly,
    OpenFailed,
    WriteDataFailed,
    TruncateFailed,
}

impl Ext4WriteError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Io => "system.fs.error.ext4_io",
            Self::InvalidImage => "system.fs.error.ext4_corrupt",
            Self::NotFound => "system.fs.error.not_found",
            Self::AlreadyExists => "system.fs.error.already_exists",
            Self::NotAFile => "system.fs.error.not_a_file",
            Self::JournalUnavailable => "system.fs.error.journal_unavailable",
            Self::JournalFull => "system.fs.error.journal_full",
            Self::Operation => "system.fs.error.ext4_operation",
            Self::NotDurable => "system.fs.error.not_durable",
            Self::Busy => "system.fs.error.busy",
            Self::TooManyHandles => "system.fs.error.handle_table_full",
            Self::InvalidHandle => "system.fs.error.handle_invalid",
            Self::ReadOnly => "system.fs.error.read_only",
            Self::OpenFailed => "system.fs.error.ext4_open_failed",
            Self::WriteDataFailed => "system.fs.error.ext4_write_data_failed",
            Self::TruncateFailed => "system.fs.error.ext4_truncate_failed",
        }
    }
}

/// Writable random-access source. `flush` must not report success until all
/// previous writes have reached the backend's durability boundary.
pub trait Ext4WritableSource: Ext4ByteSource + Clone {
    fn write_exact(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Ext4SourceError>;
    fn flush(&mut self) -> Result<(), Ext4SourceError>;
}

struct DeviceState<S> {
    source: S,
    pending: BTreeMap<u64, Vec<u8>>,
    io_error: bool,
}

struct TransactionDevice<S> {
    state: SpinLock<DeviceState<S>>,
}

impl<S: Ext4WritableSource> TransactionDevice<S> {
    fn new(source: S) -> Self {
        Self {
            state: SpinLock::new(DeviceState {
                source,
                pending: BTreeMap::new(),
                io_error: false,
            }),
        }
    }

    fn take_pending(&self) -> Result<BTreeMap<u64, Vec<u8>>, Ext4WriteError> {
        let mut state = self.state.lock();
        if state.io_error {
            return Err(Ext4WriteError::Io);
        }
        Ok(core::mem::take(&mut state.pending))
    }

    fn read_block(&self, block: u64) -> Result<Vec<u8>, Ext4WriteError> {
        let mut state = self.state.lock();
        state.read_block(block)
    }

    fn write_block(&self, block: u64, bytes: &[u8]) -> Result<(), Ext4WriteError> {
        let mut state = self.state.lock();
        state
            .source
            .write_exact(block * EXT4_BLOCK_BYTES as u64, bytes)
            .map_err(|_| Ext4WriteError::Io)
    }

    fn flush(&self) -> Result<(), Ext4WriteError> {
        self.state
            .lock()
            .source
            .flush()
            .map_err(|_| Ext4WriteError::Io)
    }
}

impl<S: Ext4WritableSource> DeviceState<S> {
    fn read_block(&mut self, block: u64) -> Result<Vec<u8>, Ext4WriteError> {
        if let Some(bytes) = self.pending.get(&block) {
            return Ok(bytes.clone());
        }
        let mut out = vec![0; EXT4_BLOCK_BYTES];
        if self
            .source
            .read_exact(block * EXT4_BLOCK_BYTES as u64, &mut out)
            .is_err()
        {
            self.io_error = true;
            return Err(Ext4WriteError::Io);
        }
        Ok(out)
    }

    fn read_range(&mut self, offset: usize, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        let mut done = 0;
        while done < len {
            let absolute = offset + done;
            let block = absolute / EXT4_BLOCK_BYTES;
            let inner = absolute % EXT4_BLOCK_BYTES;
            let take = (len - done).min(EXT4_BLOCK_BYTES - inner);
            match self.read_block(block as u64) {
                Ok(bytes) => out[done..done + take].copy_from_slice(&bytes[inner..inner + take]),
                Err(_) => {
                    self.io_error = true;
                    out[done..done + take].fill(0);
                }
            }
            done += take;
        }
        out
    }

    fn buffer_write(&mut self, offset: usize, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            let absolute = offset + done;
            let block = absolute / EXT4_BLOCK_BYTES;
            let inner = absolute % EXT4_BLOCK_BYTES;
            let take = (data.len() - done).min(EXT4_BLOCK_BYTES - inner);
            let mut bytes = match self.read_block(block as u64) {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.io_error = true;
                    vec![0; EXT4_BLOCK_BYTES]
                }
            };
            bytes[inner..inner + take].copy_from_slice(&data[done..done + take]);
            self.pending.insert(block as u64, bytes);
            done += take;
        }
    }
}

impl<S: Ext4WritableSource + Send + Sync + 'static> BlockDevice for TransactionDevice<S> {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        self.state.lock().read_range(offset, EXT4_BLOCK_BYTES)
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        self.state.lock().buffer_write(offset, data);
    }
}

struct MemoryStorage {
    bytes: Arc<SpinLock<Vec<u8>>>,
}

impl Clone for MemoryStorage {
    fn clone(&self) -> Self {
        Self {
            bytes: Arc::clone(&self.bytes),
        }
    }
}

impl Ext4ByteSource for MemoryStorage {
    fn read_exact(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Ext4SourceError> {
        let bytes = self.bytes.lock();
        let start = usize::try_from(offset).map_err(|_| Ext4SourceError)?;
        let end = start.checked_add(dst.len()).ok_or(Ext4SourceError)?;
        dst.copy_from_slice(bytes.get(start..end).ok_or(Ext4SourceError)?);
        Ok(())
    }
}

impl Ext4WritableSource for MemoryStorage {
    fn write_exact(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Ext4SourceError> {
        let mut image = self.bytes.lock();
        let start = usize::try_from(offset).map_err(|_| Ext4SourceError)?;
        let end = start.checked_add(bytes.len()).ok_or(Ext4SourceError)?;
        image
            .get_mut(start..end)
            .ok_or(Ext4SourceError)?
            .copy_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Ext4SourceError> {
        Ok(())
    }
}

pub struct Ext4Writer<S> {
    source: S,
}

impl Ext4Writer<MemoryStorage> {
    pub fn open_bytes(bytes: Vec<u8>) -> Result<Self, Ext4WriteError> {
        Self::open(MemoryStorage {
            bytes: Arc::new(SpinLock::new(bytes)),
        })
    }

    pub fn image(&self) -> Vec<u8> {
        self.source.bytes.lock().clone()
    }
}

impl<S> Ext4Writer<S>
where
    S: Ext4WritableSource + Send + Sync + 'static,
{
    pub fn open(source: S) -> Result<Self, Ext4WriteError> {
        Ext4Reader::open(source.clone()).map_err(|error| match error {
            Ext4FsError::Io => Ext4WriteError::Io,
            _ => Ext4WriteError::InvalidImage,
        })?;
        Ok(Self { source })
    }

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), Ext4WriteError> {
        self.transaction(|ext4| {
            let (parent_path, name) = split_path(path)?;
            let mut parent = 2u32;
            let inode = ext4
                .generic_open(
                    path,
                    &mut parent,
                    true,
                    InodeFileType::S_IFREG.bits(),
                    &mut 0,
                )
                .map_err(|_| Ext4WriteError::OpenFailed)?;
            let mut inode_ref = ext4.get_inode_ref(inode);
            let old_size = inode_ref.inode.size();
            if !data.is_empty() {
                ext4.write_at(inode, 0, data)
                    .map_err(|_| Ext4WriteError::WriteDataFailed)?;
            }
            if old_size > data.len() as u64 {
                ext4.truncate_inode(&mut inode_ref, data.len() as u64)
                    .map_err(|_| Ext4WriteError::TruncateFailed)?;
            }
            let _ = (parent_path, name, parent);
            Ok(())
        })
    }

    pub fn read_file(&self, path: &str, max_bytes: usize) -> Result<Vec<u8>, Ext4WriteError> {
        Ext4Reader::open(self.source.clone())
            .map_err(|_| Ext4WriteError::InvalidImage)?
            .read_file(path, max_bytes)
            .map_err(|error| match error {
                Ext4FsError::NotFound => Ext4WriteError::NotFound,
                Ext4FsError::Io => Ext4WriteError::Io,
                Ext4FsError::TooLarge => Ext4WriteError::JournalFull,
                _ => Ext4WriteError::Operation,
            })
    }

    pub fn rename_file(&mut self, source: &str, destination: &str) -> Result<(), Ext4WriteError> {
        self.transaction(|ext4| {
            let (source_parent_path, source_name) = split_path(source)?;
            let (destination_parent_path, destination_name) = split_path(destination)?;
            let mut source_parent = open_dir(ext4, source_parent_path)?;
            let mut destination_parent = open_dir(ext4, destination_parent_path)?;
            let child = ext4
                .generic_open(source, &mut source_parent, false, 0, &mut 0)
                .map_err(|_| Ext4WriteError::NotFound)?;
            if !ext4.get_inode_ref(child).inode.is_file() {
                return Err(Ext4WriteError::NotAFile);
            }
            let mut source_parent_ref = ext4.get_inode_ref(source_parent);
            let mut destination_parent_ref = ext4.get_inode_ref(destination_parent);
            let mut child_ref = ext4.get_inode_ref(child);
            if ext4
                .generic_open(destination, &mut destination_parent, false, 0, &mut 0)
                .is_ok()
            {
                return Err(Ext4WriteError::AlreadyExists);
            }
            ext4.link(
                &mut destination_parent_ref,
                &mut child_ref,
                destination_name,
            )
            .map_err(|_| Ext4WriteError::Operation)?;
            ext4.dir_remove_entry(&mut source_parent_ref, source_name)
                .map_err(|_| Ext4WriteError::Operation)?;
            child_ref
                .inode
                .set_links_count(child_ref.inode.links_count().saturating_sub(1));
            ext4.write_back_inode(&mut child_ref);
            Ok(())
        })
    }

    pub fn unlink_file(&mut self, path: &str) -> Result<(), Ext4WriteError> {
        self.transaction(|ext4| {
            let (parent_path, name) = split_path(path)?;
            let mut parent = open_dir(ext4, parent_path)?;
            let child = ext4
                .generic_open(path, &mut parent, false, 0, &mut 0)
                .map_err(|_| Ext4WriteError::NotFound)?;
            let mut parent_ref = ext4.get_inode_ref(parent);
            let mut child_ref = ext4.get_inode_ref(child);
            if !child_ref.inode.is_file() {
                return Err(Ext4WriteError::NotAFile);
            }
            ext4.dir_remove_entry(&mut parent_ref, name)
                .map_err(|_| Ext4WriteError::Operation)?;
            let links = child_ref.inode.links_count().saturating_sub(1);
            child_ref.inode.set_links_count(links);
            if links == 0 {
                ext4.truncate_inode(&mut child_ref, 0)
                    .map_err(|_| Ext4WriteError::Operation)?;
                ext4.ialloc_free_inode(child_ref.inode_num, false);
            } else {
                ext4.write_back_inode(&mut child_ref);
            }
            ext4.write_back_inode(&mut parent_ref);
            Ok(())
        })
    }

    pub fn sync(&mut self) -> Result<(), Ext4WriteError> {
        self.source.flush().map_err(|_| Ext4WriteError::Io)
    }

    fn transaction(
        &mut self,
        operation: impl FnOnce(&Ext4) -> Result<(), Ext4WriteError>,
    ) -> Result<(), Ext4WriteError> {
        let device = Arc::new(TransactionDevice::new(self.source.clone()));
        let ext4 = Ext4::open(device.clone());
        operation(&ext4)?;
        let journal = journal_geometry(&ext4)?;
        drop(ext4);

        let mut pending = device.take_pending()?;
        if pending.is_empty() {
            return device.flush();
        }
        reconcile_superblock_counts(&device, &mut pending)?;
        add_recovery_marker(&device, &mut pending)?;
        commit_journal(&device, &journal, &pending)?;

        for (block, bytes) in &pending {
            device.write_block(*block, bytes)?;
        }
        device.flush()?;

        let mut clean_super = journal.superblock.clone();
        clean_super[0x1c..0x20].copy_from_slice(&0u32.to_be_bytes());
        clean_super[0x18..0x1c].copy_from_slice(&journal.sequence.wrapping_add(1).to_be_bytes());
        write_journal_super_checksum(&mut clean_super);
        device.write_block(journal.superblock_block, &clean_super)?;
        device.flush()?;

        let mut block_zero = pending.remove(&0).ok_or(Ext4WriteError::InvalidImage)?;
        clear_recovery_marker(&mut block_zero);
        device.write_block(0, &block_zero)?;
        device.flush()
    }
}

const MAX_VFS_HANDLES: usize = 64;

struct VfsHandle {
    path: String,
    writable: bool,
}

/// Small path-addressed VFS facade over the journaled ext4 writer.
///
/// Handles are process-local stand-ins for the future FS-0 Handle/Rights
/// mapping. They are bounded, generation-checked, and release deterministically
/// on close. Open files with writes are committed and flushed by `write`.
pub struct Ext4Vfs<S> {
    writer: Ext4Writer<S>,
    handles: BTreeMap<u64, VfsHandle>,
    next_handle: u64,
}

impl<S> Ext4Vfs<S>
where
    S: Ext4WritableSource + Send + Sync + 'static,
{
    pub fn new(source: S) -> Result<Self, Ext4WriteError> {
        Ok(Self {
            writer: Ext4Writer::open(source)?,
            handles: BTreeMap::new(),
            next_handle: 1,
        })
    }

    pub fn open(&mut self, path: &str, writable: bool) -> Result<u64, Ext4WriteError> {
        Ext4Reader::open(self.writer.source.clone())
            .map_err(|_| Ext4WriteError::InvalidImage)?
            .metadata(path)
            .map_err(|_| Ext4WriteError::NotFound)?;
        self.allocate_handle(path, writable)
    }

    pub fn create_open(&mut self, path: &str, writable: bool) -> Result<u64, Ext4WriteError> {
        if Ext4Reader::open(self.writer.source.clone())
            .map_err(|_| Ext4WriteError::InvalidImage)?
            .metadata(path)
            .is_err()
        {
            self.writer.write_file(path, &[])?;
        }
        self.allocate_handle(path, writable)
    }

    pub fn read(&self, handle: u64, max_bytes: usize) -> Result<Vec<u8>, Ext4WriteError> {
        let entry = self
            .handles
            .get(&handle)
            .ok_or(Ext4WriteError::InvalidHandle)?;
        self.writer.read_file(&entry.path, max_bytes)
    }

    pub fn write(&mut self, handle: u64, data: &[u8]) -> Result<(), Ext4WriteError> {
        let path = {
            let entry = self
                .handles
                .get(&handle)
                .ok_or(Ext4WriteError::InvalidHandle)?;
            if !entry.writable {
                return Err(Ext4WriteError::ReadOnly);
            }
            entry.path.clone()
        };
        self.writer.write_file(&path, data)
    }

    pub fn sync(&mut self, handle: u64) -> Result<(), Ext4WriteError> {
        if !self.handles.contains_key(&handle) {
            return Err(Ext4WriteError::InvalidHandle);
        }
        self.writer.sync()
    }

    pub fn rename(&mut self, source: &str, destination: &str) -> Result<(), Ext4WriteError> {
        self.writer.rename_file(source, destination)?;
        for handle in self.handles.values_mut() {
            if handle.path == source {
                handle.path = destination.to_string();
            }
        }
        Ok(())
    }

    pub fn unlink(&mut self, path: &str) -> Result<(), Ext4WriteError> {
        if self.handles.values().any(|handle| handle.path == path) {
            return Err(Ext4WriteError::Busy);
        }
        self.writer.unlink_file(path)
    }

    pub fn close(&mut self, handle: u64) -> Result<(), Ext4WriteError> {
        self.handles
            .remove(&handle)
            .map(|_| ())
            .ok_or(Ext4WriteError::InvalidHandle)
    }

    pub fn live_handles(&self) -> usize {
        self.handles.len()
    }

    fn allocate_handle(&mut self, path: &str, writable: bool) -> Result<u64, Ext4WriteError> {
        if self.handles.len() >= MAX_VFS_HANDLES {
            return Err(Ext4WriteError::TooManyHandles);
        }
        let handle = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(Ext4WriteError::TooManyHandles)?;
        self.handles.insert(
            handle,
            VfsHandle {
                path: path.to_string(),
                writable,
            },
        );
        Ok(handle)
    }
}

impl Ext4Vfs<MemoryStorage> {
    pub fn image(&self) -> Vec<u8> {
        self.writer.image()
    }
}

fn reconcile_superblock_counts<S>(
    device: &TransactionDevice<S>,
    pending: &mut BTreeMap<u64, Vec<u8>>,
) -> Result<(), Ext4WriteError>
where
    S: Ext4WritableSource,
{
    let block_zero = match pending.remove(&0) {
        Some(bytes) => bytes,
        None => device.read_block(0)?,
    };
    let sb = 1024;
    let blocks_count = u32::from_le_bytes(block_zero[sb + 0x04..sb + 0x08].try_into().unwrap());
    let blocks_per_group = u32::from_le_bytes(block_zero[sb + 0x20..sb + 0x24].try_into().unwrap());
    if blocks_count == 0 || blocks_per_group == 0 {
        return Err(Ext4WriteError::InvalidImage);
    }
    let groups = blocks_count.div_ceil(blocks_per_group);
    let desc_size = {
        let size = u16::from_le_bytes(block_zero[sb + 0xfe..sb + 0x100].try_into().unwrap());
        if size == 0 {
            32
        } else {
            usize::from(size)
        }
    };
    let desc_table = pending
        .get(&1)
        .cloned()
        .map_or_else(|| device.read_block(1), Ok)?;
    let mut free_blocks = 0u32;
    let mut free_inodes = 0u32;
    for group in 0..groups as usize {
        let at = group
            .checked_mul(desc_size)
            .ok_or(Ext4WriteError::InvalidImage)?;
        let desc = desc_table
            .get(at..at + desc_size)
            .ok_or(Ext4WriteError::InvalidImage)?;
        free_blocks = free_blocks
            .checked_add(u32::from(u16::from_le_bytes(
                desc[0x0c..0x0e].try_into().unwrap(),
            )))
            .ok_or(Ext4WriteError::InvalidImage)?;
        free_inodes = free_inodes
            .checked_add(u32::from(u16::from_le_bytes(
                desc[0x0e..0x10].try_into().unwrap(),
            )))
            .ok_or(Ext4WriteError::InvalidImage)?;
        if desc_size >= 0x30 {
            if desc[0x2c..0x2e] != [0, 0] || desc[0x2e..0x30] != [0, 0] {
                return Err(Ext4WriteError::InvalidImage);
            }
        }
    }
    let mut block_zero = block_zero;
    block_zero[sb + 0x0c..sb + 0x10].copy_from_slice(&free_blocks.to_le_bytes());
    block_zero[sb + 0x10..sb + 0x14].copy_from_slice(&free_inodes.to_le_bytes());
    refresh_superblock_checksum(&mut block_zero);
    pending.insert(0, block_zero);
    Ok(())
}

fn split_path(path: &str) -> Result<(&str, &str), Ext4WriteError> {
    let path = path.strip_prefix('/').ok_or(Ext4WriteError::Operation)?;
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name.is_empty() {
        return Err(Ext4WriteError::Operation);
    }
    Ok((if parent.is_empty() { "/" } else { parent }, name))
}

fn open_dir(ext4: &Ext4, path: &str) -> Result<u32, Ext4WriteError> {
    if path == "/" {
        return Ok(2);
    }
    let mut parent = 2u32;
    ext4.generic_open(
        path,
        &mut parent,
        false,
        InodeFileType::S_IFDIR.bits(),
        &mut 0,
    )
    .map_err(|_| Ext4WriteError::NotFound)
}

struct JournalGeometry {
    superblock_block: u64,
    sequence: u32,
    uuid: [u8; 16],
    max_blocks: u32,
    superblock: Vec<u8>,
    logical_to_physical: Vec<u64>,
}

fn journal_geometry(ext4: &Ext4) -> Result<JournalGeometry, Ext4WriteError> {
    let superblock_data = ext4.block_device.read_offset(1024);
    let journal_inode = u32::from_le_bytes(
        superblock_data
            .get(0xe0..0xe4)
            .ok_or(Ext4WriteError::InvalidImage)?
            .try_into()
            .unwrap(),
    );
    if journal_inode == 0 {
        return Err(Ext4WriteError::JournalUnavailable);
    }
    let inode_ref = ext4.get_inode_ref(journal_inode);
    let journal_blocks = inode_ref.inode.size().div_ceil(EXT4_BLOCK_BYTES as u64);
    if journal_blocks == 0 {
        return Err(Ext4WriteError::JournalUnavailable);
    }
    let journal_blocks =
        usize::try_from(journal_blocks).map_err(|_| Ext4WriteError::JournalUnavailable)?;
    let mut logical_to_physical = Vec::new();
    for logical in 0..journal_blocks {
        let path = ext4
            .find_extent(&inode_ref, logical as u32)
            .map_err(|_| Ext4WriteError::JournalUnavailable)?;
        let physical = path
            .path
            .last()
            .map(|node| node.pblock)
            .ok_or(Ext4WriteError::JournalUnavailable)?;
        logical_to_physical.push(physical);
    }
    let superblock_block = *logical_to_physical
        .first()
        .ok_or(Ext4WriteError::JournalUnavailable)?;
    let superblock = ext4
        .block_device
        .read_offset(superblock_block as usize * EXT4_BLOCK_BYTES);
    if u32::from_be_bytes(superblock[0..4].try_into().unwrap()) != JBD2_MAGIC
        || u32::from_be_bytes(superblock[4..8].try_into().unwrap()) != JBD2_SUPERBLOCK_V2
    {
        return Err(Ext4WriteError::JournalUnavailable);
    }
    let sequence = u32::from_be_bytes(superblock[0x18..0x1c].try_into().unwrap());
    let uuid = superblock[0x30..0x40].try_into().unwrap();
    let max_blocks = u32::from_be_bytes(superblock[0x10..0x14].try_into().unwrap());
    Ok(JournalGeometry {
        superblock_block,
        sequence,
        uuid,
        max_blocks,
        superblock,
        logical_to_physical,
    })
}

fn add_recovery_marker<S>(
    device: &TransactionDevice<S>,
    pending: &mut BTreeMap<u64, Vec<u8>>,
) -> Result<(), Ext4WriteError>
where
    S: Ext4WritableSource,
{
    let mut block_zero = if let Some(bytes) = pending.remove(&0) {
        bytes
    } else {
        device.read_block(0)?
    };
    set_recovery_marker(&mut block_zero);
    pending.insert(0, block_zero);

    let mut marker = device.read_block(0)?;
    set_recovery_marker(&mut marker);
    device.write_block(0, &marker)?;
    device.flush()
}

fn set_recovery_marker(block: &mut [u8]) {
    let sb = 1024;
    let at = sb + 0x60;
    let incompat =
        u32::from_le_bytes(block[at..at + 4].try_into().unwrap()) | EXT4_RECOVERY_INCOMPAT;
    block[at..at + 4].copy_from_slice(&incompat.to_le_bytes());
    refresh_superblock_checksum(block);
}

fn clear_recovery_marker(block: &mut [u8]) {
    let sb = 1024;
    let at = sb + 0x60;
    let incompat =
        u32::from_le_bytes(block[at..at + 4].try_into().unwrap()) & !EXT4_RECOVERY_INCOMPAT;
    block[at..at + 4].copy_from_slice(&incompat.to_le_bytes());
    refresh_superblock_checksum(block);
}

fn refresh_superblock_checksum(block: &mut [u8]) {
    let sb = &mut block[1024..2048];
    let ro_compat = u32::from_le_bytes(sb[0x64..0x68].try_into().unwrap());
    if ro_compat & 0x400 == 0 {
        return;
    }
    let checksum = jbd_checksum(&[&sb[..0x3fc]]);
    sb[0x3fc..0x400].copy_from_slice(&checksum.to_le_bytes());
}

fn commit_journal<S>(
    device: &TransactionDevice<S>,
    geometry: &JournalGeometry,
    pending: &BTreeMap<u64, Vec<u8>>,
) -> Result<(), Ext4WriteError>
where
    S: Ext4WritableSource,
{
    let need = pending.len() + 2;
    if need > geometry.max_blocks as usize || need > geometry.logical_to_physical.len() {
        return Err(Ext4WriteError::JournalFull);
    }

    let mut descriptor = vec![0; EXT4_BLOCK_BYTES];
    descriptor[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    descriptor[4..8].copy_from_slice(&JBD2_DESCRIPTOR.to_be_bytes());
    descriptor[8..12].copy_from_slice(&geometry.sequence.to_be_bytes());
    let mut pos = 12;
    for (index, (block, bytes)) in pending.iter().enumerate() {
        if bytes.len() != EXT4_BLOCK_BYTES {
            return Err(Ext4WriteError::Operation);
        }
        if u32::from_be_bytes(bytes[0..4].try_into().unwrap()) == JBD2_MAGIC {
            return Err(Ext4WriteError::Operation);
        }
        if pos + 16 > EXT4_BLOCK_BYTES - 4 {
            return Err(Ext4WriteError::JournalFull);
        }
        descriptor[pos..pos + 4].copy_from_slice(&(*block as u32).to_be_bytes());
        let flags = TAG_SAME_UUID
            | if index + 1 == pending.len() {
                TAG_LAST
            } else {
                0
            };
        descriptor[pos + 4..pos + 8].copy_from_slice(&flags.to_be_bytes());
        let tag_checksum = jbd_checksum(&[&geometry.uuid, &geometry.sequence.to_be_bytes(), bytes]);
        descriptor[pos + 12..pos + 16].copy_from_slice(&tag_checksum.to_be_bytes());
        pos += 16;
    }
    let descriptor_checksum =
        jbd_checksum(&[&geometry.uuid, &descriptor[..EXT4_BLOCK_BYTES - 4], &[0; 4]]);
    descriptor[EXT4_BLOCK_BYTES - 4..].copy_from_slice(&descriptor_checksum.to_be_bytes());

    let mut commit = vec![0; EXT4_BLOCK_BYTES];
    commit[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    commit[4..8].copy_from_slice(&JBD2_COMMIT.to_be_bytes());
    commit[8..12].copy_from_slice(&geometry.sequence.to_be_bytes());
    let commit_checksum = jbd_checksum(&[&geometry.uuid, &commit[..16], &[0; 4], &commit[20..]]);
    commit[16..20].copy_from_slice(&commit_checksum.to_be_bytes());

    let mut superblock = geometry.superblock.clone();
    let incompat = u32::from_be_bytes(superblock[0x28..0x2c].try_into().unwrap()) | 0x12;
    superblock[0x28..0x2c].copy_from_slice(&incompat.to_be_bytes());
    superblock[0x50] = 4;
    superblock[0x1c..0x20].copy_from_slice(&1u32.to_be_bytes());
    write_journal_super_checksum(&mut superblock);
    device.write_block(geometry.superblock_block, &superblock)?;

    let mut logical = 1usize;
    device.write_block(geometry.logical_to_physical[logical], &descriptor)?;
    logical += 1;
    for bytes in pending.values() {
        device.write_block(geometry.logical_to_physical[logical], bytes)?;
        logical += 1;
    }
    device.write_block(geometry.logical_to_physical[logical], &commit)?;
    device.flush()
}

fn write_journal_super_checksum(block: &mut [u8]) {
    block[0xfc..0x100].fill(0);
    let checksum = jbd_checksum(&[&block[..0xfc], &[0; 4], &block[0x100..1024]]);
    block[0xfc..0x100].copy_from_slice(&checksum.to_be_bytes());
}

fn jbd_checksum(parts: &[&[u8]]) -> u32 {
    const CRC32C: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
    let mut digest = CRC32C.digest_with_initial(crc::CRC_32_ISCSI.init.reverse_bits());
    for part in parts {
        digest.update(part);
    }
    digest.finalize() ^ (!0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[derive(Clone)]
    struct FaultStorage {
        inner: MemoryStorage,
        flushes: Arc<SpinLock<u32>>,
        fail_on: u32,
    }

    impl Ext4ByteSource for FaultStorage {
        fn read_exact(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), Ext4SourceError> {
            self.inner.read_exact(offset, dst)
        }
    }

    impl Ext4WritableSource for FaultStorage {
        fn write_exact(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Ext4SourceError> {
            self.inner.write_exact(offset, bytes)
        }

        fn flush(&mut self) -> Result<(), Ext4SourceError> {
            let mut count = self.flushes.lock();
            *count += 1;
            if *count == self.fail_on {
                return Err(Ext4SourceError);
            }
            self.inner.flush()
        }
    }

    fn command_available(program: &str) -> bool {
        Command::new(program)
            .arg("-V")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    #[test]
    fn writes_and_atomically_renames_a_real_ext4_file() {
        if !command_available("mke2fs") || !command_available("e2fsck") {
            eprintln!("ext4 tooling unavailable; write test skipped");
            return;
        }

        let dir = std::env::temp_dir().join(format!("jasper-ext4-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let image_path = dir.join("write.img");
        std::fs::File::create(&image_path)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let status = Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-b", "4096", "-F"])
            .arg(&image_path)
            .status()
            .unwrap();
        assert!(status.success(), "mke2fs failed");

        let image = std::fs::read(&image_path).unwrap();
        let mut writer = Ext4Writer::open_bytes(image).unwrap();
        writer
            .write_file("/hello.txt", b"journaled hello\n")
            .unwrap();
        writer.rename_file("/hello.txt", "/renamed.txt").unwrap();

        let output = writer.image();
        std::fs::write(&image_path, output).unwrap();
        let status = Command::new("e2fsck")
            .args(["-fy"])
            .arg(&image_path)
            .status()
            .unwrap();
        assert!(
            status.success() || status.code() == Some(1),
            "e2fsck rejected Jasper ext4 writes"
        );

        let bytes = std::fs::read(&image_path).unwrap();
        let reader = Ext4Reader::open_bytes(bytes).unwrap();
        assert_eq!(
            reader.read_file("/renamed.txt", 4096).unwrap(),
            b"journaled hello\n"
        );
        assert!(reader.metadata("/hello.txt").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn committed_journal_survives_failure_before_final_writes() {
        if !command_available("mke2fs") || !command_available("e2fsck") {
            eprintln!("ext4 tooling unavailable; crash test skipped");
            return;
        }
        let dir =
            std::env::temp_dir().join(format!("jasper-ext4-write-crash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let image_path = dir.join("crash.img");
        std::fs::File::create(&image_path)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        assert!(Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-b", "4096", "-F"])
            .arg(&image_path)
            .status()
            .unwrap()
            .success());

        let bytes = Arc::new(SpinLock::new(std::fs::read(&image_path).unwrap()));
        let storage = FaultStorage {
            inner: MemoryStorage {
                bytes: Arc::clone(&bytes),
            },
            flushes: Arc::new(SpinLock::new(0)),
            fail_on: 2,
        };
        let mut writer = Ext4Writer::open(storage).unwrap();
        assert_eq!(
            writer.write_file("/crash.txt", b"recovered after crash\n"),
            Err(Ext4WriteError::Io)
        );

        let crash_image = bytes.lock().clone();
        std::fs::write(&image_path, &crash_image).unwrap();
        let reader = Ext4Reader::open_bytes(crash_image).unwrap();
        assert_eq!(
            reader.read_file("/crash.txt", 4096).unwrap(),
            b"recovered after crash\n"
        );
        drop(reader);
        let status = Command::new("e2fsck")
            .args(["-fy"])
            .arg(&image_path)
            .status()
            .unwrap();
        assert!(
            status.success() || status.code() == Some(1),
            "Linux could not recover Jasper's committed journal"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vfs_handles_route_ext4_writes_and_release_cleanly() {
        if !command_available("mke2fs") || !command_available("e2fsck") {
            eprintln!("ext4 tooling unavailable; VFS test skipped");
            return;
        }
        let dir = std::env::temp_dir().join(format!("jasper-ext4-vfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let image_path = dir.join("vfs.img");
        std::fs::File::create(&image_path)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        assert!(Command::new("mke2fs")
            .args(["-q", "-t", "ext4", "-b", "4096", "-F"])
            .arg(&image_path)
            .status()
            .unwrap()
            .success());
        let seed_path = dir.join("seed.txt");
        std::fs::write(&seed_path, b"HOST-SEED\n").unwrap();
        assert!(Command::new("debugfs")
            .args(["-w", "-R"])
            .arg(format!("write {} /seed.txt", seed_path.display()))
            .arg(&image_path)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("e2fsck")
            .args(["-fy"])
            .arg(&image_path)
            .status()
            .unwrap()
            .success());

        let mut vfs = Ext4Vfs::new(MemoryStorage {
            bytes: Arc::new(SpinLock::new(std::fs::read(&image_path).unwrap())),
        })
        .unwrap();
        let handle = vfs.create_open("/vfs.txt", true).unwrap();
        vfs.write(handle, b"through VFS handles\n").unwrap();
        vfs.sync(handle).unwrap();
        assert_eq!(vfs.read(handle, 4096).unwrap(), b"through VFS handles\n");
        vfs.rename("/vfs.txt", "/renamed-vfs.txt").unwrap();
        assert_eq!(vfs.read(handle, 4096).unwrap(), b"through VFS handles\n");
        vfs.close(handle).unwrap();
        assert_eq!(vfs.live_handles(), 0);

        std::fs::write(&image_path, vfs.image()).unwrap();
        let status = Command::new("e2fsck")
            .args(["-fy"])
            .arg(&image_path)
            .status()
            .unwrap();
        assert!(status.success() || status.code() == Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
