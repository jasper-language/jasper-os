//! FS-0 filesystem contract, independent of ext4, JaFS or any block driver.
//!
//! This module models the observable semantics a concrete filesystem must
//! implement: versioned capabilities, persistent object identities, directory
//! mutations, open-handle lifetime, same-mount atomic rename, durability
//! scopes, and versioned memory mappings. It does not parse disk images or
//! claim crash recovery until a concrete journal/recovery engine supplies the
//! evidence required by FS-1.

use crate::block::{Request, Terminal};
use crate::object::{HandleError, HandleId, HandleTable, Rights};

pub const CONTRACT_MAJOR: u16 = 1;
pub const CONTRACT_MINOR: u16 = 0;
pub const CONTRACT_PATCH: u16 = 0;
pub const WIRE_HEADER_BYTES: usize = 16;
pub const MAX_NAME_BYTES: usize = 64;

pub const OP_OPEN: &str = "system.fs.open";
pub const OP_CREATE: &str = "system.fs.create";
pub const OP_RENAME: &str = "system.fs.rename";
pub const OP_UNLINK: &str = "system.fs.unlink";
pub const OP_SYNC: &str = "system.fs.sync";
pub const OP_MMAP: &str = "system.fs.mmap";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ContractVersion {
    pub const V1_0_0: Self = Self {
        major: CONTRACT_MAJOR,
        minor: CONTRACT_MINOR,
        patch: CONTRACT_PATCH,
    };
}

/// Every future FS-0 wire record starts with this bounded header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireHeader {
    pub version: ContractVersion,
    pub bytes: u32,
    pub reserved: u32,
}

impl WireHeader {
    pub const fn new(bytes: usize) -> Self {
        Self {
            version: ContractVersion::V1_0_0,
            bytes: bytes as u32,
            reserved: 0,
        }
    }

    pub fn encode(self) -> [u8; WIRE_HEADER_BYTES] {
        let mut out = [0u8; WIRE_HEADER_BYTES];
        out[0..2].copy_from_slice(&self.version.major.to_le_bytes());
        out[2..4].copy_from_slice(&self.version.minor.to_le_bytes());
        out[4..6].copy_from_slice(&self.version.patch.to_le_bytes());
        out[6..8].copy_from_slice(&0u16.to_le_bytes());
        out[8..12].copy_from_slice(&self.bytes.to_le_bytes());
        out[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    pub fn decode(bytes: [u8; WIRE_HEADER_BYTES]) -> Result<Self, FsError> {
        let version = ContractVersion {
            major: u16::from_le_bytes([bytes[0], bytes[1]]),
            minor: u16::from_le_bytes([bytes[2], bytes[3]]),
            patch: u16::from_le_bytes([bytes[4], bytes[5]]),
        };
        let zero = u16::from_le_bytes([bytes[6], bytes[7]]);
        let size = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let reserved = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if version.major != CONTRACT_MAJOR
            || zero != 0
            || size < WIRE_HEADER_BYTES as u32
            || reserved != 0
        {
            return Err(FsError::InvalidVersion);
        }
        Ok(Self {
            version,
            bytes: size,
            reserved,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsCapabilities(u32);

impl FsCapabilities {
    pub const OPEN: Self = Self(1 << 0);
    pub const CREATE: Self = Self(1 << 1);
    pub const WRITE: Self = Self(1 << 2);
    pub const TRUNCATE: Self = Self(1 << 3);
    pub const UNLINK: Self = Self(1 << 4);
    pub const ATOMIC_RENAME: Self = Self(1 << 5);
    pub const FSYNC: Self = Self(1 << 6);
    pub const FDATASYNC: Self = Self(1 << 7);
    pub const MMAP: Self = Self(1 << 8);
    pub const DIRECTORY: Self = Self(1 << 9);
    pub const ALL: Self = Self(0x3ff);
    pub const NONE: Self = Self(0);

    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    InvalidVersion,
    InvalidName,
    InvalidIdentity,
    RightsDenied,
    UnsupportedCapability,
    CrossVolume,
    CrossMount,
    NotFound,
    StaleIdentity,
    AlreadyExists,
    NotDirectory,
    NotFile,
    DirectoryNotEmpty,
    DirectoryCycle,
    RootImmutable,
    NoSpace,
    IdsExhausted,
    VersionExhausted,
    HandleInvalid,
    MappingRange,
    StaleMapping,
    SyncIncomplete,
    SyncOrder,
}

impl FsError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidVersion => "system.fs.error.invalid_version",
            Self::InvalidName => "system.fs.error.invalid_name",
            Self::InvalidIdentity => "system.fs.error.invalid_identity",
            Self::RightsDenied => "system.fs.error.rights_denied",
            Self::UnsupportedCapability => "system.fs.error.unsupported_capability",
            Self::CrossVolume => "system.fs.error.cross_volume",
            Self::CrossMount => "system.fs.error.cross_mount",
            Self::NotFound => "system.fs.error.not_found",
            Self::StaleIdentity => "system.fs.error.stale_identity",
            Self::AlreadyExists => "system.fs.error.already_exists",
            Self::NotDirectory => "system.fs.error.not_directory",
            Self::NotFile => "system.fs.error.not_file",
            Self::DirectoryNotEmpty => "system.fs.error.directory_not_empty",
            Self::DirectoryCycle => "system.fs.error.directory_cycle",
            Self::RootImmutable => "system.fs.error.root_immutable",
            Self::NoSpace => "system.fs.error.no_space",
            Self::IdsExhausted => "system.fs.error.ids_exhausted",
            Self::VersionExhausted => "system.fs.error.version_exhausted",
            Self::HandleInvalid => "system.handle.error.invalid",
            Self::MappingRange => "system.fs.error.mapping_range",
            Self::StaleMapping => "system.fs.error.stale_mapping",
            Self::SyncIncomplete => "system.fs.error.sync_incomplete",
            Self::SyncOrder => "system.fs.error.sync_order",
        }
    }
}

impl From<HandleError> for FsError {
    fn from(value: HandleError) -> Self {
        match value {
            HandleError::RightsDenied => Self::RightsDenied,
            HandleError::Invalid | HandleError::TableFull => Self::HandleInvalid,
        }
    }
}

fn next_version(value: u64) -> Result<u64, FsError> {
    value.checked_add(1).ok_or(FsError::VersionExhausted)
}

/// Persistent identity is a lookup key, never an authorization token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PersistentIdentity {
    pub namespace_id: u64,
    pub object_id: u64,
    pub generation: u32,
}

impl PersistentIdentity {
    pub const fn new(namespace_id: u64, object_id: u64, generation: u32) -> Self {
        Self {
            namespace_id,
            object_id,
            generation,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.namespace_id != 0 && self.object_id != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountIdentity {
    pub namespace_id: u64,
    pub volume_id: u64,
    pub mount_generation: u32,
}

impl MountIdentity {
    pub const fn new(namespace_id: u64, volume_id: u64, mount_generation: u32) -> Self {
        Self {
            namespace_id,
            volume_id,
            mount_generation,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.namespace_id != 0 && self.volume_id != 0 && self.mount_generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryName {
    bytes: [u8; MAX_NAME_BYTES],
    len: u8,
}

impl EntryName {
    pub fn new(name: &[u8]) -> Result<Self, FsError> {
        if name.is_empty()
            || name.len() > MAX_NAME_BYTES
            || name == b"."
            || name == b".."
            || name.iter().any(|byte| *byte == 0 || *byte == b'/')
        {
            return Err(FsError::InvalidName);
        }
        let mut bytes = [0u8; MAX_NAME_BYTES];
        bytes[..name.len()].copy_from_slice(name);
        Ok(Self {
            bytes,
            len: name.len() as u8,
        })
    }

    const fn root() -> Self {
        Self {
            bytes: [0; MAX_NAME_BYTES],
            len: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub identity: PersistentIdentity,
    pub parent: PersistentIdentity,
    pub name: EntryName,
    pub kind: NodeKind,
    pub size: u64,
    pub links: u32,
    pub open_count: u32,
    pub content_epoch: u32,
    pub data_version: u64,
    pub metadata_version: u64,
    pub durable_data_version: u64,
    pub durable_metadata_version: u64,
    pub deleted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Node {
    identity: PersistentIdentity,
    parent: PersistentIdentity,
    name: EntryName,
    kind: NodeKind,
    size: u64,
    links: u32,
    open_count: u32,
    content_epoch: u32,
    data_version: u64,
    metadata_version: u64,
    durable_data_version: u64,
    durable_metadata_version: u64,
    deleted: bool,
}

impl Node {
    fn info(self) -> NodeInfo {
        NodeInfo {
            identity: self.identity,
            parent: self.parent,
            name: self.name,
            kind: self.kind,
            size: self.size,
            links: self.links,
            open_count: self.open_count,
            content_epoch: self.content_epoch,
            data_version: self.data_version,
            metadata_version: self.metadata_version,
            durable_data_version: self.durable_data_version,
            durable_metadata_version: self.durable_metadata_version,
            deleted: self.deleted,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileHandle(HandleId);

impl FileHandle {
    pub const NULL: Self = Self(HandleId::NULL);

    #[allow(clippy::useless_conversion)] // HandleRaw is u32 on the 32-bit targets.
    pub fn raw(self) -> u64 {
        u64::from(self.0.raw())
    }
}

#[derive(Clone, Copy)]
struct OpenFile {
    identity: PersistentIdentity,
    mount: MountIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenameMode {
    NoReplace,
    ReplaceFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameAuthority {
    pub source_parent: Rights,
    pub target_parent: Rights,
    pub object: Rights,
    pub replaced: Rights,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameRequest {
    pub source_parent: PersistentIdentity,
    pub source_name: EntryName,
    pub target_mount: MountIdentity,
    pub target_parent: PersistentIdentity,
    pub target_name: EntryName,
    pub mode: RenameMode,
    pub authority: RenameAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameReceipt {
    pub identity: PersistentIdentity,
    pub source_parent: PersistentIdentity,
    pub target_parent: PersistentIdentity,
    pub replaced: Option<PersistentIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncScope {
    Data,
    DataAndMetadata,
    Flush,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncTicket {
    pub identity: PersistentIdentity,
    pub mount: MountIdentity,
    pub scope: SyncScope,
    pub data_target: u64,
    pub metadata_target: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncState {
    pub data_version: u64,
    pub metadata_version: u64,
    pub durable_data_version: u64,
    pub durable_metadata_version: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncPhase {
    AwaitingWrite,
    AwaitingFlush,
    Durable,
    Failed,
}

/// Evidence produced only after the BLK-1 write and its following flush both
/// reached `Completed`. A lone write completion is not durability evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurabilityEvidence {
    write_completed: bool,
    flush_completed: bool,
}

impl DurabilityEvidence {
    pub const fn is_durable(self) -> bool {
        self.write_completed && self.flush_completed
    }
}

/// Two-request durability chain matching the BLK-1 contract. virtio-blk has
/// no independent FUA request bit, so FS-0 issues a write and then a flush and
/// only advances durable versions after both terminals complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDurabilityChain {
    phase: SyncPhase,
}

impl BlockDurabilityChain {
    pub const fn new() -> Self {
        Self {
            phase: SyncPhase::AwaitingWrite,
        }
    }

    pub fn write_request(self, pages: u64) -> Result<Request, FsError> {
        if self.phase != SyncPhase::AwaitingWrite {
            return Err(FsError::SyncOrder);
        }
        let request = Request::write(0, pages, false);
        request
            .validate(
                crate::block::Features {
                    flush: true,
                    discard: false,
                    block_size: false,
                },
                pages
                    .checked_mul(crate::block::SECTORS_PER_IO_UNIT)
                    .ok_or(FsError::SyncIncomplete)?,
            )
            .map_err(|_| FsError::SyncIncomplete)?;
        Ok(request)
    }

    pub fn write_terminal(&mut self, terminal: Terminal) -> Result<(), FsError> {
        if self.phase != SyncPhase::AwaitingWrite {
            return Err(FsError::SyncOrder);
        }
        if terminal == Terminal::Completed {
            self.phase = SyncPhase::AwaitingFlush;
            Ok(())
        } else {
            self.phase = SyncPhase::Failed;
            Err(FsError::SyncIncomplete)
        }
    }

    pub fn flush_request(self) -> Result<Request, FsError> {
        if self.phase != SyncPhase::AwaitingFlush {
            return Err(FsError::SyncOrder);
        }
        Ok(Request::flush())
    }

    pub fn flush_terminal(&mut self, terminal: Terminal) -> Result<(), FsError> {
        if self.phase != SyncPhase::AwaitingFlush {
            return Err(FsError::SyncOrder);
        }
        if terminal == Terminal::Completed {
            self.phase = SyncPhase::Durable;
            Ok(())
        } else {
            self.phase = SyncPhase::Failed;
            Err(FsError::SyncIncomplete)
        }
    }

    pub fn evidence(self) -> Option<DurabilityEvidence> {
        (self.phase == SyncPhase::Durable).then_some(DurabilityEvidence {
            write_completed: true,
            flush_completed: true,
        })
    }

    pub const fn failed(self) -> bool {
        matches!(self.phase, SyncPhase::Failed)
    }
}

impl Default for BlockDurabilityChain {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub handle: FileHandle,
    pub identity: PersistentIdentity,
    pub mount: MountIdentity,
    pub offset: u64,
    pub length: u64,
    pub writable: bool,
    pub mapping_epoch: u32,
}

/// Bounded, deterministic FS-0 namespace used by host tests and contract
/// consumers. A concrete FS-1 backend must provide the same observable rules.
pub struct FsContract<const N: usize, const H: usize> {
    mount: MountIdentity,
    capabilities: FsCapabilities,
    nodes: [Option<Node>; N],
    handles: HandleTable<OpenFile, H>,
    next_object_id: u64,
}

impl<const N: usize, const H: usize> FsContract<N, H> {
    pub fn format(
        mount: MountIdentity,
        capabilities: FsCapabilities,
        required: FsCapabilities,
    ) -> Result<Self, FsError> {
        if N == 0 || !mount.is_valid() {
            return Err(if !mount.is_valid() {
                FsError::InvalidIdentity
            } else {
                FsError::NoSpace
            });
        }
        if !capabilities.contains(required) {
            return Err(FsError::UnsupportedCapability);
        }
        let root_identity = PersistentIdentity::new(mount.namespace_id, 1, 0);
        let root = Node {
            identity: root_identity,
            parent: root_identity,
            name: EntryName::root(),
            kind: NodeKind::Directory,
            size: 0,
            links: 1,
            open_count: 0,
            content_epoch: 0,
            data_version: 0,
            metadata_version: 0,
            durable_data_version: 0,
            durable_metadata_version: 0,
            deleted: false,
        };
        let mut nodes = [const { None }; N];
        nodes[0] = Some(root);
        Ok(Self {
            mount,
            capabilities,
            nodes,
            handles: HandleTable::new(),
            next_object_id: 2,
        })
    }

    pub const fn mount(&self) -> MountIdentity {
        self.mount
    }

    pub const fn capabilities(&self) -> FsCapabilities {
        self.capabilities
    }

    pub fn root(&self) -> PersistentIdentity {
        self.nodes[0]
            .expect("a formatted FS-0 always has a root")
            .identity
    }

    pub fn lookup(
        &self,
        parent: PersistentIdentity,
        name: EntryName,
        parent_rights: Rights,
    ) -> Result<PersistentIdentity, FsError> {
        self.lookup_index(parent, name, parent_rights)
            .map(|index| self.nodes[index].expect("index points to a node").identity)
    }

    pub fn create(
        &mut self,
        parent: PersistentIdentity,
        name: EntryName,
        kind: NodeKind,
        parent_rights: Rights,
    ) -> Result<PersistentIdentity, FsError> {
        self.require_capability(FsCapabilities::CREATE)?;
        if kind == NodeKind::Directory {
            self.require_capability(FsCapabilities::DIRECTORY)?;
        }
        if !parent_rights.contains(Rights::READ.union(Rights::WRITE)) {
            return Err(FsError::RightsDenied);
        }
        let parent_index = self.find_live_identity(parent)?;
        let parent_node = self.nodes[parent_index].expect("index points to a node");
        if parent_node.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        if self.find_child(parent, name).is_some() {
            return Err(FsError::AlreadyExists);
        }
        let free = self
            .nodes
            .iter()
            .position(Option::is_none)
            .ok_or(FsError::NoSpace)?;
        if self.next_object_id == u64::MAX {
            return Err(FsError::IdsExhausted);
        }
        let next_parent_metadata = next_version(parent_node.metadata_version)?;
        let identity = PersistentIdentity::new(self.mount.namespace_id, self.next_object_id, 0);
        let node = Node {
            identity,
            parent,
            name,
            kind,
            size: 0,
            links: 1,
            open_count: 0,
            content_epoch: 0,
            data_version: 0,
            metadata_version: 1,
            durable_data_version: 0,
            durable_metadata_version: 0,
            deleted: false,
        };
        self.nodes[free] = Some(node);
        self.next_object_id += 1;
        let parent_mut = self.nodes[parent_index]
            .as_mut()
            .expect("validated parent remains present");
        parent_mut.metadata_version = next_parent_metadata;
        Ok(identity)
    }

    pub fn open(
        &mut self,
        identity: PersistentIdentity,
        access: Rights,
    ) -> Result<FileHandle, FsError> {
        self.require_capability(FsCapabilities::OPEN)?;
        if access.is_empty()
            || !access
                .difference(
                    Rights::READ
                        .union(Rights::WRITE)
                        .union(Rights::CONTROL)
                        .union(Rights::MAP),
                )
                .is_empty()
        {
            return Err(FsError::RightsDenied);
        }
        let index = self.find_live_identity(identity)?;
        let node = self.nodes[index].expect("index points to a node");
        if node.kind != NodeKind::File {
            return Err(FsError::NotFile);
        }
        let next_open_count = node.open_count.checked_add(1).ok_or(FsError::NoSpace)?;
        let open = OpenFile {
            identity,
            mount: self.mount,
        };
        let handle = self
            .handles
            .put(open, access)
            .map_err(|_| FsError::HandleInvalid)?;
        let node = self.nodes[index]
            .as_mut()
            .expect("validated file remains present");
        node.open_count = next_open_count;
        Ok(FileHandle(handle))
    }

    pub fn close(&mut self, handle: FileHandle) -> Result<(), FsError> {
        let open = *self.handles.get(handle.0)?.0;
        let index = self.find_identity_any(open.identity)?;
        let next_open_count = self.nodes[index]
            .expect("validated node remains present")
            .open_count
            .checked_sub(1)
            .ok_or(FsError::HandleInvalid)?;
        self.handles.remove(handle.0)?;
        let remove = {
            let node = self.nodes[index]
                .as_mut()
                .expect("validated node remains present");
            node.open_count = next_open_count;
            node.deleted && node.open_count == 0
        };
        if remove {
            self.nodes[index] = None;
        }
        Ok(())
    }

    pub fn info(&self, identity: PersistentIdentity) -> Result<NodeInfo, FsError> {
        let index = self.find_identity_any(identity)?;
        Ok(self.nodes[index].expect("index points to a node").info())
    }

    pub fn write(&mut self, handle: FileHandle, bytes: u64) -> Result<u64, FsError> {
        self.require_capability(FsCapabilities::WRITE)?;
        let index = self.handle_index(handle, Rights::WRITE)?;
        let node = self.nodes[index]
            .as_mut()
            .expect("validated handle points to a node");
        if node.kind != NodeKind::File {
            return Err(FsError::NotFile);
        }
        let size = node.size.checked_add(bytes).ok_or(FsError::MappingRange)?;
        let data_version = next_version(node.data_version)?;
        let metadata_version = next_version(node.metadata_version)?;
        node.size = size;
        node.data_version = data_version;
        node.metadata_version = metadata_version;
        Ok(size)
    }

    pub fn truncate(&mut self, handle: FileHandle, size: u64) -> Result<(), FsError> {
        self.require_capability(FsCapabilities::TRUNCATE)?;
        let index = self.handle_index(handle, Rights::WRITE)?;
        let node = self.nodes[index]
            .as_mut()
            .expect("validated handle points to a node");
        if node.kind != NodeKind::File {
            return Err(FsError::NotFile);
        }
        let data_version = next_version(node.data_version)?;
        let metadata_version = next_version(node.metadata_version)?;
        let content_epoch = node
            .content_epoch
            .checked_add(1)
            .ok_or(FsError::VersionExhausted)?;
        node.size = size;
        node.data_version = data_version;
        node.metadata_version = metadata_version;
        node.content_epoch = content_epoch;
        Ok(())
    }

    pub fn unlink(
        &mut self,
        parent: PersistentIdentity,
        name: EntryName,
        parent_rights: Rights,
        object_rights: Rights,
    ) -> Result<PersistentIdentity, FsError> {
        self.require_capability(FsCapabilities::UNLINK)?;
        if !parent_rights.contains(Rights::READ.union(Rights::WRITE))
            || !object_rights.contains(Rights::CONTROL)
        {
            return Err(FsError::RightsDenied);
        }
        let index = self.lookup_index(parent, name, parent_rights)?;
        let parent_index = self.find_live_identity(parent)?;
        let node = self.nodes[index].expect("index points to a node");
        if node.parent == node.identity {
            return Err(FsError::RootImmutable);
        }
        if node.kind == NodeKind::Directory && self.has_children(node.identity) {
            return Err(FsError::DirectoryNotEmpty);
        }
        let next_node_metadata = next_version(node.metadata_version)?;
        let next_parent_metadata = next_version(
            self.nodes[parent_index]
                .expect("validated parent remains present")
                .metadata_version,
        )?;
        let remove = {
            let node = self.nodes[index]
                .as_mut()
                .expect("validated node remains present");
            node.deleted = true;
            node.links = 0;
            node.metadata_version = next_node_metadata;
            node.open_count == 0
        };
        self.nodes[parent_index]
            .as_mut()
            .expect("validated parent remains present")
            .metadata_version = next_parent_metadata;
        let identity = self.nodes[index]
            .expect("validated node remains present")
            .identity;
        if remove {
            self.nodes[index] = None;
        }
        Ok(identity)
    }

    pub fn rename(&mut self, request: RenameRequest) -> Result<RenameReceipt, FsError> {
        let RenameRequest {
            source_parent,
            source_name,
            target_mount,
            target_parent,
            target_name,
            mode,
            authority,
        } = request;
        self.require_capability(FsCapabilities::ATOMIC_RENAME)?;
        if target_mount.volume_id != self.mount.volume_id {
            return Err(FsError::CrossVolume);
        }
        if target_mount != self.mount {
            return Err(FsError::CrossMount);
        }
        if !authority
            .source_parent
            .contains(Rights::READ.union(Rights::WRITE))
            || !authority
                .target_parent
                .contains(Rights::READ.union(Rights::WRITE))
            || !authority.object.contains(Rights::CONTROL)
        {
            return Err(FsError::RightsDenied);
        }
        let source_parent_index = self.find_live_identity(source_parent)?;
        let source_index =
            self.lookup_index(source_parent, source_name, authority.source_parent)?;
        let target_parent_index = self.find_live_identity(target_parent)?;
        if self.nodes[target_parent_index]
            .expect("index points to a node")
            .kind
            != NodeKind::Directory
        {
            return Err(FsError::NotDirectory);
        }
        let target_index = self.find_child(target_parent, target_name);
        let source = self.nodes[source_index].expect("index points to a node");
        if source.parent == source.identity {
            return Err(FsError::RootImmutable);
        }
        if source.kind == NodeKind::Directory
            && self.is_descendant_or_self(target_parent, source.identity)?
        {
            return Err(FsError::DirectoryCycle);
        }
        let replaced_identity = if let Some(index) = target_index {
            let target = self.nodes[index].expect("index points to a node");
            if target.identity == source.identity {
                return Ok(RenameReceipt {
                    identity: source.identity,
                    source_parent,
                    target_parent,
                    replaced: None,
                });
            }
            if mode == RenameMode::NoReplace {
                return Err(FsError::AlreadyExists);
            }
            if source.kind != NodeKind::File || target.kind != NodeKind::File {
                return Err(FsError::NotFile);
            }
            if !authority.replaced.contains(Rights::CONTROL) {
                return Err(FsError::RightsDenied);
            }
            Some((index, target.identity))
        } else {
            None
        };

        // All validation is complete. The following changes are committed as
        // one namespace transaction and cannot partially fail.
        let next_source_metadata = next_version(source.metadata_version)?;
        let source_parent_node =
            self.nodes[source_parent_index].expect("validated source parent remains present");
        let next_source_parent_metadata = next_version(source_parent_node.metadata_version)?;
        let next_target_parent_metadata = if source_parent_index != target_parent_index {
            next_version(
                self.nodes[target_parent_index]
                    .expect("validated target parent remains present")
                    .metadata_version,
            )?
        } else {
            next_source_parent_metadata
        };
        let next_replaced_metadata = if let Some((index, _)) = replaced_identity {
            Some(next_version(
                self.nodes[index]
                    .expect("validated target remains present")
                    .metadata_version,
            )?)
        } else {
            None
        };
        {
            let node = self.nodes[source_index]
                .as_mut()
                .expect("validated source remains present");
            node.parent = target_parent;
            node.name = target_name;
            node.metadata_version = next_source_metadata;
        }
        self.nodes[source_parent_index]
            .as_mut()
            .expect("validated source parent remains present")
            .metadata_version = next_source_parent_metadata;
        self.nodes[target_parent_index]
            .as_mut()
            .expect("validated target parent remains present")
            .metadata_version = next_target_parent_metadata;
        if let (Some((index, _)), Some(metadata_version)) =
            (replaced_identity, next_replaced_metadata)
        {
            let remove = {
                let node = self.nodes[index]
                    .as_mut()
                    .expect("validated target remains present");
                node.deleted = true;
                node.links = 0;
                node.metadata_version = metadata_version;
                node.open_count == 0
            };
            if remove {
                self.nodes[index] = None;
            }
        }
        Ok(RenameReceipt {
            identity: source.identity,
            source_parent,
            target_parent,
            replaced: replaced_identity.map(|(_, identity)| identity),
        })
    }

    pub fn begin_sync(&self, handle: FileHandle, scope: SyncScope) -> Result<SyncTicket, FsError> {
        let required = match scope {
            SyncScope::Data => FsCapabilities::FDATASYNC,
            SyncScope::DataAndMetadata | SyncScope::Flush => FsCapabilities::FSYNC,
        };
        self.require_capability(required)?;
        let index = self.handle_index(handle, Rights::WRITE)?;
        let node = self.nodes[index].expect("validated handle points to a node");
        let (data_target, metadata_target) = match scope {
            SyncScope::Data => (node.data_version, 0),
            SyncScope::DataAndMetadata | SyncScope::Flush => {
                (node.data_version, node.metadata_version)
            }
        };
        Ok(SyncTicket {
            identity: node.identity,
            mount: self.mount,
            scope,
            data_target,
            metadata_target,
        })
    }

    pub fn complete_sync(
        &mut self,
        handle: FileHandle,
        ticket: SyncTicket,
        acknowledged: bool,
    ) -> Result<SyncState, FsError> {
        if !acknowledged {
            let index = self.handle_index(handle, Rights::NONE)?;
            let node = self.nodes[index].expect("validated handle points to a node");
            return Ok(self.sync_state_from_node(node));
        }
        if ticket.mount != self.mount {
            return Err(FsError::CrossMount);
        }
        let index = self.handle_index(handle, Rights::NONE)?;
        {
            let node = self.nodes[index]
                .as_mut()
                .expect("validated handle points to a node");
            if node.identity != ticket.identity {
                return Err(FsError::StaleIdentity);
            }
            node.durable_data_version = node
                .durable_data_version
                .max(ticket.data_target.min(node.data_version));
            node.durable_metadata_version = node
                .durable_metadata_version
                .max(ticket.metadata_target.min(node.metadata_version));
        }
        let state = self
            .sync_state_from_node(self.nodes[index].expect("validated handle points to a node"));
        Ok(state)
    }

    pub fn complete_sync_durable(
        &mut self,
        handle: FileHandle,
        ticket: SyncTicket,
        evidence: DurabilityEvidence,
    ) -> Result<SyncState, FsError> {
        if !evidence.is_durable() {
            return Err(FsError::SyncIncomplete);
        }
        self.complete_sync(handle, ticket, true)
    }

    pub fn sync_state(&self, identity: PersistentIdentity) -> Result<SyncState, FsError> {
        let index = self.find_identity_any(identity)?;
        Ok(self.sync_state_from_node(self.nodes[index].expect("index points to a node")))
    }

    pub fn map(
        &self,
        handle: FileHandle,
        offset: u64,
        length: u64,
        writable: bool,
    ) -> Result<Mapping, FsError> {
        self.require_capability(FsCapabilities::MMAP)?;
        let required = Rights::READ.union(Rights::MAP).union(if writable {
            Rights::WRITE
        } else {
            Rights::NONE
        });
        let index = self.handle_index(handle, required)?;
        let node = self.nodes[index].expect("validated handle points to a node");
        if !offset.is_multiple_of(crate::memory_object::PAGE_BYTES) || length == 0 {
            return Err(FsError::MappingRange);
        }
        if offset
            .checked_add(length)
            .filter(|end| *end <= node.size)
            .is_none()
        {
            return Err(FsError::MappingRange);
        }
        Ok(Mapping {
            handle,
            identity: node.identity,
            mount: self.mount,
            offset,
            length,
            writable,
            mapping_epoch: node.content_epoch,
        })
    }

    pub fn mapping_write(
        &mut self,
        mapping: Mapping,
        offset: u64,
        length: u64,
    ) -> Result<u64, FsError> {
        if !mapping.writable {
            return Err(FsError::RightsDenied);
        }
        if length == 0 {
            return Err(FsError::MappingRange);
        }
        let index = self.handle_index(
            mapping.handle,
            Rights::READ.union(Rights::WRITE).union(Rights::MAP),
        )?;
        let node = self.nodes[index]
            .as_mut()
            .expect("validated handle points to a node");
        if mapping.identity != node.identity || mapping.mount != self.mount {
            return Err(FsError::StaleMapping);
        }
        if mapping.mapping_epoch != node.content_epoch {
            return Err(FsError::StaleMapping);
        }
        if offset
            .checked_add(length)
            .filter(|end| *end <= mapping.length)
            .is_none()
        {
            return Err(FsError::MappingRange);
        }
        let data_version = next_version(node.data_version)?;
        node.data_version = data_version;
        Ok(node.data_version)
    }

    pub fn mapping_valid(&self, mapping: Mapping) -> bool {
        self.handle_index(mapping.handle, Rights::READ.union(Rights::MAP))
            .ok()
            .and_then(|index| self.nodes[index])
            .is_some_and(|node| {
                mapping.identity == node.identity
                    && mapping.mount == self.mount
                    && mapping.mapping_epoch == node.content_epoch
            })
    }

    pub fn live_handles(&self) -> usize {
        self.handles.live_handles()
    }

    pub fn live_nodes(&self) -> usize {
        self.nodes.iter().filter(|node| node.is_some()).count()
    }

    fn sync_state_from_node(&self, node: Node) -> SyncState {
        SyncState {
            data_version: node.data_version,
            metadata_version: node.metadata_version,
            durable_data_version: node.durable_data_version,
            durable_metadata_version: node.durable_metadata_version,
        }
    }

    fn require_capability(&self, capability: FsCapabilities) -> Result<(), FsError> {
        if self.capabilities.contains(capability) {
            Ok(())
        } else {
            Err(FsError::UnsupportedCapability)
        }
    }

    fn is_descendant_or_self(
        &self,
        candidate: PersistentIdentity,
        ancestor: PersistentIdentity,
    ) -> Result<bool, FsError> {
        let mut cursor = candidate;
        loop {
            if cursor == ancestor {
                return Ok(true);
            }
            let node = self.nodes[self.find_identity_any(cursor)?]
                .expect("validated node remains present");
            if node.parent == node.identity {
                return Ok(false);
            }
            cursor = node.parent;
        }
    }

    fn handle_index(&self, handle: FileHandle, required: Rights) -> Result<usize, FsError> {
        let open = self.handles.get_checked(handle.0, required)?;
        if open.mount != self.mount {
            return Err(FsError::CrossMount);
        }
        self.find_identity_any(open.identity)
    }

    fn lookup_index(
        &self,
        parent: PersistentIdentity,
        name: EntryName,
        parent_rights: Rights,
    ) -> Result<usize, FsError> {
        if !parent_rights.contains(Rights::READ) {
            return Err(FsError::RightsDenied);
        }
        let parent_index = self.find_live_identity(parent)?;
        if self.nodes[parent_index]
            .expect("index points to a node")
            .kind
            != NodeKind::Directory
        {
            return Err(FsError::NotDirectory);
        }
        self.find_child(parent, name).ok_or(FsError::NotFound)
    }

    fn find_child(&self, parent: PersistentIdentity, name: EntryName) -> Option<usize> {
        self.nodes.iter().position(|candidate| {
            candidate
                .is_some_and(|node| !node.deleted && node.parent == parent && node.name == name)
        })
    }

    fn find_live_identity(&self, identity: PersistentIdentity) -> Result<usize, FsError> {
        let index = self.find_identity_any(identity)?;
        if self.nodes[index].expect("index points to a node").deleted {
            return Err(FsError::StaleIdentity);
        }
        Ok(index)
    }

    fn find_identity_any(&self, identity: PersistentIdentity) -> Result<usize, FsError> {
        if !identity.is_valid() || identity.namespace_id != self.mount.namespace_id {
            return Err(FsError::InvalidIdentity);
        }
        self.nodes
            .iter()
            .position(|candidate| candidate.is_some_and(|node| node.identity == identity))
            .ok_or(FsError::StaleIdentity)
    }

    fn has_children(&self, parent: PersistentIdentity) -> bool {
        self.nodes.iter().any(|candidate| {
            candidate.is_some_and(|node| {
                !node.deleted && node.parent == parent && node.identity != parent
            })
        })
    }
}

/// Bounded, two-slot metadata journal for the FS-0 contract.
///
/// A checkpoint frame is written to the inactive slot and flushed before its
/// commit frame is written. Only a matching, flushed commit frame makes the
/// new checkpoint recoverable. A crash at any earlier point leaves the prior
/// committed checkpoint intact. The journal is a metadata format model, not a
/// concrete ext4/JaFS disk layout.
pub mod journal {
    use super::*;

    pub const CHECKPOINT_MAGIC: [u8; 8] = *b"FS0META1";
    pub const JOURNAL_MAGIC: [u8; 8] = *b"FS0JNL1\0";
    pub const CHECKPOINT_HEADER_BYTES: usize = 64;
    pub const NODE_RECORD_BYTES: usize = 160;
    pub const RECORD_HEADER_BYTES: usize = 48;
    pub const MAX_JOURNAL_NODES: usize = 4096;
    pub const STORAGE_UNIT_BYTES: usize = 4096;
    pub const SECTORS_PER_STORAGE_UNIT: u64 =
        STORAGE_UNIT_BYTES as u64 / crate::block::SECTOR_BYTES;

    const KIND_CHECKPOINT: u8 = 1;
    const KIND_COMMIT: u8 = 2;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum JournalError {
        Storage,
        ShortBuffer,
        InvalidRecord,
        Checksum,
        NoCommittedCheckpoint,
        SequenceExhausted,
        CheckpointTooLarge,
        InvalidCheckpoint,
        MountMismatch,
        CapabilityMismatch,
    }

    impl JournalError {
        pub const fn name(self) -> &'static str {
            match self {
                Self::Storage => "system.fs.error.journal_storage",
                Self::ShortBuffer => "system.fs.error.journal_short_buffer",
                Self::InvalidRecord => "system.fs.error.journal_invalid_record",
                Self::Checksum => "system.fs.error.journal_checksum",
                Self::NoCommittedCheckpoint => "system.fs.error.journal_no_checkpoint",
                Self::SequenceExhausted => "system.fs.error.journal_sequence_exhausted",
                Self::CheckpointTooLarge => "system.fs.error.journal_checkpoint_too_large",
                Self::InvalidCheckpoint => "system.fs.error.journal_invalid_checkpoint",
                Self::MountMismatch => "system.fs.error.journal_mount_mismatch",
                Self::CapabilityMismatch => "system.fs.error.journal_capability_mismatch",
            }
        }
    }

    pub trait JournalStorage {
        fn capacity(&self) -> usize;
        fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), JournalError>;
        fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), JournalError>;
        fn flush(&mut self) -> Result<(), JournalError>;
    }

    /// One 4 KiB aligned backend operation. Implementations must return only
    /// after the block request has reached a `Completed` terminal.
    pub trait SectorIo {
        fn capacity_sectors(&self) -> u64;
        fn read_unit(
            &mut self,
            sector: u64,
            out: &mut [u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError>;
        fn write_unit(
            &mut self,
            sector: u64,
            bytes: &[u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError>;
        fn flush(&mut self) -> Result<(), JournalError>;
    }

    /// Byte-addressable view over an aligned sector device.
    ///
    /// Partial writes are read-modify-write operations. Each unit write must
    /// complete before the call returns, but durability is established only by
    /// an explicit `flush`, matching the BLK-1 write-completed + flush-completed
    /// chain consumed by FS-0.
    pub struct BlockJournalStorage<D: SectorIo> {
        device: D,
        base_sector: u64,
        capacity_bytes: usize,
    }

    impl<D: SectorIo> BlockJournalStorage<D> {
        pub fn new(
            device: D,
            base_sector: u64,
            capacity_bytes: usize,
        ) -> Result<Self, JournalError> {
            if capacity_bytes == 0
                || capacity_bytes % STORAGE_UNIT_BYTES != 0
                || base_sector % SECTORS_PER_STORAGE_UNIT != 0
            {
                return Err(JournalError::Storage);
            }
            let units = (capacity_bytes / STORAGE_UNIT_BYTES) as u64;
            let sectors = units
                .checked_mul(SECTORS_PER_STORAGE_UNIT)
                .ok_or(JournalError::Storage)?;
            let end = base_sector
                .checked_add(sectors)
                .ok_or(JournalError::Storage)?;
            if end > device.capacity_sectors() {
                return Err(JournalError::Storage);
            }
            Ok(Self {
                device,
                base_sector,
                capacity_bytes,
            })
        }

        fn sector_for(&self, unit: usize) -> Result<u64, JournalError> {
            let unit_sectors = (unit as u64)
                .checked_mul(SECTORS_PER_STORAGE_UNIT)
                .ok_or(JournalError::Storage)?;
            self.base_sector
                .checked_add(unit_sectors)
                .ok_or(JournalError::Storage)
        }

        fn end(offset: usize, len: usize, capacity: usize) -> Result<usize, JournalError> {
            let end = offset.checked_add(len).ok_or(JournalError::Storage)?;
            if end > capacity {
                return Err(JournalError::Storage);
            }
            Ok(end)
        }
    }

    impl<D: SectorIo> JournalStorage for BlockJournalStorage<D> {
        fn capacity(&self) -> usize {
            self.capacity_bytes
        }

        fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), JournalError> {
            Self::end(offset, out.len(), self.capacity_bytes)?;
            let mut done = 0usize;
            while done < out.len() {
                let absolute = offset + done;
                let unit = absolute / STORAGE_UNIT_BYTES;
                let within = absolute % STORAGE_UNIT_BYTES;
                let take = (STORAGE_UNIT_BYTES - within).min(out.len() - done);
                let mut bytes = [0u8; STORAGE_UNIT_BYTES];
                self.device.read_unit(self.sector_for(unit)?, &mut bytes)?;
                out[done..done + take].copy_from_slice(&bytes[within..within + take]);
                done += take;
            }
            Ok(())
        }

        fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), JournalError> {
            Self::end(offset, bytes.len(), self.capacity_bytes)?;
            let mut done = 0usize;
            while done < bytes.len() {
                let absolute = offset + done;
                let unit = absolute / STORAGE_UNIT_BYTES;
                let within = absolute % STORAGE_UNIT_BYTES;
                let take = (STORAGE_UNIT_BYTES - within).min(bytes.len() - done);
                let sector = self.sector_for(unit)?;
                let mut unit_bytes = [0u8; STORAGE_UNIT_BYTES];
                self.device.read_unit(sector, &mut unit_bytes)?;
                unit_bytes[within..within + take].copy_from_slice(&bytes[done..done + take]);
                self.device.write_unit(sector, &unit_bytes)?;
                done += take;
            }
            Ok(())
        }

        fn flush(&mut self) -> Result<(), JournalError> {
            self.device.flush()
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RecordHeader {
        pub version: ContractVersion,
        pub kind: u8,
        pub body_len: u32,
        pub sequence: u64,
        pub payload_hash: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct JournalHead {
        pub slot: usize,
        pub sequence: u64,
        pub checkpoint_bytes: usize,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CommitReceipt {
        pub slot: usize,
        pub sequence: u64,
        pub checkpoint_bytes: usize,
    }

    pub struct ReplayReceipt<const N: usize, const H: usize> {
        pub sequence: u64,
        pub slot: usize,
        pub ignored_slot: usize,
        pub checkpoint_bytes: usize,
        pub state: FsContract<N, H>,
    }

    fn put_u16(out: &mut [u8], at: usize, value: u16) {
        out[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(out: &mut [u8], at: usize, value: u32) {
        out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(out: &mut [u8], at: usize, value: u64) {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u16(input: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([input[at], input[at + 1]])
    }

    fn get_u32(input: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(input[at..at + 4].try_into().expect("fixed-width field"))
    }

    fn get_u64(input: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(input[at..at + 8].try_into().expect("fixed-width field"))
    }

    const fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        let mut index = 0;
        while index < bytes.len() {
            hash ^= bytes[index] as u64;
            hash = hash.wrapping_mul(0x100000001b3);
            index += 1;
        }
        hash
    }

    pub fn checkpoint_bytes<const N: usize, const H: usize>(
        fs: &FsContract<N, H>,
    ) -> Result<usize, JournalError> {
        let count = fs.nodes.iter().filter(|node| node.is_some()).count();
        if count == 0 || count > MAX_JOURNAL_NODES {
            return Err(JournalError::InvalidCheckpoint);
        }
        CHECKPOINT_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(NODE_RECORD_BYTES)
                    .ok_or(JournalError::CheckpointTooLarge)?,
            )
            .ok_or(JournalError::CheckpointTooLarge)
    }

    pub fn encode_checkpoint<const N: usize, const H: usize>(
        fs: &FsContract<N, H>,
        out: &mut [u8],
    ) -> Result<usize, JournalError> {
        let total = checkpoint_bytes(fs)?;
        if out.len() < total {
            return Err(JournalError::ShortBuffer);
        }
        out[..total].fill(0);
        let count = fs.nodes.iter().filter(|node| node.is_some()).count();
        out[0..8].copy_from_slice(&CHECKPOINT_MAGIC);
        put_u16(out, 8, CONTRACT_MAJOR);
        put_u16(out, 10, CONTRACT_MINOR);
        put_u16(out, 12, CONTRACT_PATCH);
        put_u64(out, 16, fs.mount.namespace_id);
        put_u64(out, 24, fs.mount.volume_id);
        put_u32(out, 32, fs.mount.mount_generation);
        put_u32(out, 36, fs.capabilities.bits());
        put_u64(out, 40, fs.next_object_id);
        put_u32(out, 48, count as u32);
        for (ordinal, node) in fs.nodes.iter().flatten().enumerate() {
            let at = CHECKPOINT_HEADER_BYTES + ordinal * NODE_RECORD_BYTES;
            put_u64(out, at, node.identity.namespace_id);
            put_u64(out, at + 8, node.identity.object_id);
            put_u32(out, at + 16, node.identity.generation);
            put_u64(out, at + 20, node.parent.namespace_id);
            put_u64(out, at + 28, node.parent.object_id);
            put_u32(out, at + 36, node.parent.generation);
            out[at + 40] = match node.kind {
                NodeKind::File => 0,
                NodeKind::Directory => 1,
            };
            out[at + 41] = node.name.len;
            out[at + 44..at + 44 + MAX_NAME_BYTES].copy_from_slice(&node.name.bytes);
            put_u64(out, at + 108, node.size);
            put_u32(out, at + 116, node.links);
            put_u32(out, at + 120, node.content_epoch);
            put_u64(out, at + 124, node.data_version);
            put_u64(out, at + 132, node.metadata_version);
            put_u64(out, at + 140, node.durable_data_version);
            put_u64(out, at + 148, node.durable_metadata_version);
        }
        Ok(total)
    }

    pub fn restore_checkpoint<const N: usize, const H: usize>(
        bytes: &[u8],
        expected_mount: MountIdentity,
        required: FsCapabilities,
    ) -> Result<FsContract<N, H>, JournalError> {
        if N == 0 || bytes.len() < CHECKPOINT_HEADER_BYTES {
            return Err(JournalError::ShortBuffer);
        }
        if bytes[0..8] != CHECKPOINT_MAGIC
            || get_u16(bytes, 8) != CONTRACT_MAJOR
            || get_u16(bytes, 10) != CONTRACT_MINOR
            || get_u16(bytes, 12) != CONTRACT_PATCH
            || get_u16(bytes, 14) != 0
            || get_u32(bytes, 52) != 0
            || get_u32(bytes, 56) != 0
            || get_u32(bytes, 60) != 0
        {
            return Err(JournalError::InvalidCheckpoint);
        }
        let mount = MountIdentity::new(get_u64(bytes, 16), get_u64(bytes, 24), get_u32(bytes, 32));
        if mount != expected_mount {
            return Err(JournalError::MountMismatch);
        }
        let capabilities =
            FsCapabilities::from_bits(get_u32(bytes, 36)).ok_or(JournalError::InvalidCheckpoint)?;
        if !capabilities.contains(required) {
            return Err(JournalError::CapabilityMismatch);
        }
        let next_object_id = get_u64(bytes, 40);
        let count = get_u32(bytes, 48) as usize;
        if count == 0 || count > N || count > MAX_JOURNAL_NODES {
            return Err(JournalError::InvalidCheckpoint);
        }
        let required_len = CHECKPOINT_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(NODE_RECORD_BYTES)
                    .ok_or(JournalError::InvalidCheckpoint)?,
            )
            .ok_or(JournalError::InvalidCheckpoint)?;
        if bytes.len() < required_len {
            return Err(JournalError::ShortBuffer);
        }
        let mut nodes = [const { None }; N];
        let mut max_object_id = 0u64;
        for (ordinal, slot) in nodes.iter_mut().take(count).enumerate() {
            let at = CHECKPOINT_HEADER_BYTES + ordinal * NODE_RECORD_BYTES;
            let identity = PersistentIdentity::new(
                get_u64(bytes, at),
                get_u64(bytes, at + 8),
                get_u32(bytes, at + 16),
            );
            let parent = PersistentIdentity::new(
                get_u64(bytes, at + 20),
                get_u64(bytes, at + 28),
                get_u32(bytes, at + 36),
            );
            let kind = match bytes[at + 40] {
                0 => NodeKind::File,
                1 => NodeKind::Directory,
                _ => return Err(JournalError::InvalidCheckpoint),
            };
            let name_len = bytes[at + 41] as usize;
            if name_len > MAX_NAME_BYTES
                || bytes[at + 42] != 0
                || bytes[at + 43] != 0
                || bytes[at + 44 + name_len..at + 44 + MAX_NAME_BYTES]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(JournalError::InvalidCheckpoint);
            }
            let name = if name_len == 0 {
                EntryName::root()
            } else {
                EntryName::new(&bytes[at + 44..at + 44 + name_len])
                    .map_err(|_| JournalError::InvalidCheckpoint)?
            };
            let links = get_u32(bytes, at + 116);
            if !identity.is_valid()
                || identity.namespace_id != mount.namespace_id
                || links == 0
                || bytes[at + 156..at + NODE_RECORD_BYTES]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(JournalError::InvalidCheckpoint);
            }
            max_object_id = max_object_id.max(identity.object_id);
            *slot = Some(Node {
                identity,
                parent,
                name,
                kind,
                size: get_u64(bytes, at + 108),
                links,
                open_count: 0,
                content_epoch: get_u32(bytes, at + 120),
                data_version: get_u64(bytes, at + 124),
                metadata_version: get_u64(bytes, at + 132),
                durable_data_version: get_u64(bytes, at + 140),
                durable_metadata_version: get_u64(bytes, at + 148),
                deleted: false,
            });
        }
        if next_object_id <= max_object_id || next_object_id == 0 {
            return Err(JournalError::InvalidCheckpoint);
        }
        let root_identity = PersistentIdentity::new(mount.namespace_id, 1, 0);
        let roots = nodes[..count]
            .iter()
            .filter(|node| node.is_some_and(|node| node.identity == root_identity))
            .count();
        if roots != 1 {
            return Err(JournalError::InvalidCheckpoint);
        }
        for (index, node) in nodes[..count].iter().enumerate() {
            let node = node.ok_or(JournalError::InvalidCheckpoint)?;
            if node.identity == root_identity {
                if node.parent != root_identity
                    || node.name.len != 0
                    || node.kind != NodeKind::Directory
                {
                    return Err(JournalError::InvalidCheckpoint);
                }
            } else {
                if node.parent == node.identity || node.name.len == 0 {
                    return Err(JournalError::InvalidCheckpoint);
                }
                let parent = nodes[..count]
                    .iter()
                    .flatten()
                    .find(|parent| parent.identity == node.parent)
                    .ok_or(JournalError::InvalidCheckpoint)?;
                if parent.kind != NodeKind::Directory {
                    return Err(JournalError::InvalidCheckpoint);
                }
            }
            for other in nodes[..count].iter().skip(index + 1).flatten() {
                if other.identity == node.identity
                    || (other.parent == node.parent && other.name == node.name)
                {
                    return Err(JournalError::InvalidCheckpoint);
                }
            }
            let mut cursor = node.parent;
            let mut steps = 0usize;
            while cursor != root_identity {
                let parent = nodes[..count]
                    .iter()
                    .flatten()
                    .find(|parent| parent.identity == cursor)
                    .ok_or(JournalError::InvalidCheckpoint)?;
                cursor = parent.parent;
                steps += 1;
                if steps > count {
                    return Err(JournalError::InvalidCheckpoint);
                }
            }
        }
        Ok(FsContract {
            mount,
            capabilities,
            nodes,
            handles: HandleTable::new(),
            next_object_id,
        })
    }

    fn encode_header(header: RecordHeader, out: &mut [u8; RECORD_HEADER_BYTES]) {
        out.fill(0);
        out[0..8].copy_from_slice(&JOURNAL_MAGIC);
        put_u16(out, 8, header.version.major);
        put_u16(out, 10, header.version.minor);
        put_u16(out, 12, header.version.patch);
        out[14] = header.kind;
        out[15] = 0;
        put_u32(out, 16, header.body_len);
        put_u32(out, 20, 0);
        put_u64(out, 24, header.sequence);
        put_u64(out, 32, header.payload_hash);
        let hash = fnv1a(&out[..40]);
        put_u64(out, 40, hash);
    }

    fn decode_header(bytes: &[u8; RECORD_HEADER_BYTES]) -> Result<RecordHeader, JournalError> {
        if bytes[0..8] != JOURNAL_MAGIC
            || get_u16(bytes, 8) != CONTRACT_MAJOR
            || get_u16(bytes, 10) != CONTRACT_MINOR
            || get_u16(bytes, 12) != CONTRACT_PATCH
            || bytes[15] != 0
            || get_u32(bytes, 20) != 0
        {
            return Err(JournalError::InvalidRecord);
        }
        if fnv1a(&bytes[..40]) != get_u64(bytes, 40) {
            return Err(JournalError::Checksum);
        }
        Ok(RecordHeader {
            version: ContractVersion::V1_0_0,
            kind: bytes[14],
            body_len: get_u32(bytes, 16),
            sequence: get_u64(bytes, 24),
            payload_hash: get_u64(bytes, 32),
        })
    }

    fn hash_storage_body(
        storage: &mut impl JournalStorage,
        offset: usize,
        len: usize,
    ) -> Result<u64, JournalError> {
        let mut hash = 0xcbf29ce484222325u64;
        let mut scratch = [0u8; 64];
        let mut done = 0usize;
        while done < len {
            let take = (len - done).min(scratch.len());
            storage.read(offset + done, &mut scratch[..take])?;
            for byte in &scratch[..take] {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            done += take;
        }
        Ok(hash)
    }

    fn scan_slot(
        storage: &mut impl JournalStorage,
        slot_offset: usize,
        slot_bytes: usize,
    ) -> Result<Option<(RecordHeader, RecordHeader)>, JournalError> {
        if slot_bytes < RECORD_HEADER_BYTES * 2 {
            return Ok(None);
        }
        let mut raw = [0u8; RECORD_HEADER_BYTES];
        if storage.read(slot_offset, &mut raw).is_err() {
            return Ok(None);
        }
        let payload = match decode_header(&raw) {
            Ok(header) if header.kind == KIND_CHECKPOINT && header.body_len > 0 => header,
            _ => return Ok(None),
        };
        let body_len = payload.body_len as usize;
        if body_len
            .checked_add(RECORD_HEADER_BYTES * 2)
            .is_none_or(|size| size > slot_bytes)
        {
            return Ok(None);
        }
        if hash_storage_body(storage, slot_offset + RECORD_HEADER_BYTES, body_len)?
            != payload.payload_hash
        {
            return Ok(None);
        }
        if storage
            .read(slot_offset + RECORD_HEADER_BYTES + body_len, &mut raw)
            .is_err()
        {
            return Ok(None);
        }
        let commit = match decode_header(&raw) {
            Ok(header)
                if header.kind == KIND_COMMIT
                    && header.body_len == 0
                    && header.payload_hash == 0
                    && header.sequence == payload.sequence =>
            {
                header
            }
            _ => return Ok(None),
        };
        Ok(Some((payload, commit)))
    }

    pub struct FsJournal<'a, S: JournalStorage> {
        storage: &'a mut S,
        slot_bytes: usize,
        head: JournalHead,
    }

    impl<'a, S: JournalStorage> FsJournal<'a, S> {
        pub fn format(storage: &'a mut S) -> Result<Self, JournalError> {
            let capacity = storage.capacity();
            if capacity < RECORD_HEADER_BYTES * 4 || capacity % 2 != 0 {
                return Err(JournalError::Storage);
            }
            Ok(Self {
                storage,
                slot_bytes: capacity / 2,
                head: JournalHead {
                    slot: 1,
                    sequence: 0,
                    checkpoint_bytes: 0,
                },
            })
        }

        pub fn open(storage: &'a mut S) -> Result<Self, JournalError> {
            let capacity = storage.capacity();
            if capacity < RECORD_HEADER_BYTES * 4 || capacity % 2 != 0 {
                return Err(JournalError::Storage);
            }
            let slot_bytes = capacity / 2;
            let slot0 = scan_slot(storage, 0, slot_bytes)?;
            let slot1 = scan_slot(storage, slot_bytes, slot_bytes)?;
            let (slot, selected) = match (slot0, slot1) {
                (None, None) => return Err(JournalError::NoCommittedCheckpoint),
                (Some(record), None) => (0, record),
                (None, Some(record)) => (1, record),
                (Some(a), Some(b)) if a.0.sequence >= b.0.sequence => (0, a),
                (Some(_), Some(record)) => (1, record),
            };
            let sequence = selected.0.sequence;
            Ok(Self {
                storage,
                slot_bytes,
                head: JournalHead {
                    slot,
                    sequence,
                    checkpoint_bytes: selected.0.body_len as usize,
                },
            })
        }

        pub const fn head(&self) -> JournalHead {
            self.head
        }

        pub fn commit<const N: usize, const H: usize>(
            &mut self,
            fs: &FsContract<N, H>,
            scratch: &mut [u8],
        ) -> Result<CommitReceipt, JournalError> {
            let body_len = encode_checkpoint(fs, scratch)?;
            if body_len
                .checked_add(RECORD_HEADER_BYTES * 2)
                .is_none_or(|size| size > self.slot_bytes)
            {
                return Err(JournalError::CheckpointTooLarge);
            }
            let sequence = self
                .head
                .sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceExhausted)?;
            let slot = 1 - self.head.slot;
            let slot_offset = slot * self.slot_bytes;
            let payload_header = RecordHeader {
                version: ContractVersion::V1_0_0,
                kind: KIND_CHECKPOINT,
                body_len: body_len as u32,
                sequence,
                payload_hash: fnv1a(&scratch[..body_len]),
            };
            let mut header = [0u8; RECORD_HEADER_BYTES];
            encode_header(payload_header, &mut header);
            self.storage.write(slot_offset, &header)?;
            self.storage
                .write(slot_offset + RECORD_HEADER_BYTES, &scratch[..body_len])?;
            self.storage.flush()?;

            let commit_header = RecordHeader {
                version: ContractVersion::V1_0_0,
                kind: KIND_COMMIT,
                body_len: 0,
                sequence,
                payload_hash: 0,
            };
            encode_header(commit_header, &mut header);
            self.storage
                .write(slot_offset + RECORD_HEADER_BYTES + body_len, &header)?;
            self.storage.flush()?;
            self.head = JournalHead {
                slot,
                sequence,
                checkpoint_bytes: body_len,
            };
            Ok(CommitReceipt {
                slot,
                sequence,
                checkpoint_bytes: body_len,
            })
        }

        pub fn recover<const N: usize, const H: usize>(
            &mut self,
            expected_mount: MountIdentity,
            required: FsCapabilities,
            scratch: &mut [u8],
        ) -> Result<ReplayReceipt<N, H>, JournalError> {
            let head = self.head;
            if scratch.len() < head.checkpoint_bytes {
                return Err(JournalError::ShortBuffer);
            }
            let offset = head.slot * self.slot_bytes + RECORD_HEADER_BYTES;
            self.storage
                .read(offset, &mut scratch[..head.checkpoint_bytes])?;
            let state = restore_checkpoint::<N, H>(
                &scratch[..head.checkpoint_bytes],
                expected_mount,
                required,
            )?;
            Ok(ReplayReceipt {
                sequence: head.sequence,
                slot: head.slot,
                ignored_slot: 1 - head.slot,
                checkpoint_bytes: head.checkpoint_bytes,
                state,
            })
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn versions_never_wrap() {
        let version: u64 = kani::any();
        match next_version(version) {
            Ok(next) => assert_eq!(next, version + 1),
            Err(error) => {
                assert_eq!(error, FsError::VersionExhausted);
                assert_eq!(version, u64::MAX);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_object::PAGE_BYTES;

    const MOUNT: MountIdentity = MountIdentity::new(0x5157, 0x0909, 1);
    const FULL: FsCapabilities = FsCapabilities::ALL;

    fn fs<const N: usize, const H: usize>() -> FsContract<N, H> {
        FsContract::format(MOUNT, FULL, FsCapabilities::NONE).unwrap()
    }

    fn name(value: &[u8]) -> EntryName {
        EntryName::new(value).unwrap()
    }

    fn create_file<const N: usize, const H: usize>(
        fs: &mut FsContract<N, H>,
        parent: PersistentIdentity,
        value: &[u8],
    ) -> PersistentIdentity {
        fs.create(
            parent,
            name(value),
            NodeKind::File,
            Rights::READ.union(Rights::WRITE),
        )
        .unwrap()
    }

    fn rename_authority() -> RenameAuthority {
        RenameAuthority {
            source_parent: Rights::READ.union(Rights::WRITE),
            target_parent: Rights::READ.union(Rights::WRITE),
            object: Rights::CONTROL,
            replaced: Rights::CONTROL,
        }
    }

    fn rename_request(
        source_parent: PersistentIdentity,
        source_name: &[u8],
        target_mount: MountIdentity,
        target_parent: PersistentIdentity,
        target_name: &[u8],
        mode: RenameMode,
    ) -> RenameRequest {
        RenameRequest {
            source_parent,
            source_name: name(source_name),
            target_mount,
            target_parent,
            target_name: name(target_name),
            mode,
            authority: rename_authority(),
        }
    }

    fn read_write() -> Rights {
        Rights::READ.union(Rights::WRITE)
    }

    fn read_write_map() -> Rights {
        read_write().union(Rights::MAP)
    }

    #[test]
    fn wire_header_is_exact_and_unknown_fields_fail_closed() {
        let header = WireHeader::new(40);
        let encoded = header.encode();
        assert_eq!(WireHeader::decode(encoded), Ok(header));

        let mut bad_major = encoded;
        bad_major[0..2].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(WireHeader::decode(bad_major), Err(FsError::InvalidVersion));

        let mut bad_reserved = encoded;
        bad_reserved[12] = 1;
        assert_eq!(
            WireHeader::decode(bad_reserved),
            Err(FsError::InvalidVersion)
        );
    }

    #[test]
    fn capabilities_reject_unknown_bits_and_required_features() {
        assert_eq!(
            FsCapabilities::from_bits(FsCapabilities::ALL.bits()),
            Some(FULL)
        );
        assert_eq!(FsCapabilities::from_bits(1 << 31), None);
        assert_eq!(
            FsContract::<4, 4>::format(MOUNT, FsCapabilities::OPEN, FsCapabilities::ATOMIC_RENAME,)
                .err(),
            Some(FsError::UnsupportedCapability)
        );
    }

    #[test]
    fn names_reject_paths_dots_and_embedded_nul() {
        assert!(EntryName::new(b"file").is_ok());
        for invalid in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
            assert_eq!(EntryName::new(invalid), Err(FsError::InvalidName));
        }
        assert_eq!(
            EntryName::new(&[b'a'; MAX_NAME_BYTES + 1]),
            Err(FsError::InvalidName)
        );
    }

    #[test]
    fn create_and_lookup_are_failure_atomic_and_never_reuse_ids() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let first = create_file(&mut fs, root, b"first");
        assert_eq!(fs.lookup(root, name(b"first"), Rights::READ), Ok(first));
        assert_eq!(
            fs.create(
                root,
                name(b"first"),
                NodeKind::File,
                Rights::READ.union(Rights::WRITE)
            ),
            Err(FsError::AlreadyExists)
        );
        let second = create_file(&mut fs, root, b"second");
        assert_ne!(first.object_id, second.object_id);
        assert_eq!(
            fs.lookup(root, name(b"missing"), Rights::READ),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn stale_and_foreign_persistent_ids_cannot_resolve() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let stale = PersistentIdentity {
            generation: 99,
            ..file
        };
        assert_eq!(fs.open(stale, Rights::READ), Err(FsError::StaleIdentity));
        let foreign = PersistentIdentity {
            namespace_id: MOUNT.namespace_id + 1,
            ..file
        };
        assert_eq!(
            fs.open(foreign, Rights::READ),
            Err(FsError::InvalidIdentity)
        );
    }

    #[test]
    fn open_requires_file_rights_and_handle_table_failure_has_no_side_effect() {
        let mut fs = fs::<8, 1>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        assert_eq!(fs.open(file, Rights::NONE), Err(FsError::RightsDenied));
        let first = fs.open(file, Rights::READ).unwrap();
        assert_eq!(fs.open(file, Rights::READ), Err(FsError::HandleInvalid));
        assert_eq!(fs.info(file).unwrap().open_count, 1);
        fs.close(first).unwrap();
        assert_eq!(fs.info(file).unwrap().open_count, 0);
        assert_eq!(fs.live_handles(), 0);
    }

    #[test]
    fn rename_preserves_identity_and_updates_only_namespace_metadata() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"old");
        let receipt = fs
            .rename(rename_request(
                root,
                b"old",
                MOUNT,
                root,
                b"new",
                RenameMode::NoReplace,
            ))
            .unwrap();
        assert_eq!(receipt.identity, file);
        assert_eq!(
            fs.lookup(root, name(b"old"), Rights::READ),
            Err(FsError::NotFound)
        );
        assert_eq!(fs.lookup(root, name(b"new"), Rights::READ), Ok(file));
        assert_eq!(fs.info(file).unwrap().identity, file);
        assert_eq!(fs.info(file).unwrap().size, 0);
    }

    #[test]
    fn rename_rejects_cross_volume_and_cross_mount_without_mutation() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"old");
        let before = fs.info(file).unwrap();
        assert_eq!(
            fs.rename(rename_request(
                root,
                b"old",
                MountIdentity {
                    volume_id: MOUNT.volume_id + 1,
                    ..MOUNT
                },
                root,
                b"new",
                RenameMode::NoReplace,
            )),
            Err(FsError::CrossVolume)
        );
        assert_eq!(
            fs.rename(rename_request(
                root,
                b"old",
                MountIdentity {
                    mount_generation: MOUNT.mount_generation + 1,
                    ..MOUNT
                },
                root,
                b"new",
                RenameMode::NoReplace,
            )),
            Err(FsError::CrossMount)
        );
        assert_eq!(fs.info(file).unwrap(), before);
        assert_eq!(fs.lookup(root, name(b"old"), Rights::READ), Ok(file));
    }

    #[test]
    fn replace_rename_keeps_open_target_alive_until_last_close() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let source = create_file(&mut fs, root, b"source");
        let target = create_file(&mut fs, root, b"target");
        let target_handle = fs.open(target, read_write()).unwrap();
        let receipt = fs
            .rename(rename_request(
                root,
                b"source",
                MOUNT,
                root,
                b"target",
                RenameMode::ReplaceFile,
            ))
            .unwrap();
        assert_eq!(receipt.replaced, Some(target));
        assert_eq!(fs.lookup(root, name(b"target"), Rights::READ), Ok(source));
        assert!(fs.info(target).unwrap().deleted);
        fs.write(target_handle, 1).unwrap();
        assert_eq!(fs.open(target, Rights::READ), Err(FsError::StaleIdentity));
        fs.close(target_handle).unwrap();
        assert_eq!(fs.info(target), Err(FsError::StaleIdentity));
    }

    #[test]
    fn unlink_keeps_open_handle_but_blocks_new_lookup() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let handle = fs.open(file, read_write()).unwrap();
        assert_eq!(
            fs.unlink(root, name(b"file"), read_write(), Rights::CONTROL,),
            Ok(file)
        );
        assert_eq!(
            fs.lookup(root, name(b"file"), Rights::READ),
            Err(FsError::NotFound)
        );
        fs.write(handle, 7).unwrap();
        assert_eq!(fs.info(file).unwrap().size, 7);
        fs.close(handle).unwrap();
        assert_eq!(fs.info(file), Err(FsError::StaleIdentity));
    }

    #[test]
    fn directories_cannot_be_unlinked_while_nonempty() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let dir = fs
            .create(root, name(b"dir"), NodeKind::Directory, read_write())
            .unwrap();
        create_file(&mut fs, dir, b"child");
        assert_eq!(
            fs.unlink(root, name(b"dir"), read_write(), Rights::CONTROL,),
            Err(FsError::DirectoryNotEmpty)
        );
        assert_eq!(fs.lookup(root, name(b"dir"), Rights::READ), Ok(dir));
    }

    #[test]
    fn directory_rename_cannot_create_a_cycle() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let outer = fs
            .create(
                root,
                name(b"outer"),
                NodeKind::Directory,
                Rights::READ.union(Rights::WRITE),
            )
            .unwrap();
        let inner = fs
            .create(
                outer,
                name(b"inner"),
                NodeKind::Directory,
                Rights::READ.union(Rights::WRITE),
            )
            .unwrap();
        let before = fs.info(outer).unwrap();
        assert_eq!(
            fs.rename(rename_request(
                root,
                b"outer",
                MOUNT,
                inner,
                b"moved",
                RenameMode::NoReplace,
            )),
            Err(FsError::DirectoryCycle)
        );
        assert_eq!(fs.info(outer).unwrap(), before);
        assert_eq!(fs.lookup(root, name(b"outer"), Rights::READ), Ok(outer));
    }

    #[test]
    fn sync_failure_preserves_durability_and_new_writes_stay_dirty() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let handle = fs.open(file, read_write()).unwrap();
        fs.write(handle, 4096).unwrap();
        let ticket = fs.begin_sync(handle, SyncScope::DataAndMetadata).unwrap();
        let before = fs.sync_state(file).unwrap();
        assert_eq!(fs.complete_sync(handle, ticket, false), Ok(before));

        fs.write(handle, 4096).unwrap();
        let ticket = fs.begin_sync(handle, SyncScope::DataAndMetadata).unwrap();
        fs.write(handle, 1).unwrap();
        let state = fs.complete_sync(handle, ticket, true).unwrap();
        assert_eq!(state.durable_data_version, ticket.data_target);
        assert_eq!(state.durable_data_version, state.data_version - 1);
    }

    #[test]
    fn fdatasync_uses_its_own_declared_capability() {
        let capabilities = FsCapabilities::from_bits(
            FsCapabilities::CREATE.bits()
                | FsCapabilities::OPEN.bits()
                | FsCapabilities::WRITE.bits()
                | FsCapabilities::FDATASYNC.bits(),
        )
        .unwrap();
        let mut fs =
            FsContract::<8, 8>::format(MOUNT, capabilities, FsCapabilities::FDATASYNC).unwrap();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let handle = fs.open(file, read_write()).unwrap();
        assert!(fs.begin_sync(handle, SyncScope::Data).is_ok());
        assert_eq!(
            fs.begin_sync(handle, SyncScope::DataAndMetadata),
            Err(FsError::UnsupportedCapability)
        );
    }

    #[test]
    fn version_exhaustion_does_not_partially_mutate_a_file() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let handle = fs.open(file, read_write()).unwrap();
        let index = fs.find_identity_any(file).unwrap();
        fs.nodes[index].as_mut().unwrap().data_version = u64::MAX;
        let before = fs.info(file).unwrap();
        assert_eq!(fs.write(handle, 1), Err(FsError::VersionExhausted));
        assert_eq!(fs.info(file).unwrap(), before);
    }

    #[test]
    fn truncate_invalidates_mapping_epoch_but_not_open_handle() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let handle = fs.open(file, read_write_map()).unwrap();
        fs.write(handle, PAGE_BYTES * 2).unwrap();
        let mapping = fs.map(handle, 0, PAGE_BYTES, true).unwrap();
        assert!(fs.mapping_valid(mapping));
        fs.truncate(handle, PAGE_BYTES).unwrap();
        assert!(!fs.mapping_valid(mapping));
        assert_eq!(fs.mapping_write(mapping, 0, 1), Err(FsError::StaleMapping));
        assert_eq!(fs.info(file).unwrap().open_count, 1);
    }

    #[test]
    fn mmap_requires_alignment_range_and_map_rights() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let read_only = fs.open(file, Rights::READ).unwrap();
        let writer = fs.open(file, Rights::WRITE).unwrap();
        fs.write(writer, PAGE_BYTES).unwrap();
        assert_eq!(
            fs.map(read_only, 0, PAGE_BYTES, false),
            Err(FsError::RightsDenied)
        );
        let mapped = fs.open(file, read_write_map()).unwrap();
        assert_eq!(
            fs.map(mapped, 1, PAGE_BYTES, true),
            Err(FsError::MappingRange)
        );
        assert_eq!(fs.map(mapped, 0, 0, true), Err(FsError::MappingRange));
        assert_eq!(
            fs.map(mapped, 0, PAGE_BYTES * 2, true),
            Err(FsError::MappingRange)
        );
    }

    #[test]
    fn handle_operations_after_close_fail_closed() {
        let mut fs = fs::<8, 8>();
        let root = fs.root();
        let file = create_file(&mut fs, root, b"file");
        let handle = fs.open(file, read_write()).unwrap();
        fs.close(handle).unwrap();
        assert_eq!(fs.write(handle, 1), Err(FsError::HandleInvalid));
        assert_eq!(
            fs.begin_sync(handle, SyncScope::Data),
            Err(FsError::HandleInvalid)
        );
    }

    #[test]
    fn every_declared_error_has_a_system_fs_name_or_handle_name() {
        let errors = [
            FsError::InvalidVersion,
            FsError::InvalidName,
            FsError::InvalidIdentity,
            FsError::RightsDenied,
            FsError::UnsupportedCapability,
            FsError::CrossVolume,
            FsError::CrossMount,
            FsError::NotFound,
            FsError::StaleIdentity,
            FsError::AlreadyExists,
            FsError::NotDirectory,
            FsError::NotFile,
            FsError::DirectoryNotEmpty,
            FsError::DirectoryCycle,
            FsError::RootImmutable,
            FsError::NoSpace,
            FsError::IdsExhausted,
            FsError::VersionExhausted,
            FsError::HandleInvalid,
            FsError::MappingRange,
            FsError::StaleMapping,
            FsError::SyncIncomplete,
            FsError::SyncOrder,
        ];
        assert!(errors.iter().all(|error| {
            error.name().starts_with("system.fs.error.")
                || error.name() == "system.handle.error.invalid"
        }));
    }
}

#[cfg(test)]
mod journal_tests {
    use super::journal::{
        encode_checkpoint, BlockJournalStorage, FsJournal, JournalError, JournalStorage, SectorIo,
        CHECKPOINT_HEADER_BYTES, NODE_RECORD_BYTES, RECORD_HEADER_BYTES, STORAGE_UNIT_BYTES,
    };
    use super::*;

    const NODES: usize = 8;
    const HANDLES: usize = 8;
    const DISK_BYTES: usize = 8192;
    const SCRATCH_BYTES: usize = CHECKPOINT_HEADER_BYTES + NODES * NODE_RECORD_BYTES;

    #[derive(Clone)]
    struct FaultDisk<const BYTES: usize> {
        working: [u8; BYTES],
        durable: [u8; BYTES],
        writes: usize,
        flushes: usize,
        fail_write: Option<usize>,
        fail_flush: Option<usize>,
    }

    impl<const BYTES: usize> FaultDisk<BYTES> {
        fn new() -> Self {
            Self {
                working: [0; BYTES],
                durable: [0; BYTES],
                writes: 0,
                flushes: 0,
                fail_write: None,
                fail_flush: None,
            }
        }

        fn arm(&mut self, fail_write: Option<usize>, fail_flush: Option<usize>) {
            self.writes = 0;
            self.flushes = 0;
            self.fail_write = fail_write;
            self.fail_flush = fail_flush;
        }

        fn power_loss(&mut self) {
            self.working = self.durable;
            self.arm(None, None);
        }

        fn corrupt_durable(&mut self, offset: usize) {
            self.durable[offset] ^= 0x5a;
            self.working[offset] ^= 0x5a;
        }
    }

    impl<const BYTES: usize> JournalStorage for FaultDisk<BYTES> {
        fn capacity(&self) -> usize {
            BYTES
        }

        fn read(&mut self, offset: usize, out: &mut [u8]) -> Result<(), JournalError> {
            let end = offset.checked_add(out.len()).ok_or(JournalError::Storage)?;
            if end > BYTES {
                return Err(JournalError::Storage);
            }
            out.copy_from_slice(&self.working[offset..end]);
            Ok(())
        }

        fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), JournalError> {
            let operation = self.writes;
            self.writes += 1;
            if self.fail_write == Some(operation) {
                return Err(JournalError::Storage);
            }
            let end = offset
                .checked_add(bytes.len())
                .ok_or(JournalError::Storage)?;
            if end > BYTES {
                return Err(JournalError::Storage);
            }
            self.working[offset..end].copy_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), JournalError> {
            let operation = self.flushes;
            self.flushes += 1;
            if self.fail_flush == Some(operation) {
                return Err(JournalError::Storage);
            }
            self.durable = self.working;
            Ok(())
        }
    }

    struct SectorFaultDisk<const BYTES: usize> {
        working: [u8; BYTES],
        durable: [u8; BYTES],
        base_sector: u64,
        fail_write: Option<usize>,
        fail_flush: Option<usize>,
        writes: usize,
        flushes: usize,
    }

    impl<const BYTES: usize> SectorFaultDisk<BYTES> {
        fn new(base_sector: u64) -> Self {
            Self {
                working: [0; BYTES],
                durable: [0; BYTES],
                base_sector,
                fail_write: None,
                fail_flush: None,
                writes: 0,
                flushes: 0,
            }
        }

        fn power_loss(&mut self) {
            self.working = self.durable;
            self.fail_write = None;
            self.fail_flush = None;
            self.writes = 0;
            self.flushes = 0;
        }
    }

    impl<'a, const BYTES: usize> SectorIo for &'a mut SectorFaultDisk<BYTES> {
        fn capacity_sectors(&self) -> u64 {
            self.base_sector + (BYTES / STORAGE_UNIT_BYTES) as u64 * super::journal::SECTORS_PER_STORAGE_UNIT
        }

        fn read_unit(
            &mut self,
            sector: u64,
            out: &mut [u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            if sector < self.base_sector
                || sector % super::journal::SECTORS_PER_STORAGE_UNIT != 0
            {
                return Err(JournalError::Storage);
            }
            let unit = ((sector - self.base_sector)
                / super::journal::SECTORS_PER_STORAGE_UNIT) as usize;
            let start = unit
                .checked_mul(STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            let end = start
                .checked_add(STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            if end > BYTES {
                return Err(JournalError::Storage);
            }
            out.copy_from_slice(&self.working[start..end]);
            Ok(())
        }

        fn write_unit(
            &mut self,
            sector: u64,
            bytes: &[u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let operation = self.writes;
            self.writes += 1;
            if self.fail_write == Some(operation) {
                return Err(JournalError::Storage);
            }
            if sector < self.base_sector
                || sector % super::journal::SECTORS_PER_STORAGE_UNIT != 0
            {
                return Err(JournalError::Storage);
            }
            let unit = ((sector - self.base_sector)
                / super::journal::SECTORS_PER_STORAGE_UNIT) as usize;
            let start = unit
                .checked_mul(STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            let end = start
                .checked_add(STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            if end > BYTES {
                return Err(JournalError::Storage);
            }
            self.working[start..end].copy_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), JournalError> {
            let operation = self.flushes;
            self.flushes += 1;
            if self.fail_flush == Some(operation) {
                return Err(JournalError::Storage);
            }
            self.durable = self.working;
            Ok(())
        }
    }

    fn mount() -> MountIdentity {
        MountIdentity::new(41, 73, 1)
    }

    fn blank_fs() -> FsContract<NODES, HANDLES> {
        FsContract::format(mount(), FsCapabilities::ALL, FsCapabilities::NONE).unwrap()
    }

    fn create(fs: &mut FsContract<NODES, HANDLES>, name: &[u8]) -> PersistentIdentity {
        let root = fs.root();
        fs.create(
            root,
            EntryName::new(name).unwrap(),
            NodeKind::File,
            Rights::READ.union(Rights::WRITE),
        )
        .unwrap()
    }

    fn committed_disk() -> FaultDisk<DISK_BYTES> {
        let mut disk = FaultDisk::new();
        let mut fs = blank_fs();
        create(&mut fs, b"seed");
        let mut scratch = [0u8; SCRATCH_BYTES];
        let mut journal = FsJournal::format(&mut disk).unwrap();
        assert_eq!(journal.commit(&fs, &mut scratch).unwrap().sequence, 1);
        drop(journal);
        disk.arm(None, None);
        disk
    }

    #[test]
    fn aligned_storage_preserves_partial_writes_until_flush() {
        const BYTES: usize = STORAGE_UNIT_BYTES * 2;
        const BASE: u64 = 16;
        let mut disk = SectorFaultDisk::<BYTES>::new(BASE);
        {
            let mut storage = BlockJournalStorage::new(&mut disk, BASE, BYTES).unwrap();
            storage.write(3, &[0xaa; 97]).unwrap();
            storage.write(50, &[0x55; 10]).unwrap();
        }
        assert_eq!(disk.durable[3], 0);
        assert_eq!(disk.working[3], 0xaa);
        assert_eq!(disk.working[3 + 96], 0xaa);
        assert_eq!(disk.working[50], 0x55);
        {
            let mut storage = BlockJournalStorage::new(&mut disk, BASE, BYTES).unwrap();
            storage.flush().unwrap();
        }
        assert_eq!(disk.durable[3], 0xaa);
        assert_eq!(disk.durable[3 + 96], 0xaa);
        assert_eq!(disk.durable[50], 0x55);
        assert_eq!(disk.durable[1], 0);
    }

    #[test]
    fn journal_through_aligned_storage_survives_power_loss() {
        const BYTES: usize = STORAGE_UNIT_BYTES * 2;
        const BASE: u64 = 32;
        let mut disk = SectorFaultDisk::<BYTES>::new(BASE);
        let mut fs = blank_fs();
        create(&mut fs, b"block-backed");
        let mut scratch = [0u8; SCRATCH_BYTES];
        {
            let mut storage = BlockJournalStorage::new(&mut disk, BASE, BYTES).unwrap();
            let mut journal = FsJournal::format(&mut storage).unwrap();
            assert_eq!(journal.commit(&fs, &mut scratch).unwrap().sequence, 1);
        }
        disk.power_loss();
        let mut storage = BlockJournalStorage::new(&mut disk, BASE, BYTES).unwrap();
        let mut journal = FsJournal::open(&mut storage).unwrap();
        let replay = journal
            .recover::<NODES, HANDLES>(mount(), FsCapabilities::OPEN, &mut scratch)
            .unwrap();
        assert_eq!(replay.sequence, 1);
        assert!(replay
            .state
            .lookup(
                replay.state.root(),
                EntryName::new(b"block-backed").unwrap(),
                Rights::READ,
            )
            .is_ok());
    }

    fn recover(disk: &mut FaultDisk<DISK_BYTES>) -> (u64, FsContract<NODES, HANDLES>) {
        let mut scratch = [0u8; SCRATCH_BYTES];
        let mut journal = FsJournal::open(disk).unwrap();
        let replay = journal
            .recover::<NODES, HANDLES>(mount(), FsCapabilities::OPEN, &mut scratch)
            .unwrap();
        (replay.sequence, replay.state)
    }

    #[test]
    fn checkpoint_round_trip_preserves_metadata_not_runtime_handles() {
        let mut fs = blank_fs();
        let file = create(&mut fs, b"file");
        let handle = fs.open(file, Rights::READ.union(Rights::WRITE)).unwrap();
        fs.write(handle, 4096).unwrap();
        let source = fs.info(file).unwrap();
        let mut encoded = [0u8; SCRATCH_BYTES];
        let bytes = encode_checkpoint(&fs, &mut encoded).unwrap();
        let restored = journal::restore_checkpoint::<NODES, HANDLES>(
            &encoded[..bytes],
            mount(),
            FsCapabilities::OPEN,
        )
        .unwrap();
        let recovered = restored.info(file).unwrap();
        assert_eq!(recovered.identity, source.identity);
        assert_eq!(recovered.size, source.size);
        assert_eq!(recovered.data_version, source.data_version);
        assert_eq!(recovered.open_count, 0);
        assert_eq!(restored.live_handles(), 0);
    }

    #[test]
    fn malformed_checkpoint_identity_and_parent_kind_fail_closed() {
        let mut fs = blank_fs();
        let root = fs.root();
        let directory = fs
            .create(
                root,
                EntryName::new(b"dir").unwrap(),
                NodeKind::Directory,
                Rights::READ.union(Rights::WRITE),
            )
            .unwrap();
        fs.create(
            directory,
            EntryName::new(b"file").unwrap(),
            NodeKind::File,
            Rights::READ.union(Rights::WRITE),
        )
        .unwrap();
        let mut encoded = [0u8; SCRATCH_BYTES];
        let bytes = encode_checkpoint(&fs, &mut encoded).unwrap();
        let second = CHECKPOINT_HEADER_BYTES + NODE_RECORD_BYTES;
        let third = CHECKPOINT_HEADER_BYTES + 2 * NODE_RECORD_BYTES;

        let mut duplicate = encoded;
        let copied_identity: [u8; 20] = duplicate[second..second + 20].try_into().unwrap();
        duplicate[third..third + 20].copy_from_slice(&copied_identity);
        assert!(matches!(
            journal::restore_checkpoint::<NODES, HANDLES>(
                &duplicate[..bytes],
                mount(),
                FsCapabilities::OPEN,
            ),
            Err(JournalError::InvalidCheckpoint)
        ));

        let mut non_directory_parent = encoded;
        non_directory_parent[second + 40] = 0;
        assert!(matches!(
            journal::restore_checkpoint::<NODES, HANDLES>(
                &non_directory_parent[..bytes],
                mount(),
                FsCapabilities::OPEN,
            ),
            Err(JournalError::InvalidCheckpoint)
        ));
    }

    #[test]
    fn every_precommit_crash_point_keeps_previous_checkpoint() {
        let crash_cases = [
            (Some(0), None),
            (Some(1), None),
            (None, Some(0)),
            (Some(2), None),
            (None, Some(1)),
        ];
        for (fail_write, fail_flush) in crash_cases {
            let mut disk = committed_disk();
            disk.arm(fail_write, fail_flush);
            let mut journal = FsJournal::open(&mut disk).unwrap();
            let mut scratch = [0u8; SCRATCH_BYTES];
            let mut fs = journal
                .recover::<NODES, HANDLES>(mount(), FsCapabilities::OPEN, &mut scratch)
                .unwrap()
                .state;
            create(&mut fs, b"pending");
            assert_eq!(
                journal.commit(&fs, &mut scratch),
                Err(JournalError::Storage)
            );
            drop(journal);
            disk.power_loss();

            let (sequence, recovered) = recover(&mut disk);
            assert_eq!(sequence, 1);
            assert!(recovered
                .lookup(
                    recovered.root(),
                    EntryName::new(b"seed").unwrap(),
                    Rights::READ
                )
                .is_ok());
            assert_eq!(
                recovered.lookup(
                    recovered.root(),
                    EntryName::new(b"pending").unwrap(),
                    Rights::READ
                ),
                Err(FsError::NotFound)
            );
        }
    }

    #[test]
    fn replay_is_idempotent_and_committed_state_survives_remount() {
        let mut disk = committed_disk();
        let mut journal = FsJournal::open(&mut disk).unwrap();
        let mut scratch = [0u8; SCRATCH_BYTES];
        let mut fs = journal
            .recover::<NODES, HANDLES>(mount(), FsCapabilities::OPEN, &mut scratch)
            .unwrap()
            .state;
        create(&mut fs, b"durable");
        let receipt = journal.commit(&fs, &mut scratch).unwrap();
        assert_eq!(receipt.sequence, 2);
        drop(journal);
        disk.power_loss();

        let (sequence_a, mut replay_a) = recover(&mut disk);
        let (sequence_b, mut replay_b) = recover(&mut disk);
        assert_eq!((sequence_a, sequence_b), (2, 2));
        assert_eq!(
            replay_a
                .lookup(
                    replay_a.root(),
                    EntryName::new(b"durable").unwrap(),
                    Rights::READ
                )
                .unwrap(),
            replay_b
                .lookup(
                    replay_b.root(),
                    EntryName::new(b"durable").unwrap(),
                    Rights::READ
                )
                .unwrap()
        );
        let identity_a = create(&mut replay_a, b"same");
        let identity_b = create(&mut replay_b, b"same");
        assert_eq!(identity_a, identity_b);
    }

    #[test]
    fn torn_payload_or_commit_falls_back_to_previous_generation() {
        for corrupt_commit in [false, true] {
            let mut disk = committed_disk();
            let mut journal = FsJournal::open(&mut disk).unwrap();
            let mut scratch = [0u8; SCRATCH_BYTES];
            let mut fs = journal
                .recover::<NODES, HANDLES>(mount(), FsCapabilities::OPEN, &mut scratch)
                .unwrap()
                .state;
            create(&mut fs, b"newer");
            let receipt = journal.commit(&fs, &mut scratch).unwrap();
            drop(journal);
            let slot_offset = receipt.slot * (DISK_BYTES / 2);
            let corrupt_at = if corrupt_commit {
                slot_offset + RECORD_HEADER_BYTES + receipt.checkpoint_bytes + 24
            } else {
                slot_offset + RECORD_HEADER_BYTES + 16
            };
            disk.corrupt_durable(corrupt_at);
            disk.power_loss();
            let (sequence, recovered) = recover(&mut disk);
            assert_eq!(sequence, 1);
            assert_eq!(
                recovered.lookup(
                    recovered.root(),
                    EntryName::new(b"newer").unwrap(),
                    Rights::READ
                ),
                Err(FsError::NotFound)
            );
        }
    }

    #[test]
    fn block_write_or_flush_failure_never_advances_durability() {
        let mut fs = blank_fs();
        let file = create(&mut fs, b"sync");
        let handle = fs.open(file, Rights::READ.union(Rights::WRITE)).unwrap();
        fs.write(handle, 4096).unwrap();
        let ticket = fs.begin_sync(handle, SyncScope::DataAndMetadata).unwrap();

        let mut write_failed = BlockDurabilityChain::new();
        assert_eq!(write_failed.flush_request(), Err(FsError::SyncOrder));
        assert_eq!(
            write_failed.write_terminal(Terminal::Failed),
            Err(FsError::SyncIncomplete)
        );
        assert_eq!(write_failed.evidence(), None);

        let mut flush_failed = BlockDurabilityChain::new();
        flush_failed.write_terminal(Terminal::Completed).unwrap();
        assert_eq!(
            flush_failed.flush_terminal(Terminal::Cancelled),
            Err(FsError::SyncIncomplete)
        );
        assert!(flush_failed.failed());
        assert_eq!(fs.sync_state(file).unwrap().durable_data_version, 0);

        let mut complete = BlockDurabilityChain::new();
        assert_eq!(
            complete.write_request(1).unwrap().kind,
            crate::block::RequestKind::Write
        );
        complete.write_terminal(Terminal::Completed).unwrap();
        assert_eq!(
            complete.flush_request().unwrap().kind,
            crate::block::RequestKind::Flush
        );
        complete.flush_terminal(Terminal::Completed).unwrap();
        let state = fs
            .complete_sync_durable(handle, ticket, complete.evidence().unwrap())
            .unwrap();
        assert_eq!(state.durable_data_version, ticket.data_target);
        assert_eq!(state.durable_metadata_version, ticket.metadata_target);
    }

    #[test]
    fn acknowledged_sync_checkpoint_survives_power_loss() {
        let mut disk = FaultDisk::new();
        let mut fs = blank_fs();
        let file = create(&mut fs, b"durable-sync");
        let handle = fs.open(file, Rights::READ.union(Rights::WRITE)).unwrap();
        fs.write(handle, 4096).unwrap();
        let ticket = fs.begin_sync(handle, SyncScope::DataAndMetadata).unwrap();
        let mut chain = BlockDurabilityChain::new();
        chain.write_terminal(Terminal::Completed).unwrap();
        chain.flush_terminal(Terminal::Completed).unwrap();
        fs.complete_sync_durable(handle, ticket, chain.evidence().unwrap())
            .unwrap();

        let mut scratch = [0u8; SCRATCH_BYTES];
        {
            let mut journal = FsJournal::format(&mut disk).unwrap();
            journal.commit(&fs, &mut scratch).unwrap();
        }
        disk.power_loss();
        let (_, recovered) = recover(&mut disk);
        let state = recovered.sync_state(file).unwrap();
        assert_eq!(state.durable_data_version, ticket.data_target);
        assert_eq!(state.durable_metadata_version, ticket.metadata_target);
    }
}
