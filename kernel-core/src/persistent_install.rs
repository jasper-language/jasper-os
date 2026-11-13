//! Crash-safe package-byte store and installation-state persistence.
//!
//! Package bytes are content-addressed and shared. Installation, grants,
//! runtime principals and independently owned data are stored in one bounded
//! `InstallModel` snapshot with an A/B commit marker. A package blob is written
//! and flushed before the state snapshot; an interrupted metadata commit is
//! ignored and its orphan blob is reclaimed on reopen.
//!
//! 内容寻址的共享包字节与安装状态持久化。安装登记、授权、运行主体和独立数据
//! 作为一个有界 `InstallModel` 快照通过 A/B 提交标记切换；中断的元数据提交保留
//! 旧快照，孤立包字节在重开时回收。

use crate::fs::journal::{SectorIo, SECTORS_PER_STORAGE_UNIT, STORAGE_UNIT_BYTES};
use crate::native_install::{
    Actor, DataKey, DataOwnerKind, DataSnapshot, GrantKey, GrantRights, GrantSpec, InstallError,
    InstallModel, InstallSpec, InstallStateSnapshot, InstallationKey, InstallationSnapshot,
    OwnerScope, PackageKey, PackageSnapshot, PackageSource, PackageSpec, PrincipalKind,
    PrincipalSpec, RuntimeKey, RuntimeSnapshot, Subject, UpdateAuthority, CONTENT_BYTES,
};
use crate::security_domain::DomainKey;
use alloc::boxed::Box;

type Model = InstallModel<16, 32, 64, 16, 32>;
type State = InstallStateSnapshot<16, 32, 64, 16, 32>;

const FORMAT_UNITS: usize = 1;
const SLOT_BODY_UNITS: usize = 4;
const SLOT_MARKER_UNITS: usize = 1;
const SLOT_UNITS: usize = SLOT_BODY_UNITS + SLOT_MARKER_UNITS;
const METADATA_UNITS: usize = FORMAT_UNITS + 2 * SLOT_UNITS;
const BLOB_SLOTS: usize = 16;
const BLOB_BODY_UNITS: usize = 1;
const BLOB_UNITS: usize = 1 + BLOB_BODY_UNITS;
const TOTAL_UNITS: usize = METADATA_UNITS + BLOB_SLOTS * BLOB_UNITS;
const SNAPSHOT_MAX_BYTES: usize = SLOT_BODY_UNITS * STORAGE_UNIT_BYTES;

const FORMAT_MAGIC: &[u8; 8] = b"JSIINST1";
const SNAPSHOT_MAGIC: &[u8; 8] = b"JSISNAP1";
const BLOB_MAGIC: &[u8; 8] = b"JSIBLOB1";
const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistentInstallError {
    Io,
    InvalidFormat,
    Corrupt,
    Capacity,
    SnapshotTooLarge,
    SequenceExhausted,
    InvalidPackage,
    DigestMismatch,
    NotFound,
    Install(InstallError),
}

impl PersistentInstallError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Io => "system.install.store.error.io",
            Self::InvalidFormat => "system.install.store.error.format",
            Self::Corrupt => "system.install.store.error.corrupt",
            Self::Capacity => "system.install.store.error.capacity",
            Self::SnapshotTooLarge => "system.install.store.error.snapshot",
            Self::SequenceExhausted => "system.install.store.error.sequence",
            Self::InvalidPackage => "system.install.store.error.package",
            Self::DigestMismatch => "system.install.store.error.digest",
            Self::NotFound => "system.install.store.error.not_found",
            Self::Install(error) => error.name(),
        }
    }
}

#[derive(Clone, Copy)]
struct BlobRecord {
    content: [u8; CONTENT_BYTES],
    len: u32,
    checksum: u32,
}

/// A bounded persistent installation store over one `SectorIo` device.
pub struct PersistentInstallStore<D: SectorIo> {
    device: D,
    model: Box<Model>,
    sequence: u64,
    blobs: [Option<BlobRecord>; BLOB_SLOTS],
}

impl<D: SectorIo> PersistentInstallStore<D> {
    #[inline(never)]
    pub fn format(device: D) -> Result<Self, PersistentInstallError> {
        if device.capacity_sectors()
            < (TOTAL_UNITS as u64)
                .checked_mul(SECTORS_PER_STORAGE_UNIT)
                .ok_or(PersistentInstallError::Capacity)?
        {
            return Err(PersistentInstallError::Capacity);
        }
        let mut store = Self {
            device,
            model: Box::new(Model::new()),
            sequence: 0,
            blobs: [None; BLOB_SLOTS],
        };
        // Invalidate every prior commit before publishing the new format
        // header. Otherwise an old snapshot can have a greater sequence and
        // would win the A/B election on reopen.
        for slot in 0..2 {
            store.write_unit(
                FORMAT_UNITS + slot * SLOT_UNITS + SLOT_BODY_UNITS,
                &[0u8; STORAGE_UNIT_BYTES],
            )?;
        }
        for slot in 0..BLOB_SLOTS {
            store.write_unit(
                METADATA_UNITS + slot * BLOB_UNITS,
                &[0u8; STORAGE_UNIT_BYTES],
            )?;
        }
        store.flush()?;
        let mut header = [0u8; STORAGE_UNIT_BYTES];
        header[..8].copy_from_slice(FORMAT_MAGIC);
        header[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        store.write_unit(0, &header)?;
        store.flush()?;
        let empty = store.model.clone();
        store.commit_model(empty)?;
        Ok(store)
    }

    #[inline(never)]
    pub fn open(mut device: D) -> Result<Self, PersistentInstallError> {
        let mut header = [0u8; STORAGE_UNIT_BYTES];
        device
            .read_unit(0, &mut header)
            .map_err(|_| PersistentInstallError::Io)?;
        if &header[..8] != FORMAT_MAGIC
            || u32::from_le_bytes(header[8..12].try_into().unwrap()) != FORMAT_VERSION
        {
            return Err(PersistentInstallError::InvalidFormat);
        }
        let mut selected: Option<(u64, Box<State>)> = None;
        for slot in 0..2 {
            if let Some((sequence, state)) = read_slot(&mut device, slot)? {
                if selected.as_ref().is_none_or(|(current, _)| sequence > *current) {
                    selected = Some((sequence, state));
                }
            }
        }
        let (sequence, state) = selected.ok_or(PersistentInstallError::Corrupt)?;
        let model = Model::restore_state(*state).map_err(PersistentInstallError::Install)?;
        let mut store = Self {
            device,
            model: Box::new(model),
            sequence,
            blobs: [None; BLOB_SLOTS],
        };
        store.scan_blobs()?;
        store.reclaim_orphan_blobs()?;
        Ok(store)
    }

    pub fn state(&self) -> State {
        self.model.snapshot_state()
    }

    pub fn package(&self, key: PackageKey) -> Result<PackageSnapshot, PersistentInstallError> {
        self.model
            .package(key)
            .map_err(PersistentInstallError::Install)
    }

    pub fn installation(
        &self,
        key: InstallationKey,
    ) -> Result<InstallationSnapshot, PersistentInstallError> {
        self.model
            .installation(key)
            .map_err(PersistentInstallError::Install)
    }

    pub fn runtime(&self, key: RuntimeKey) -> Result<RuntimeSnapshot, PersistentInstallError> {
        self.model
            .runtime(key)
            .map_err(PersistentInstallError::Install)
    }

    pub fn can_discover(&self, actor: Actor<'_>, installation: InstallationKey, now: u64) -> bool {
        self.model.can_discover(actor, installation, now)
    }

    pub fn can_start(&self, actor: Actor<'_>, installation: InstallationKey, now: u64) -> bool {
        self.model.can_start(actor, installation, now)
    }

    pub fn can_update(&self, actor: Actor<'_>, installation: InstallationKey) -> bool {
        self.model.can_update(actor, installation)
    }

    pub fn find_package(&self, spec: PackageSpec) -> Option<PackageKey> {
        self.model.find_package(spec)
    }

    pub fn installation_count_for(&self, package: PackageKey) -> usize {
        self.model.installation_count_for(package)
    }

    pub fn read_package_bytes(
        &mut self,
        content: [u8; CONTENT_BYTES],
        out: &mut [u8],
    ) -> Result<usize, PersistentInstallError> {
        let slot = self
            .blobs
            .iter()
            .position(|record| record.is_some_and(|record| record.content == content))
            .ok_or(PersistentInstallError::NotFound)?;
        let record = self.blobs[slot].ok_or(PersistentInstallError::Corrupt)?;
        if out.len() < record.len as usize {
            return Err(PersistentInstallError::Capacity);
        }
        self.read_blob_body(slot, &mut out[..record.len as usize])?;
        Ok(record.len as usize)
    }

    pub fn install_package(
        &mut self,
        spec: PackageSpec,
        bytes: &[u8],
    ) -> Result<PackageKey, PersistentInstallError> {
        if !valid_package(spec) || bytes.is_empty() || bytes.len() > STORAGE_UNIT_BYTES {
            return Err(PersistentInstallError::InvalidPackage);
        }
        if let Some(key) = self.model.find_package(spec) {
            if !self.blob_matches(spec.content, bytes)? {
                return Err(PersistentInstallError::DigestMismatch);
            }
            return Ok(key);
        }
        let mut next = self.model.clone();
        let key = next
            .add_package(spec)
            .map_err(PersistentInstallError::Install)?;
        self.ensure_blob(spec.content, bytes)?;
        self.commit_model(next)?;
        Ok(key)
    }

    pub fn install(
        &mut self,
        spec: InstallSpec,
    ) -> Result<InstallationKey, PersistentInstallError> {
        if let Some(key) = self.model.find_installation(spec) {
            return Ok(key);
        }
        let mut next = self.model.clone();
        let key = next
            .install(spec)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)?;
        Ok(key)
    }

    pub fn add_grant(&mut self, spec: GrantSpec) -> Result<GrantKey, PersistentInstallError> {
        if let Some(key) = self.model.find_grant(spec) {
            return Ok(key);
        }
        let mut next = self.model.clone();
        let key = next
            .add_grant(spec)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)?;
        Ok(key)
    }

    pub fn revoke_grant(&mut self, key: GrantKey) -> Result<(), PersistentInstallError> {
        let mut next = self.model.clone();
        next.revoke_grant(key)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)
    }

    pub fn set_update_authority(
        &mut self,
        actor: Actor<'_>,
        installation: InstallationKey,
        authority: UpdateAuthority,
    ) -> Result<(), PersistentInstallError> {
        let mut next = self.model.clone();
        next.set_update_authority(actor, installation, authority)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)
    }

    pub fn start(
        &mut self,
        actor: Actor<'_>,
        installation: InstallationKey,
        principal: PrincipalSpec,
        now: u64,
    ) -> Result<RuntimeKey, PersistentInstallError> {
        let mut next = self.model.clone();
        let key = next
            .start(actor, installation, principal, now)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)?;
        Ok(key)
    }

    pub fn stop_runtime(&mut self, key: RuntimeKey) -> Result<(), PersistentInstallError> {
        let mut next = self.model.clone();
        next.stop_runtime(key)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)
    }

    pub fn create_data(
        &mut self,
        installation: InstallationKey,
        owner: Subject,
        kind: DataOwnerKind,
    ) -> Result<DataKey, PersistentInstallError> {
        let package = self
            .model
            .installation(installation)
            .map_err(PersistentInstallError::Install)?
            .package;
        if let Some(key) = self.model.find_data(package, owner, kind) {
            return Ok(key);
        }
        let mut next = self.model.clone();
        let key = next
            .create_data(installation, owner, kind)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)?;
        Ok(key)
    }

    pub fn destroy_data(&mut self, key: DataKey) -> Result<(), PersistentInstallError> {
        let mut next = self.model.clone();
        next.destroy_data(key)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)
    }

    pub fn uninstall(
        &mut self,
        actor: Actor<'_>,
        key: InstallationKey,
    ) -> Result<(), PersistentInstallError> {
        let mut next = self.model.clone();
        next.uninstall(actor, key)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)
    }

    pub fn set_enabled(
        &mut self,
        actor: Actor<'_>,
        installation: InstallationKey,
        enabled: bool,
    ) -> Result<(), PersistentInstallError> {
        let mut next = self.model.clone();
        next.set_enabled(actor, installation, enabled)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)
    }

    pub fn destroy_package(&mut self, key: PackageKey) -> Result<(), PersistentInstallError> {
        let package = self
            .model
            .package(key)
            .map_err(PersistentInstallError::Install)?;
        let mut next = self.model.clone();
        next.destroy_package(key)
            .map_err(PersistentInstallError::Install)?;
        self.commit_model(next)?;
        if !self.model.content_referenced(package.spec.content) {
            // The metadata snapshot is authoritative; failure here leaves only
            // an orphan blob that `open` reclaims.
            let _ = self.free_blob(package.spec.content);
        }
        Ok(())
    }

    pub fn into_device(self) -> D {
        self.device
    }

    #[inline(never)]
    fn commit_model(&mut self, next: Box<Model>) -> Result<(), PersistentInstallError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(PersistentInstallError::SequenceExhausted)?;
        let slot = sequence as usize & 1;
        let base = FORMAT_UNITS + slot * SLOT_UNITS;
        let mut writer = SnapshotUnitWriter::new(&mut self.device, base);
        let len = encode_model(next.as_ref(), &mut writer)?;
        let encoded_checksum = writer.finish()?;
        let mut marker = [0u8; STORAGE_UNIT_BYTES];
        marker[..8].copy_from_slice(SNAPSHOT_MAGIC);
        marker[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        marker[12..20].copy_from_slice(&sequence.to_le_bytes());
        marker[20..24].copy_from_slice(&(len as u32).to_le_bytes());
        marker[24..28].copy_from_slice(&encoded_checksum.to_le_bytes());
        self.write_unit(base + SLOT_BODY_UNITS, &marker)?;
        self.flush()?;
        self.model = next;
        self.sequence = sequence;
        Ok(())
    }

    fn ensure_blob(
        &mut self,
        content: [u8; CONTENT_BYTES],
        bytes: &[u8],
    ) -> Result<(), PersistentInstallError> {
        if self.blob_matches(content, bytes)? {
            return Ok(());
        }
        if self
            .blobs
            .iter()
            .flatten()
            .any(|record| record.content == content)
        {
            return Err(PersistentInstallError::DigestMismatch);
        }
        let slot = self
            .blobs
            .iter()
            .position(Option::is_none)
            .ok_or(PersistentInstallError::Capacity)?;
        let base = METADATA_UNITS + slot * BLOB_UNITS;
        let mut body = [0u8; STORAGE_UNIT_BYTES];
        body[..bytes.len()].copy_from_slice(bytes);
        self.write_unit(base + 1, &body)?;
        self.flush()?;
        let mut header = [0u8; STORAGE_UNIT_BYTES];
        header[..8].copy_from_slice(BLOB_MAGIC);
        header[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        header[12..12 + CONTENT_BYTES].copy_from_slice(&content);
        header[44..48].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        header[48..52].copy_from_slice(&checksum(bytes).to_le_bytes());
        self.write_unit(base, &header)?;
        self.flush()?;
        self.blobs[slot] = Some(BlobRecord {
            content,
            len: bytes.len() as u32,
            checksum: checksum(bytes),
        });
        Ok(())
    }

    fn blob_matches(
        &mut self,
        content: [u8; CONTENT_BYTES],
        bytes: &[u8],
    ) -> Result<bool, PersistentInstallError> {
        let Some(slot) = self
            .blobs
            .iter()
            .position(|record| record.is_some_and(|record| record.content == content))
        else {
            return Ok(false);
        };
        let record = self.blobs[slot].ok_or(PersistentInstallError::Corrupt)?;
        if record.len as usize != bytes.len() {
            return Ok(false);
        }
        let mut stored = [0u8; STORAGE_UNIT_BYTES];
        self.read_blob_body(slot, &mut stored[..bytes.len()])?;
        Ok(stored[..bytes.len()] == *bytes)
    }

    fn scan_blobs(&mut self) -> Result<(), PersistentInstallError> {
        for slot in 0..BLOB_SLOTS {
            let base = METADATA_UNITS + slot * BLOB_UNITS;
            let mut header = [0u8; STORAGE_UNIT_BYTES];
            self.device
                .read_unit(sector_for_unit(base)?, &mut header)
                .map_err(|_| PersistentInstallError::Io)?;
            if &header[..8] != BLOB_MAGIC {
                continue;
            }
            let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
            let len = u32::from_le_bytes(header[44..48].try_into().unwrap()) as usize;
            let expected = u32::from_le_bytes(header[48..52].try_into().unwrap());
            if version != FORMAT_VERSION || len == 0 || len > STORAGE_UNIT_BYTES {
                continue;
            }
            let mut body = [0u8; STORAGE_UNIT_BYTES];
            self.device
                .read_unit(sector_for_unit(base + 1)?, &mut body)
                .map_err(|_| PersistentInstallError::Io)?;
            if checksum(&body[..len]) != expected {
                continue;
            }
            let mut content = [0u8; CONTENT_BYTES];
            content.copy_from_slice(&header[12..12 + CONTENT_BYTES]);
            self.blobs[slot] = Some(BlobRecord {
                content,
                len: len as u32,
                checksum: expected,
            });
        }
        Ok(())
    }

    fn reclaim_orphan_blobs(&mut self) -> Result<(), PersistentInstallError> {
        for slot in 0..BLOB_SLOTS {
            let Some(record) = self.blobs[slot] else {
                continue;
            };
            if !self.model.content_referenced(record.content) {
                self.clear_blob_slot(slot)?;
            }
        }
        Ok(())
    }

    fn free_blob(&mut self, content: [u8; CONTENT_BYTES]) -> Result<(), PersistentInstallError> {
        if let Some(slot) = self
            .blobs
            .iter()
            .position(|record| record.is_some_and(|record| record.content == content))
        {
            self.clear_blob_slot(slot)?;
        }
        Ok(())
    }

    fn clear_blob_slot(&mut self, slot: usize) -> Result<(), PersistentInstallError> {
        let base = METADATA_UNITS + slot * BLOB_UNITS;
        self.write_unit(base, &[0u8; STORAGE_UNIT_BYTES])?;
        self.flush()?;
        self.blobs[slot] = None;
        Ok(())
    }

    fn read_blob_body(
        &mut self,
        slot: usize,
        out: &mut [u8],
    ) -> Result<(), PersistentInstallError> {
        let record = self.blobs[slot].ok_or(PersistentInstallError::NotFound)?;
        if out.len() != record.len as usize {
            return Err(PersistentInstallError::Capacity);
        }
        let mut body = [0u8; STORAGE_UNIT_BYTES];
        let base = METADATA_UNITS + slot * BLOB_UNITS;
        self.device
            .read_unit(sector_for_unit(base + 1)?, &mut body)
            .map_err(|_| PersistentInstallError::Io)?;
        if checksum(&body[..out.len()]) != record.checksum {
            return Err(PersistentInstallError::Corrupt);
        }
        out.copy_from_slice(&body[..out.len()]);
        Ok(())
    }

    fn write_unit(
        &mut self,
        unit: usize,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), PersistentInstallError> {
        self.device
            .write_unit(sector_for_unit(unit)?, bytes)
            .map_err(|_| PersistentInstallError::Io)
    }

    fn flush(&mut self) -> Result<(), PersistentInstallError> {
        self.device.flush().map_err(|_| PersistentInstallError::Io)
    }
}

fn sector_for_unit(unit: usize) -> Result<u64, PersistentInstallError> {
    (unit as u64)
        .checked_mul(SECTORS_PER_STORAGE_UNIT)
        .ok_or(PersistentInstallError::Capacity)
}

fn valid_package(spec: PackageSpec) -> bool {
    spec.app_id != 0
        && spec.publisher != 0
        && spec.version != 0
        && spec.content.iter().any(|byte| *byte != 0)
}

#[inline(never)]
fn read_slot<D: SectorIo>(
    device: &mut D,
    slot: usize,
) -> Result<Option<(u64, Box<State>)>, PersistentInstallError> {
    let base = FORMAT_UNITS + slot * SLOT_UNITS;
    let mut marker = [0u8; STORAGE_UNIT_BYTES];
    device
        .read_unit(sector_for_unit(base + SLOT_BODY_UNITS)?, &mut marker)
        .map_err(|_| PersistentInstallError::Io)?;
    if &marker[..8] != SNAPSHOT_MAGIC
        || u32::from_le_bytes(marker[8..12].try_into().unwrap()) != FORMAT_VERSION
    {
        return Ok(None);
    }
    let sequence = u64::from_le_bytes(marker[12..20].try_into().unwrap());
    let len = u32::from_le_bytes(marker[20..24].try_into().unwrap()) as usize;
    let expected = u32::from_le_bytes(marker[24..28].try_into().unwrap());
    if len == 0 || len > SNAPSHOT_MAX_BYTES {
        return Ok(None);
    }
    let mut hash = 0x811c_9dc5u32;
    let mut remaining = len;
    for unit in 0..SLOT_BODY_UNITS {
        let mut bytes = [0u8; STORAGE_UNIT_BYTES];
        device
            .read_unit(sector_for_unit(base + unit)?, &mut bytes)
            .map_err(|_| PersistentInstallError::Io)?;
        let take = remaining.min(STORAGE_UNIT_BYTES);
        for byte in &bytes[..take] {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        remaining -= take;
        if remaining == 0 {
            break;
        }
    }
    if hash != expected {
        return Ok(None);
    }
    let mut source = SnapshotUnitReader::new(device, base, len);
    let state = decode_state(&mut source)?;
    source.finish()?;
    Ok(Some((sequence, state)))
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[inline(never)]
fn encode_model<S: SnapshotSink>(
    model: &Model,
    sink: &mut S,
) -> Result<usize, PersistentInstallError> {
    let (
        packages,
        package_generations,
        installations,
        installation_generations,
        grants,
        grant_generations,
        runtimes,
        runtime_generations,
        data,
        data_generations,
    ) = model.encoding_parts();
    sink.put(SNAPSHOT_MAGIC)?;
    sink.put_u32(FORMAT_VERSION)?;
    for record in packages {
        sink.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            sink.put_u64(record.key.to_raw())?;
            sink.put_u64(record.spec.app_id)?;
            sink.put_u64(record.spec.publisher)?;
            sink.put(&record.spec.content)?;
            sink.put_u32(record.spec.version)?;
        }
    }
    for generation in package_generations {
        sink.put_u32(*generation)?;
    }
    for record in installations {
        sink.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            sink.put_u64(record.key.to_raw())?;
            sink.put_u64(record.package.to_raw())?;
            put_scope(sink, record.scope)?;
            sink.put_u8(package_source_tag(record.source))?;
            put_subject(sink, record.update_authority.subject)?;
            sink.put_u8(u8::from(record.enabled))?;
        }
    }
    for generation in installation_generations {
        sink.put_u32(*generation)?;
    }
    for record in grants {
        sink.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            sink.put_u64(record.key.to_raw())?;
            sink.put_u64(record.installation.to_raw())?;
            put_subject(sink, record.subject)?;
            sink.put_u32(record.rights.0)?;
            sink.put_u8(u8::from(record.expires_at.is_some()))?;
            if let Some(expires) = record.expires_at {
                sink.put_u64(expires)?;
            }
            sink.put_u8(u8::from(record.active))?;
        }
    }
    for generation in grant_generations {
        sink.put_u32(*generation)?;
    }
    for record in runtimes {
        sink.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            sink.put_u64(record.key.to_raw())?;
            sink.put_u64(record.installation.to_raw())?;
            sink.put_u8(principal_kind_tag(record.principal.kind))?;
            put_subject(sink, record.principal.subject)?;
            sink.put_u32(record.principal.generation)?;
            sink.put_u32(record.principal.domain.id)?;
            sink.put_u32(record.principal.domain.generation)?;
            sink.put_u32(record.principal.rights.0)?;
            sink.put_u64(record.started_at)?;
        }
    }
    for generation in runtime_generations {
        sink.put_u32(*generation)?;
    }
    for record in data {
        sink.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            sink.put_u64(record.key.to_raw())?;
            sink.put_u64(record.package.to_raw())?;
            put_subject(sink, record.owner)?;
            sink.put_u8(data_kind_tag(record.kind))?;
        }
    }
    for generation in data_generations {
        sink.put_u32(*generation)?;
    }
    Ok(sink.written())
}

#[inline(never)]
fn decode_state<R: SnapshotSource>(source: &mut R) -> Result<Box<State>, PersistentInstallError> {
    let mut cursor = DecodeReader { source };
    let mut magic = [0u8; 8];
    cursor.read_exact(&mut magic)?;
    if &magic != SNAPSHOT_MAGIC || cursor.get_u32()? != FORMAT_VERSION {
        return Err(PersistentInstallError::Corrupt);
    }
    let mut state = Box::new(State {
        packages: [None; 16],
        package_generations: [0; 16],
        installations: [None; 32],
        installation_generations: [0; 32],
        grants: [None; 64],
        grant_generations: [0; 64],
        runtimes: [None; 16],
        runtime_generations: [0; 16],
        data: [None; 32],
        data_generations: [0; 32],
    });
    for record in &mut state.packages {
        if cursor.get_u8()? != 0 {
            let key =
                PackageKey::from_raw(cursor.get_u64()?).ok_or(PersistentInstallError::Corrupt)?;
            let app_id = cursor.get_u64()?;
            let publisher = cursor.get_u64()?;
            let mut content = [0u8; CONTENT_BYTES];
            cursor.read_exact(&mut content)?;
            let version = cursor.get_u32()?;
            *record = Some(PackageSnapshot {
                key,
                spec: PackageSpec {
                    app_id,
                    publisher,
                    content,
                    version,
                },
            });
        }
    }
    for generation in &mut state.package_generations {
        *generation = cursor.get_u32()?;
    }
    for record in &mut state.installations {
        if cursor.get_u8()? != 0 {
            let key = InstallationKey::from_raw(cursor.get_u64()?)
                .ok_or(PersistentInstallError::Corrupt)?;
            let package =
                PackageKey::from_raw(cursor.get_u64()?).ok_or(PersistentInstallError::Corrupt)?;
            let scope = get_scope(&mut cursor)?;
            let source = get_package_source(cursor.get_u8()?)?;
            let update_authority = UpdateAuthority {
                subject: get_subject(&mut cursor)?,
            };
            let enabled = cursor.get_u8()? != 0;
            *record = Some(InstallationSnapshot {
                key,
                package,
                scope,
                source,
                update_authority,
                enabled,
            });
        }
    }
    for generation in &mut state.installation_generations {
        *generation = cursor.get_u32()?;
    }
    for record in &mut state.grants {
        if cursor.get_u8()? != 0 {
            let key =
                GrantKey::from_raw(cursor.get_u64()?).ok_or(PersistentInstallError::Corrupt)?;
            let installation = InstallationKey::from_raw(cursor.get_u64()?)
                .ok_or(PersistentInstallError::Corrupt)?;
            let subject = get_subject(&mut cursor)?;
            let rights = GrantRights(cursor.get_u32()?);
            let expires_at = if cursor.get_u8()? != 0 {
                Some(cursor.get_u64()?)
            } else {
                None
            };
            let active = cursor.get_u8()? != 0;
            *record = Some(crate::native_install::GrantSnapshot {
                key,
                installation,
                subject,
                rights,
                expires_at,
                active,
            });
        }
    }
    for generation in &mut state.grant_generations {
        *generation = cursor.get_u32()?;
    }
    for record in &mut state.runtimes {
        if cursor.get_u8()? != 0 {
            let key =
                RuntimeKey::from_raw(cursor.get_u64()?).ok_or(PersistentInstallError::Corrupt)?;
            let installation = InstallationKey::from_raw(cursor.get_u64()?)
                .ok_or(PersistentInstallError::Corrupt)?;
            let kind = get_principal_kind(cursor.get_u8()?)?;
            let subject = get_subject(&mut cursor)?;
            let generation = cursor.get_u32()?;
            let domain = DomainKey {
                id: cursor.get_u32()?,
                generation: cursor.get_u32()?,
            };
            let rights = GrantRights(cursor.get_u32()?);
            let started_at = cursor.get_u64()?;
            *record = Some(RuntimeSnapshot {
                key,
                installation,
                principal: crate::native_install::RuntimePrincipal {
                    kind,
                    subject,
                    generation,
                    domain,
                    rights,
                },
                started_at,
            });
        }
    }
    for generation in &mut state.runtime_generations {
        *generation = cursor.get_u32()?;
    }
    for record in &mut state.data {
        if cursor.get_u8()? != 0 {
            let key =
                DataKey::from_raw(cursor.get_u64()?).ok_or(PersistentInstallError::Corrupt)?;
            let package =
                PackageKey::from_raw(cursor.get_u64()?).ok_or(PersistentInstallError::Corrupt)?;
            let owner = get_subject(&mut cursor)?;
            let kind = get_data_kind(cursor.get_u8()?)?;
            *record = Some(DataSnapshot {
                key,
                package,
                owner,
                kind,
            });
        }
    }
    for generation in &mut state.data_generations {
        *generation = cursor.get_u32()?;
    }
    Ok(state)
}

trait SnapshotSink {
    fn put(&mut self, value: &[u8]) -> Result<(), PersistentInstallError>;
    fn written(&self) -> usize;

    fn put_u8(&mut self, value: u8) -> Result<(), PersistentInstallError> {
        self.put(&[value])
    }
    fn put_u32(&mut self, value: u32) -> Result<(), PersistentInstallError> {
        self.put(&value.to_le_bytes())
    }
    fn put_u64(&mut self, value: u64) -> Result<(), PersistentInstallError> {
        self.put(&value.to_le_bytes())
    }
}

struct SnapshotUnitWriter<'a, D: SectorIo> {
    device: &'a mut D,
    base: usize,
    unit: [u8; STORAGE_UNIT_BYTES],
    filled: usize,
    units_written: usize,
    written: usize,
    checksum: u32,
}

impl<'a, D: SectorIo> SnapshotUnitWriter<'a, D> {
    fn new(device: &'a mut D, base: usize) -> Self {
        Self {
            device,
            base,
            unit: [0u8; STORAGE_UNIT_BYTES],
            filled: 0,
            units_written: 0,
            written: 0,
            checksum: 0x811c_9dc5,
        }
    }

    #[inline(never)]
    fn flush_unit(&mut self) -> Result<(), PersistentInstallError> {
        if self.filled == 0 {
            return Ok(());
        }
        if self.units_written >= SLOT_BODY_UNITS {
            return Err(PersistentInstallError::SnapshotTooLarge);
        }
        self.unit[self.filled..].fill(0);
        self.device
            .write_unit(sector_for_unit(self.base + self.units_written)?, &self.unit)
            .map_err(|_| PersistentInstallError::Io)?;
        self.unit.fill(0);
        self.filled = 0;
        self.units_written += 1;
        Ok(())
    }

    #[inline(never)]
    fn finish(mut self) -> Result<u32, PersistentInstallError> {
        self.flush_unit()?;
        self.device
            .flush()
            .map_err(|_| PersistentInstallError::Io)?;
        Ok(self.checksum)
    }
}

impl<D: SectorIo> SnapshotSink for SnapshotUnitWriter<'_, D> {
    #[inline(never)]
    fn put(&mut self, value: &[u8]) -> Result<(), PersistentInstallError> {
        let end = self
            .written
            .checked_add(value.len())
            .ok_or(PersistentInstallError::SnapshotTooLarge)?;
        if end > SNAPSHOT_MAX_BYTES {
            return Err(PersistentInstallError::SnapshotTooLarge);
        }
        for byte in value {
            if self.filled == STORAGE_UNIT_BYTES {
                self.flush_unit()?;
            }
            self.unit[self.filled] = *byte;
            self.filled += 1;
            self.checksum ^= u32::from(*byte);
            self.checksum = self.checksum.wrapping_mul(0x0100_0193);
        }
        self.written = end;
        Ok(())
    }

    fn written(&self) -> usize {
        self.written
    }
}

trait SnapshotSource {
    fn read_exact(&mut self, output: &mut [u8]) -> Result<(), PersistentInstallError>;
}

struct SnapshotUnitReader<'a, D: SectorIo> {
    device: &'a mut D,
    base: usize,
    remaining: usize,
    unit_index: usize,
    unit: [u8; STORAGE_UNIT_BYTES],
    unit_len: usize,
    unit_at: usize,
}

impl<'a, D: SectorIo> SnapshotUnitReader<'a, D> {
    fn new(device: &'a mut D, base: usize, len: usize) -> Self {
        Self {
            device,
            base,
            remaining: len,
            unit_index: 0,
            unit: [0u8; STORAGE_UNIT_BYTES],
            unit_len: 0,
            unit_at: 0,
        }
    }

    fn finish(self) -> Result<(), PersistentInstallError> {
        if self.remaining == 0 {
            Ok(())
        } else {
            Err(PersistentInstallError::Corrupt)
        }
    }
}

impl<D: SectorIo> SnapshotSource for SnapshotUnitReader<'_, D> {
    fn read_exact(&mut self, output: &mut [u8]) -> Result<(), PersistentInstallError> {
        if output.len() > self.remaining {
            return Err(PersistentInstallError::Corrupt);
        }
        let mut copied = 0;
        while copied < output.len() {
            if self.unit_at == self.unit_len {
                if self.remaining == 0 || self.unit_index >= SLOT_BODY_UNITS {
                    return Err(PersistentInstallError::Corrupt);
                }
                self.device
                    .read_unit(
                        sector_for_unit(self.base + self.unit_index)?,
                        &mut self.unit,
                    )
                    .map_err(|_| PersistentInstallError::Io)?;
                self.unit_len = self.remaining.min(STORAGE_UNIT_BYTES);
                self.unit_at = 0;
                self.unit_index += 1;
            }
            let take = (output.len() - copied).min(self.unit_len - self.unit_at);
            output[copied..copied + take]
                .copy_from_slice(&self.unit[self.unit_at..self.unit_at + take]);
            copied += take;
            self.unit_at += take;
            self.remaining -= take;
        }
        Ok(())
    }
}

struct DecodeReader<'a, R: SnapshotSource> {
    source: &'a mut R,
}

impl<R: SnapshotSource> DecodeReader<'_, R> {
    fn read_exact(&mut self, output: &mut [u8]) -> Result<(), PersistentInstallError> {
        self.source.read_exact(output)
    }
    fn get_u8(&mut self) -> Result<u8, PersistentInstallError> {
        let mut bytes = [0u8; 1];
        self.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }
    fn get_u32(&mut self) -> Result<u32, PersistentInstallError> {
        let mut bytes = [0u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn get_u64(&mut self) -> Result<u64, PersistentInstallError> {
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

fn put_scope<S: SnapshotSink>(
    writer: &mut S,
    scope: OwnerScope,
) -> Result<(), PersistentInstallError> {
    let (tag, id) = match scope {
        OwnerScope::System => (0, 0),
        OwnerScope::Device(id) => (1, id),
        OwnerScope::User(id) => (2, id),
        OwnerScope::Group(id) => (3, id),
        OwnerScope::Tenant(id) => (4, id),
        OwnerScope::Workload(id) => (5, id),
    };
    writer.put_u8(tag)?;
    writer.put_u64(id)
}

fn get_scope<R: SnapshotSource>(
    reader: &mut DecodeReader<'_, R>,
) -> Result<OwnerScope, PersistentInstallError> {
    let tag = reader.get_u8()?;
    let id = reader.get_u64()?;
    match (tag, id) {
        (0, 0) => Ok(OwnerScope::System),
        (1, id) if id != 0 => Ok(OwnerScope::Device(id)),
        (2, id) if id != 0 => Ok(OwnerScope::User(id)),
        (3, id) if id != 0 => Ok(OwnerScope::Group(id)),
        (4, id) if id != 0 => Ok(OwnerScope::Tenant(id)),
        (5, id) if id != 0 => Ok(OwnerScope::Workload(id)),
        _ => Err(PersistentInstallError::Corrupt),
    }
}

fn put_subject<S: SnapshotSink>(
    writer: &mut S,
    subject: Subject,
) -> Result<(), PersistentInstallError> {
    let (tag, id) = match subject {
        Subject::System => (0, 0),
        Subject::Device(id) => (1, id),
        Subject::User(id) => (2, id),
        Subject::Group(id) => (3, id),
        Subject::Tenant(id) => (4, id),
        Subject::Workload(id) => (5, id),
        Subject::Service(id) => (6, id),
    };
    writer.put_u8(tag)?;
    writer.put_u64(id)
}

fn get_subject<R: SnapshotSource>(
    reader: &mut DecodeReader<'_, R>,
) -> Result<Subject, PersistentInstallError> {
    let tag = reader.get_u8()?;
    let id = reader.get_u64()?;
    match (tag, id) {
        (0, 0) => Ok(Subject::System),
        (1, id) if id != 0 => Ok(Subject::Device(id)),
        (2, id) if id != 0 => Ok(Subject::User(id)),
        (3, id) if id != 0 => Ok(Subject::Group(id)),
        (4, id) if id != 0 => Ok(Subject::Tenant(id)),
        (5, id) if id != 0 => Ok(Subject::Workload(id)),
        (6, id) if id != 0 => Ok(Subject::Service(id)),
        _ => Err(PersistentInstallError::Corrupt),
    }
}

fn package_source_tag(source: PackageSource) -> u8 {
    match source {
        PackageSource::SystemBuiltin => 0,
        PackageSource::Store => 1,
        PackageSource::UserImport => 2,
        PackageSource::Enterprise => 3,
        PackageSource::Developer => 4,
    }
}

fn get_package_source(tag: u8) -> Result<PackageSource, PersistentInstallError> {
    match tag {
        0 => Ok(PackageSource::SystemBuiltin),
        1 => Ok(PackageSource::Store),
        2 => Ok(PackageSource::UserImport),
        3 => Ok(PackageSource::Enterprise),
        4 => Ok(PackageSource::Developer),
        _ => Err(PersistentInstallError::Corrupt),
    }
}

fn principal_kind_tag(kind: PrincipalKind) -> u8 {
    match kind {
        PrincipalKind::User => 0,
        PrincipalKind::Service => 1,
        PrincipalKind::Workload => 2,
        PrincipalKind::Sandbox => 3,
    }
}

fn get_principal_kind(tag: u8) -> Result<PrincipalKind, PersistentInstallError> {
    match tag {
        0 => Ok(PrincipalKind::User),
        1 => Ok(PrincipalKind::Service),
        2 => Ok(PrincipalKind::Workload),
        3 => Ok(PrincipalKind::Sandbox),
        _ => Err(PersistentInstallError::Corrupt),
    }
}

fn data_kind_tag(kind: DataOwnerKind) -> u8 {
    match kind {
        DataOwnerKind::PrivateUser => 0,
        DataOwnerKind::SharedService => 1,
        DataOwnerKind::Tenant => 2,
        DataOwnerKind::Cache => 3,
    }
}

fn get_data_kind(tag: u8) -> Result<DataOwnerKind, PersistentInstallError> {
    match tag {
        0 => Ok(DataOwnerKind::PrivateUser),
        1 => Ok(DataOwnerKind::SharedService),
        2 => Ok(DataOwnerKind::Tenant),
        3 => Ok(DataOwnerKind::Cache),
        _ => Err(PersistentInstallError::Corrupt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::journal::JournalError;

    struct MemoryDisk {
        bytes: Vec<u8>,
        writes: usize,
        fail_write_at: Option<usize>,
    }

    impl MemoryDisk {
        fn new(units: usize) -> Self {
            Self {
                bytes: vec![0u8; units * STORAGE_UNIT_BYTES],
                writes: 0,
                fail_write_at: None,
            }
        }
    }

    impl SectorIo for MemoryDisk {
        fn capacity_sectors(&self) -> u64 {
            (self.bytes.len() / 512) as u64
        }

        fn read_unit(
            &mut self,
            sector: u64,
            out: &mut [u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let start = usize::try_from(sector)
                .ok()
                .and_then(|sector| sector.checked_mul(512))
                .ok_or(JournalError::Storage)?;
            let source = self
                .bytes
                .get(start..start + STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            out.copy_from_slice(source);
            Ok(())
        }

        fn write_unit(
            &mut self,
            sector: u64,
            bytes: &[u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let start = usize::try_from(sector)
                .ok()
                .and_then(|sector| sector.checked_mul(512))
                .ok_or(JournalError::Storage)?;
            let target = self
                .bytes
                .get_mut(start..start + STORAGE_UNIT_BYTES)
                .ok_or(JournalError::Storage)?;
            let write = self.writes;
            self.writes = self.writes.saturating_add(1);
            if self.fail_write_at == Some(write) {
                target[..STORAGE_UNIT_BYTES / 2].copy_from_slice(&bytes[..STORAGE_UNIT_BYTES / 2]);
                return Err(JournalError::Storage);
            }
            target.copy_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
    }

    fn package_spec(byte: u8) -> PackageSpec {
        PackageSpec {
            app_id: 0x100 + u64::from(byte),
            publisher: 7,
            content: [byte; CONTENT_BYTES],
            version: 1,
        }
    }

    fn install_spec(package: PackageKey, user: u64, source: PackageSource) -> InstallSpec {
        InstallSpec {
            package,
            scope: OwnerScope::User(user),
            source,
            update_authority: UpdateAuthority {
                subject: Subject::User(user),
            },
        }
    }

    #[test]
    fn committed_state_and_shared_bytes_survive_reopen() {
        let disk = MemoryDisk::new(TOTAL_UNITS);
        let mut store = PersistentInstallStore::format(disk).unwrap();
        let spec = package_spec(0x41);
        let package = store.install_package(spec, b"shared-package").unwrap();
        assert_eq!(store.install_package(spec, b"shared-package"), Ok(package));
        let first = store
            .install(install_spec(package, 7, PackageSource::Store))
            .unwrap();
        let second = store
            .install(install_spec(package, 8, PackageSource::Store))
            .unwrap();
        assert_eq!(
            store.install(install_spec(package, 7, PackageSource::UserImport)),
            Err(PersistentInstallError::Install(InstallError::Duplicate))
        );
        let mut bytes = [0u8; 32];
        assert_eq!(
            store.read_package_bytes(spec.content, &mut bytes),
            Ok(b"shared-package".len())
        );
        assert_eq!(&bytes[..b"shared-package".len()], b"shared-package");

        let disk = store.into_device();
        let reopened = PersistentInstallStore::open(disk).unwrap();
        assert_eq!(reopened.package(package).unwrap().spec, spec);
        assert_eq!(reopened.installation(first).unwrap().package, package);
        assert_eq!(reopened.installation(second).unwrap().package, package);
        assert_eq!(reopened.installation_count_for(package), 2);
    }

    #[test]
    fn interrupted_metadata_commit_keeps_previous_state_and_reclaims_blob() {
        let disk = MemoryDisk::new(TOTAL_UNITS);
        let mut store = PersistentInstallStore::format(disk).unwrap();
        let first = package_spec(0x31);
        let first_key = store.install_package(first, b"first").unwrap();
        let installation = store
            .install(install_spec(first_key, 7, PackageSource::Store))
            .unwrap();

        let second = package_spec(0x32);
        store.device.fail_write_at = Some(store.device.writes + BLOB_UNITS);
        assert_eq!(
            store.install_package(second, b"second"),
            Err(PersistentInstallError::Io)
        );
        assert_eq!(store.find_package(second), None);

        let disk = store.into_device();
        let mut reopened = PersistentInstallStore::open(disk).unwrap();
        assert_eq!(reopened.package(first_key).unwrap().spec, first);
        assert_eq!(
            reopened.installation(installation).unwrap().package,
            first_key
        );
        assert_eq!(reopened.find_package(second), None);
        assert_eq!(
            reopened.read_package_bytes(second.content, &mut [0u8; 32]),
            Err(PersistentInstallError::NotFound)
        );
    }

    #[test]
    fn grant_runtime_and_owned_data_are_persisted_independently() {
        let disk = MemoryDisk::new(TOTAL_UNITS);
        let mut store = PersistentInstallStore::format(disk).unwrap();
        let package = store
            .install_package(package_spec(0x51), b"application")
            .unwrap();
        let installation = store
            .install(install_spec(package, 7, PackageSource::Store))
            .unwrap();
        let grant = store
            .add_grant(GrantSpec {
                installation,
                subject: Subject::User(7),
                rights: GrantRights::DISCOVER.union(GrantRights::START),
                expires_at: None,
            })
            .unwrap();
        let actor7 = Actor::new(&[Subject::User(7)]);
        let runtime = store
            .start(
                actor7,
                installation,
                PrincipalSpec {
                    kind: PrincipalKind::User,
                    subject: Subject::User(7),
                    generation: 1,
                    domain: DomainKey {
                        id: 7,
                        generation: 1,
                    },
                },
                11,
            )
            .unwrap();
        let data = store
            .create_data(installation, Subject::User(7), DataOwnerKind::PrivateUser)
            .unwrap();

        let disk = store.into_device();
        let mut reopened = PersistentInstallStore::open(disk).unwrap();
        assert!(reopened.can_discover(actor7, installation, 12));
        assert!(reopened.can_start(actor7, installation, 12));
        assert_eq!(reopened.runtime(runtime).unwrap().started_at, 11);
        reopened.revoke_grant(grant).unwrap();
        assert!(!reopened.can_start(actor7, installation, 13));
        reopened.stop_runtime(runtime).unwrap();
        reopened.uninstall(actor7, installation).unwrap();
        assert_eq!(
            reopened.destroy_package(package),
            Err(PersistentInstallError::Install(InstallError::InUse))
        );
        reopened.destroy_data(data).unwrap();
        reopened.destroy_package(package).unwrap();
        assert_eq!(
            reopened.read_package_bytes(package_spec(0x51).content, &mut [0u8; 32]),
            Err(PersistentInstallError::NotFound)
        );
    }

    #[test]
    fn shared_package_cannot_be_deleted_until_every_registration_is_gone() {
        let disk = MemoryDisk::new(TOTAL_UNITS);
        let mut store = PersistentInstallStore::format(disk).unwrap();
        let package = store
            .install_package(package_spec(0x61), b"shared")
            .unwrap();
        let first = store
            .install(install_spec(package, 7, PackageSource::Store))
            .unwrap();
        let second = store
            .install(install_spec(package, 8, PackageSource::Store))
            .unwrap();
        let actor7 = Actor::new(&[Subject::User(7)]);
        let actor8 = Actor::new(&[Subject::User(8)]);
        store.uninstall(actor7, first).unwrap();
        assert_eq!(
            store.destroy_package(package),
            Err(PersistentInstallError::Install(InstallError::InUse))
        );
        store.uninstall(actor8, second).unwrap();
        store.destroy_package(package).unwrap();
        assert_eq!(store.installation_count_for(package), 0);
    }

    #[test]
    fn malformed_snapshot_and_invalid_package_fail_closed() {
        let disk = MemoryDisk::new(TOTAL_UNITS);
        let mut store = PersistentInstallStore::format(disk).unwrap();
        assert_eq!(
            store.install_package(
                PackageSpec {
                    app_id: 0,
                    ..package_spec(1)
                },
                b"bad",
            ),
            Err(PersistentInstallError::InvalidPackage)
        );
        let mut disk = store.into_device();
        let marker_sector = sector_for_unit(FORMAT_UNITS + SLOT_UNITS + SLOT_BODY_UNITS).unwrap();
        let start = marker_sector as usize * 512;
        disk.bytes[start + 24] ^= 0xff;
        assert!(matches!(
            PersistentInstallStore::open(disk),
            Err(PersistentInstallError::Corrupt)
        ));
    }

    #[test]
    fn reformat_discards_all_prior_state_and_package_bytes() {
        let disk = MemoryDisk::new(TOTAL_UNITS);
        let mut store = PersistentInstallStore::format(disk).unwrap();
        let old = package_spec(0x71);
        store.install_package(old, b"old-package").unwrap();

        let disk = store.into_device();
        let mut formatted = PersistentInstallStore::format(disk).unwrap();
        let state = formatted.state();
        assert!(state.packages.iter().all(Option::is_none));
        assert!(state.installations.iter().all(Option::is_none));
        assert!(state.grants.iter().all(Option::is_none));
        assert!(state.runtimes.iter().all(Option::is_none));
        assert!(state.data.iter().all(Option::is_none));
        assert_eq!(formatted.find_package(old), None);
        assert_eq!(
            formatted.read_package_bytes(old.content, &mut [0u8; 32]),
            Err(PersistentInstallError::NotFound)
        );

        let replacement = package_spec(0x72);
        let key = formatted
            .install_package(replacement, b"replacement")
            .unwrap();
        let reopened = PersistentInstallStore::open(formatted.into_device()).unwrap();
        assert_eq!(reopened.package(key).unwrap().spec, replacement);
        assert_eq!(reopened.find_package(old), None);
    }
}
