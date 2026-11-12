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
    model: Model,
    sequence: u64,
    blobs: [Option<BlobRecord>; BLOB_SLOTS],
}

impl<D: SectorIo> PersistentInstallStore<D> {
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
            model: Model::new(),
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
        let mut selected: Option<(u64, State)> = None;
        for slot in 0..2 {
            if let Some((sequence, state)) = read_slot(&mut device, slot)? {
                if selected.is_none_or(|(current, _)| sequence > current) {
                    selected = Some((sequence, state));
                }
            }
        }
        let (sequence, state) = selected.ok_or(PersistentInstallError::Corrupt)?;
        let model = Model::restore_state(state).map_err(PersistentInstallError::Install)?;
        let mut store = Self {
            device,
            model,
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

    fn commit_model(&mut self, next: Model) -> Result<(), PersistentInstallError> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(PersistentInstallError::SequenceExhausted)?;
        let state = next.snapshot_state();
        let mut encoded = [0u8; SNAPSHOT_MAX_BYTES];
        let len = encode_state(&state, &mut encoded)?;
        let slot = sequence as usize & 1;
        let base = FORMAT_UNITS + slot * SLOT_UNITS;
        for unit in 0..SLOT_BODY_UNITS {
            let mut bytes = [0u8; STORAGE_UNIT_BYTES];
            let start = unit * STORAGE_UNIT_BYTES;
            let end = (start + STORAGE_UNIT_BYTES).min(len);
            if start < len {
                bytes[..end - start].copy_from_slice(&encoded[start..end]);
            }
            self.write_unit(base + unit, &bytes)?;
        }
        self.flush()?;
        let mut marker = [0u8; STORAGE_UNIT_BYTES];
        marker[..8].copy_from_slice(SNAPSHOT_MAGIC);
        marker[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        marker[12..20].copy_from_slice(&sequence.to_le_bytes());
        marker[20..24].copy_from_slice(&(len as u32).to_le_bytes());
        marker[24..28].copy_from_slice(&checksum(&encoded[..len]).to_le_bytes());
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

fn read_slot<D: SectorIo>(
    device: &mut D,
    slot: usize,
) -> Result<Option<(u64, State)>, PersistentInstallError> {
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
    let mut encoded = [0u8; SNAPSHOT_MAX_BYTES];
    for unit in 0..SLOT_BODY_UNITS {
        let mut bytes = [0u8; STORAGE_UNIT_BYTES];
        device
            .read_unit(sector_for_unit(base + unit)?, &mut bytes)
            .map_err(|_| PersistentInstallError::Io)?;
        let start = unit * STORAGE_UNIT_BYTES;
        let end = (start + STORAGE_UNIT_BYTES).min(len);
        if start < len {
            encoded[start..end].copy_from_slice(&bytes[..end - start]);
        }
    }
    if checksum(&encoded[..len]) != expected {
        return Ok(None);
    }
    let state = decode_state(&encoded[..len])?;
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

fn encode_state(
    state: &State,
    out: &mut [u8; SNAPSHOT_MAX_BYTES],
) -> Result<usize, PersistentInstallError> {
    let mut cursor = Writer { bytes: out, at: 0 };
    cursor.put(SNAPSHOT_MAGIC)?;
    cursor.put_u32(FORMAT_VERSION)?;
    for record in &state.packages {
        cursor.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            cursor.put_u64(record.key.to_raw())?;
            cursor.put_u64(record.spec.app_id)?;
            cursor.put_u64(record.spec.publisher)?;
            cursor.put(&record.spec.content)?;
            cursor.put_u32(record.spec.version)?;
        }
    }
    for generation in state.package_generations {
        cursor.put_u32(generation)?;
    }
    for record in &state.installations {
        cursor.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            cursor.put_u64(record.key.to_raw())?;
            cursor.put_u64(record.package.to_raw())?;
            put_scope(&mut cursor, record.scope)?;
            cursor.put_u8(package_source_tag(record.source))?;
            put_subject(&mut cursor, record.update_authority.subject)?;
            cursor.put_u8(u8::from(record.enabled))?;
        }
    }
    for generation in state.installation_generations {
        cursor.put_u32(generation)?;
    }
    for record in &state.grants {
        cursor.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            cursor.put_u64(record.key.to_raw())?;
            cursor.put_u64(record.installation.to_raw())?;
            put_subject(&mut cursor, record.subject)?;
            cursor.put_u32(record.rights.0)?;
            cursor.put_u8(u8::from(record.expires_at.is_some()))?;
            if let Some(expires) = record.expires_at {
                cursor.put_u64(expires)?;
            }
            cursor.put_u8(u8::from(record.active))?;
        }
    }
    for generation in state.grant_generations {
        cursor.put_u32(generation)?;
    }
    for record in &state.runtimes {
        cursor.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            cursor.put_u64(record.key.to_raw())?;
            cursor.put_u64(record.installation.to_raw())?;
            cursor.put_u8(principal_kind_tag(record.principal.kind))?;
            put_subject(&mut cursor, record.principal.subject)?;
            cursor.put_u32(record.principal.generation)?;
            cursor.put_u32(record.principal.domain.id)?;
            cursor.put_u32(record.principal.domain.generation)?;
            cursor.put_u32(record.principal.rights.0)?;
            cursor.put_u64(record.started_at)?;
        }
    }
    for generation in state.runtime_generations {
        cursor.put_u32(generation)?;
    }
    for record in &state.data {
        cursor.put_u8(u8::from(record.is_some()))?;
        if let Some(record) = record {
            cursor.put_u64(record.key.to_raw())?;
            cursor.put_u64(record.package.to_raw())?;
            put_subject(&mut cursor, record.owner)?;
            cursor.put_u8(data_kind_tag(record.kind))?;
        }
    }
    for generation in state.data_generations {
        cursor.put_u32(generation)?;
    }
    Ok(cursor.at)
}

fn decode_state(bytes: &[u8]) -> Result<State, PersistentInstallError> {
    let mut cursor = Reader { bytes, at: 0 };
    if cursor.get(8)? != SNAPSHOT_MAGIC || cursor.get_u32()? != FORMAT_VERSION {
        return Err(PersistentInstallError::Corrupt);
    }
    let mut packages = [None; 16];
    for record in &mut packages {
        if cursor.get_u8()? != 0 {
            let key =
                PackageKey::from_raw(cursor.get_u64()?).ok_or(PersistentInstallError::Corrupt)?;
            let app_id = cursor.get_u64()?;
            let publisher = cursor.get_u64()?;
            let mut content = [0u8; CONTENT_BYTES];
            content.copy_from_slice(cursor.get(CONTENT_BYTES)?);
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
    let mut package_generations = [0u32; 16];
    for generation in &mut package_generations {
        *generation = cursor.get_u32()?;
    }
    let mut installations = [None; 32];
    for record in &mut installations {
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
    let mut installation_generations = [0u32; 32];
    for generation in &mut installation_generations {
        *generation = cursor.get_u32()?;
    }
    let mut grants = [None; 64];
    for record in &mut grants {
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
    let mut grant_generations = [0u32; 64];
    for generation in &mut grant_generations {
        *generation = cursor.get_u32()?;
    }
    let mut runtimes = [None; 16];
    for record in &mut runtimes {
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
    let mut runtime_generations = [0u32; 16];
    for generation in &mut runtime_generations {
        *generation = cursor.get_u32()?;
    }
    let mut data = [None; 32];
    for record in &mut data {
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
    let mut data_generations = [0u32; 32];
    for generation in &mut data_generations {
        *generation = cursor.get_u32()?;
    }
    if cursor.at != bytes.len() {
        return Err(PersistentInstallError::Corrupt);
    }
    Ok(State {
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
    })
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn put(&mut self, value: &[u8]) -> Result<(), PersistentInstallError> {
        let end = self
            .at
            .checked_add(value.len())
            .ok_or(PersistentInstallError::SnapshotTooLarge)?;
        if end > self.bytes.len() {
            return Err(PersistentInstallError::SnapshotTooLarge);
        }
        self.bytes[self.at..end].copy_from_slice(value);
        self.at = end;
        Ok(())
    }
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

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn get(&mut self, len: usize) -> Result<&'a [u8], PersistentInstallError> {
        let end = self
            .at
            .checked_add(len)
            .ok_or(PersistentInstallError::Corrupt)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(PersistentInstallError::Corrupt)?;
        self.at = end;
        Ok(value)
    }
    fn get_u8(&mut self) -> Result<u8, PersistentInstallError> {
        Ok(self.get(1)?[0])
    }
    fn get_u32(&mut self) -> Result<u32, PersistentInstallError> {
        Ok(u32::from_le_bytes(
            self.get(4)?
                .try_into()
                .map_err(|_| PersistentInstallError::Corrupt)?,
        ))
    }
    fn get_u64(&mut self) -> Result<u64, PersistentInstallError> {
        Ok(u64::from_le_bytes(
            self.get(8)?
                .try_into()
                .map_err(|_| PersistentInstallError::Corrupt)?,
        ))
    }
}

fn put_scope(writer: &mut Writer<'_>, scope: OwnerScope) -> Result<(), PersistentInstallError> {
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

fn get_scope(reader: &mut Reader<'_>) -> Result<OwnerScope, PersistentInstallError> {
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

fn put_subject(writer: &mut Writer<'_>, subject: Subject) -> Result<(), PersistentInstallError> {
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

fn get_subject(reader: &mut Reader<'_>) -> Result<Subject, PersistentInstallError> {
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
