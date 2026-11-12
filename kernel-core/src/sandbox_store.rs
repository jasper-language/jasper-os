//! Real block-backed root filesystem storage for Sandbox images and CoW volumes.
//!
//! Immutable image extents are written once and never exposed through a write
//! operation. A volume may override whole 4 KiB units in a private upper layer;
//! reads fall through child volume, parent volume, then image. Every overwrite
//! is staged in a different physical unit and the logical mapping is changed
//! only after the device write and quota charge succeed.
//!
//! Sandbox 镜像和写时复制卷的真实块存储后端。镜像区只写一次且没有写入接口；
//! 卷以私有 4 KiB 上层块覆盖镜像，读取顺序为子卷、父卷、镜像。每次覆盖先写
//! staging 块，设备写入和配额记账都成功后才切换逻辑映射，失败不会暴露半写
//! 数据，也不会修改旧映射。

use crate::fs::journal::{JournalError, SectorIo, SECTORS_PER_STORAGE_UNIT, STORAGE_UNIT_BYTES};
use crate::sandbox::SandboxKey;
use crate::sandbox_image::{
    ImageKey, ImageLayerSpec, ImageSnapshot, ImageSpec, SandboxStorageError, SandboxStorageTable,
    VolumeKey, VolumeSnapshot,
};
use crate::security_domain::DomainKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxStoreError {
    InvalidImage,
    InvalidVolume,
    InvalidLayer,
    InvalidLimit,
    Misaligned,
    Range,
    Capacity,
    Quota,
    InUse,
    StaleKey,
    ReadOnly,
    Io,
}

impl SandboxStoreError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidImage => "system.sandbox.store.error.image",
            Self::InvalidVolume => "system.sandbox.store.error.volume",
            Self::InvalidLayer => "system.sandbox.store.error.layer",
            Self::InvalidLimit => "system.sandbox.store.error.limit",
            Self::Misaligned => "system.sandbox.store.error.misaligned",
            Self::Range => "system.sandbox.store.error.range",
            Self::Capacity => "system.sandbox.store.error.capacity",
            Self::Quota => "system.sandbox.store.error.quota",
            Self::InUse => "system.sandbox.store.error.in_use",
            Self::StaleKey => "system.sandbox.store.error.stale_key",
            Self::ReadOnly => "system.sandbox.store.error.read_only",
            Self::Io => "system.sandbox.store.error.io",
        }
    }
}

#[derive(Clone, Copy)]
struct ImageExtent {
    key: ImageKey,
    start_unit: usize,
    units: usize,
}

#[derive(Clone, Copy)]
struct VolumeData<const W: usize> {
    key: VolumeKey,
    parent: Option<VolumeKey>,
    blocks: [Option<usize>; W],
    used_units: usize,
}

/// A bounded block store whose metadata is owned by [`SandboxStorageTable`].
///
/// `U` is the number of usable physical 4 KiB units, `R` bounds the image
/// rootfs size, and `W` bounds one writable volume. All logical mappings are
/// fixed arrays, so allocation failure cannot partially extend bookkeeping.
pub struct SandboxBlockStore<
    D: SectorIo,
    const U: usize,
    const R: usize,
    const W: usize,
    const I: usize,
    const L: usize,
    const V: usize,
> {
    device: D,
    occupied: [bool; U],
    images: [Option<ImageExtent>; I],
    volumes: [Option<VolumeData<W>>; V],
    storage: SandboxStorageTable<I, L, V>,
}

impl<
        D: SectorIo,
        const U: usize,
        const R: usize,
        const W: usize,
        const I: usize,
        const L: usize,
        const V: usize,
    > SandboxBlockStore<D, U, R, W, I, L, V>
{
    pub fn new(device: D) -> Result<Self, SandboxStoreError> {
        let needed_sectors = (U as u64)
            .checked_mul(SECTORS_PER_STORAGE_UNIT)
            .ok_or(SandboxStoreError::Capacity)?;
        if U == 0 || R == 0 || W == 0 || needed_sectors > device.capacity_sectors() {
            return Err(SandboxStoreError::Capacity);
        }
        Ok(Self {
            device,
            occupied: [false; U],
            images: [None; I],
            volumes: [None; V],
            storage: SandboxStorageTable::new(),
        })
    }

    /// Install an immutable image and its real bytes atomically.
    ///
    /// `data` must contain exactly the declared rootfs bytes. The content
    /// digest remains an externally verified identity fact, not a hash check
    /// duplicated by this storage layer.
    pub fn install_image(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        spec: ImageSpec,
        layers: &[ImageLayerSpec],
        data: &[u8],
    ) -> Result<ImageKey, SandboxStoreError> {
        if spec.rootfs_bytes == 0
            || spec.rootfs_bytes % STORAGE_UNIT_BYTES as u64 != 0
            || data.len() != spec.rootfs_bytes as usize
        {
            return Err(SandboxStoreError::Misaligned);
        }
        let units = usize::try_from(spec.rootfs_bytes / STORAGE_UNIT_BYTES as u64)
            .map_err(|_| SandboxStoreError::Capacity)?;
        if units > R {
            return Err(SandboxStoreError::Capacity);
        }
        let image_slot = self
            .images
            .iter()
            .position(Option::is_none)
            .ok_or(SandboxStoreError::Capacity)?;
        let start_unit = self
            .contiguous_free(units)
            .ok_or(SandboxStoreError::Capacity)?;
        for unit in start_unit..start_unit + units {
            self.occupied[unit] = true;
        }
        for (index, chunk) in data.chunks_exact(STORAGE_UNIT_BYTES).enumerate() {
            let mut bytes = [0u8; STORAGE_UNIT_BYTES];
            bytes.copy_from_slice(chunk);
            if self.write_physical(start_unit + index, &bytes).is_err() {
                self.release_units(start_unit, units);
                return Err(SandboxStoreError::Io);
            }
        }
        let key = match self.storage.add_image(domain, sandbox, spec, layers) {
            Ok(key) => key,
            Err(error) => {
                self.release_units(start_unit, units);
                return Err(map_storage(error));
            }
        };
        self.images[image_slot] = Some(ImageExtent {
            key,
            start_unit,
            units,
        });
        Ok(key)
    }

    pub fn image(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
    ) -> Result<ImageSnapshot, SandboxStoreError> {
        self.storage
            .image(domain, sandbox, image)
            .map_err(map_storage)
    }

    pub fn read_image_unit(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
        logical_unit: usize,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), SandboxStoreError> {
        let snapshot = self.image(domain, sandbox, image)?;
        let units = checked_units(snapshot.rootfs_bytes)?;
        if logical_unit >= units {
            return Err(SandboxStoreError::Range);
        }
        let extent = self
            .image_extent(image)
            .ok_or(SandboxStoreError::StaleKey)?;
        if logical_unit >= extent.units {
            return Err(SandboxStoreError::Range);
        }
        self.read_physical(extent.start_unit + logical_unit, out)
    }

    /// The image device is immutable. This operation exists to make the
    /// rejection explicit and testable.
    pub fn write_image_unit(
        &mut self,
        _domain: DomainKey,
        _sandbox: SandboxKey,
        _image: ImageKey,
        _logical_unit: usize,
        _bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), SandboxStoreError> {
        Err(SandboxStoreError::ReadOnly)
    }

    pub fn destroy_image(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
    ) -> Result<(), SandboxStoreError> {
        let extent = self
            .image_extent(image)
            .ok_or(SandboxStoreError::StaleKey)?;
        self.storage
            .destroy_image(domain, sandbox, image)
            .map_err(map_storage)?;
        self.release_units(extent.start_unit, extent.units);
        let slot = self
            .images
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.key == image))
            .ok_or(SandboxStoreError::StaleKey)?;
        self.images[slot] = None;
        Ok(())
    }

    pub fn create_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
        capacity_bytes: u64,
    ) -> Result<VolumeKey, SandboxStoreError> {
        self.validate_volume_layout(capacity_bytes)?;
        let slot = self
            .volumes
            .iter()
            .position(Option::is_none)
            .ok_or(SandboxStoreError::Capacity)?;
        let key = self
            .storage
            .create_volume(domain, sandbox, image, capacity_bytes)
            .map_err(map_storage)?;
        self.volumes[slot] = Some(VolumeData {
            key,
            parent: None,
            blocks: [None; W],
            used_units: 0,
        });
        Ok(key)
    }

    pub fn clone_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        parent: VolumeKey,
        capacity_bytes: u64,
    ) -> Result<VolumeKey, SandboxStoreError> {
        self.validate_volume_layout(capacity_bytes)?;
        let slot = self
            .volumes
            .iter()
            .position(Option::is_none)
            .ok_or(SandboxStoreError::Capacity)?;
        let key = self
            .storage
            .clone_volume(domain, sandbox, parent, capacity_bytes)
            .map_err(map_storage)?;
        self.volumes[slot] = Some(VolumeData {
            key,
            parent: Some(parent),
            blocks: [None; W],
            used_units: 0,
        });
        Ok(key)
    }

    pub fn volume(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        volume: VolumeKey,
    ) -> Result<VolumeSnapshot, SandboxStoreError> {
        self.storage
            .volume(domain, sandbox, volume)
            .map_err(map_storage)
    }

    pub fn read_volume_unit(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        volume: VolumeKey,
        logical_unit: usize,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), SandboxStoreError> {
        let snapshot = self.volume(domain, sandbox, volume)?;
        let image = self.image(domain, sandbox, snapshot.image)?;
        if logical_unit >= checked_units(image.rootfs_bytes)? {
            return Err(SandboxStoreError::Range);
        }
        let data = self
            .volume_data(volume)
            .ok_or(SandboxStoreError::StaleKey)?;
        if let Some(block) = data.blocks.get(logical_unit).copied().flatten() {
            return self.read_physical(block, out);
        }
        if let Some(parent) = data.parent {
            return self.read_volume_unit(domain, sandbox, parent, logical_unit, out);
        }
        let extent = self
            .image_extent(snapshot.image)
            .ok_or(SandboxStoreError::StaleKey)?;
        if logical_unit >= extent.units {
            return Err(SandboxStoreError::Range);
        }
        self.read_physical(extent.start_unit + logical_unit, out)
    }

    /// Replace one complete logical block in a private CoW upper layer.
    ///
    /// A write to a cloned child never changes the parent. A failed device
    /// write or quota charge leaves the old logical view unchanged.
    pub fn write_volume_unit(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        volume: VolumeKey,
        logical_unit: usize,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<VolumeSnapshot, SandboxStoreError> {
        let snapshot = self.volume(domain, sandbox, volume)?;
        let image = self.image(domain, sandbox, snapshot.image)?;
        if logical_unit >= checked_units(image.rootfs_bytes)? {
            return Err(SandboxStoreError::Range);
        }
        let slot = self
            .volume_slot(volume)
            .ok_or(SandboxStoreError::StaleKey)?;
        let data = self.volumes[slot]
            .as_ref()
            .ok_or(SandboxStoreError::StaleKey)?;
        if logical_unit >= data.blocks.len()
            || data.used_units >= checked_units(snapshot.capacity_bytes)?
                && data.blocks[logical_unit].is_none()
        {
            return Err(SandboxStoreError::Capacity);
        }
        let old = data.blocks[logical_unit];
        let staging = self.free_unit().ok_or(SandboxStoreError::Capacity)?;
        self.occupied[staging] = true;
        if self.write_physical(staging, bytes).is_err() {
            self.occupied[staging] = false;
            return Err(SandboxStoreError::Io);
        }
        if old.is_none() {
            if let Err(error) =
                self.storage
                    .charge_volume(domain, sandbox, volume, STORAGE_UNIT_BYTES as u64)
            {
                self.occupied[staging] = false;
                return Err(map_storage(error));
            }
        }
        let data = self.volumes[slot]
            .as_mut()
            .ok_or(SandboxStoreError::StaleKey)?;
        data.blocks[logical_unit] = Some(staging);
        if old.is_some() {
            self.occupied[old.expect("checked above")] = false;
        } else {
            data.used_units += 1;
        }
        self.volume(domain, sandbox, volume)
    }

    pub fn destroy_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        volume: VolumeKey,
    ) -> Result<(), SandboxStoreError> {
        let slot = self
            .volume_slot(volume)
            .ok_or(SandboxStoreError::StaleKey)?;
        self.storage
            .destroy_volume(domain, sandbox, volume)
            .map_err(map_storage)?;
        let data = self.volumes[slot]
            .take()
            .ok_or(SandboxStoreError::StaleKey)?;
        for block in data.blocks.iter().flatten() {
            self.occupied[*block] = false;
        }
        Ok(())
    }

    fn validate_volume_layout(&self, capacity_bytes: u64) -> Result<(), SandboxStoreError> {
        if capacity_bytes == 0 || capacity_bytes % STORAGE_UNIT_BYTES as u64 != 0 {
            return Err(SandboxStoreError::Misaligned);
        }
        if checked_units(capacity_bytes)? > W {
            return Err(SandboxStoreError::InvalidLimit);
        }
        Ok(())
    }

    fn contiguous_free(&self, units: usize) -> Option<usize> {
        if units == 0 || units > U {
            return None;
        }
        self.occupied
            .windows(units)
            .position(|window| window.iter().all(|used| !*used))
    }

    fn free_unit(&self) -> Option<usize> {
        self.occupied.iter().position(|used| !*used)
    }

    fn release_units(&mut self, start: usize, units: usize) {
        for unit in start..start.saturating_add(units).min(U) {
            self.occupied[unit] = false;
        }
    }

    fn image_extent(&self, key: ImageKey) -> Option<ImageExtent> {
        self.images
            .iter()
            .flatten()
            .find(|entry| entry.key == key)
            .copied()
    }

    fn volume_data(&self, key: VolumeKey) -> Option<VolumeData<W>> {
        self.volumes
            .iter()
            .flatten()
            .find(|entry| entry.key == key)
            .copied()
    }

    fn volume_slot(&self, key: VolumeKey) -> Option<usize> {
        self.volumes
            .iter()
            .position(|entry| entry.is_some_and(|entry| entry.key == key))
    }

    fn sector_for(&self, unit: usize) -> Result<u64, SandboxStoreError> {
        if unit >= U {
            return Err(SandboxStoreError::Range);
        }
        let sector = (unit as u64)
            .checked_mul(SECTORS_PER_STORAGE_UNIT)
            .ok_or(SandboxStoreError::Range)?;
        if sector
            .checked_add(SECTORS_PER_STORAGE_UNIT)
            .is_none_or(|end| end > self.device.capacity_sectors())
        {
            return Err(SandboxStoreError::Capacity);
        }
        Ok(sector)
    }

    fn read_physical(
        &mut self,
        unit: usize,
        out: &mut [u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), SandboxStoreError> {
        let sector = self.sector_for(unit)?;
        self.device.read_unit(sector, out).map_err(map_io)
    }

    fn write_physical(
        &mut self,
        unit: usize,
        bytes: &[u8; STORAGE_UNIT_BYTES],
    ) -> Result<(), SandboxStoreError> {
        let sector = self.sector_for(unit)?;
        self.device.write_unit(sector, bytes).map_err(map_io)
    }
}

fn checked_units(bytes: u64) -> Result<usize, SandboxStoreError> {
    if bytes == 0 || bytes % STORAGE_UNIT_BYTES as u64 != 0 {
        return Err(SandboxStoreError::Misaligned);
    }
    usize::try_from(bytes / STORAGE_UNIT_BYTES as u64).map_err(|_| SandboxStoreError::Capacity)
}

fn map_storage(error: SandboxStorageError) -> SandboxStoreError {
    match error {
        SandboxStorageError::InvalidImage => SandboxStoreError::InvalidImage,
        SandboxStorageError::InvalidVolume => SandboxStoreError::InvalidVolume,
        SandboxStorageError::InvalidLayer => SandboxStoreError::InvalidLayer,
        SandboxStorageError::InvalidLimit => SandboxStoreError::InvalidLimit,
        SandboxStorageError::Capacity => SandboxStoreError::Capacity,
        SandboxStorageError::Quota => SandboxStoreError::Quota,
        SandboxStorageError::InUse => SandboxStoreError::InUse,
        SandboxStorageError::IdExhausted => SandboxStoreError::StaleKey,
    }
}

fn map_io(_: JournalError) -> SandboxStoreError {
    SandboxStoreError::Io
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxTable;
    use crate::sandbox_image::{ContentDigest, ImageVersion, SignedImage};
    use crate::workload::{ResourceLimits, WorkloadTable};

    const TEST_BYTES: usize = 16 * STORAGE_UNIT_BYTES;

    struct TestDisk {
        bytes: [u8; TEST_BYTES],
        writes: usize,
        fail_write: Option<usize>,
    }

    impl TestDisk {
        fn new(fill: u8) -> Self {
            Self {
                bytes: [fill; TEST_BYTES],
                writes: 0,
                fail_write: None,
            }
        }
    }

    impl SectorIo for TestDisk {
        fn capacity_sectors(&self) -> u64 {
            (TEST_BYTES / crate::block::SECTOR_BYTES as usize) as u64
        }

        fn read_unit(
            &mut self,
            sector: u64,
            out: &mut [u8; STORAGE_UNIT_BYTES],
        ) -> Result<(), JournalError> {
            let start = sector as usize * crate::block::SECTOR_BYTES as usize;
            let end = start + STORAGE_UNIT_BYTES;
            let source = self.bytes.get(start..end).ok_or(JournalError::Storage)?;
            out.copy_from_slice(source);
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
            let start = sector as usize * crate::block::SECTOR_BYTES as usize;
            let end = start + STORAGE_UNIT_BYTES;
            self.bytes
                .get_mut(start..end)
                .ok_or(JournalError::Storage)?
                .copy_from_slice(bytes);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), JournalError> {
            Ok(())
        }
    }

    const LIMITS: ResourceLimits = ResourceLimits {
        cpu_permille: 100,
        memory_bytes: 4096,
        threads: 1,
        ring_entries: 1,
        io_bytes: 4096,
        io_ops: 8,
    };

    fn domain() -> DomainKey {
        DomainKey {
            id: 7,
            generation: 1,
        }
    }

    fn sandbox(domain: DomainKey) -> SandboxKey {
        let mut workloads = WorkloadTable::<2>::new();
        let mut sandboxes = SandboxTable::<2>::new();
        let key = sandboxes.create(&mut workloads, domain, LIMITS).unwrap();
        core::mem::forget(sandboxes);
        core::mem::forget(workloads);
        key
    }

    fn digest(byte: u8) -> ContentDigest {
        ContentDigest::new([byte; 32]).unwrap()
    }

    fn image_spec() -> ImageSpec {
        ImageSpec {
            image: SignedImage {
                content: digest(1),
                signer: 9,
                signature: digest(2),
                version: ImageVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            },
            rootfs_bytes: (2 * STORAGE_UNIT_BYTES) as u64,
            writable_bytes: (4 * STORAGE_UNIT_BYTES) as u64,
            max_volumes: 4,
        }
    }

    fn layer() -> [ImageLayerSpec; 1] {
        [ImageLayerSpec {
            content: digest(3),
            bytes: (2 * STORAGE_UNIT_BYTES) as u64,
        }]
    }

    fn store() -> SandboxBlockStore<TestDisk, 10, 2, 4, 1, 2, 2> {
        SandboxBlockStore::new(TestDisk::new(0)).unwrap()
    }

    #[test]
    fn image_is_real_read_only_block_storage() {
        let domain = domain();
        let sandbox = sandbox(domain);
        let mut store = store();
        let mut data = [0u8; 2 * STORAGE_UNIT_BYTES];
        data[0] = 0x11;
        data[STORAGE_UNIT_BYTES] = 0x22;
        let image = store
            .install_image(domain, sandbox, image_spec(), &layer(), &data)
            .unwrap();
        let mut unit = [0u8; STORAGE_UNIT_BYTES];
        store
            .read_image_unit(domain, sandbox, image, 1, &mut unit)
            .unwrap();
        assert_eq!(unit[0], 0x22);
        let replacement = [0xaa; STORAGE_UNIT_BYTES];
        assert_eq!(
            store.write_image_unit(domain, sandbox, image, 0, &replacement),
            Err(SandboxStoreError::ReadOnly)
        );
        store
            .read_image_unit(domain, sandbox, image, 0, &mut unit)
            .unwrap();
        assert_eq!(unit[0], 0x11);
    }

    #[test]
    fn volume_overlay_and_clone_preserve_parents() {
        let domain = domain();
        let sandbox = sandbox(domain);
        let mut store = store();
        let data = [0x10u8; 2 * STORAGE_UNIT_BYTES];
        let image = store
            .install_image(domain, sandbox, image_spec(), &layer(), &data)
            .unwrap();
        let parent = store
            .create_volume(domain, sandbox, image, (2 * STORAGE_UNIT_BYTES) as u64)
            .unwrap();
        let mut unit = [0u8; STORAGE_UNIT_BYTES];
        store
            .read_volume_unit(domain, sandbox, parent, 0, &mut unit)
            .unwrap();
        assert_eq!(unit, [0x10; STORAGE_UNIT_BYTES]);
        store
            .write_volume_unit(domain, sandbox, parent, 0, &[0x20; STORAGE_UNIT_BYTES])
            .unwrap();
        let child = store
            .clone_volume(domain, sandbox, parent, (2 * STORAGE_UNIT_BYTES) as u64)
            .unwrap();
        store
            .read_volume_unit(domain, sandbox, child, 0, &mut unit)
            .unwrap();
        assert_eq!(unit, [0x20; STORAGE_UNIT_BYTES]);
        store
            .write_volume_unit(domain, sandbox, child, 0, &[0x30; STORAGE_UNIT_BYTES])
            .unwrap();
        store
            .read_volume_unit(domain, sandbox, parent, 0, &mut unit)
            .unwrap();
        assert_eq!(unit, [0x20; STORAGE_UNIT_BYTES]);
        store
            .read_image_unit(domain, sandbox, image, 0, &mut unit)
            .unwrap();
        assert_eq!(unit, [0x10; STORAGE_UNIT_BYTES]);
    }

    #[test]
    fn failed_overwrite_keeps_old_mapping_and_quota() {
        let domain = domain();
        let sandbox = sandbox(domain);
        let mut store = store();
        let image = store
            .install_image(
                domain,
                sandbox,
                image_spec(),
                &layer(),
                &[0x40; 2 * STORAGE_UNIT_BYTES],
            )
            .unwrap();
        let volume = store
            .create_volume(domain, sandbox, image, (2 * STORAGE_UNIT_BYTES) as u64)
            .unwrap();
        store
            .write_volume_unit(domain, sandbox, volume, 0, &[0x50; STORAGE_UNIT_BYTES])
            .unwrap();
        store.device.fail_write = Some(store.device.writes);
        assert_eq!(
            store.write_volume_unit(domain, sandbox, volume, 0, &[0x60; STORAGE_UNIT_BYTES],),
            Err(SandboxStoreError::Io)
        );
        let mut unit = [0u8; STORAGE_UNIT_BYTES];
        store
            .read_volume_unit(domain, sandbox, volume, 0, &mut unit)
            .unwrap();
        assert_eq!(unit, [0x50; STORAGE_UNIT_BYTES]);
        assert_eq!(
            store.volume(domain, sandbox, volume).unwrap().used_bytes,
            STORAGE_UNIT_BYTES as u64
        );
    }

    #[test]
    fn ranges_alignment_and_parent_lifetime_fail_closed() {
        let domain = domain();
        let sandbox = sandbox(domain);
        let mut store = store();
        let image = store
            .install_image(
                domain,
                sandbox,
                image_spec(),
                &layer(),
                &[0x70; 2 * STORAGE_UNIT_BYTES],
            )
            .unwrap();
        assert_eq!(
            store.create_volume(domain, sandbox, image, 1),
            Err(SandboxStoreError::Misaligned)
        );
        let parent = store
            .create_volume(domain, sandbox, image, (2 * STORAGE_UNIT_BYTES) as u64)
            .unwrap();
        let child = store
            .clone_volume(domain, sandbox, parent, (2 * STORAGE_UNIT_BYTES) as u64)
            .unwrap();
        let mut unit = [0u8; STORAGE_UNIT_BYTES];
        assert_eq!(
            store.read_volume_unit(domain, sandbox, child, 2, &mut unit),
            Err(SandboxStoreError::Range)
        );
        assert_eq!(
            store.destroy_volume(domain, sandbox, parent),
            Err(SandboxStoreError::InUse)
        );
        store.destroy_volume(domain, sandbox, child).unwrap();
        store.destroy_volume(domain, sandbox, parent).unwrap();
        assert_eq!(
            store.read_volume_unit(domain, sandbox, parent, 0, &mut unit),
            Err(SandboxStoreError::InvalidVolume)
        );
        store.destroy_image(domain, sandbox, image).unwrap();
    }
}
