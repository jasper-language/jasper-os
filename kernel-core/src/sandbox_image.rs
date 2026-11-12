//! Bounded Sandbox image, immutable-layer and copy-on-write volume contracts.
//!
//! This module models storage identity and ownership only. It does not parse
//! image bytes, implement a filesystem, or treat a logical path as authority.
//! An image instance is visible only through its owning security domain and
//! Sandbox. Writable volume state is independent from immutable image layers.
//!
//! 本模块只定义 Sandbox 镜像、不可变层与写时复制卷的身份和所有权契约。
//! 不解析镜像字节、不实现文件系统，也不把逻辑路径当作授权凭证。镜像实例
//! 仅对所属安全域和 Sandbox 可见；卷的可写状态与镜像只读层完全分离。

use crate::sandbox::SandboxKey;
use crate::security_domain::DomainKey;

pub const DIGEST_BYTES: usize = 32;
pub const MAX_IMAGE_LAYERS: usize = 16;

/// A non-zero content digest. Verification is supplied by the caller before
/// this value enters the registry; equality is identity comparison, not proof.
///
/// 非零内容摘要。调用者在进入注册表前完成验证；相等仅表示身份比较，不是
/// 密码学证明。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentDigest([u8; DIGEST_BYTES]);

impl ContentDigest {
    pub fn new(bytes: [u8; DIGEST_BYTES]) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    pub const fn bytes(self) -> [u8; DIGEST_BYTES] {
        self.0
    }
}

impl Default for ContentDigest {
    fn default() -> Self {
        Self([0; DIGEST_BYTES])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ImageVersion {
    const fn is_valid(self) -> bool {
        self.major != 0
    }
}

/// Signed content identity and format version. `signer` is the immutable
/// publisher identity; `signature` is the verified signature digest.
///
/// 已签名内容身份与格式版本。`signer` 是不可变发布者身份，`signature` 是
/// 已验证的签名摘要。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedImage {
    pub content: ContentDigest,
    pub signer: u64,
    pub signature: ContentDigest,
    pub version: ImageVersion,
}

impl SignedImage {
    const fn is_valid(self) -> bool {
        self.signer != 0 && self.version.is_valid()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageSpec {
    pub image: SignedImage,
    pub rootfs_bytes: u64,
    pub writable_bytes: u64,
    pub max_volumes: u16,
}

impl ImageSpec {
    const fn is_valid(self) -> bool {
        self.image.is_valid()
            && self.rootfs_bytes != 0
            && self.writable_bytes != 0
            && self.max_volumes != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageLayerSpec {
    pub content: ContentDigest,
    pub bytes: u64,
}

impl Default for ImageLayerSpec {
    fn default() -> Self {
        Self {
            content: ContentDigest::default(),
            bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxStorageError {
    InvalidImage,
    InvalidVolume,
    InvalidLayer,
    InvalidLimit,
    Capacity,
    IdExhausted,
    Quota,
    InUse,
}

impl SandboxStorageError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidImage => "system.sandbox.image.error.not_found",
            Self::InvalidVolume => "system.sandbox.volume.error.not_found",
            Self::InvalidLayer => "system.sandbox.image.error.layer",
            Self::InvalidLimit => "system.sandbox.storage.error.limit",
            Self::Capacity => "system.sandbox.storage.error.capacity",
            Self::IdExhausted => "system.sandbox.storage.error.ids_exhausted",
            Self::Quota => "system.sandbox.volume.error.quota",
            Self::InUse => "system.sandbox.storage.error.in_use",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageKey {
    slot: u16,
    generation: u32,
}

impl ImageKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeKey {
    slot: u16,
    generation: u32,
}

impl VolumeKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageSnapshot {
    pub key: ImageKey,
    pub image: SignedImage,
    pub rootfs_bytes: u64,
    pub writable_bytes: u64,
    pub max_volumes: u16,
    pub volumes: u16,
    pub layers: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerSnapshot {
    pub content: ContentDigest,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeSnapshot {
    pub key: VolumeKey,
    pub image: ImageKey,
    pub parent: Option<VolumeKey>,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Clone, Copy)]
struct ImageRecord {
    key: ImageKey,
    domain: DomainKey,
    sandbox: SandboxKey,
    spec: ImageSpec,
    layer_start: u16,
    layer_count: u16,
    volumes: u16,
}

#[derive(Clone, Copy)]
struct LayerRecord {
    spec: ImageLayerSpec,
}

#[derive(Clone, Copy)]
struct VolumeRecord {
    key: VolumeKey,
    domain: DomainKey,
    sandbox: SandboxKey,
    image: ImageKey,
    parent: Option<VolumeKey>,
    capacity_bytes: u64,
    used_bytes: u64,
}

/// Fixed-capacity storage registry. Rejections perform no partial writes.
///
/// 固定容量存储注册表；任何拒绝都不产生部分写入。
pub struct SandboxStorageTable<const I: usize, const L: usize, const V: usize> {
    images: [Option<ImageRecord>; I],
    image_generations: [u32; I],
    layers: [Option<LayerRecord>; L],
    volumes: [Option<VolumeRecord>; V],
    volume_generations: [u32; V],
}

impl<const I: usize, const L: usize, const V: usize> SandboxStorageTable<I, L, V> {
    pub const fn new() -> Self {
        Self {
            images: [None; I],
            image_generations: [0; I],
            layers: [None; L],
            volumes: [None; V],
            volume_generations: [0; V],
        }
    }

    /// Register one immutable image and all of its signed layers atomically.
    ///
    /// 原子登记一个不可变镜像及其全部已签名层。
    pub fn add_image(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        spec: ImageSpec,
        layers: &[ImageLayerSpec],
    ) -> Result<ImageKey, SandboxStorageError> {
        if !domain.is_valid() || !spec.is_valid() {
            return Err(SandboxStorageError::InvalidImage);
        }
        if layers.is_empty() || layers.len() > MAX_IMAGE_LAYERS {
            return Err(SandboxStorageError::InvalidLayer);
        }
        let mut total = 0u64;
        for layer in layers {
            if layer.bytes == 0 {
                return Err(SandboxStorageError::InvalidLayer);
            }
            total = total
                .checked_add(layer.bytes)
                .ok_or(SandboxStorageError::InvalidLayer)?;
        }
        if total != spec.rootfs_bytes {
            return Err(SandboxStorageError::InvalidLayer);
        }

        let (slot, generation) = self.vacant_image()?;
        let layer_count = u16::try_from(layers.len()).map_err(|_| SandboxStorageError::Capacity)?;
        let start = self
            .layers
            .windows(layers.len())
            .position(|window| window.iter().all(Option::is_none))
            .ok_or(SandboxStorageError::Capacity)?;
        if start > u16::MAX as usize {
            return Err(SandboxStorageError::Capacity);
        }

        for (offset, layer) in layers.iter().copied().enumerate() {
            self.layers[start + offset] = Some(LayerRecord { spec: layer });
        }
        let key = ImageKey {
            slot: slot as u16,
            generation,
        };
        self.image_generations[slot] = generation;
        self.images[slot] = Some(ImageRecord {
            key,
            domain,
            sandbox,
            spec,
            layer_start: start as u16,
            layer_count,
            volumes: 0,
        });
        Ok(key)
    }

    /// Remove an immutable image after all of its volumes are gone.
    ///
    /// 所有卷销毁后删除不可变镜像及其层；旧 key 永不复活。
    pub fn destroy_image(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: ImageKey,
    ) -> Result<(), SandboxStorageError> {
        let slot = self.image_slot(domain, sandbox, key)?;
        let record = self.images[slot].ok_or(SandboxStorageError::InvalidImage)?;
        if record.volumes != 0 {
            return Err(SandboxStorageError::InUse);
        }
        let start = record.layer_start as usize;
        let end = start + record.layer_count as usize;
        if self.layers.get(start..end).is_none() {
            return Err(SandboxStorageError::InvalidImage);
        }
        for layer in &mut self.layers[start..end] {
            *layer = None;
        }
        self.images[slot] = None;
        Ok(())
    }

    /// Query an image only through its owning domain and Sandbox.
    ///
    /// 仅通过所属安全域与 Sandbox 查询镜像。
    pub fn image(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: ImageKey,
    ) -> Result<ImageSnapshot, SandboxStorageError> {
        let record = self.image_record(domain, sandbox, key)?;
        Ok(ImageSnapshot {
            key,
            image: record.spec.image,
            rootfs_bytes: record.spec.rootfs_bytes,
            writable_bytes: record.spec.writable_bytes,
            max_volumes: record.spec.max_volumes,
            volumes: record.volumes,
            layers: record.layer_count,
        })
    }

    /// Read an immutable lower layer through the owning image principal.
    ///
    /// 通过镜像所有者读取一个不可变下层。
    pub fn image_layer(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
        index: u16,
    ) -> Result<LayerSnapshot, SandboxStorageError> {
        let record = self.image_record(domain, sandbox, image)?;
        if index >= record.layer_count {
            return Err(SandboxStorageError::InvalidLayer);
        }
        let slot = record.layer_start as usize + index as usize;
        self.layers
            .get(slot)
            .and_then(|entry| entry.as_ref())
            .map(|entry| LayerSnapshot {
                content: entry.spec.content,
                bytes: entry.spec.bytes,
            })
            .ok_or(SandboxStorageError::InvalidLayer)
    }

    /// Create a writable upper volume over an immutable image.
    ///
    /// 在不可变镜像上创建可写上层卷。
    pub fn create_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
        capacity_bytes: u64,
    ) -> Result<VolumeKey, SandboxStorageError> {
        self.create_volume_inner(domain, sandbox, image, capacity_bytes, None)
    }

    /// Derive an independent copy-on-write volume from an existing volume.
    /// The child starts with its own empty writable upper; reads may fall
    /// through to the parent until the upper layer is populated.
    ///
    /// 从现有卷派生独立 CoW 卷；子卷拥有空的可写上层，上层尚未填充时可
    /// 回溯父卷。父子身份与资源记账保持独立。
    pub fn clone_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        parent: VolumeKey,
        capacity_bytes: u64,
    ) -> Result<VolumeKey, SandboxStorageError> {
        let parent_record = self.volume_record(domain, sandbox, parent)?;
        self.create_volume_inner(
            domain,
            sandbox,
            parent_record.image,
            capacity_bytes,
            Some(parent),
        )
    }

    fn create_volume_inner(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        image: ImageKey,
        capacity_bytes: u64,
        parent: Option<VolumeKey>,
    ) -> Result<VolumeKey, SandboxStorageError> {
        let image_slot = self.image_slot(domain, sandbox, image)?;
        let image_record = self.images[image_slot]
            .as_ref()
            .ok_or(SandboxStorageError::InvalidImage)?;
        if capacity_bytes == 0 || capacity_bytes > image_record.spec.writable_bytes {
            return Err(SandboxStorageError::InvalidLimit);
        }
        if image_record.volumes >= image_record.spec.max_volumes {
            return Err(SandboxStorageError::Capacity);
        }
        let (slot, generation) = self.vacant_volume()?;
        let key = VolumeKey {
            slot: slot as u16,
            generation,
        };
        self.volume_generations[slot] = generation;
        self.volumes[slot] = Some(VolumeRecord {
            key,
            domain,
            sandbox,
            image,
            parent,
            capacity_bytes,
            used_bytes: 0,
        });
        self.images[image_slot]
            .as_mut()
            .expect("checked image")
            .volumes += 1;
        Ok(key)
    }

    pub fn volume(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: VolumeKey,
    ) -> Result<VolumeSnapshot, SandboxStorageError> {
        let record = self.volume_record(domain, sandbox, key)?;
        Ok(VolumeSnapshot {
            key,
            image: record.image,
            parent: record.parent,
            capacity_bytes: record.capacity_bytes,
            used_bytes: record.used_bytes,
        })
    }

    /// Charge writable upper-layer bytes without affecting ancestors.
    ///
    /// 对可写上层记账，不影响任何祖先卷。
    pub fn charge_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: VolumeKey,
        bytes: u64,
    ) -> Result<VolumeSnapshot, SandboxStorageError> {
        let slot = self.volume_slot(domain, sandbox, key)?;
        let record = self.volumes[slot]
            .as_mut()
            .ok_or(SandboxStorageError::InvalidVolume)?;
        let next = record
            .used_bytes
            .checked_add(bytes)
            .ok_or(SandboxStorageError::Quota)?;
        if next > record.capacity_bytes {
            return Err(SandboxStorageError::Quota);
        }
        record.used_bytes = next;
        Ok(VolumeSnapshot {
            key,
            image: record.image,
            parent: record.parent,
            capacity_bytes: record.capacity_bytes,
            used_bytes: record.used_bytes,
        })
    }

    /// Release writable upper-layer bytes without affecting the image.
    ///
    /// 归还可写上层空间，不影响不可变镜像。
    pub fn release_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: VolumeKey,
        bytes: u64,
    ) -> Result<VolumeSnapshot, SandboxStorageError> {
        let slot = self.volume_slot(domain, sandbox, key)?;
        let record = self.volumes[slot]
            .as_mut()
            .ok_or(SandboxStorageError::InvalidVolume)?;
        let next = record
            .used_bytes
            .checked_sub(bytes)
            .ok_or(SandboxStorageError::Quota)?;
        record.used_bytes = next;
        Ok(VolumeSnapshot {
            key,
            image: record.image,
            parent: record.parent,
            capacity_bytes: record.capacity_bytes,
            used_bytes: record.used_bytes,
        })
    }

    /// Destroy a volume only when no CoW child references it.
    ///
    /// 仅在没有 CoW 子卷引用时销毁卷。
    pub fn destroy_volume(
        &mut self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: VolumeKey,
    ) -> Result<(), SandboxStorageError> {
        let slot = self.volume_slot(domain, sandbox, key)?;
        if self
            .volumes
            .iter()
            .flatten()
            .any(|volume| volume.parent == Some(key))
        {
            return Err(SandboxStorageError::InUse);
        }
        let image = self.volumes[slot]
            .as_ref()
            .ok_or(SandboxStorageError::InvalidVolume)?
            .image;
        self.volumes[slot] = None;
        let image_slot = self
            .images
            .iter()
            .position(|record| record.is_some_and(|record| record.key == image))
            .ok_or(SandboxStorageError::InvalidImage)?;
        self.images[image_slot]
            .as_mut()
            .expect("checked image")
            .volumes -= 1;
        Ok(())
    }

    pub fn image_count(&self) -> usize {
        self.images.iter().flatten().count()
    }

    pub fn volume_count(&self) -> usize {
        self.volumes.iter().flatten().count()
    }

    /// True when destroying this Sandbox identity would orphan storage.
    pub fn has_storage_for(&self, sandbox: SandboxKey) -> bool {
        self.images
            .iter()
            .flatten()
            .any(|image| image.sandbox == sandbox)
            || self
                .volumes
                .iter()
                .flatten()
                .any(|volume| volume.sandbox == sandbox)
    }

    fn image_record(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: ImageKey,
    ) -> Result<ImageRecord, SandboxStorageError> {
        let slot = self.image_slot(domain, sandbox, key)?;
        self.images[slot].ok_or(SandboxStorageError::InvalidImage)
    }

    fn image_slot(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: ImageKey,
    ) -> Result<usize, SandboxStorageError> {
        self.images
            .get(key.slot as usize)
            .and_then(|entry| *entry)
            .filter(|record| {
                record.key == key && record.domain == domain && record.sandbox == sandbox
            })
            .map(|_| key.slot as usize)
            .ok_or(SandboxStorageError::InvalidImage)
    }

    fn volume_record(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: VolumeKey,
    ) -> Result<VolumeRecord, SandboxStorageError> {
        let slot = self.volume_slot(domain, sandbox, key)?;
        self.volumes[slot].ok_or(SandboxStorageError::InvalidVolume)
    }

    fn volume_slot(
        &self,
        domain: DomainKey,
        sandbox: SandboxKey,
        key: VolumeKey,
    ) -> Result<usize, SandboxStorageError> {
        self.volumes
            .get(key.slot as usize)
            .and_then(|entry| *entry)
            .filter(|record| {
                record.key == key && record.domain == domain && record.sandbox == sandbox
            })
            .map(|_| key.slot as usize)
            .ok_or(SandboxStorageError::InvalidVolume)
    }

    fn vacant_image(&self) -> Result<(usize, u32), SandboxStorageError> {
        let slot = self
            .images
            .iter()
            .position(Option::is_none)
            .ok_or(SandboxStorageError::Capacity)?;
        if slot > u16::MAX as usize {
            return Err(SandboxStorageError::Capacity);
        }
        let generation = self.image_generations[slot]
            .checked_add(1)
            .ok_or(SandboxStorageError::IdExhausted)?;
        Ok((slot, generation))
    }

    fn vacant_volume(&self) -> Result<(usize, u32), SandboxStorageError> {
        let slot = self
            .volumes
            .iter()
            .position(Option::is_none)
            .ok_or(SandboxStorageError::Capacity)?;
        if slot > u16::MAX as usize {
            return Err(SandboxStorageError::Capacity);
        }
        let generation = self.volume_generations[slot]
            .checked_add(1)
            .ok_or(SandboxStorageError::IdExhausted)?;
        Ok((slot, generation))
    }
}

impl<const I: usize, const L: usize, const V: usize> Default for SandboxStorageTable<I, L, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxTable;
    use crate::workload::{ResourceLimits, WorkloadTable};

    const LIMITS: ResourceLimits = ResourceLimits {
        cpu_permille: 100,
        memory_bytes: 4096,
        threads: 1,
        ring_entries: 1,
        io_bytes: 4096,
        io_ops: 8,
    };

    fn domain(id: u32) -> DomainKey {
        DomainKey { id, generation: 1 }
    }

    fn sandbox(domain: DomainKey, workloads: &mut WorkloadTable<2>) -> SandboxKey {
        let mut sandboxes = SandboxTable::<2>::new();
        let key = sandboxes.create(workloads, domain, LIMITS).unwrap();
        // Leak only the table in the test harness by returning its stable key.
        core::mem::forget(sandboxes);
        key
    }

    fn digest(seed: u8) -> ContentDigest {
        ContentDigest::new([seed; DIGEST_BYTES]).unwrap()
    }

    fn spec(max_volumes: u16) -> ImageSpec {
        ImageSpec {
            image: SignedImage {
                content: digest(1),
                signer: 7,
                signature: digest(2),
                version: ImageVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            },
            rootfs_bytes: 12,
            writable_bytes: 100,
            max_volumes,
        }
    }

    fn layers() -> [ImageLayerSpec; 2] {
        [
            ImageLayerSpec {
                content: digest(3),
                bytes: 5,
            },
            ImageLayerSpec {
                content: digest(4),
                bytes: 7,
            },
        ]
    }

    #[test]
    fn image_creation_is_validated_and_failure_atomic() {
        let domain = domain(1);
        let mut workloads = WorkloadTable::<2>::new();
        let sandbox = sandbox(domain, &mut workloads);
        let mut storage = SandboxStorageTable::<1, 2, 1>::new();
        assert_eq!(
            storage.add_image(
                domain,
                sandbox,
                ImageSpec {
                    max_volumes: 0,
                    ..spec(1)
                },
                &layers()
            ),
            Err(SandboxStorageError::InvalidImage)
        );
        assert_eq!(storage.image_count(), 0);

        let mut short = layers();
        short[1].bytes = 6;
        assert_eq!(
            storage.add_image(domain, sandbox, spec(1), &short),
            Err(SandboxStorageError::InvalidLayer)
        );
        assert_eq!(storage.image_count(), 0);

        let image = storage
            .add_image(domain, sandbox, spec(1), &layers())
            .unwrap();
        let snapshot = storage.image(domain, sandbox, image).unwrap();
        assert_eq!(snapshot.layers, 2);
        assert_eq!(
            storage
                .image_layer(domain, sandbox, image, 1)
                .unwrap()
                .bytes,
            7
        );
    }

    #[test]
    fn wrong_domain_or_sandbox_is_indistinguishable_from_missing() {
        let owner_domain = domain(1);
        let other_domain = domain(2);
        let mut workloads = WorkloadTable::<2>::new();
        let owner_sandbox = sandbox(owner_domain, &mut workloads);
        let other_sandbox = sandbox(other_domain, &mut workloads);
        let mut storage = SandboxStorageTable::<1, 2, 1>::new();
        let image = storage
            .add_image(owner_domain, owner_sandbox, spec(1), &layers())
            .unwrap();
        let volume = storage
            .create_volume(owner_domain, owner_sandbox, image, 64)
            .unwrap();

        assert_eq!(
            storage.image(other_domain, other_sandbox, image),
            Err(SandboxStorageError::InvalidImage)
        );
        assert_eq!(
            storage.volume(other_domain, other_sandbox, volume),
            Err(SandboxStorageError::InvalidVolume)
        );
        assert_eq!(
            storage.charge_volume(other_domain, other_sandbox, volume, 1),
            Err(SandboxStorageError::InvalidVolume)
        );
    }

    #[test]
    fn cow_clone_has_independent_upper_state_and_parent_lifetime() {
        let domain = domain(1);
        let mut workloads = WorkloadTable::<2>::new();
        let sandbox = sandbox(domain, &mut workloads);
        let mut storage = SandboxStorageTable::<1, 2, 2>::new();
        let image = storage
            .add_image(domain, sandbox, spec(2), &layers())
            .unwrap();
        let parent = storage.create_volume(domain, sandbox, image, 64).unwrap();
        storage.charge_volume(domain, sandbox, parent, 40).unwrap();
        let child = storage.clone_volume(domain, sandbox, parent, 32).unwrap();
        assert_eq!(
            storage.volume(domain, sandbox, child).unwrap().parent,
            Some(parent)
        );
        assert_eq!(
            storage.volume(domain, sandbox, child).unwrap().used_bytes,
            0
        );
        storage.charge_volume(domain, sandbox, child, 9).unwrap();
        assert_eq!(
            storage.volume(domain, sandbox, parent).unwrap().used_bytes,
            40
        );
        assert_eq!(
            storage.destroy_volume(domain, sandbox, parent),
            Err(SandboxStorageError::InUse)
        );
        storage.destroy_volume(domain, sandbox, child).unwrap();
        storage.destroy_volume(domain, sandbox, parent).unwrap();
    }

    #[test]
    fn quota_and_capacity_rejections_do_not_mutate_usage() {
        let domain = domain(1);
        let mut workloads = WorkloadTable::<2>::new();
        let sandbox = sandbox(domain, &mut workloads);
        let mut storage = SandboxStorageTable::<1, 2, 1>::new();
        let image = storage
            .add_image(domain, sandbox, spec(1), &layers())
            .unwrap();
        let volume = storage.create_volume(domain, sandbox, image, 10).unwrap();
        storage.charge_volume(domain, sandbox, volume, 7).unwrap();
        assert_eq!(
            storage.charge_volume(domain, sandbox, volume, 4),
            Err(SandboxStorageError::Quota)
        );
        assert_eq!(
            storage.volume(domain, sandbox, volume).unwrap().used_bytes,
            7
        );
        assert_eq!(
            storage.create_volume(domain, sandbox, image, 1),
            Err(SandboxStorageError::Capacity)
        );
    }

    #[test]
    fn destroyed_volume_generation_never_revives() {
        let domain = domain(1);
        let mut workloads = WorkloadTable::<2>::new();
        let sandbox = sandbox(domain, &mut workloads);
        let mut storage = SandboxStorageTable::<1, 2, 1>::new();
        let image = storage
            .add_image(domain, sandbox, spec(2), &layers())
            .unwrap();
        let old = storage.create_volume(domain, sandbox, image, 8).unwrap();
        storage.destroy_volume(domain, sandbox, old).unwrap();
        let new = storage.create_volume(domain, sandbox, image, 8).unwrap();
        assert_ne!(old, new);
        assert_eq!(
            storage.volume(domain, sandbox, old),
            Err(SandboxStorageError::InvalidVolume)
        );
    }

    #[test]
    fn layer_and_image_capacity_fail_without_partial_registration() {
        let domain = domain(1);
        let mut workloads = WorkloadTable::<2>::new();
        let sandbox = sandbox(domain, &mut workloads);
        let mut storage = SandboxStorageTable::<1, 17, 1>::new();
        let mut many = [ImageLayerSpec {
            content: digest(5),
            bytes: 1,
        }; MAX_IMAGE_LAYERS + 1];
        for (index, layer) in many.iter_mut().enumerate() {
            layer.content = digest(index as u8 + 10);
        }
        let too_large = ImageSpec {
            rootfs_bytes: many.len() as u64,
            ..spec(1)
        };
        assert_eq!(
            storage.add_image(domain, sandbox, too_large, &many),
            Err(SandboxStorageError::InvalidLayer)
        );
        assert_eq!(storage.image_count(), 0);

        let image = storage
            .add_image(domain, sandbox, spec(1), &layers())
            .unwrap();
        assert_eq!(
            storage.add_image(domain, sandbox, spec(1), &layers()),
            Err(SandboxStorageError::Capacity)
        );
        assert_eq!(storage.image_count(), 1);
        assert_eq!(storage.image(domain, sandbox, image).unwrap().layers, 2);
    }

    #[test]
    fn image_destroy_requires_volume_drain_and_reclaims_layers() {
        let domain = domain(1);
        let mut workloads = WorkloadTable::<2>::new();
        let sandbox = sandbox(domain, &mut workloads);
        let mut storage = SandboxStorageTable::<2, 4, 1>::new();
        let image = storage
            .add_image(domain, sandbox, spec(1), &layers())
            .unwrap();
        let volume = storage.create_volume(domain, sandbox, image, 8).unwrap();
        assert_eq!(
            storage.destroy_image(domain, sandbox, image),
            Err(SandboxStorageError::InUse)
        );
        storage.destroy_volume(domain, sandbox, volume).unwrap();
        storage.destroy_image(domain, sandbox, image).unwrap();
        assert_eq!(storage.image_count(), 0);
        assert_eq!(
            storage.image(domain, sandbox, image),
            Err(SandboxStorageError::InvalidImage)
        );
        assert!(!storage.has_storage_for(sandbox));

        let replacement = storage
            .add_image(domain, sandbox, spec(1), &layers())
            .unwrap();
        assert_eq!(
            storage.image(domain, sandbox, replacement).unwrap().layers,
            2
        );
    }
}
