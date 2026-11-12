//! Versioned user-ABI records for Sandbox images and CoW volumes.
//!
//! The records carry stable keys and immutable facts only. They never carry a
//! security domain or a logical path; the kernel supplies the caller's domain
//! and checks the owning Sandbox before every operation.
//!
//! Sandbox 镜像与 CoW 卷的版本化用户 ABI 记录。记录只携带稳定 key 与不可变
//! 事实，不携带安全域或逻辑路径；内核提供调用者域，并在每次操作前检查镜像/
//! 卷所属 Sandbox。

use crate::sandbox::SandboxKey;
use crate::sandbox_image::{
    ContentDigest, ImageKey, ImageLayerSpec, ImageSnapshot, ImageSpec, ImageVersion, LayerSnapshot,
    SignedImage, VolumeKey, VolumeSnapshot, DIGEST_BYTES, MAX_IMAGE_LAYERS,
};

pub const IMAGE_MAGIC: u32 = u32::from_le_bytes(*b"JSI1");
pub const VOLUME_MAGIC: u32 = u32::from_le_bytes(*b"JSV1");
pub const VERSION: u16 = 1;

pub const IMAGE_ADD_BYTES: usize = 760;
pub const IMAGE_INFO_BYTES: usize = 128;
pub const LAYER_INFO_BYTES: usize = 48;
pub const VOLUME_CREATE_BYTES: usize = 32;
pub const VOLUME_INFO_BYTES: usize = 48;

const LAYER_RECORD_BYTES: usize = 40;
const LAYER_RECORD_OFFSET: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageAddArgs {
    pub sandbox: SandboxKey,
    pub spec: ImageSpec,
    pub layer_count: u16,
    pub layers: [ImageLayerSpec; MAX_IMAGE_LAYERS],
}

impl ImageAddArgs {
    pub fn encode(self) -> Option<[u8; IMAGE_ADD_BYTES]> {
        if self.layer_count as usize > MAX_IMAGE_LAYERS {
            return None;
        }
        let mut out = [0u8; IMAGE_ADD_BYTES];
        out[0..4].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.sandbox.to_raw().to_le_bytes());
        encode_signed_image(&mut out, 16, self.spec.image);
        out[96..104].copy_from_slice(&self.spec.rootfs_bytes.to_le_bytes());
        out[104..112].copy_from_slice(&self.spec.writable_bytes.to_le_bytes());
        out[112..114].copy_from_slice(&self.spec.max_volumes.to_le_bytes());
        out[114..116].copy_from_slice(&self.layer_count.to_le_bytes());
        for (index, layer) in self.layers[..self.layer_count as usize].iter().enumerate() {
            let offset = LAYER_RECORD_OFFSET + index * LAYER_RECORD_BYTES;
            out[offset..offset + DIGEST_BYTES].copy_from_slice(&layer.content.bytes());
            out[offset + DIGEST_BYTES..offset + LAYER_RECORD_BYTES]
                .copy_from_slice(&layer.bytes.to_le_bytes());
        }
        Some(out)
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != IMAGE_ADD_BYTES
            || read_u32(raw, 0)? != IMAGE_MAGIC
            || read_u16(raw, 4)? != VERSION
            || read_u16(raw, 6)? != 0
            || raw[94..96].iter().any(|byte| *byte != 0)
            || raw[116..120].iter().any(|byte| *byte != 0)
        {
            return None;
        }
        let layer_count = read_u16(raw, 114)?;
        if layer_count as usize > MAX_IMAGE_LAYERS {
            return None;
        }
        let mut layers = [ImageLayerSpec::default(); MAX_IMAGE_LAYERS];
        for (index, layer) in layers[..layer_count as usize].iter_mut().enumerate() {
            let offset = LAYER_RECORD_OFFSET + index * LAYER_RECORD_BYTES;
            *layer = ImageLayerSpec {
                content: ContentDigest::new(read_digest(raw, offset)?)?,
                bytes: read_u64(raw, offset + DIGEST_BYTES)?,
            };
        }
        let unused = LAYER_RECORD_OFFSET + layer_count as usize * LAYER_RECORD_BYTES;
        if raw[unused..].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(Self {
            sandbox: SandboxKey::from_raw(read_u64(raw, 8)?)?,
            spec: ImageSpec {
                image: decode_signed_image(raw, 16)?,
                rootfs_bytes: read_u64(raw, 96)?,
                writable_bytes: read_u64(raw, 104)?,
                max_volumes: read_u16(raw, 112)?,
            },
            layer_count,
            layers,
        })
    }

    pub fn used_layers(&self) -> &[ImageLayerSpec] {
        &self.layers[..self.layer_count as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageInfo {
    pub key: ImageKey,
    pub image: SignedImage,
    pub rootfs_bytes: u64,
    pub writable_bytes: u64,
    pub max_volumes: u16,
    pub volumes: u16,
    pub layers: u16,
}

impl ImageInfo {
    pub const fn from_snapshot(snapshot: ImageSnapshot) -> Self {
        Self {
            key: snapshot.key,
            image: snapshot.image,
            rootfs_bytes: snapshot.rootfs_bytes,
            writable_bytes: snapshot.writable_bytes,
            max_volumes: snapshot.max_volumes,
            volumes: snapshot.volumes,
            layers: snapshot.layers,
        }
    }

    pub fn encode(self) -> [u8; IMAGE_INFO_BYTES] {
        let mut out = [0u8; IMAGE_INFO_BYTES];
        out[0..4].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.key.to_raw().to_le_bytes());
        encode_signed_image(&mut out, 16, self.image);
        out[96..104].copy_from_slice(&self.rootfs_bytes.to_le_bytes());
        out[104..112].copy_from_slice(&self.writable_bytes.to_le_bytes());
        out[112..114].copy_from_slice(&self.max_volumes.to_le_bytes());
        out[114..116].copy_from_slice(&self.volumes.to_le_bytes());
        out[116..118].copy_from_slice(&self.layers.to_le_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerInfo {
    pub content: ContentDigest,
    pub bytes: u64,
}

impl LayerInfo {
    pub const fn from_snapshot(snapshot: LayerSnapshot) -> Self {
        Self {
            content: snapshot.content,
            bytes: snapshot.bytes,
        }
    }

    pub fn encode(self) -> [u8; LAYER_INFO_BYTES] {
        let mut out = [0u8; LAYER_INFO_BYTES];
        out[0..4].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..40].copy_from_slice(&self.content.bytes());
        out[40..48].copy_from_slice(&self.bytes.to_le_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeCreateArgs {
    pub sandbox: SandboxKey,
    pub image: ImageKey,
    pub capacity_bytes: u64,
}

impl VolumeCreateArgs {
    pub fn encode(self) -> [u8; VOLUME_CREATE_BYTES] {
        let mut out = [0u8; VOLUME_CREATE_BYTES];
        out[0..4].copy_from_slice(&VOLUME_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.sandbox.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.image.to_raw().to_le_bytes());
        out[24..32].copy_from_slice(&self.capacity_bytes.to_le_bytes());
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != VOLUME_CREATE_BYTES
            || read_u32(raw, 0)? != VOLUME_MAGIC
            || read_u16(raw, 4)? != VERSION
            || read_u16(raw, 6)? != 0
        {
            return None;
        }
        Some(Self {
            sandbox: SandboxKey::from_raw(read_u64(raw, 8)?)?,
            image: ImageKey::from_raw(read_u64(raw, 16)?)?,
            capacity_bytes: read_u64(raw, 24)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeCloneArgs {
    pub sandbox: SandboxKey,
    pub parent: VolumeKey,
    pub capacity_bytes: u64,
}

impl VolumeCloneArgs {
    pub fn encode(self) -> [u8; VOLUME_CREATE_BYTES] {
        let mut out = [0u8; VOLUME_CREATE_BYTES];
        out[0..4].copy_from_slice(&VOLUME_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.sandbox.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.parent.to_raw().to_le_bytes());
        out[24..32].copy_from_slice(&self.capacity_bytes.to_le_bytes());
        out
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != VOLUME_CREATE_BYTES
            || read_u32(raw, 0)? != VOLUME_MAGIC
            || read_u16(raw, 4)? != VERSION
            || read_u16(raw, 6)? != 0
        {
            return None;
        }
        Some(Self {
            sandbox: SandboxKey::from_raw(read_u64(raw, 8)?)?,
            parent: VolumeKey::from_raw(read_u64(raw, 16)?)?,
            capacity_bytes: read_u64(raw, 24)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeInfo {
    pub key: VolumeKey,
    pub image: ImageKey,
    pub parent: Option<VolumeKey>,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
}

impl VolumeInfo {
    pub const fn from_snapshot(snapshot: VolumeSnapshot) -> Self {
        Self {
            key: snapshot.key,
            image: snapshot.image,
            parent: snapshot.parent,
            capacity_bytes: snapshot.capacity_bytes,
            used_bytes: snapshot.used_bytes,
        }
    }

    pub fn encode(self) -> [u8; VOLUME_INFO_BYTES] {
        let mut out = [0u8; VOLUME_INFO_BYTES];
        out[0..4].copy_from_slice(&VOLUME_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.key.to_raw().to_le_bytes());
        out[16..24].copy_from_slice(&self.image.to_raw().to_le_bytes());
        out[24..32].copy_from_slice(&self.parent.map_or(0, VolumeKey::to_raw).to_le_bytes());
        out[32..40].copy_from_slice(&self.capacity_bytes.to_le_bytes());
        out[40..48].copy_from_slice(&self.used_bytes.to_le_bytes());
        out
    }
}

fn encode_signed_image<const N: usize>(out: &mut [u8; N], offset: usize, image: SignedImage) {
    out[offset..offset + DIGEST_BYTES].copy_from_slice(&image.content.bytes());
    out[offset + 32..offset + 40].copy_from_slice(&image.signer.to_le_bytes());
    out[offset + 40..offset + 72].copy_from_slice(&image.signature.bytes());
    out[offset + 72..offset + 74].copy_from_slice(&image.version.major.to_le_bytes());
    out[offset + 74..offset + 76].copy_from_slice(&image.version.minor.to_le_bytes());
    out[offset + 76..offset + 78].copy_from_slice(&image.version.patch.to_le_bytes());
}

fn decode_signed_image(raw: &[u8], offset: usize) -> Option<SignedImage> {
    Some(SignedImage {
        content: ContentDigest::new(read_digest(raw, offset)?)?,
        signer: read_u64(raw, offset + 32)?,
        signature: ContentDigest::new(read_digest(raw, offset + 40)?)?,
        version: ImageVersion {
            major: read_u16(raw, offset + 72)?,
            minor: read_u16(raw, offset + 74)?,
            patch: read_u16(raw, offset + 76)?,
        },
    })
}

fn read_digest(raw: &[u8], offset: usize) -> Option<[u8; DIGEST_BYTES]> {
    Some(raw.get(offset..offset + DIGEST_BYTES)?.try_into().ok()?)
}

fn read_u16(raw: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        raw.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(raw: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        raw.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(raw: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        raw.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxTable;
    use crate::sandbox_image::SandboxStorageTable;
    use crate::security_domain::DomainKey;
    use crate::workload::{ResourceLimits, WorkloadTable};

    const LIMITS: ResourceLimits = ResourceLimits {
        cpu_permille: 100,
        memory_bytes: 4096,
        threads: 1,
        ring_entries: 1,
        io_bytes: 4096,
        io_ops: 8,
    };

    fn digest(byte: u8) -> ContentDigest {
        ContentDigest::new([byte; DIGEST_BYTES]).unwrap()
    }

    fn setup() -> (DomainKey, SandboxKey, ImageKey) {
        let domain = DomainKey {
            id: 71,
            generation: 1,
        };
        let mut workloads = WorkloadTable::<2>::new();
        let mut sandboxes = SandboxTable::<1>::new();
        let sandbox = sandboxes.create(&mut workloads, domain, LIMITS).unwrap();
        let mut storage = SandboxStorageTable::<1, 2, 1>::new();
        let spec = ImageSpec {
            image: SignedImage {
                content: digest(1),
                signer: 9,
                signature: digest(2),
                version: ImageVersion {
                    major: 1,
                    minor: 2,
                    patch: 3,
                },
            },
            rootfs_bytes: 12,
            writable_bytes: 64,
            max_volumes: 1,
        };
        let layers = [
            ImageLayerSpec {
                content: digest(3),
                bytes: 5,
            },
            ImageLayerSpec {
                content: digest(4),
                bytes: 7,
            },
        ];
        let image = storage.add_image(domain, sandbox, spec, &layers).unwrap();
        core::mem::forget(storage);
        core::mem::forget(sandboxes);
        (domain, sandbox, image)
    }

    #[test]
    fn image_add_descriptor_roundtrips_strictly() {
        let (_, sandbox, image) = setup();
        let mut layers = [ImageLayerSpec::default(); MAX_IMAGE_LAYERS];
        layers[0] = ImageLayerSpec {
            content: digest(5),
            bytes: 9,
        };
        let args = ImageAddArgs {
            sandbox,
            spec: ImageSpec {
                image: SignedImage {
                    content: digest(6),
                    signer: 4,
                    signature: digest(7),
                    version: ImageVersion {
                        major: 1,
                        minor: 0,
                        patch: 0,
                    },
                },
                rootfs_bytes: 9,
                writable_bytes: 32,
                max_volumes: 1,
            },
            layer_count: 1,
            layers,
        };
        let encoded = args.encode().unwrap();
        assert_eq!(ImageAddArgs::decode(&encoded), Some(args));
        for offset in [0, 4, 6, 94, 116] {
            let mut invalid = encoded;
            invalid[offset] ^= 0x80;
            assert_eq!(ImageAddArgs::decode(&invalid), None);
        }
        let _ = image;
    }

    #[test]
    fn query_records_have_one_fixed_layout() {
        let volume = VolumeInfo {
            key: VolumeKey::from_raw((3 << 16) | 4).unwrap(),
            image: ImageKey::from_raw((5 << 16) | 6).unwrap(),
            parent: None,
            capacity_bytes: 64,
            used_bytes: 7,
        }
        .encode();
        assert_eq!(&volume[0..4], b"JSV1");
        assert_eq!(u64::from_le_bytes(volume[40..48].try_into().unwrap()), 7);
        assert_eq!(volume.len(), VOLUME_INFO_BYTES);

        let layer = LayerInfo {
            content: digest(8),
            bytes: 12,
        }
        .encode();
        assert_eq!(&layer[0..4], b"JSI1");
        assert_eq!(u64::from_le_bytes(layer[40..48].try_into().unwrap()), 12);
        assert_eq!(layer.len(), LAYER_INFO_BYTES);
    }

    #[test]
    fn volume_descriptors_reject_reserved_and_truncated_inputs() {
        let sandbox = SandboxKey::from_raw((1 << 16) | 1).unwrap();
        let image = ImageKey::from_raw((2 << 16) | 1).unwrap();
        let create = VolumeCreateArgs {
            sandbox,
            image,
            capacity_bytes: 32,
        };
        let encoded = create.encode();
        assert_eq!(VolumeCreateArgs::decode(&encoded), Some(create));
        assert_eq!(VolumeCreateArgs::decode(&encoded[..31]), None);
        let mut invalid = encoded;
        invalid[6] = 1;
        assert_eq!(VolumeCreateArgs::decode(&invalid), None);

        let parent = VolumeKey::from_raw((3 << 16) | 1).unwrap();
        let clone = VolumeCloneArgs {
            sandbox,
            parent,
            capacity_bytes: 16,
        };
        assert_eq!(VolumeCloneArgs::decode(&clone.encode()), Some(clone));
    }
}
