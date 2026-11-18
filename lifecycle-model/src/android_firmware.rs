//! Android boot image and AVB firmware verification.
//! Android 启动镜像与 AVB 固件验证。
//!
//! This is system-service/preflight logic. AVB proves the identity and
//! integrity of an upstream firmware artifact; it is not a Jasper
//! authorization root. The caller must separately bind the verified signer
//! fingerprint, content digest and rollback index into Jasper's lifecycle and
//! Driver Host authorization policy.
//! 本模块属于系统服务/预检层。AVB 只证明上游固件制品身份与完整性，不是
//! Jasper 授权根；调用方必须另行将受信 signer 指纹、内容摘要和防回滚索引绑定到
//! Jasper 生命周期与 Driver Host 授权策略。

extern crate alloc;

use rsa::sha2::{Digest, Sha256, Sha512};
use rsa::{BoxedUint, Pkcs1v15Sign, PublicKey};

const AVB_MAGIC: &[u8; 4] = b"AVB0";
const AVB_FOOTER_MAGIC: &[u8; 4] = b"AVBf";
const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
const AVB_HEADER_BYTES: usize = 256;
const AVB_FOOTER_BYTES: usize = 64;
const BOOT_V4_HEADER_BYTES: usize = 1584;
const BOOT_PAGE_BYTES: usize = 4096;
const MAX_DESCRIPTORS: usize = 256; // JASPER-HARDCODE-REVIEW: issue=21 source=avb-vbmeta-descriptor-bound reason=bounded-decoder-defense-in-depth

/// Supported AVB signature algorithm encodings.
/// 支持的 AVB 签名算法编号。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvbAlgorithm {
    /// AVB algorithm 0, no authentication data.
    /// AVB 算法 0，不含认证数据。
    None,
    /// SHA-256 with RSA-2048.
    /// SHA-256 与 RSA-2048。
    Sha256Rsa2048,
    /// SHA-256 with RSA-4096.
    /// SHA-256 与 RSA-4096。
    Sha256Rsa4096,
    /// SHA-256 with RSA-8192.
    /// SHA-256 与 RSA-8192。
    Sha256Rsa8192,
    /// SHA-512 with RSA-2048.
    /// SHA-512 与 RSA-2048。
    Sha512Rsa2048,
    /// SHA-512 with RSA-4096.
    /// SHA-512 与 RSA-4096。
    Sha512Rsa4096,
    /// SHA-512 with RSA-8192.
    /// SHA-512 与 RSA-8192。
    Sha512Rsa8192,
}

impl AvbAlgorithm {
    fn parse(raw: u32) -> Result<Self, AvbError> {
        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::Sha256Rsa2048),
            2 => Ok(Self::Sha256Rsa4096),
            3 => Ok(Self::Sha256Rsa8192),
            4 => Ok(Self::Sha512Rsa2048),
            5 => Ok(Self::Sha512Rsa4096),
            6 => Ok(Self::Sha512Rsa8192),
            _ => Err(AvbError::UnsupportedAlgorithm),
        }
    }

    const fn key_bits(self) -> Option<u32> {
        match self {
            Self::Sha256Rsa2048 | Self::Sha512Rsa2048 => Some(2048),
            Self::Sha256Rsa4096 | Self::Sha512Rsa4096 => Some(4096),
            Self::Sha256Rsa8192 | Self::Sha512Rsa8192 => Some(8192),
            Self::None => None,
        }
    }

    const fn hash_bytes(self) -> Option<usize> {
        match self {
            Self::Sha256Rsa2048 | Self::Sha256Rsa4096 | Self::Sha256Rsa8192 => Some(32),
            Self::Sha512Rsa2048 | Self::Sha512Rsa4096 | Self::Sha512Rsa8192 => Some(64),
            Self::None => None,
        }
    }
}

/// Structured firmware-image verification failure.
/// 结构化固件镜像验证失败原因。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvbError {
    /// A fixed structure needed by the parser is truncated.
    /// 固定结构被截断。
    Truncated,
    /// A required magic value is absent.
    /// 缺少必需魔数。
    BadMagic,
    /// The image uses an unsupported format version.
    /// 镜像使用了不支持的格式版本。
    UnsupportedVersion,
    /// A checked offset or length exceeds its enclosing object.
    /// 偏移或长度超出所属对象。
    OutOfBounds,
    /// An AVB signature algorithm is unknown.
    /// AVB 签名算法未知。
    UnsupportedAlgorithm,
    /// The AVB header is not signed.
    /// AVB 头没有签名。
    Unsigned,
    /// The AVB authentication block does not match its protected bytes.
    /// AVB 认证块与被保护字节不匹配。
    AuthenticationHash,
    /// The RSA signature is invalid or its key is malformed.
    /// RSA 签名无效或公钥格式错误。
    Signature,
    /// A descriptor is malformed or exceeds its bounded region.
    /// 描述符损坏或超出有界区域。
    Descriptor,
    /// The expected partition descriptor is absent.
    /// 缺少目标分区描述符。
    PartitionMissing,
    /// A protected image digest does not match its descriptor.
    /// 被保护镜像摘要与描述符不一致。
    ContentHash,
    /// The Android boot image magic is absent.
    /// Android 启动镜像缺少魔数。
    BootMagic,
    /// The Android boot image is not the supported v4 header layout.
    /// Android 启动镜像不是受支持的 v4 头布局。
    BootVersion,
    /// Android boot segment ranges are inconsistent.
    /// Android 启动段范围不一致。
    BootLayout,
}

impl core::fmt::Display for AvbError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "firmware structure is truncated",
            Self::BadMagic => "firmware magic is invalid",
            Self::UnsupportedVersion => "firmware format version is unsupported",
            Self::OutOfBounds => "firmware range is out of bounds",
            Self::UnsupportedAlgorithm => "AVB signature algorithm is unsupported",
            Self::Unsigned => "AVB metadata is unsigned",
            Self::AuthenticationHash => "AVB authentication hash does not match",
            Self::Signature => "AVB RSA signature is invalid",
            Self::Descriptor => "AVB descriptor is malformed",
            Self::PartitionMissing => "AVB partition descriptor is missing",
            Self::ContentHash => "AVB protected content hash does not match",
            Self::BootMagic => "Android boot image magic is invalid",
            Self::BootVersion => "Android boot image is not supported v4",
            Self::BootLayout => "Android boot image segment layout is invalid",
        })
    }
}

impl core::error::Error for AvbError {}

/// Verified AVB metadata and signer identity.
/// 已验证的 AVB 元数据与签名者身份。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedVbmeta {
    algorithm: AvbAlgorithm,
    rollback_index: u64,
    rollback_index_location: u32,
    flags: u32,
    descriptor_count: u16,
    signer_fingerprint: [u8; 32],
}

impl VerifiedVbmeta {
    /// Cryptographic algorithm used by the verified metadata.
    /// 已验证元数据使用的密码算法。
    pub const fn algorithm(self) -> AvbAlgorithm {
        self.algorithm
    }

    /// Verified AVB anti-rollback index.
    /// 已验证的 AVB 防回滚索引。
    pub const fn rollback_index(self) -> u64 {
        self.rollback_index
    }

    /// Slot/location of the anti-rollback index, when nonzero.
    /// 防回滚索引的槽位/位置；零表示默认位置。
    pub const fn rollback_index_location(self) -> u32 {
        self.rollback_index_location
    }

    /// AVB vbmeta flags carried by the signed header.
    /// 已签名头携带的 AVB vbmeta 标志。
    pub const fn flags(self) -> u32 {
        self.flags
    }

    /// Number of bounded descriptors authenticated by this metadata.
    /// 此元数据认证的有界描述符数量。
    pub const fn descriptor_count(self) -> u16 {
        self.descriptor_count
    }

    /// SHA-256 identity of the complete AVB public-key encoding.
    ///
    /// This fingerprint can be bound to a Jasper trust-policy entry; AVB trust
    /// by itself never grants local installation or device access.
    /// 完整 AVB 公钥编码的 SHA-256 身份。可将其绑定到 Jasper 信任策略；AVB
    /// 自身永远不授予本地安装或设备访问权限。
    pub const fn signer_fingerprint(self) -> [u8; 32] {
        self.signer_fingerprint
    }
}

/// Parsed Android boot image v4 layout.
/// 已解析的 Android v4 启动镜像布局。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndroidBootImage {
    kernel_offset: usize,
    kernel_size: usize,
    ramdisk_offset: usize,
    ramdisk_size: usize,
    signature_size: usize,
    original_image_size: usize,
    vbmeta_offset: usize,
    vbmeta_size: usize,
    os_version: u32,
}

impl AndroidBootImage {
    /// File offset of the protected kernel segment.
    /// 受保护内核段的文件偏移。
    pub const fn kernel_offset(self) -> usize {
        self.kernel_offset
    }

    /// Kernel segment length.
    /// 内核段长度。
    pub const fn kernel_size(self) -> usize {
        self.kernel_size
    }

    /// File offset of the optional ramdisk segment.
    /// 可选 ramdisk 段的文件偏移。
    pub const fn ramdisk_offset(self) -> usize {
        self.ramdisk_offset
    }

    /// Ramdisk segment length; zero is possible in vendor-specific boot images.
    /// ramdisk 段长度；厂商特定启动镜像中可为零。
    pub const fn ramdisk_size(self) -> usize {
        self.ramdisk_size
    }

    /// Android v4 boot-signature section length.
    /// Android v4 启动签名段长度。
    pub const fn signature_size(self) -> usize {
        self.signature_size
    }

    /// AVB-protected original image length before the vbmeta structure.
    /// vbmeta 结构之前受 AVB 保护的原始镜像长度。
    pub const fn original_image_size(self) -> usize {
        self.original_image_size
    }

    /// Encoded Android OS/security-patch version.
    /// 编码后的 Android 系统/安全补丁版本。
    pub const fn os_version(self) -> u32 {
        self.os_version
    }
}

/// Firmware facts that a Jasper lifecycle service may consume after it has
/// independently applied its own signer trust, authorization and device gates.
/// Jasper 生命周期服务在另行应用自身签名者信任、授权和设备门后可消费的事实。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedFirmware {
    /// Parsed boot layout.
    /// 已解析的启动布局。
    pub boot: AndroidBootImage,
    /// Verified AVB metadata.
    /// 已验证的 AVB 元数据。
    pub vbmeta: VerifiedVbmeta,
    /// Salted content digest from the matching partition descriptor.
    /// 目标分区描述符中的加盐内容摘要。
    pub content_digest: [u8; 32],
}

impl VerifiedFirmware {
    /// Facts to map into Jasper's independent lifecycle package policy.
    ///
    /// The caller supplies its own security epoch when constructing the
    /// lifecycle package. The returned tuple is
    /// `(content digest, signer fingerprint, AVB rollback index)`.
    /// 映射到 Jasper 独立生命周期包策略的事实。调用方构造生命周期包时另行提供
    /// 自身 security epoch；返回值依次为内容摘要、signer 指纹、AVB 防回滚索引。
    pub const fn lifecycle_facts(self) -> ([u8; 32], [u8; 32], u64) {
        (
            self.content_digest,
            self.vbmeta.signer_fingerprint,
            self.vbmeta.rollback_index,
        )
    }
}

/// Verify a signed AVB vbmeta structure.
/// 验证已签名的 AVB vbmeta 结构。
pub fn verify_vbmeta(bytes: &[u8]) -> Result<VerifiedVbmeta, AvbError> {
    if bytes.len() < AVB_HEADER_BYTES {
        return Err(AvbError::Truncated);
    }
    if &bytes[..4] != AVB_MAGIC {
        return Err(AvbError::BadMagic);
    }
    let required_major = be_u32(bytes, 4)?;
    let required_minor = be_u32(bytes, 8)?;
    if required_major > 1 || (required_major == 1 && required_minor > 0) {
        return Err(AvbError::UnsupportedVersion);
    }
    let auth_size = usize_from_u64(be_u64(bytes, 12)?)?;
    let auxiliary_size = usize_from_u64(be_u64(bytes, 20)?)?;
    let algorithm = AvbAlgorithm::parse(be_u32(bytes, 28)?)?;
    let hash_offset = usize_from_u64(be_u64(bytes, 32)?)?;
    let hash_size = usize_from_u64(be_u64(bytes, 40)?)?;
    let signature_offset = usize_from_u64(be_u64(bytes, 48)?)?;
    let signature_size = usize_from_u64(be_u64(bytes, 56)?)?;
    let public_key_offset = usize_from_u64(be_u64(bytes, 64)?)?;
    let public_key_size = usize_from_u64(be_u64(bytes, 72)?)?;
    let public_key_metadata_offset = usize_from_u64(be_u64(bytes, 80)?)?;
    let public_key_metadata_size = usize_from_u64(be_u64(bytes, 88)?)?;
    let descriptors_offset = usize_from_u64(be_u64(bytes, 96)?)?;
    let descriptors_size = usize_from_u64(be_u64(bytes, 104)?)?;
    let rollback_index = be_u64(bytes, 112)?;
    let flags = be_u32(bytes, 120)?;
    let rollback_index_location = be_u32(bytes, 124)?;

    let auxiliary_start = AVB_HEADER_BYTES
        .checked_add(auth_size)
        .ok_or(AvbError::OutOfBounds)?;
    let total = auxiliary_start
        .checked_add(auxiliary_size)
        .ok_or(AvbError::OutOfBounds)?;
    if total > bytes.len() {
        return Err(AvbError::OutOfBounds);
    }
    let auxiliary = &bytes[auxiliary_start..total];
    require_range(auth_size, hash_offset, hash_size)?;
    require_range(auth_size, signature_offset, signature_size)?;
    require_range(auxiliary_size, public_key_offset, public_key_size)?;
    require_range(
        auxiliary_size,
        public_key_metadata_offset,
        public_key_metadata_size,
    )?;
    require_range(auxiliary_size, descriptors_offset, descriptors_size)?;

    let expected_hash_size = algorithm.hash_bytes().ok_or(AvbError::Unsigned)?;
    let expected_key_bits = algorithm.key_bits().ok_or(AvbError::Unsigned)?;
    if hash_size != expected_hash_size
        || signature_size
            != usize::try_from(expected_key_bits / 8).map_err(|_| AvbError::Signature)?
    {
        return Err(AvbError::Signature);
    }
    let signed_hash = algorithm.digest(&[&bytes[..AVB_HEADER_BYTES], auxiliary]);
    let stored_hash =
        &bytes[AVB_HEADER_BYTES + hash_offset..AVB_HEADER_BYTES + hash_offset + hash_size];
    if signed_hash.as_slice() != stored_hash {
        return Err(AvbError::AuthenticationHash);
    }

    let public_key_blob = &auxiliary[public_key_offset..public_key_offset + public_key_size];
    let expected_key_size = 8usize
        .checked_add(
            (expected_key_bits as usize / 8)
                .checked_mul(2)
                .ok_or(AvbError::Signature)?,
        )
        .ok_or(AvbError::Signature)?;
    if public_key_blob.len() != expected_key_size
        || be_u32(public_key_blob, 0)? != expected_key_bits
    {
        return Err(AvbError::Signature);
    }
    let modulus_bytes = expected_key_bits as usize / 8;
    let modulus = &public_key_blob[8..8 + modulus_bytes];
    let modulus =
        BoxedUint::from_be_slice(modulus, expected_key_bits).map_err(|_| AvbError::Signature)?;
    let exponent = BoxedUint::from(65_537u64);
    let public_key = PublicKey::new(modulus, exponent).map_err(|_| AvbError::Signature)?;
    let signer_fingerprint: [u8; 32] = Sha256::digest(public_key_blob).into();
    let signature = &bytes
        [AVB_HEADER_BYTES + signature_offset..AVB_HEADER_BYTES + signature_offset + signature_size];
    match algorithm {
        AvbAlgorithm::Sha256Rsa2048 | AvbAlgorithm::Sha256Rsa4096 | AvbAlgorithm::Sha256Rsa8192 => {
            public_key
                .verify(Pkcs1v15Sign::new::<Sha256>(), &signed_hash, signature)
                .map_err(|_| AvbError::Signature)?
        }
        AvbAlgorithm::Sha512Rsa2048 | AvbAlgorithm::Sha512Rsa4096 | AvbAlgorithm::Sha512Rsa8192 => {
            public_key
                .verify(Pkcs1v15Sign::new::<Sha512>(), &signed_hash, signature)
                .map_err(|_| AvbError::Signature)?
        }
        AvbAlgorithm::None => return Err(AvbError::Unsigned),
    }
    let descriptor_count = count_descriptors(auxiliary, descriptors_offset, descriptors_size)?;
    Ok(VerifiedVbmeta {
        algorithm,
        rollback_index,
        rollback_index_location,
        flags,
        descriptor_count,
        signer_fingerprint,
    })
}

/// Verify a stock-style Android boot image v4, its embedded signed vbmeta and
/// the named partition hash descriptor.
/// 验证 stock 风格 Android v4 启动镜像、内嵌已签名 vbmeta 和目标分区哈希描述符。
pub fn verify_android_boot_image(
    bytes: &[u8],
    expected_partition: &str,
) -> Result<VerifiedFirmware, AvbError> {
    let footer = parse_footer(bytes)?;
    let boot = parse_boot_v4(bytes, footer)?;
    let vbmeta_end = boot
        .vbmeta_offset
        .checked_add(boot.vbmeta_size)
        .ok_or(AvbError::OutOfBounds)?;
    let vbmeta_bytes = bytes
        .get(boot.vbmeta_offset..vbmeta_end)
        .ok_or(AvbError::OutOfBounds)?;
    let vbmeta = verify_vbmeta(vbmeta_bytes)?;
    let content_digest = verify_partition_descriptor(
        vbmeta_bytes,
        bytes,
        boot.original_image_size,
        expected_partition.as_bytes(),
    )?;
    Ok(VerifiedFirmware {
        boot,
        vbmeta,
        content_digest,
    })
}

#[derive(Clone, Copy)]
struct AvbFooter {
    original_image_size: usize,
    vbmeta_offset: usize,
    vbmeta_size: usize,
}

fn parse_footer(bytes: &[u8]) -> Result<AvbFooter, AvbError> {
    if bytes.len() < AVB_FOOTER_BYTES {
        return Err(AvbError::Truncated);
    }
    let footer = &bytes[bytes.len() - AVB_FOOTER_BYTES..];
    if &footer[..4] != AVB_FOOTER_MAGIC {
        return Err(AvbError::BadMagic);
    }
    if be_u32(footer, 4)? > 1 {
        return Err(AvbError::UnsupportedVersion);
    }
    let original_image_size = usize_from_u64(be_u64(footer, 12)?)?;
    let vbmeta_offset = usize_from_u64(be_u64(footer, 20)?)?;
    let vbmeta_size = usize_from_u64(be_u64(footer, 28)?)?;
    let vbmeta_end = vbmeta_offset
        .checked_add(vbmeta_size)
        .ok_or(AvbError::OutOfBounds)?;
    if original_image_size > vbmeta_offset || vbmeta_end > bytes.len() {
        return Err(AvbError::OutOfBounds);
    }
    Ok(AvbFooter {
        original_image_size,
        vbmeta_offset,
        vbmeta_size,
    })
}

fn parse_boot_v4(bytes: &[u8], footer: AvbFooter) -> Result<AndroidBootImage, AvbError> {
    if bytes.len() < BOOT_V4_HEADER_BYTES {
        return Err(AvbError::Truncated);
    }
    if &bytes[..8] != BOOT_MAGIC {
        return Err(AvbError::BootMagic);
    }
    if le_u32(bytes, 40)? != 4 || le_u32(bytes, 20)? as usize != BOOT_V4_HEADER_BYTES {
        return Err(AvbError::BootVersion);
    }
    let kernel_size = usize_from_u32(le_u32(bytes, 8)?)?;
    let ramdisk_size = usize_from_u32(le_u32(bytes, 12)?)?;
    let signature_size = usize_from_u32(le_u32(bytes, 1580)?)?;
    if kernel_size == 0 {
        return Err(AvbError::BootLayout);
    }
    let kernel_offset = BOOT_PAGE_BYTES;
    let ramdisk_offset = align_up(
        kernel_offset
            .checked_add(kernel_size)
            .ok_or(AvbError::OutOfBounds)?,
        BOOT_PAGE_BYTES,
    )?;
    let signature_offset = align_up(
        ramdisk_offset
            .checked_add(ramdisk_size)
            .ok_or(AvbError::OutOfBounds)?,
        BOOT_PAGE_BYTES,
    )?;
    let required_end = signature_offset
        .checked_add(signature_size)
        .ok_or(AvbError::OutOfBounds)?;
    if required_end > footer.original_image_size
        || footer.original_image_size > footer.vbmeta_offset
    {
        return Err(AvbError::BootLayout);
    }
    Ok(AndroidBootImage {
        kernel_offset,
        kernel_size,
        ramdisk_offset,
        ramdisk_size,
        signature_size,
        original_image_size: footer.original_image_size,
        vbmeta_offset: footer.vbmeta_offset,
        vbmeta_size: footer.vbmeta_size,
        os_version: le_u32(bytes, 16)?,
    })
}

fn verify_partition_descriptor(
    vbmeta: &[u8],
    image: &[u8],
    expected_image_size: usize,
    expected_partition: &[u8],
) -> Result<[u8; 32], AvbError> {
    let auth_size = usize_from_u64(be_u64(vbmeta, 12)?)?;
    let auxiliary_size = usize_from_u64(be_u64(vbmeta, 20)?)?;
    let auxiliary_start = AVB_HEADER_BYTES
        .checked_add(auth_size)
        .ok_or(AvbError::OutOfBounds)?;
    let auxiliary_end = auxiliary_start
        .checked_add(auxiliary_size)
        .ok_or(AvbError::OutOfBounds)?;
    let auxiliary = vbmeta
        .get(auxiliary_start..auxiliary_end)
        .ok_or(AvbError::OutOfBounds)?;
    let descriptors_offset = usize_from_u64(be_u64(vbmeta, 96)?)?;
    let descriptors_size = usize_from_u64(be_u64(vbmeta, 104)?)?;
    let mut offset = descriptors_offset;
    let end = descriptors_offset
        .checked_add(descriptors_size)
        .ok_or(AvbError::Descriptor)?;
    if end > auxiliary.len() {
        return Err(AvbError::Descriptor);
    }
    let mut visited = 0usize;
    while offset < end {
        visited += 1;
        if visited > MAX_DESCRIPTORS {
            return Err(AvbError::Descriptor);
        }
        let remaining = &auxiliary[offset..end];
        if remaining.len() < 16 {
            return Err(AvbError::Truncated);
        }
        let tag = be_u64(remaining, 0)?;
        let following = usize_from_u64(be_u64(remaining, 8)?)?;
        let total = 16usize.checked_add(following).ok_or(AvbError::Descriptor)?;
        if total > remaining.len() {
            return Err(AvbError::Descriptor);
        }
        if tag == 2 {
            if let Some(descriptor) = parse_hash_descriptor(&remaining[..total])? {
                if descriptor.image_size > expected_image_size {
                    return Err(AvbError::ContentHash);
                }
                if descriptor.name == expected_partition {
                    if descriptor.image_size != expected_image_size
                        || descriptor.digest.iter().all(|byte| *byte == 0)
                    {
                        return Err(AvbError::ContentHash);
                    }
                    let digest = match descriptor.hash_algorithm {
                        b"sha256" => {
                            let mut hasher = Sha256::new();
                            hasher.update(descriptor.salt);
                            hasher.update(&image[..descriptor.image_size]);
                            let actual: [u8; 32] = hasher.finalize().into();
                            if actual != descriptor.digest {
                                return Err(AvbError::ContentHash);
                            }
                            actual
                        }
                        _ => return Err(AvbError::ContentHash),
                    };
                    return Ok(digest);
                }
            }
        }
        offset = offset
            .checked_add(align_up(total, 8)?)
            .ok_or(AvbError::Descriptor)?;
    }
    Err(AvbError::PartitionMissing)
}

struct HashDescriptor<'a> {
    name: &'a [u8],
    salt: &'a [u8],
    digest: [u8; 32],
    image_size: usize,
    hash_algorithm: &'a [u8],
}

fn parse_hash_descriptor(descriptor: &[u8]) -> Result<Option<HashDescriptor<'_>>, AvbError> {
    if descriptor.len() < 132 {
        return Err(AvbError::Descriptor);
    }
    let image_size = usize_from_u64(be_u64(descriptor, 16)?)?;
    let hash_algorithm = descriptor[24..56]
        .split(|byte| *byte == 0)
        .next()
        .ok_or(AvbError::Descriptor)?;
    let partition_name_len = usize_from_u32(be_u32(descriptor, 56)?)?;
    let salt_len = usize_from_u32(be_u32(descriptor, 60)?)?;
    let digest_len = usize_from_u32(be_u32(descriptor, 64)?)?;
    let payload = &descriptor[132..];
    let lengths = partition_name_len
        .checked_add(salt_len)
        .and_then(|value| value.checked_add(digest_len))
        .ok_or(AvbError::Descriptor)?;
    if lengths > payload.len() || payload.len() - lengths > 7 {
        return Err(AvbError::Descriptor);
    }
    if payload[lengths..].iter().any(|byte| *byte != 0) || digest_len > 32 {
        return Err(AvbError::Descriptor);
    }
    let name = &payload[..partition_name_len];
    let salt = &payload[partition_name_len..partition_name_len + salt_len];
    let digest_slice =
        &payload[partition_name_len + salt_len..partition_name_len + salt_len + digest_len];
    let mut digest = [0u8; 32];
    digest[..digest_len].copy_from_slice(digest_slice);
    Ok(Some(HashDescriptor {
        name,
        salt,
        digest,
        image_size,
        hash_algorithm,
    }))
}

fn count_descriptors(
    auxiliary: &[u8],
    descriptors_offset: usize,
    descriptors_size: usize,
) -> Result<u16, AvbError> {
    let end = descriptors_offset
        .checked_add(descriptors_size)
        .ok_or(AvbError::Descriptor)?;
    if end > auxiliary.len() {
        return Err(AvbError::Descriptor);
    }
    let mut offset = descriptors_offset;
    let mut count = 0u16;
    while offset < end {
        if count as usize >= MAX_DESCRIPTORS {
            return Err(AvbError::Descriptor);
        }
        let remaining = &auxiliary[offset..end];
        if remaining.len() < 16 {
            return Err(AvbError::Truncated);
        }
        let following = usize_from_u64(be_u64(remaining, 8)?)?;
        let total = 16usize.checked_add(following).ok_or(AvbError::Descriptor)?;
        if total > remaining.len() {
            return Err(AvbError::Descriptor);
        }
        count += 1;
        offset = offset
            .checked_add(align_up(total, 8)?)
            .ok_or(AvbError::Descriptor)?;
    }
    Ok(count)
}

fn require_range(container: usize, offset: usize, size: usize) -> Result<(), AvbError> {
    let end = offset.checked_add(size).ok_or(AvbError::OutOfBounds)?;
    (end <= container)
        .then_some(())
        .ok_or(AvbError::OutOfBounds)
}

fn align_up(value: usize, alignment: usize) -> Result<usize, AvbError> {
    if alignment == 0 {
        return Err(AvbError::OutOfBounds);
    }
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or(AvbError::OutOfBounds)
}

fn usize_from_u32(value: u32) -> Result<usize, AvbError> {
    usize::try_from(value).map_err(|_| AvbError::OutOfBounds)
}

fn usize_from_u64(value: u64) -> Result<usize, AvbError> {
    usize::try_from(value).map_err(|_| AvbError::OutOfBounds)
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32, AvbError> {
    let end = offset.checked_add(4).ok_or(AvbError::Truncated)?;
    let bytes = bytes.get(offset..end).ok_or(AvbError::Truncated)?;
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| AvbError::Truncated)?,
    ))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, AvbError> {
    let end = offset.checked_add(4).ok_or(AvbError::Truncated)?;
    let bytes = bytes.get(offset..end).ok_or(AvbError::Truncated)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| AvbError::Truncated)?,
    ))
}

fn be_u64(bytes: &[u8], offset: usize) -> Result<u64, AvbError> {
    let end = offset.checked_add(8).ok_or(AvbError::Truncated)?;
    let bytes = bytes.get(offset..end).ok_or(AvbError::Truncated)?;
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| AvbError::Truncated)?,
    ))
}

trait AlgorithmDigest {
    fn digest(self, input: &[&[u8]]) -> alloc::vec::Vec<u8>;
}

impl AlgorithmDigest for AvbAlgorithm {
    fn digest(self, input: &[&[u8]]) -> alloc::vec::Vec<u8> {
        match self.hash_bytes() {
            Some(32) => {
                let mut digest = Sha256::new();
                for chunk in input {
                    digest.update(chunk);
                }
                digest.finalize().to_vec()
            }
            Some(64) => {
                let mut digest = Sha512::new();
                for chunk in input {
                    digest.update(chunk);
                }
                digest.finalize().to_vec()
            }
            _ => alloc::vec::Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn put_le32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_be32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn put_be64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn rejects_truncated_magic_and_unsigned_metadata() {
        assert_eq!(verify_vbmeta(&[]), Err(AvbError::Truncated));
        let mut header = [0u8; AVB_HEADER_BYTES];
        header[..4].copy_from_slice(AVB_MAGIC);
        assert_eq!(verify_vbmeta(&header), Err(AvbError::Unsigned));
    }

    #[test]
    fn rejects_truncated_boot_footer() {
        assert_eq!(
            verify_android_boot_image(&[0u8; 16], "boot"),
            Err(AvbError::Truncated)
        );
    }

    #[test]
    fn parses_bounded_v4_layout_from_little_endian_header() {
        let mut image = vec![0u8; 64 * 1024];
        image[..8].copy_from_slice(BOOT_MAGIC);
        put_le32(&mut image, 8, 8192);
        put_le32(&mut image, 12, 0);
        put_le32(&mut image, 20, BOOT_V4_HEADER_BYTES as u32);
        put_le32(&mut image, 40, 4);
        put_le32(&mut image, 1580, 0);
        let footer = image.len() - AVB_FOOTER_BYTES;
        image[footer..footer + 4].copy_from_slice(AVB_FOOTER_MAGIC);
        put_be32(&mut image, footer + 4, 1);
        put_be64(&mut image, footer + 12, 32 * 1024);
        put_be64(&mut image, footer + 20, 32 * 1024);
        put_be64(&mut image, footer + 28, AVB_HEADER_BYTES as u64);

        let parsed = parse_footer(&image).unwrap();
        let boot = parse_boot_v4(&image, parsed).unwrap();
        assert_eq!(boot.kernel_offset(), BOOT_PAGE_BYTES);
        assert_eq!(boot.kernel_size(), 8192);
        assert_eq!(boot.ramdisk_offset(), 12 * 1024);
        assert_eq!(boot.original_image_size(), 32 * 1024);
    }

    #[test]
    fn rejects_avb_blocks_outside_the_supplied_slice() {
        let mut metadata = [0u8; AVB_HEADER_BYTES];
        metadata[..4].copy_from_slice(AVB_MAGIC);
        put_be32(&mut metadata, 4, 1);
        put_be64(&mut metadata, 12, 64);
        put_be64(&mut metadata, 20, 64);
        put_be32(&mut metadata, 28, 2);
        assert_eq!(verify_vbmeta(&metadata), Err(AvbError::OutOfBounds));
    }

    #[test]
    fn hash_descriptor_rejects_nonzero_padding_and_incomplete_fields() {
        assert!(matches!(
            parse_hash_descriptor(&[0u8; 8]),
            Err(AvbError::Descriptor)
        ));
        let mut descriptor = [0u8; 132];
        put_be32(&mut descriptor, 64, 32);
        assert!(matches!(
            parse_hash_descriptor(&descriptor),
            Err(AvbError::Descriptor)
        ));
    }
}
