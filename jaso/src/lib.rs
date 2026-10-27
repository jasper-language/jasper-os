//! `.jaso` 模块格式 format 1（beta 1）：结构读取与校验（核心层）。
//! The `.jaso` module format, format 1 ("beta 1"): structural reading and validation of the core layer.
//!
//! 字节级规范见仓库 `jaso/SPEC.md`；本 crate 是它的参考实现。要点：
//!
//! * **头部**（80 字节）：魔数、`format = 1`、模块种类（Native / Managed / Hybrid）、头部 `arch`（0 = any）、
//!   装载阶段、段目录位置、文件长度、整个文件的 SHA-256（[`digest_of`]）
//! * **段目录**：每项 32 字节；段种类 Manifest、Segment、Exports、Relocs、Signature、Platform、Images、Ext、Code
//! * **平台段**（[`platform`]）与**镜像索引段**：一个文件可带至多 8 个镜像，每个镜像引用一条平台记录，
//!   并以目录下标区间认领自己的 Segment / Exports / Relocs / Code 段；装载器按宿主平台选第一个匹配的镜像
//! * **扩展段**：`名字 + 版本 + 关键标志`；已知的交给所属层，未知且非关键的跳过，未知且关键的拒绝
//! * **签名段**：Ed25519，文件最后 104 字节；签名覆盖见 [`signed_digest_of`]，信任判定在 [`trust`]
//!
//! # 校验的原则
//! 解析器不信任任何字段：所有偏移与长度都做检查式运算，任何越界、重叠、未知取值、非零保留字段都拒绝，**从不 panic**。
//! 违反多条规则时，按 SPEC §12.1 的检查顺序报告**第一条**（[`JasoError::code`] 给出稳定错误码），
//! 这样不同实现对同一文件报告同一个码。完整性校验只证明「文件未被改动」，不证明来源。

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod build;
pub mod code;
pub mod manifest;
#[cfg(feature = "alloc")]
pub mod migrate;
#[cfg(feature = "pack")]
pub mod pack;
pub mod placement;
pub mod platform;
pub mod trust;
pub mod wire;

pub use code::ErrorCode;
pub use manifest::{Dependency, Lifecycle, Manifest, ManifestError, VersionRange};
pub use platform::{FloatAbi, HostPlatform, Platform, PlatformField, PlatformMismatch, Target};

use sha2::{Digest, Sha256};

/// 文件魔数。
pub const MAGIC: [u8; 8] = *b"\x89JASO\r\n\x1a";
/// 本实现支持的格式版本（1 = beta 1）。
pub const FORMAT_VERSION: u16 = 1;
/// 头部长度。
pub const HEADER_SIZE: usize = 80;
/// 段目录项长度。
pub const SECTION_SIZE: usize = 32;
/// 导出项长度。
pub const EXPORT_SIZE: usize = 16;
/// 重定位项长度。
pub const RELOC_SIZE: usize = 16;
/// 镜像索引项长度。
pub const IMAGE_ENTRY_SIZE: usize = 32;
/// 页大小（段对齐的单位）。
pub const PAGE: u32 = 4096;
/// digest 字段在头部中的偏移。
pub const DIGEST_OFFSET: usize = 40;
/// 映像大小上限（64 MiB）。
pub const MAX_IMAGE: u32 = 64 << 20;
/// 段目录项数上限。
pub const MAX_SECTIONS: u32 = 64;
/// 镜像数上限。
pub const MAX_IMAGES: u32 = 8;
/// 扩展段数上限。
pub const MAX_EXTENSIONS: u32 = 32;
/// 扩展名长度上限。
pub const MAX_EXTENSION_NAME: usize = 64;
/// 导出项数上限。
pub const MAX_EXPORTS: u32 = 1024;
/// 导出名长度上限。
pub const MAX_NAME: u32 = 128;
/// 签名段长度：scheme(4) + 保留(4) + 发布者公钥(32) + 签名值(64)。
/// Size of the signature section.
pub const SIGNATURE_SIZE: usize = 104;
/// 签名段内签名值的偏移（相对段起点）。
/// Offset of the signature value inside the signature section.
pub const SIGNATURE_VALUE_OFFSET: usize = 40;
/// 签名算法：Ed25519（RFC 8032，严格验签）。
/// Signature scheme: Ed25519.
pub const SIG_ED25519: u32 = 1;
/// 签名消息的域分隔前缀：防止同一把密钥在别的协议里签过的消息被当作模块签名。
/// Domain-separation prefix of the signed message.
pub const SIGNATURE_DOMAIN: &[u8] = b"jaso.signature.v1\0";

/// 段标志：可读。
pub const FLAG_R: u32 = 1;
/// 段标志：可写。
pub const FLAG_W: u32 = 2;
/// 段标志：可执行。
pub const FLAG_X: u32 = 4;
/// 扩展段的目录标志：关键。
pub const EXT_CRITICAL: u32 = 1;
/// 导出种类：C 调用约定的函数（原生镜像）。
pub const EXPORT_FUNC: u32 = 1;
/// 导出种类：托管符号（托管镜像，`value = 0`）。
pub const EXPORT_MANAGED: u32 = 2;
/// 重定位种类：写入「基址 + addend」（8 字节，64 位指令集）。
/// Relocation kind: write `base + addend` as 8 bytes (64-bit ISAs).
pub const RELOC_RELATIVE64: u32 = 1;
/// 重定位种类：写入「基址 + addend」（4 字节，32 位指令集；装入基址与结果都在 32 位地址空间内）。
/// Relocation kind: write `base + addend` as 4 bytes (32-bit ISAs).
pub const RELOC_RELATIVE32: u32 = 2;
/// 代码段载体：只存储不压缩的 JVM class 归档（ZIP）。
pub const CODE_JVM_CLASSES: u32 = 1;
/// 代码段头部长度：`format u32` + 保留 u32。
pub const CODE_HEADER: usize = 8;

/// Jasper 层的类型化导入声明扩展（Hybrid 文件必需，关键）。
pub const EXT_JASPER_IMPORT: &str = "jasper.import";
/// Jasper 层的源码扩展（可选，非关键）。
pub const EXT_JASPER_SOURCE: &str = "jasper.source";
/// 核心层认识的扩展：(名字, 版本, 必须的关键标志)。
pub const KNOWN_EXTENSIONS: [(&str, u32, bool); 2] = [(EXT_JASPER_IMPORT, 1, true), (EXT_JASPER_SOURCE, 1, false)];

/// 模块种类。
/// Module kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    /// 原生代码。
    Native = 1,
    /// 托管运行时镜像（beta 的唯一载体：JVM class 文件）。
    Managed = 2,
    /// 原生代码 + 自带的 Jasper 绑定（`jasper.import`）。
    Hybrid = 3,
}

impl ModuleKind {
    /// 从字段值解析。
    pub const fn from_u16(v: u16) -> Option<ModuleKind> {
        match v {
            1 => Some(ModuleKind::Native),
            2 => Some(ModuleKind::Managed),
            3 => Some(ModuleKind::Hybrid),
            _ => None,
        }
    }

    /// 该模块种类允许的镜像种类。
    pub const fn image_kind(self) -> ImageKind {
        match self {
            ModuleKind::Native | ModuleKind::Hybrid => ImageKind::Native,
            ModuleKind::Managed => ImageKind::Managed,
        }
    }
}

/// 镜像种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    /// 原生镜像：映像段 + 导出 + 重定位。
    Native = 1,
    /// 托管镜像：代码段 + 导出。
    Managed = 2,
}

impl ImageKind {
    const fn from_u16(v: u16) -> Option<ImageKind> {
        match v {
            1 => Some(ImageKind::Native),
            2 => Some(ImageKind::Managed),
            _ => None,
        }
    }
}

/// 目标指令集。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// x86_64。
    X86_64 = 1,
    /// AArch64。
    Aarch64 = 2,
    /// RISC-V 64。
    Riscv64 = 3,
    /// RISC-V 32。
    Riscv32 = 4,
}

impl Arch {
    /// 从字段值解析。
    pub const fn from_u16(v: u16) -> Option<Arch> {
        match v {
            1 => Some(Arch::X86_64),
            2 => Some(Arch::Aarch64),
            3 => Some(Arch::Riscv64),
            4 => Some(Arch::Riscv32),
            _ => None,
        }
    }

    /// 名字（`x86_64` / `aarch64` / `riscv64` / `riscv32`）。
    pub const fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
            Arch::Riscv64 => "riscv64",
            Arch::Riscv32 => "riscv32",
        }
    }

    /// 由名字解析。
    pub fn from_name(s: &str) -> Option<Arch> {
        [Arch::X86_64, Arch::Aarch64, Arch::Riscv64, Arch::Riscv32].into_iter().find(|a| a.name() == s)
    }

    /// 该指令集的指针宽度（字节）：RISC-V32 为 4，其余为 8。
    /// Pointer width of the ISA in bytes.
    pub const fn pointer_bytes(self) -> u32 {
        match self {
            Arch::Riscv32 => 4,
            Arch::X86_64 | Arch::Aarch64 | Arch::Riscv64 => 8,
        }
    }

    /// 该指令集唯一允许的重定位种类（按指针宽度：[`RELOC_RELATIVE32`] 或 [`RELOC_RELATIVE64`]）。
    /// The only relocation kind allowed for this ISA.
    pub const fn relative_reloc(self) -> u32 {
        if self.pointer_bytes() == 4 {
            RELOC_RELATIVE32
        } else {
            RELOC_RELATIVE64
        }
    }

    /// 本程序编译所针对的指令集（不在上述四种之内时为 `None`）。
    pub const fn current() -> Option<Arch> {
        if cfg!(target_arch = "x86_64") {
            Some(Arch::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else if cfg!(target_arch = "riscv64") {
            Some(Arch::Riscv64)
        } else if cfg!(target_arch = "riscv32") {
            Some(Arch::Riscv32)
        } else {
            None
        }
    }
}

/// 装载阶段：模块允许在什么时候被装入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// 运行时由用户态装载器装入（插件、按需装载）。
    Runtime = 0,
    /// 启动期装入。
    Boot = 1,
    /// 构建期组合（随镜像一起链接）。
    Build = 2,
}

impl Stage {
    /// 从字段值解析。
    pub const fn from_u8(v: u8) -> Option<Stage> {
        match v {
            0 => Some(Stage::Runtime),
            1 => Some(Stage::Boot),
            2 => Some(Stage::Build),
            _ => None,
        }
    }

    /// 名字。
    pub const fn name(self) -> &'static str {
        match self {
            Stage::Runtime => "runtime",
            Stage::Boot => "boot",
            Stage::Build => "build",
        }
    }

    /// 由名字解析。
    pub fn from_name(s: &str) -> Option<Stage> {
        [Stage::Runtime, Stage::Boot, Stage::Build].into_iter().find(|a| a.name() == s)
    }
}

/// 段的种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// 清单。
    Manifest = 1,
    /// 映像段。
    Segment = 2,
    /// 导出表。
    Exports = 3,
    /// 重定位表。
    Relocs = 4,
    /// 发布者签名。
    Signature = 5,
    /// 平台描述。
    Platform = 6,
    /// 镜像索引。
    Images = 7,
    /// 扩展。
    Ext = 8,
    /// 托管代码。
    Code = 9,
}

impl SectionKind {
    const fn from_u32(v: u32) -> Option<SectionKind> {
        match v {
            1 => Some(SectionKind::Manifest),
            2 => Some(SectionKind::Segment),
            3 => Some(SectionKind::Exports),
            4 => Some(SectionKind::Relocs),
            5 => Some(SectionKind::Signature),
            6 => Some(SectionKind::Platform),
            7 => Some(SectionKind::Images),
            8 => Some(SectionKind::Ext),
            9 => Some(SectionKind::Code),
            _ => None,
        }
    }

    /// 是否属于某个镜像（经镜像索引认领）；否则属于整个文件。
    const fn image_owned(self) -> bool {
        matches!(self, SectionKind::Segment | SectionKind::Exports | SectionKind::Relocs | SectionKind::Code)
    }

    /// 整个文件中允许的个数上限（属于镜像的段由镜像组成规则限制）。
    const fn max_per_file(self) -> u32 {
        match self {
            SectionKind::Manifest | SectionKind::Signature | SectionKind::Platform | SectionKind::Images => 1,
            SectionKind::Ext => MAX_EXTENSIONS,
            SectionKind::Segment | SectionKind::Exports | SectionKind::Relocs | SectionKind::Code => MAX_SECTIONS,
        }
    }
}

/// 结构读取错误（SPEC §12.1）。[`JasoError::code`] 给出 SPEC §13 的稳定错误码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JasoError {
    /// 文件短于头部。
    Truncated,
    /// 魔数不符。
    BadMagic,
    /// 格式版本不受支持。
    UnsupportedVersion(u16),
    /// 未知的模块种类。
    UnsupportedKind(u16),
    /// 未知的指令集编号。
    UnknownArch(u16),
    /// 未知的装载阶段编号。
    UnknownStage(u8),
    /// 头部字段非法（头部长度、保留字段）。
    BadHeader,
    /// `file_len` 与实际长度不符。
    LengthMismatch,
    /// 完整性校验失败（内容被改动）。
    DigestMismatch,
    /// 段目录越界、项数超限，或按种类的目录字段非法。
    BadSectionDir,
    /// 某段的内容越出文件。
    SectionOutOfFile,
    /// 未知的段种类。
    UnknownSection(u32),
    /// 某种段多于允许的个数。
    DuplicateSection(u32),
    /// 缺少必需的段。
    MissingSection(u32),
    /// 平台段布局或取值非法。
    PlatformMalformed,
    /// 头部 `arch` 与被引用的平台记录不一致。
    PlatformArch,
    /// 镜像索引非法，或段未正确归属到镜像。
    ImageIndex,
    /// 镜像种类不为模块种类所允许。
    ImageKindNotAllowed,
    /// 映像大小非法。
    BadImageSize,
    /// 映像段非法（未对齐、越界、标志非法、`mem_size < file_size`）。
    BadSegment,
    /// 映像段同时可写可执行。
    WriteExecute,
    /// 两个映像段占用了同一页。
    SegmentOverlap,
    /// 导出表格式非法（越界、名字非法或重复、种类或取值不对）。
    BadExports,
    /// 原生导出不在可执行段内。
    ExportOutOfRange,
    /// 重定位表格式非法或种类不对。
    BadReloc,
    /// 重定位目标越界、未对齐或落在可执行段内。
    RelocOutOfRange,
    /// 托管代码段格式非法。
    BadCode,
    /// 清单错误。
    Manifest(ManifestError),
    /// 清单 `core.stage` 与头部不符。
    ManifestStage,
    /// 清单 `core.abi` 与被引用的平台记录不符。
    PlatformAbi,
    /// 导出表与清单 `core.exports` 不一一对应（多出、缺少或清单内重名）。
    ExportsMismatch,
    /// 扩展段格式非法，或保留名的关键标志不对。
    ExtensionMalformed,
    /// 未知的关键扩展，或已知名字的未知版本被标为关键。
    ExtensionCritical,
    /// 两个扩展段同名。
    ExtensionDuplicate,
    /// Hybrid 文件没有恰好一个 `jasper.import`。
    ExtensionRequired,
    /// 签名段格式非法（长度、算法、保留字段，或不在文件末尾、与其它内容重叠）。
    /// Malformed signature section.
    BadSignatureSection,
}

impl JasoError {
    /// 稳定错误码（SPEC §13）。
    pub const fn code(self) -> ErrorCode {
        match self {
            JasoError::Truncated => ErrorCode::FormatTruncated,
            JasoError::BadMagic => ErrorCode::FormatMagic,
            JasoError::UnsupportedVersion(_) => ErrorCode::VersionUnsupported,
            JasoError::UnsupportedKind(_) => ErrorCode::FormatKind,
            JasoError::UnknownArch(_) => ErrorCode::FormatArch,
            JasoError::UnknownStage(_) => ErrorCode::FormatStage,
            JasoError::BadHeader => ErrorCode::FormatHeader,
            JasoError::LengthMismatch => ErrorCode::FormatLength,
            JasoError::DigestMismatch => ErrorCode::FormatDigest,
            JasoError::BadSectionDir => ErrorCode::SectionDir,
            JasoError::SectionOutOfFile => ErrorCode::SectionBounds,
            JasoError::UnknownSection(_) => ErrorCode::SectionUnknown,
            JasoError::DuplicateSection(_) => ErrorCode::SectionDuplicate,
            JasoError::MissingSection(_) => ErrorCode::SectionMissing,
            JasoError::PlatformMalformed => ErrorCode::PlatformMalformed,
            JasoError::PlatformArch => ErrorCode::PlatformArch,
            JasoError::ImageIndex => ErrorCode::ImageIndex,
            JasoError::ImageKindNotAllowed => ErrorCode::ImageKind,
            JasoError::BadImageSize => ErrorCode::ImageSize,
            JasoError::BadSegment => ErrorCode::ImageSegment,
            JasoError::WriteExecute => ErrorCode::ImageWx,
            JasoError::SegmentOverlap => ErrorCode::ImageOverlap,
            JasoError::BadExports => ErrorCode::ImageExports,
            JasoError::ExportOutOfRange => ErrorCode::ImageExportRange,
            JasoError::BadReloc => ErrorCode::ImageReloc,
            JasoError::RelocOutOfRange => ErrorCode::ImageRelocRange,
            JasoError::BadCode => ErrorCode::ImageCode,
            JasoError::Manifest(m) => m.code(),
            JasoError::ManifestStage => ErrorCode::ManifestStage,
            JasoError::PlatformAbi => ErrorCode::PlatformAbi,
            JasoError::ExportsMismatch => ErrorCode::ImageExportsMismatch,
            JasoError::ExtensionMalformed => ErrorCode::ExtensionMalformed,
            JasoError::ExtensionCritical => ErrorCode::ExtensionCritical,
            JasoError::ExtensionDuplicate => ErrorCode::ExtensionDuplicate,
            JasoError::ExtensionRequired => ErrorCode::ExtensionRequired,
            JasoError::BadSignatureSection => ErrorCode::SignatureSection,
        }
    }
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// 计算文件的 SHA-256（digest 字段按全零计算）。`bytes` 至少要有头部那么长。
pub fn digest_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&bytes[..DIGEST_OFFSET]);
    h.update([0u8; 32]);
    h.update(&bytes[DIGEST_OFFSET + 32..]);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_slice());
    out
}

/// 计算签名覆盖内容的 SHA-256：digest 字段与签名值（`sig_offset` 为签名段起点）都按全零计算。
/// 发布者公钥与签名算法字段仍在覆盖范围内，换公钥必然使签名失效。
/// `bytes` 至少要有头部那么长，签名段须完整落在 `bytes` 内。
/// SHA-256 over everything except the integrity digest and the signature value.
pub fn signed_digest_of(bytes: &[u8], sig_offset: usize) -> [u8; 32] {
    let value = sig_offset + SIGNATURE_VALUE_OFFSET;
    let mut h = Sha256::new();
    h.update(&bytes[..DIGEST_OFFSET]);
    h.update([0u8; 32]);
    h.update(&bytes[DIGEST_OFFSET + 32..value]);
    h.update([0u8; 64]);
    h.update(&bytes[value + 64..]);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_slice());
    out
}

/// 由签名覆盖摘要得到被签名的消息：[`SIGNATURE_DOMAIN`] ‖ 摘要。
/// The message that is actually signed.
pub fn signed_message(digest: &[u8; 32]) -> [u8; SIGNATURE_DOMAIN.len() + 32] {
    let mut m = [0u8; SIGNATURE_DOMAIN.len() + 32];
    m[..SIGNATURE_DOMAIN.len()].copy_from_slice(SIGNATURE_DOMAIN);
    m[SIGNATURE_DOMAIN.len()..].copy_from_slice(digest);
    m
}

/// `[off, off + len)` 是否落在长度为 `total` 的范围内（检查式运算，不回绕）。
pub const fn range_within(off: u32, len: u32, total: usize) -> bool {
    match off.checked_add(len) {
        Some(end) => end as usize <= total,
        None => false,
    }
}

/// 签名段的内容（格式已校验；是否可信由 [`trust::TrustPolicy`] 判断）。
/// The parsed signature section (format-checked only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureSection {
    /// 签名算法（beta 只有 [`SIG_ED25519`]）。
    pub scheme: u32,
    /// 签名者声称的发布者公钥。
    pub publisher_key: [u8; 32],
    /// 签名值。
    pub signature: [u8; 64],
    /// 签名段在文件中的偏移。
    pub file_offset: u32,
}

/// 段目录项。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Dir {
    kind: u32,
    flags: u32,
    file_offset: u32,
    file_size: u32,
    vaddr: u32,
    mem_size: u32,
    reserved: u64,
}

fn dir_at(bytes: &[u8], dir_offset: u32, i: u32) -> Dir {
    let o = dir_offset as usize + i as usize * SECTION_SIZE;
    Dir {
        kind: u32_at(bytes, o),
        flags: u32_at(bytes, o + 4),
        file_offset: u32_at(bytes, o + 8),
        file_size: u32_at(bytes, o + 12),
        vaddr: u32_at(bytes, o + 16),
        mem_size: u32_at(bytes, o + 20),
        reserved: u64_at(bytes, o + 24),
    }
}

fn section_of<'a>(bytes: &'a [u8], d: &Dir) -> &'a [u8] {
    &bytes[d.file_offset as usize..(d.file_offset + d.file_size) as usize]
}

/// 一个映像段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// 相对装入基址的起始偏移（页对齐）。
    pub vaddr: u32,
    /// 装入后占用的字节数（≥ `data.len()`，多出部分清零）。
    pub mem_size: u32,
    /// 权限标志（[`FLAG_R`] | [`FLAG_W`] | [`FLAG_X`]）。
    pub flags: u32,
    /// 文件中的内容。
    pub data: &'a [u8],
}

impl Segment<'_> {
    /// 占用的页范围 `[首页, 尾页 + 1)`（按字节偏移，页对齐）。
    pub fn page_span(&self) -> (u32, u32) {
        (self.vaddr, self.vaddr + self.mem_size.div_ceil(PAGE) * PAGE)
    }
}

/// 一个导出项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Export<'a> {
    /// 名字。
    pub name: &'a str,
    /// 原生：映像内偏移；托管：0。
    pub value: u32,
    /// 种类（[`EXPORT_FUNC`] 或 [`EXPORT_MANAGED`]）。
    pub kind: u32,
}

/// 一个重定位项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    /// 写入位置（映像内偏移）。
    pub offset: u32,
    /// 种类（[`RELOC_RELATIVE64`] 或 [`RELOC_RELATIVE32`]，与平台的指针宽度一致）。
    pub kind: u32,
    /// 加数（映像内偏移）。
    pub addend: u64,
}

/// 托管镜像的代码段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code<'a> {
    /// 载体（beta 只有 [`CODE_JVM_CLASSES`]）。
    pub format: u32,
    /// 载荷（核心层不解释，交给托管运行时）。
    pub payload: &'a [u8],
}

/// 一个扩展段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    /// 名字，如 `jasper.import`。
    pub name: &'a str,
    /// 版本。
    pub version: u32,
    /// 关键标志。
    pub critical: bool,
    /// 内容。
    pub content: &'a [u8],
}

impl Extension<'_> {
    /// 是否为核心层认识的 `(名字, 版本)`。
    pub fn is_known(&self) -> bool {
        KNOWN_EXTENSIONS.iter().any(|&(n, v, _)| n == self.name && v == self.version)
    }
}

/// 扩展段布局（SPEC §9.1）；不合格返回 `None`。
fn parse_extension(b: &[u8], flags: u32) -> Option<Extension<'_>> {
    if b.len() < 8 {
        return None;
    }
    let version = u32_at(b, 0);
    let name_len = u16_at(b, 4) as usize;
    if version == 0 || name_len == 0 || name_len > MAX_EXTENSION_NAME || u16_at(b, 6) != 0 {
        return None;
    }
    let content_at = (8 + name_len).next_multiple_of(8);
    if content_at > b.len() || b[8 + name_len..content_at].iter().any(|&c| c != 0) {
        return None;
    }
    let name = core::str::from_utf8(&b[8..8 + name_len]).ok()?;
    let charset = name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(&c));
    if !charset || !name.contains('.') {
        return None;
    }
    Some(Extension { name, version, critical: flags & EXT_CRITICAL != 0, content: &b[content_at..] })
}

/// 镜像索引中的一项（原始字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    kind: u16,
    platform: u16,
    first: u32,
    count: u32,
    image_size: u32,
    reserved_zero: bool,
}

impl Entry {
    fn contains(&self, i: u32) -> bool {
        i >= self.first && i - self.first < self.count
    }
}

/// 一个镜像（已校验）：平台记录、映像大小与自己认领的段。
/// One validated image of a `.jaso` file.
#[derive(Debug, Clone, Copy)]
pub struct ImageRef<'a> {
    bytes: &'a [u8],
    dir_offset: u32,
    /// 在镜像索引中的下标。
    pub index: u32,
    /// 镜像种类。
    pub kind: ImageKind,
    /// 平台记录。
    pub platform: Platform<'a>,
    /// 原生：装入后占用的字节数（页对齐）；托管：0。
    pub image_size: u32,
    first: u32,
    count: u32,
}

fn is_symbol(s: &str) -> bool {
    manifest::symbol_ok(s)
}

impl<'a> ImageRef<'a> {
    fn dirs(&self) -> impl Iterator<Item = Dir> + '_ {
        (self.first..self.first + self.count).map(|i| dir_at(self.bytes, self.dir_offset, i))
    }

    fn dir_of(&self, kind: SectionKind) -> Option<Dir> {
        self.dirs().find(|d| d.kind == kind as u32)
    }

    fn count_of(&self, kind: SectionKind) -> usize {
        self.dirs().filter(|d| d.kind == kind as u32).count()
    }

    /// 镜像组成、各段、导出、重定位或代码（SPEC §7、§8；第 5 步）。
    fn check(&self) -> Result<(), JasoError> {
        let (segs, exps, rels, codes) =
            (self.count_of(SectionKind::Segment), self.count_of(SectionKind::Exports), self.count_of(SectionKind::Relocs), self.count_of(SectionKind::Code));
        let composed = match self.kind {
            ImageKind::Native => segs >= 1 && exps <= 1 && rels <= 1 && codes == 0,
            ImageKind::Managed => codes == 1 && exps <= 1 && segs == 0 && rels == 0,
        };
        if !composed {
            return Err(JasoError::ImageIndex);
        }
        match self.kind {
            ImageKind::Native => {
                for d in self.dirs().filter(|d| d.kind == SectionKind::Segment as u32) {
                    self.check_segment(&d)?;
                }
                let segs: [Option<Segment<'a>>; MAX_SECTIONS as usize] = self.segment_table();
                for (i, a) in segs.iter().enumerate() {
                    for b in &segs[i + 1..] {
                        if let (Some(a), Some(b)) = (a, b) {
                            let (sa, sb) = (a.page_span(), b.page_span());
                            if sa.0 < sb.1 && sb.0 < sa.1 {
                                return Err(JasoError::SegmentOverlap);
                            }
                        }
                    }
                }
                self.check_exports()?;
                self.check_relocs()
            }
            ImageKind::Managed => {
                self.code().ok_or(JasoError::BadCode)?;
                self.check_exports()
            }
        }
    }

    fn segment_table(&self) -> [Option<Segment<'a>>; MAX_SECTIONS as usize] {
        let mut t = [None; MAX_SECTIONS as usize];
        for (slot, s) in t.iter_mut().zip(self.segments()) {
            *slot = Some(s);
        }
        t
    }

    fn check_segment(&self, d: &Dir) -> Result<(), JasoError> {
        if d.flags & !(FLAG_R | FLAG_W | FLAG_X) != 0 || d.flags & FLAG_R == 0 {
            return Err(JasoError::BadSegment);
        }
        if d.flags & FLAG_W != 0 && d.flags & FLAG_X != 0 {
            return Err(JasoError::WriteExecute);
        }
        if d.vaddr % PAGE != 0 || d.mem_size == 0 || d.mem_size < d.file_size {
            return Err(JasoError::BadSegment);
        }
        let end = d.mem_size.checked_next_multiple_of(PAGE).and_then(|m| d.vaddr.checked_add(m));
        if end.is_none_or(|e| e > self.image_size) {
            return Err(JasoError::BadSegment);
        }
        Ok(())
    }

    /// 偏移 `off` 起 `len` 字节是否整个落在某个满足 `want(flags)` 的段内。
    fn in_segment(&self, off: u64, len: u64, want: impl Fn(u32) -> bool) -> bool {
        self.segments().any(|s| {
            let (start, end) = (s.vaddr as u64, s.vaddr as u64 + s.mem_size as u64);
            want(s.flags) && off >= start && off.checked_add(len).is_some_and(|e| e <= end)
        })
    }

    fn check_exports(&self) -> Result<(), JasoError> {
        let Some(d) = self.dir_of(SectionKind::Exports) else { return Ok(()) };
        let b = section_of(self.bytes, &d);
        if b.len() < 4 {
            return Err(JasoError::BadExports);
        }
        let count = u32_at(b, 0);
        if count > MAX_EXPORTS || 4 + count as usize * EXPORT_SIZE > b.len() {
            return Err(JasoError::BadExports);
        }
        let names_start = 4 + count as usize * EXPORT_SIZE;
        for i in 0..count {
            let e = export_at(b, i).ok_or(JasoError::BadExports)?;
            if (u32_at(b, 4 + i as usize * EXPORT_SIZE) as usize) < names_start {
                return Err(JasoError::BadExports);
            }
            if (0..i).any(|j| export_at(b, j).is_some_and(|p| p.name == e.name)) {
                return Err(JasoError::BadExports);
            }
            match self.kind {
                ImageKind::Native => {
                    if e.kind != EXPORT_FUNC {
                        return Err(JasoError::BadExports);
                    }
                    if !self.in_segment(e.value as u64, 1, |f| f & FLAG_X != 0) {
                        return Err(JasoError::ExportOutOfRange);
                    }
                }
                ImageKind::Managed => {
                    if e.kind != EXPORT_MANAGED || e.value != 0 {
                        return Err(JasoError::BadExports);
                    }
                }
            }
        }
        Ok(())
    }

    /// 导出表与清单声明一一对应：每个声明都在表中、表中每项都被声明、声明内不重名（表内重名已由 check_exports 排除）。
    fn check_declared_exports(&self, manifest: &Manifest<'_>) -> Result<(), JasoError> {
        let mut n = 0usize;
        for (i, name) in manifest.exports().enumerate() {
            if manifest.exports().take(i).any(|p| p == name) || self.export(name).is_none() {
                return Err(JasoError::ExportsMismatch);
            }
            n += 1;
        }
        if n != self.exports().count() {
            return Err(JasoError::ExportsMismatch);
        }
        Ok(())
    }

    fn check_relocs(&self) -> Result<(), JasoError> {
        let Some(d) = self.dir_of(SectionKind::Relocs) else { return Ok(()) };
        let b = section_of(self.bytes, &d);
        if b.len() < 4 {
            return Err(JasoError::BadReloc);
        }
        let count = u32_at(b, 0) as usize;
        if count.checked_mul(RELOC_SIZE).and_then(|n| n.checked_add(4)) != Some(b.len()) {
            return Err(JasoError::BadReloc);
        }
        let width = self.platform.pointer_bytes as u32;
        let want = if width == 4 { RELOC_RELATIVE32 } else { RELOC_RELATIVE64 };
        for r in self.relocs() {
            if r.kind != want {
                return Err(JasoError::BadReloc);
            }
            if r.offset % width != 0 || r.addend >= self.image_size as u64 || !self.in_segment(r.offset as u64, width as u64, |f| f & FLAG_X == 0) {
                return Err(JasoError::RelocOutOfRange);
            }
        }
        Ok(())
    }

    /// 全部映像段（托管镜像没有）。
    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        self.dirs().filter(|d| d.kind == SectionKind::Segment as u32).map(|d| Segment {
            vaddr: d.vaddr,
            mem_size: d.mem_size,
            flags: d.flags,
            data: section_of(self.bytes, &d),
        })
    }

    /// 全部导出项。
    pub fn exports(&self) -> impl Iterator<Item = Export<'a>> + '_ {
        let b = self.dir_of(SectionKind::Exports).map(|d| section_of(self.bytes, &d)).unwrap_or(&[]);
        let n = if b.len() >= 4 { u32_at(b, 0) } else { 0 };
        (0..n).filter_map(move |i| export_at(b, i))
    }

    /// 按名字查导出项。
    pub fn export(&self, name: &str) -> Option<Export<'a>> {
        self.exports().find(|e| e.name == name)
    }

    /// 全部重定位项。
    pub fn relocs(&self) -> impl Iterator<Item = Reloc> + '_ {
        let b = self.dir_of(SectionKind::Relocs).map(|d| section_of(self.bytes, &d)).unwrap_or(&[]);
        let n = if b.len() >= 4 { u32_at(b, 0) } else { 0 };
        (0..n).map(move |i| {
            let o = 4 + i as usize * RELOC_SIZE;
            Reloc { offset: u32_at(b, o), kind: u32_at(b, o + 4), addend: u64_at(b, o + 8) }
        })
    }

    /// 托管代码段（原生镜像或格式不合格时为 `None`）。
    pub fn code(&self) -> Option<Code<'a>> {
        let b = section_of(self.bytes, &self.dir_of(SectionKind::Code)?);
        if b.len() <= CODE_HEADER || u32_at(b, 0) != CODE_JVM_CLASSES || u32_at(b, 4) != 0 {
            return None;
        }
        Some(Code { format: u32_at(b, 0), payload: &b[CODE_HEADER..] })
    }
}

fn export_at(b: &[u8], i: u32) -> Option<Export<'_>> {
    let o = 4 + i as usize * EXPORT_SIZE;
    let (no, nl) = (u32_at(b, o) as usize, u32_at(b, o + 4));
    if nl == 0 || nl > MAX_NAME {
        return None;
    }
    let name = core::str::from_utf8(b.get(no..no.checked_add(nl as usize)?)?).ok()?;
    if !is_symbol(name) {
        return None;
    }
    Some(Export { name, value: u32_at(b, o + 8), kind: u32_at(b, o + 12) })
}

/// 校验通过的 `.jaso` 文件视图（只借用输入字节，不分配）。
/// A validated `.jaso` file.
#[derive(Debug, Clone, Copy)]
pub struct Jaso<'a> {
    bytes: &'a [u8],
    /// 模块种类。
    pub kind: ModuleKind,
    /// 头部 `arch`：`None` 表示 any（托管或多指令集文件）。
    pub arch: Option<Arch>,
    /// 装载阶段。
    pub stage: Stage,
    /// 文件的 SHA-256（已校验）。
    pub digest: [u8; 32],
    /// 清单。
    pub manifest: Manifest<'a>,
    section_count: u32,
    dir_offset: u32,
    platforms: Dir,
    images: Dir,
    signature: Option<Dir>,
}

impl<'a> Jaso<'a> {
    /// 解析并完整校验一个 `.jaso` 文件（SPEC §12.1，按其顺序报告第一处违例）。
    /// 成功返回的视图中，所有偏移都已证明在界内。
    pub fn parse(bytes: &'a [u8]) -> Result<Jaso<'a>, JasoError> {
        // 1. 头部
        if bytes.len() < HEADER_SIZE {
            return Err(JasoError::Truncated);
        }
        if bytes[..8] != MAGIC {
            return Err(JasoError::BadMagic);
        }
        let format = u16_at(bytes, 8);
        if format != FORMAT_VERSION {
            return Err(JasoError::UnsupportedVersion(format));
        }
        let kind_v = u16_at(bytes, 10);
        let kind = ModuleKind::from_u16(kind_v).ok_or(JasoError::UnsupportedKind(kind_v))?;
        let arch = match u16_at(bytes, 12) {
            0 => None,
            v => Some(Arch::from_u16(v).ok_or(JasoError::UnknownArch(v))?),
        };
        let stage = Stage::from_u8(bytes[14]).ok_or(JasoError::UnknownStage(bytes[14]))?;
        if bytes[15] != 0 || u32_at(bytes, 16) as usize != HEADER_SIZE || u32_at(bytes, 32) != 0 || u32_at(bytes, 36) != 0 || u64_at(bytes, 72) != 0 {
            return Err(JasoError::BadHeader);
        }
        if u32_at(bytes, 28) as usize != bytes.len() || bytes.len() > u32::MAX as usize {
            return Err(JasoError::LengthMismatch);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[DIGEST_OFFSET..DIGEST_OFFSET + 32]);
        if digest_of(bytes) != digest {
            return Err(JasoError::DigestMismatch);
        }

        // 2. 段目录的位置与项数，然后逐项
        let section_count = u32_at(bytes, 20);
        let dir_offset = u32_at(bytes, 24);
        if section_count == 0 || section_count > MAX_SECTIONS || (dir_offset as usize) < HEADER_SIZE {
            return Err(JasoError::BadSectionDir);
        }
        if !range_within(dir_offset, section_count * SECTION_SIZE as u32, bytes.len()) {
            return Err(JasoError::BadSectionDir);
        }
        let mut img = Jaso {
            bytes,
            kind,
            arch,
            stage,
            digest,
            manifest: Manifest::empty(),
            section_count,
            dir_offset,
            platforms: Dir::default(),
            images: Dir::default(),
            signature: None,
        };
        let mut counts = [0u32; 10];
        let mut manifest = None;
        let (mut platforms, mut images) = (None, None);
        for i in 0..section_count {
            let d = img.dir(i);
            let k = SectionKind::from_u32(d.kind).ok_or(JasoError::UnknownSection(d.kind))?;
            let fields_ok = d.reserved == 0
                && match k {
                    SectionKind::Segment => true,
                    SectionKind::Ext => d.flags & !EXT_CRITICAL == 0 && d.vaddr == 0 && d.mem_size == 0,
                    _ => d.flags == 0 && d.vaddr == 0 && d.mem_size == 0,
                };
            if !fields_ok {
                return Err(JasoError::BadSectionDir);
            }
            if !range_within(d.file_offset, d.file_size, bytes.len()) || (d.file_offset as usize) < HEADER_SIZE && d.file_size > 0 {
                return Err(JasoError::SectionOutOfFile);
            }
            counts[k as usize] += 1;
            if counts[k as usize] > k.max_per_file() {
                return Err(JasoError::DuplicateSection(d.kind));
            }
            match k {
                SectionKind::Manifest => manifest = Some(d),
                SectionKind::Platform => platforms = Some(d),
                SectionKind::Images => images = Some(d),
                SectionKind::Signature => img.signature = Some(d),
                _ => {}
            }
        }

        // 3. 必需段
        let manifest = manifest.ok_or(JasoError::MissingSection(SectionKind::Manifest as u32))?;
        img.platforms = platforms.ok_or(JasoError::MissingSection(SectionKind::Platform as u32))?;
        img.images = images.ok_or(JasoError::MissingSection(SectionKind::Images as u32))?;

        // 4. 平台段，然后镜像索引（含段的归属）
        img.check_platforms()?;
        img.check_images()?;

        // 5. 逐个镜像
        for im in img.images() {
            im.check()?;
        }

        // 6. 清单，然后 core.abi 与平台，然后导出声明
        let text = core::str::from_utf8(img.section_bytes(&manifest)).map_err(|_| JasoError::Manifest(ManifestError::NotUtf8))?;
        img.manifest = Manifest::parse(text).map_err(JasoError::Manifest)?;
        if img.manifest.stage != stage {
            return Err(JasoError::ManifestStage);
        }
        if img.images().any(|im| im.platform.abi != img.manifest.abi) {
            return Err(JasoError::PlatformAbi);
        }
        for im in img.images() {
            im.check_declared_exports(&img.manifest)?;
        }

        // 7. 扩展（按目录顺序），然后 Hybrid 的要求
        img.check_extensions()?;

        // 8. 签名段布局
        img.check_signature()?;
        Ok(img)
    }

    fn dir(&self, i: u32) -> Dir {
        dir_at(self.bytes, self.dir_offset, i)
    }

    fn section_bytes(&self, d: &Dir) -> &'a [u8] {
        section_of(self.bytes, d)
    }

    fn platform_count(&self) -> u32 {
        u32_at(self.section_bytes(&self.platforms), 0)
    }

    fn platform_raw(&self, i: u32) -> &'a [u8] {
        let o = 8 + i as usize * platform::PLATFORM_RECORD;
        &self.section_bytes(&self.platforms)[o..o + platform::PLATFORM_RECORD]
    }

    fn check_platforms(&self) -> Result<(), JasoError> {
        let b = self.section_bytes(&self.platforms);
        if b.len() < 8 {
            return Err(JasoError::PlatformMalformed);
        }
        let count = u32_at(b, 0);
        if count == 0 || count > platform::MAX_PLATFORMS || u32_at(b, 4) != 0 || b.len() != 8 + count as usize * platform::PLATFORM_RECORD {
            return Err(JasoError::PlatformMalformed);
        }
        for i in 0..count {
            Platform::parse(self.platform_raw(i)).ok_or(JasoError::PlatformMalformed)?;
        }
        Ok(())
    }

    fn image_count(&self) -> u32 {
        u32_at(self.section_bytes(&self.images), 0)
    }

    fn entry(&self, i: u32) -> Entry {
        let b = self.section_bytes(&self.images);
        let o = 8 + i as usize * IMAGE_ENTRY_SIZE;
        Entry {
            kind: u16_at(b, o),
            platform: u16_at(b, o + 2),
            first: u32_at(b, o + 4),
            count: u32_at(b, o + 8),
            image_size: u32_at(b, o + 12),
            reserved_zero: b[o + 16..o + 32].iter().all(|&c| c == 0),
        }
    }

    fn check_images(&self) -> Result<(), JasoError> {
        let b = self.section_bytes(&self.images);
        if b.len() < 8 {
            return Err(JasoError::ImageIndex);
        }
        let count = u32_at(b, 0);
        if count == 0 || count > MAX_IMAGES || u32_at(b, 4) != 0 || b.len() != 8 + count as usize * IMAGE_ENTRY_SIZE {
            return Err(JasoError::ImageIndex);
        }
        for i in 0..count {
            let e = self.entry(i);
            let ik = ImageKind::from_u16(e.kind).ok_or(JasoError::ImageIndex)?;
            if !e.reserved_zero || e.platform as u32 >= self.platform_count() {
                return Err(JasoError::ImageIndex);
            }
            if e.count == 0 || e.first.checked_add(e.count).is_none_or(|end| end > self.section_count) {
                return Err(JasoError::ImageIndex);
            }
            let p = Platform::parse(self.platform_raw(e.platform as u32)).ok_or(JasoError::PlatformMalformed)?;
            if p.isa.is_none() != (ik == ImageKind::Managed) {
                return Err(JasoError::ImageIndex);
            }
            if ik != self.kind.image_kind() {
                return Err(JasoError::ImageKindNotAllowed);
            }
            let size_ok = match ik {
                ImageKind::Native => e.image_size % PAGE == 0 && e.image_size >= PAGE && e.image_size <= MAX_IMAGE,
                ImageKind::Managed => e.image_size == 0,
            };
            if !size_ok {
                return Err(JasoError::BadImageSize);
            }
        }
        // 镜像之间：区间互不重叠；共用平台记录的两项除区间外必须相同
        for i in 0..count {
            for j in i + 1..count {
                let (a, b) = (self.entry(i), self.entry(j));
                if a.first < b.first + b.count && b.first < a.first + a.count {
                    return Err(JasoError::ImageIndex);
                }
                if a.platform == b.platform && (a.kind != b.kind || a.image_size != b.image_size) {
                    return Err(JasoError::ImageIndex);
                }
            }
        }
        // 段的归属：属于镜像的段恰好落在一个区间内，属于文件的段不落在任何区间内
        for s in 0..self.section_count {
            let owned = SectionKind::from_u32(self.dir(s).kind).is_some_and(SectionKind::image_owned);
            let inside = (0..count).any(|i| self.entry(i).contains(s));
            if owned != inside {
                return Err(JasoError::ImageIndex);
            }
        }
        // 头部 arch ≠ any 时，被引用的平台记录都必须是这一指令集
        if let Some(a) = self.arch {
            if self.images().any(|im| im.platform.isa != Some(a)) {
                return Err(JasoError::PlatformArch);
            }
        }
        Ok(())
    }

    fn check_extensions(&self) -> Result<(), JasoError> {
        for i in 0..self.section_count {
            let d = self.dir(i);
            if d.kind != SectionKind::Ext as u32 {
                continue;
            }
            let e = parse_extension(self.section_bytes(&d), d.flags).ok_or(JasoError::ExtensionMalformed)?;
            let earlier = (0..i).map(|j| self.dir(j)).filter(|p| p.kind == SectionKind::Ext as u32);
            if earlier.filter_map(|p| parse_extension(self.section_bytes(&p), p.flags)).any(|p| p.name == e.name) {
                return Err(JasoError::ExtensionDuplicate);
            }
            match KNOWN_EXTENSIONS.iter().find(|&&(n, v, _)| n == e.name && v == e.version) {
                Some(&(_, _, critical)) if critical != e.critical => return Err(JasoError::ExtensionMalformed),
                Some(_) => {}
                None if e.critical => return Err(JasoError::ExtensionCritical),
                None => {}
            }
        }
        if self.kind == ModuleKind::Hybrid && self.extension(EXT_JASPER_IMPORT, 1).is_none() {
            return Err(JasoError::ExtensionRequired);
        }
        Ok(())
    }

    /// 签名段：恰好 [`SIGNATURE_SIZE`] 字节、算法已知、保留为 0，位于文件末尾，
    /// 段目录与其它所有段都在它之前结束（签名值不与任何被签名的内容共用字节）。
    fn check_signature(&self) -> Result<(), JasoError> {
        let Some(d) = self.signature else { return Ok(()) };
        let b = self.section_bytes(&d);
        if b.len() != SIGNATURE_SIZE || d.file_offset as usize + SIGNATURE_SIZE != self.bytes.len() {
            return Err(JasoError::BadSignatureSection);
        }
        if u32_at(b, 0) != SIG_ED25519 || u32_at(b, 4) != 0 {
            return Err(JasoError::BadSignatureSection);
        }
        let dir_end = self.dir_offset as usize + self.section_count as usize * SECTION_SIZE;
        if dir_end > d.file_offset as usize {
            return Err(JasoError::BadSignatureSection);
        }
        for i in 0..self.section_count {
            let o = self.dir(i);
            if o.kind != SectionKind::Signature as u32 && o.file_size > 0 && o.file_offset + o.file_size > d.file_offset {
                return Err(JasoError::BadSignatureSection);
            }
        }
        Ok(())
    }

    /// 全部镜像（按索引顺序）。
    pub fn images(&self) -> impl Iterator<Item = ImageRef<'a>> + '_ {
        (0..self.image_count()).filter_map(|i| self.image(i))
    }

    /// 第 `i` 个镜像。
    pub fn image(&self, i: u32) -> Option<ImageRef<'a>> {
        if i >= self.image_count() {
            return None;
        }
        let e = self.entry(i);
        let platform = Platform::parse(self.platform_raw(e.platform as u32))?;
        let kind = ImageKind::from_u16(e.kind)?;
        Some(ImageRef {
            bytes: self.bytes,
            dir_offset: self.dir_offset,
            index: i,
            kind,
            platform,
            image_size: e.image_size,
            first: e.first,
            count: e.count,
        })
    }

    /// 按宿主平台选择镜像（SPEC §12.2 第 3 步）：第一个平台记录与宿主相符的镜像；
    /// 都不符时报告镜像 0 第一个不符的字段。
    pub fn select(&self, host: &HostPlatform<'_>) -> Result<ImageRef<'a>, PlatformMismatch> {
        let mut first = None;
        for im in self.images() {
            match im.platform.mismatch(host) {
                None => return Ok(im),
                Some(m) => {
                    first.get_or_insert(m);
                }
            }
        }
        // 校验通过的文件至少有一个镜像，`first` 必然已填
        Err(first.unwrap_or(PlatformMismatch { field: PlatformField::Isa, expected: platform_text(""), actual: platform_text("") }))
    }

    /// 全部扩展段（按目录顺序；包括被跳过的未知非关键扩展）。
    pub fn extensions(&self) -> impl Iterator<Item = Extension<'a>> + '_ {
        (0..self.section_count)
            .map(|i| self.dir(i))
            .filter(|d| d.kind == SectionKind::Ext as u32)
            .filter_map(|d| parse_extension(self.section_bytes(&d), d.flags))
    }

    /// 按名字与版本查扩展段。
    pub fn extension(&self, name: &str, version: u32) -> Option<Extension<'a>> {
        self.extensions().find(|e| e.name == name && e.version == version)
    }

    /// 签名段（没有签名时为 `None`）。
    /// The signature section, if the file is signed.
    pub fn signature(&self) -> Option<SignatureSection> {
        let d = self.signature?;
        let b = self.section_bytes(&d);
        let mut publisher_key = [0u8; 32];
        publisher_key.copy_from_slice(&b[8..40]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&b[SIGNATURE_VALUE_OFFSET..SIGNATURE_VALUE_OFFSET + 64]);
        Some(SignatureSection { scheme: u32_at(b, 0), publisher_key, signature, file_offset: d.file_offset })
    }

    /// 签名覆盖内容的摘要（没有签名时为 `None`），见 [`signed_digest_of`]。
    /// Digest of the signed content, if the file is signed.
    pub fn signed_digest(&self) -> Option<[u8; 32]> {
        self.signature.map(|d| signed_digest_of(self.bytes, d.file_offset as usize))
    }

    /// 文件的原始字节。
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

fn platform_text(s: &str) -> platform::ShortText {
    platform::ShortText::new(s)
}

/// 宿主接口表 v1：装载器在调用模块的 `jaso_init` 时传入。
///
/// 模块**不按名字导入**任何宿主符号——宿主能力只经这张显式的表提供，表头带版本与长度，
/// 日后增加函数只在末尾追加（`size` 随之变大），旧模块按自己认识的长度读取。
/// 清单中 `core.host = jaso.host.v1` 表示模块需要这张表。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostV1 {
    /// 表版本（= 1）。
    pub version: u32,
    /// 表长度（字节）。
    pub size: u32,
    /// 输出一行文本（UTF-8）。
    pub log: extern "C" fn(ptr: *const u8, len: usize),
    /// 分配：失败返回空指针。
    pub alloc: extern "C" fn(size: usize, align: usize) -> *mut u8,
    /// 释放：参数与分配时一致。
    pub dealloc: extern "C" fn(ptr: *mut u8, size: usize, align: usize),
}

/// 宿主接口表的版本号。
pub const HOST_TABLE_VERSION: u32 = 1;
/// 宿主接口表 v1 的名字（清单 `core.host` 的取值）。
pub const HOST_V1: &str = "jaso.host.v1";
/// 模块初始化导出的名字：`extern "C" fn(host: *const HostV1) -> i32`，返回 0 表示成功。
pub const INIT_SYMBOL: &str = "jaso_init";
/// 可选的启动导出：`extern "C" fn() -> i32`。
pub const START_SYMBOL: &str = "jaso_start";
/// 可选的停止导出：`extern "C" fn() -> i32`。
pub const STOP_SYMBOL: &str = "jaso_stop";
/// 本实现支持的原生调用约定（清单 `core.abi` 与平台记录 `abi` 的取值）：C 调用约定、v1。
pub const ABI_C_V1: &str = "c.v1";

#[cfg(kani)]
mod kani_proofs;
#[cfg(test)]
mod tests;
#[cfg(all(test, feature = "sign"))]
mod trust_tests;
