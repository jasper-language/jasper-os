//! 稳定错误码（SPEC §13）：同一文件在同一上下文下，各实现必须报告同一个码。
//! Stable error codes shared by every `.jaso` implementation.
//!
//! 码名是稳定标识（一致性向量的 `.expect` 写码名），编号用于紧凑的二进制传输。
//! 标为 *load* 的码需要宿主上下文（平台、信任表、已装入模块、授予的能力），结构读取不会产生它们。

macro_rules! codes {
    ($($(#[$m:meta])* $v:ident = $n:literal, $s:literal, $load:literal;)*) => {
        /// 错误码。
        /// An error code from SPEC §13.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $($(#[$m])* $v,)*
        }

        impl ErrorCode {
            /// 全部错误码（按编号升序）。
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$v),*];

            /// 稳定码名，如 `image.wx`。
            pub const fn name(self) -> &'static str {
                match self {
                    $(ErrorCode::$v => $s,)*
                }
            }

            /// 编号。
            pub const fn number(self) -> u16 {
                match self {
                    $(ErrorCode::$v => $n,)*
                }
            }

            /// 是否需要宿主上下文（*load* 类）。
            pub const fn is_load(self) -> bool {
                match self {
                    $(ErrorCode::$v => $load,)*
                }
            }
        }
    };
}

codes! {
    /// 短于头部。
    FormatTruncated = 101, "format.truncated", false;
    /// 魔数不符。
    FormatMagic = 102, "format.magic", false;
    /// `header_size` ≠ 80 或头部保留字段非 0。
    FormatHeader = 103, "format.header", false;
    /// `file_len` 与实际长度不符。
    FormatLength = 104, "format.length", false;
    /// 完整性摘要不符。
    FormatDigest = 105, "format.digest", false;
    /// 未知的模块种类。
    FormatKind = 106, "format.kind", false;
    /// 未知的 `arch` 取值。
    FormatArch = 107, "format.arch", false;
    /// 未知的 `stage` 取值。
    FormatStage = 108, "format.stage", false;
    /// `format` ≠ 1。
    VersionUnsupported = 201, "version.unsupported", false;
    /// 段目录越界、项数不对或按种类的目录字段非法。
    SectionDir = 301, "section.dir", false;
    /// 段内容越出文件。
    SectionBounds = 302, "section.bounds", false;
    /// 未知的段种类。
    SectionUnknown = 303, "section.unknown", false;
    /// 某种段多于允许的个数。
    SectionDuplicate = 304, "section.duplicate", false;
    /// 缺少必需的段。
    SectionMissing = 305, "section.missing", false;
    /// 清单不是 UTF-8。
    ManifestUtf8 = 401, "manifest.utf8", false;
    /// 某行不是 `键 = 值`。
    ManifestLine = 402, "manifest.line", false;
    /// 未知的 `core.*` 键或扩展键格式非法。
    ManifestKey = 403, "manifest.key", false;
    /// 缺少必需键。
    ManifestMissing = 404, "manifest.missing", false;
    /// 单值键重复，或依赖名重复。
    ManifestDuplicate = 405, "manifest.duplicate", false;
    /// 取值非法。
    ManifestValue = 406, "manifest.value", false;
    /// 个数超限。
    ManifestLimit = 407, "manifest.limit", false;
    /// `core.stage` 与头部 `stage` 不符。
    ManifestStage = 408, "manifest.stage", false;
    /// 平台段布局或取值非法。
    PlatformMalformed = 501, "platform.malformed", false;
    /// 头部 `arch` 与被引用的平台记录不一致。
    PlatformArch = 502, "platform.arch", false;
    /// `core.abi` 与被引用的平台 `abi` 不符。
    PlatformAbi = 503, "platform.abi", false;
    /// *load*：没有与宿主平台匹配的镜像。
    PlatformMismatch = 504, "platform.mismatch", true;
    /// 镜像索引段非法，或段未正确归属到镜像。
    ImageIndex = 601, "image.index", false;
    /// 镜像种类不为模块种类所允许。
    ImageKind = 602, "image.kind", false;
    /// `image_size` 非法。
    ImageSize = 603, "image.size", false;
    /// 映像段非法。
    ImageSegment = 604, "image.segment", false;
    /// 映像段同时可写可执行。
    ImageWx = 605, "image.wx", false;
    /// 两个映像段共用一页。
    ImageOverlap = 606, "image.overlap", false;
    /// 导出表格式非法。
    ImageExports = 607, "image.exports", false;
    /// 原生导出不在可执行段内。
    ImageExportRange = 608, "image.export_range", false;
    /// 导出表与 `core.exports` 不一一对应。
    ImageExportsMismatch = 609, "image.exports_mismatch", false;
    /// 重定位表格式非法或种类不对。
    ImageReloc = 610, "image.reloc", false;
    /// 重定位目标越界、未对齐或在可执行段内。
    ImageRelocRange = 611, "image.reloc_range", false;
    /// 代码段格式非法。
    ImageCode = 612, "image.code", false;
    /// 签名段格式非法或位置不对。
    SignatureSection = 701, "signature.section", false;
    /// *load*：签名验证失败。
    SignatureInvalid = 702, "signature.invalid", true;
    /// *load*：强制模式下的未签名文件。
    TrustUnsigned = 801, "trust.unsigned", true;
    /// *load*：缺少 `core.publisher` 或发布者不受信。
    TrustPublisher = 802, "trust.publisher", true;
    /// *load*：签名公钥与受信表不符。
    TrustKey = 803, "trust.key", true;
    /// *load*：模块名不在发布者的命名空间内。
    TrustNamespace = 804, "trust.namespace", true;
    /// *load*：所需能力未被授予。
    CapabilityDenied = 901, "capability.denied", true;
    /// *load*：依赖缺失或版本不在区间内。
    DependencyUnsatisfied = 1001, "dependency.unsatisfied", true;
    /// *load*：宿主运行时版本不在 `core.runtime` 区间内。
    DependencyRuntime = 1002, "dependency.runtime", true;
    /// 扩展段格式非法，或保留名的关键标志不对。
    ExtensionMalformed = 1101, "extension.malformed", false;
    /// 未知的关键扩展或不支持的版本。
    ExtensionCritical = 1102, "extension.critical", false;
    /// 两个扩展段同名。
    ExtensionDuplicate = 1103, "extension.duplicate", false;
    /// Hybrid 文件没有恰好一个 `jasper.import`。
    ExtensionRequired = 1104, "extension.required", false;
    /// *load*：`jasper.import` 语法不合法，或与 `core.exports` / `core.requires` 不一致。
    ExtensionBinding = 1105, "extension.binding", true;
}

impl ErrorCode {
    /// 由码名查找。
    pub fn from_name(s: &str) -> Option<ErrorCode> {
        ErrorCode::ALL.iter().copied().find(|c| c.name() == s)
    }

    /// 由编号查找。
    pub fn from_number(n: u16) -> Option<ErrorCode> {
        ErrorCode::ALL.iter().copied().find(|c| c.number() == n)
    }
}
