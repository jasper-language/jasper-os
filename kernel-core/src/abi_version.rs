//! 原生 ABI 世代：版本值、用户程序 ABI 章、兼容性判定与错误分类（issue #8）。
//! Native ABI generations: version values, the program ABI stamp, compatibility rules and rejection classes.
//!
//! # 语义（用户 2026-10-26 裁决）
//! * 版本形如 `Major.Minor.Patch`，**与内核自身版本独立编号**。
//! * 同一个 `Major` 内，新 `Minor` 必须向后兼容此前所有稳定 `Minor`：
//!   程序声明的 `program.major == kernel.major && program.min_minor <= kernel.minor`。
//! * 跨 `Major` 不承担兼容义务：装载器必须在执行任何用户代码之前明确拒绝。
//! * `Patch` 不参与功能门槛（安全修复是否另设门槛由发布裁决），但会记录在 ABI 章里供审计。
//!
//! # 为什么单独成模块
//! 版本判定必须同时被三处使用：内核启动/装载路径、构建脚本（给用户程序盖章）、宿主测试与形式化验证。
//! 放在 `kernel-core` 让它保持 `no_std`、零分配、可在宿主上穷举；不允许各调用者各写一份比较逻辑。
//!
//! # ABI 章（program ABI stamp）
//! 用户程序携带一个 28 字节的 ELF 注释节 `.note.jasper.abi`：
//! ```text
//! 偏移  宽度  内容
//! 0     4     namesz = 8
//! 4     4     descsz = 8
//! 8     4     type   = 1（程序 ABI 要求）
//! 12    8     name   = "JASPER\0\0"
//! 20    2     major
//! 22    2     min_minor（程序需要的最低次版本）
//! 24    2     patch
//! 26    2     flags = 0（保留，必须为 0）
//! ```
//! 本章由用户程序的构建脚本从 `abi/abi-version.txt` 盖章，由内核装载器在映射任何页之前校验。
//! The stamp is produced by each user program's build script and checked before any page is mapped.

mod generated {
    include!(concat!(env!("OUT_DIR"), "/abi_version_generated.rs"));
}

/// 一个 ABI 版本（内核声明或程序要求）。
/// An ABI version (declared by the kernel or required by a program).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AbiVersion {
    /// 主版本（世代）。
    pub major: u16,
    /// 次版本（世代内的兼容增量）。
    pub minor: u16,
    /// 修订版本（不改变契约）。
    pub patch: u16,
}

impl AbiVersion {
    /// 构造一个版本。
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        AbiVersion { major, minor, patch }
    }

    /// 打包成系统调用可返回的 64 位值：`major << 32 | minor << 16 | patch`。
    /// Packs the version into a 64-bit value: `major << 32 | minor << 16 | patch`.
    pub const fn packed(self) -> u64 {
        ((self.major as u64) << 32) | ((self.minor as u64) << 16) | self.patch as u64
    }

    /// 从 [`Self::packed`] 的编码解出（高位必须为 0，否则返回 `None`）。
    /// Decodes [`Self::packed`]; `None` when any reserved high bit is set.
    pub const fn unpack(value: u64) -> Option<Self> {
        if value >> 48 != 0 {
            return None;
        }
        Some(AbiVersion {
            major: ((value >> 32) & 0xffff) as u16,
            minor: ((value >> 16) & 0xffff) as u16,
            patch: (value & 0xffff) as u16,
        })
    }
}

/// 当前工具链/内核声明的原生 ABI 世代（由 `abi/abi-version.txt` 在构建期生成）。
/// The native ABI generation of this build, generated from `abi/abi-version.txt`.
pub const NATIVE: AbiVersion = AbiVersion::new(generated::ABI_MAJOR, generated::ABI_MINOR, generated::ABI_PATCH);

/// ABI 章的固定字节数。
pub const NOTE_BYTES: usize = 28;
/// ABI 章的名字（8 字节，含两个 NUL 填充）。
pub const NOTE_NAME: [u8; 8] = *b"JASPER\0\0";
/// ABI 章的类型：程序 ABI 要求。
pub const NOTE_TYPE: u32 = 1;
/// ABI 章在 ELF 中的节名。
pub const NOTE_SECTION: &str = ".note.jasper.abi";

/// 程序声明的 ABI 要求。
/// The ABI requirement carried by a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramAbi {
    /// 程序要求的 ABI 主版本。
    pub major: u16,
    /// 程序需要的最低次版本（同主版本内）。
    pub min_minor: u16,
    /// 程序编译时的修订版本（只记录，不作功能门槛）。
    pub patch: u16,
}

impl ProgramAbi {
    /// 程序对当前原生世代的要求（构建脚本盖章用）。
    /// The requirement this build stamps into its own user programs.
    pub const fn native_requirement() -> Self {
        ProgramAbi { major: NATIVE.major, min_minor: NATIVE.minor, patch: NATIVE.patch }
    }
}

/// ABI 章解析失败的原因。
/// Why an ABI stamp could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteError {
    /// 章短于 28 字节。
    Truncated,
    /// `namesz`、`descsz` 或 `type` 与规范不符。
    BadHeader,
    /// 名字不是 `JASPER\0\0`。
    BadName,
    /// 保留字段非 0（未来扩展必须换新 type，不能静默解释旧章）。
    BadFlags,
}

impl NoteError {
    /// 规范错误名（用于内核日志与验收匹配）。
    pub const fn name(self) -> &'static str {
        "system.error.abi_metadata"
    }
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, NoteError> {
    let s = b.get(off..off + 2).ok_or(NoteError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, NoteError> {
    let s = b.get(off..off + 4).ok_or(NoteError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// 解析一个 ABI 章。只接受规范中的精确尺寸，绝不按「前缀合法」放行。
/// Parses an ABI stamp; only the exact documented shape is accepted.
pub fn parse_note(note: &[u8]) -> Result<ProgramAbi, NoteError> {
    if note.len() != NOTE_BYTES {
        return Err(NoteError::Truncated);
    }
    let namesz = u32_at(note, 0)?;
    let descsz = u32_at(note, 4)?;
    let ty = u32_at(note, 8)?;
    if namesz != NOTE_NAME.len() as u32 || descsz != 8 || ty != NOTE_TYPE {
        return Err(NoteError::BadHeader);
    }
    if note[12..20] != NOTE_NAME {
        return Err(NoteError::BadName);
    }
    let major = u16_at(note, 20)?;
    let min_minor = u16_at(note, 22)?;
    let patch = u16_at(note, 24)?;
    if u16_at(note, 26)? != 0 {
        return Err(NoteError::BadFlags);
    }
    Ok(ProgramAbi { major, min_minor, patch })
}

/// 生成一个 ABI 章（与链接脚本生成的内容逐字节一致；测试、负例与审计工具共用）。
/// Encodes an ABI stamp byte-for-byte compatible with the linker-script emission.
pub fn encode_note(program: ProgramAbi) -> [u8; NOTE_BYTES] {
    let mut b = [0u8; NOTE_BYTES];
    b[0..4].copy_from_slice(&(NOTE_NAME.len() as u32).to_le_bytes());
    b[4..8].copy_from_slice(&8u32.to_le_bytes());
    b[8..12].copy_from_slice(&NOTE_TYPE.to_le_bytes());
    b[12..20].copy_from_slice(&NOTE_NAME);
    b[20..22].copy_from_slice(&program.major.to_le_bytes());
    b[22..24].copy_from_slice(&program.min_minor.to_le_bytes());
    b[24..26].copy_from_slice(&program.patch.to_le_bytes());
    b
}

/// 装载被拒的原因（每一项都对应一个登记的错误码）。
/// Why a program image was rejected at load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiReject {
    /// 映像没有 ABI 章。
    Missing,
    /// ABI 章存在但格式不合法。
    Malformed(NoteError),
    /// 主版本不同：跨世代拒绝，绝不按旧编号猜测语义。
    MajorMismatch {
        /// 程序要求的主版本。
        program: u16,
        /// 内核声明的主版本。
        kernel: u16,
    },
    /// 主版本相同但程序要求的次版本高于内核。
    MinorTooNew {
        /// 程序要求的最低次版本。
        required: u16,
        /// 内核提供的次版本。
        kernel: u16,
    },
}

impl AbiReject {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            AbiReject::Missing | AbiReject::Malformed(_) => "system.error.abi_metadata",
            AbiReject::MajorMismatch { .. } | AbiReject::MinorTooNew { .. } => "system.error.abi_mismatch",
        }
    }

    /// 是否为元数据类错误（缺少/格式错误）。
    pub const fn is_metadata(self) -> bool {
        matches!(self, AbiReject::Missing | AbiReject::Malformed(_))
    }
}

/// 兼容性判定：仅当主版本相同且程序要求的最低次版本不高于内核次版本时通过。
/// Same major and `program.min_minor <= kernel.minor` is the complete stable contract.
pub fn compatible(program: ProgramAbi, kernel: AbiVersion) -> Result<(), AbiReject> {
    if program.major != kernel.major {
        return Err(AbiReject::MajorMismatch { program: program.major, kernel: kernel.major });
    }
    if program.min_minor > kernel.minor {
        return Err(AbiReject::MinorTooNew { required: program.min_minor, kernel: kernel.minor });
    }
    Ok(())
}

/// 装载检查的完整入口：没有章、章损坏、版本不兼容都在这里被拒绝；成功时返回解析出的程序要求。
/// The complete loader check: missing, malformed and incompatible stamps are rejected here.
pub fn check_image(stamp: Option<ProgramAbi>, kernel: AbiVersion) -> Result<ProgramAbi, AbiReject> {
    let program = stamp.ok_or(AbiReject::Missing)?;
    compatible(program, kernel)?;
    Ok(program)
}

/// 解析 `abi/abi-version.txt` 的文本（构建工具与宿主测试共用；内核运行时不需要）。
/// Parses the version source; used by build tools and host tests, never by the running kernel.
pub fn parse_source(text: &str) -> Result<AbiVersion, SourceError> {
    let mut values: [Option<u16>; 3] = [None; 3];
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(SourceError::Malformed { line: line_no + 1 })?;
        let slot = match key.trim() {
            "major" => 0,
            "minor" => 1,
            "patch" => 2,
            _ => return Err(SourceError::UnknownKey { line: line_no + 1 }),
        };
        let parsed: u16 = value.trim().parse().map_err(|_| SourceError::Malformed { line: line_no + 1 })?;
        if values[slot].replace(parsed).is_some() {
            return Err(SourceError::DuplicateKey { line: line_no + 1 });
        }
    }
    match (values[0], values[1], values[2]) {
        (Some(major), Some(minor), Some(patch)) => Ok(AbiVersion::new(major, minor, patch)),
        _ => Err(SourceError::MissingKey),
    }
}

/// `abi/abi-version.txt` 的解析错误。
/// Parse errors of the version source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    /// 缺 `=` 或值不是 `u16`。
    Malformed {
        /// 行号（1 起）。
        line: usize,
    },
    /// 未知键。
    UnknownKey {
        /// 行号（1 起）。
        line: usize,
    },
    /// 同一个键出现多次。
    DuplicateKey {
        /// 行号（1 起）。
        line: usize,
    },
    /// 缺少 major / minor / patch 之一。
    MissingKey,
}

#[cfg(all(kani, feature = "abi-fv"))]
#[kani::proof]
fn abi_compatibility_is_exactly_same_major_and_minor_bound() {
    let pmaj: u16 = kani::any();
    let pmin: u16 = kani::any();
    let ppatch: u16 = kani::any();
    let kmaj: u16 = kani::any();
    let kmin: u16 = kani::any();
    let kpatch: u16 = kani::any();
    let program = ProgramAbi { major: pmaj, min_minor: pmin, patch: ppatch };
    let kernel = AbiVersion::new(kmaj, kmin, kpatch);
    let expected = pmaj == kmaj && pmin <= kmin;
    assert_eq!(compatible(program, kernel).is_ok(), expected);
    assert_eq!(check_image(Some(program), kernel).is_ok(), expected);
    assert_eq!(check_image(None, kernel), Err(AbiReject::Missing));
}

#[cfg(all(kani, feature = "abi-fv"))]
#[kani::proof]
fn abi_note_encode_parse_roundtrip() {
    let program = ProgramAbi { major: kani::any(), min_minor: kani::any(), patch: kani::any() };
    let bytes = encode_note(program);
    assert_eq!(bytes.len(), NOTE_BYTES);
    assert_eq!(&bytes[12..20], &NOTE_NAME);
    assert_eq!(parse_note(&bytes), Ok(program));
}

#[cfg(all(kani, feature = "abi-fv"))]
#[kani::proof]
fn abi_packed_rejects_reserved_high_bits() {
    let value: u64 = kani::any();
    assert_eq!(AbiVersion::unpack(value).is_some(), value >> 48 == 0);
    if let Some(v) = AbiVersion::unpack(value) {
        assert_eq!(v.packed(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 逐字节往返：编出来的章必须能被解析回同一个要求。
    #[test]
    fn note_roundtrip_and_exact_shape() {
        let p = ProgramAbi { major: 1, min_minor: 9, patch: 3 };
        let b = encode_note(p);
        assert_eq!(b.len(), NOTE_BYTES);
        assert_eq!(parse_note(&b), Ok(p));
        assert_eq!(&b[12..20], b"JASPER\0\0");
        // 任何长度变化都必须被拒绝，而不是按前缀解释
        assert_eq!(parse_note(&b[..NOTE_BYTES - 1]), Err(NoteError::Truncated));
        let mut longer = [0u8; NOTE_BYTES + 1];
        longer[..NOTE_BYTES].copy_from_slice(&b);
        assert_eq!(parse_note(&longer), Err(NoteError::Truncated));
    }

    /// 每个字段被破坏都必须被明确拒绝。
    #[test]
    fn malformed_notes_are_rejected_by_field() {
        let p = ProgramAbi { major: 1, min_minor: 0, patch: 0 };
        let good = encode_note(p);
        let cases: [(&str, usize, [u8; 4], NoteError); 3] = [
            ("namesz", 0, 7u32.to_le_bytes(), NoteError::BadHeader),
            ("descsz", 4, 9u32.to_le_bytes(), NoteError::BadHeader),
            ("type", 8, 2u32.to_le_bytes(), NoteError::BadHeader),
        ];
        for (what, at, bytes, expected) in cases {
            let mut b = good;
            b[at..at + bytes.len()].copy_from_slice(&bytes);
            assert_eq!(parse_note(&b), Err(expected), "{what}");
        }
        // flags 是 16 位保留字段：任何非 0 都必须拒绝
        let mut bad_flags = good;
        bad_flags[26..28].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(parse_note(&bad_flags), Err(NoteError::BadFlags));
        let mut bad_name = good;
        bad_name[12] = b'X';
        assert_eq!(parse_note(&bad_name), Err(NoteError::BadName));
    }

    /// 兼容性只由「主版本相同 + 最低次版本不高于内核」决定；Patch 不参与门槛。
    #[test]
    fn compatibility_is_major_then_minor() {
        let kernel = AbiVersion::new(1, 9, 4);
        assert_eq!(compatible(ProgramAbi { major: 1, min_minor: 0, patch: 0 }, kernel), Ok(()));
        assert_eq!(compatible(ProgramAbi { major: 1, min_minor: 9, patch: 0 }, kernel), Ok(()));
        assert_eq!(compatible(ProgramAbi { major: 1, min_minor: 1, patch: 99 }, kernel), Ok(()));
        assert_eq!(
            compatible(ProgramAbi { major: 1, min_minor: 10, patch: 0 }, kernel),
            Err(AbiReject::MinorTooNew { required: 10, kernel: 9 })
        );
        assert_eq!(
            compatible(ProgramAbi { major: 2, min_minor: 0, patch: 0 }, kernel),
            Err(AbiReject::MajorMismatch { program: 2, kernel: 1 })
        );
    }

    /// 没有章与章损坏是两类元数据错误；不兼容是另一类错误。
    #[test]
    fn check_image_distinguishes_missing_malformed_and_mismatch() {
        let kernel = AbiVersion::new(1, 0, 0);
        assert_eq!(check_image(None, kernel), Err(AbiReject::Missing));
        assert_eq!(
            check_image(Some(ProgramAbi { major: 2, min_minor: 0, patch: 0 }), kernel),
            Err(AbiReject::MajorMismatch { program: 2, kernel: 1 })
        );
        assert_eq!(check_image(Some(ProgramAbi { major: 1, min_minor: 0, patch: 0 }), kernel), Ok(ProgramAbi { major: 1, min_minor: 0, patch: 0 }));
        assert_eq!(AbiReject::Missing.name(), "system.error.abi_metadata");
        assert_eq!(AbiReject::Malformed(NoteError::BadName).name(), "system.error.abi_metadata");
        assert_eq!(AbiReject::MajorMismatch { program: 2, kernel: 1 }.name(), "system.error.abi_mismatch");
    }

    /// 真源与构建期生成的常量必须一致；这是防止版本声明漂移的最后一道宿主测试。
    #[test]
    fn generated_native_matches_single_source() {
        let source = include_str!("../../abi/abi-version.txt");
        assert_eq!(parse_source(source), Ok(NATIVE));
    }

    /// 打包/解包是双射；保留高位必须拒绝。
    #[test]
    fn packed_version_roundtrip_and_reserved_bits() {
        for v in [AbiVersion::new(0, 0, 0), AbiVersion::new(1, 9, 65535), AbiVersion::new(65535, 0, 7)] {
            assert_eq!(AbiVersion::unpack(v.packed()), Some(v));
        }
        assert_eq!(AbiVersion::unpack(1 << 48), None);
        assert_eq!(NATIVE.packed() >> 48, 0);
    }

    /// 版本真源的格式错误不能被当作默认值。
    #[test]
    fn source_parser_rejects_incomplete_or_unknown_input() {
        assert_eq!(parse_source("major = 1\nminor = 0\npatch = 0\n"), Ok(AbiVersion::new(1, 0, 0)));
        assert_eq!(parse_source("major = 1\nminor = 0\n"), Err(SourceError::MissingKey));
        assert_eq!(parse_source("major = 1\nminor = 0\npatch = 0\npatch = 1\n"), Err(SourceError::DuplicateKey { line: 4 }));
        assert_eq!(parse_source("major = 1\nminor = 0\nbuild = 1\n"), Err(SourceError::UnknownKey { line: 3 }));
        assert_eq!(parse_source("major = 1\nminor = x\npatch = 0\n"), Err(SourceError::Malformed { line: 2 }));
        assert_eq!(parse_source("major = 65536\nminor = 0\npatch = 0\n"), Err(SourceError::Malformed { line: 1 }));
    }
}
