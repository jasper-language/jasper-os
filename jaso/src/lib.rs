//! `.jaso` 模块格式 v0（Native-only）：解析与校验。
//! The `.jaso` module format, version 0 (native code only): parsing and validation.
//!
//! # 定位
//! `.jaso` 是语言无关的模块工件。v0 只定义 **Native** 一种：原生代码 + 清单（manifest）+ 段目录 + 完整性校验。
//! **v0 是实验格式、未冻结**：在出现第二个真实使用者之前不承诺二进制兼容（`format` 字段为 0 即表示这一点）。
//! 托管（Managed）与混合（Hybrid）种类只在 `kind` 字段里保留编号，解析器一律拒绝。
//!
//! # 文件布局（小端）
//! ```text
//! 0   头部（HEADER_SIZE = 80 字节）
//!       magic[8] = 89 'J' 'A' 'S' 'O' 0D 0A 1A
//!       format u16 = 0 · kind u16（1 = Native）· arch u16 · stage u8 · 保留 u8
//!       header_size u32 = 80 · section_count u32 · section_dir_offset u32 · file_len u32
//!       image_size u32（装入后占用的字节数，页对齐）· 保留 u32
//!       digest[32]（偏移 40）：SHA-256(整个文件，其中 digest 字段按 32 个零字节计算)
//!       保留 8 字节（置 0）
//! ... 段目录：section_count 项，每项 32 字节
//!       kind u32 · flags u32 · file_offset u32 · file_size u32 · vaddr u32 · mem_size u32 · 保留 u64
//! ... 各段内容
//! ```
//! 段的种类：
//! * **Manifest**（恰好一个）：UTF-8 文本清单，见 [`manifest`]
//! * **Segment**（至少一个）：装入映像的一段；`vaddr` 页对齐，`mem_size ≥ file_size`（多出部分清零），
//!   `flags` = R(1) | W(2) | X(4)，必须可读，**不得同时可写可执行**；各段占用的页互不重叠
//! * **Exports**（至多一个）：`count u32` + `count × {name_offset u32, name_len u32, value u32, kind u32}` + 名字字节；
//!   `value` 是映像内偏移；`kind = 1`（C 调用约定的函数）时必须落在可执行段内
//! * **Relocs**（至多一个）：`count u32` + `count × {offset u32, kind u32, addend u64}`；v0 只有 `kind = 1`：
//!   在 `offset` 处写入 `装入基址 + addend`（8 字节）。`offset` 必须落在不可执行的段内
//!
//! # 校验的原则
//! 解析器不信任任何字段：所有偏移与长度都做检查式运算，任何越界、重叠、未知取值都拒绝，**从不 panic**
//! （宿主测试里有对随机变异输入的覆盖）。完整性校验只证明「文件未被改动」，不证明来源；来源认证（签名）另行设计。

#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod build;
pub mod manifest;
#[cfg(feature = "pack")]
pub mod pack;

pub use manifest::{Manifest, ManifestError};

use sha2::{Digest, Sha256};

/// 文件魔数。
pub const MAGIC: [u8; 8] = *b"\x89JASO\r\n\x1a";
/// 本实现支持的格式版本（0 = 实验、未冻结）。
pub const FORMAT_VERSION: u16 = 0;
/// 头部长度。
pub const HEADER_SIZE: usize = 80;
/// 段目录项长度。
pub const SECTION_SIZE: usize = 32;
/// 导出项长度。
pub const EXPORT_SIZE: usize = 16;
/// 重定位项长度。
pub const RELOC_SIZE: usize = 16;
/// 页大小（段对齐的单位）。
pub const PAGE: u32 = 4096;
/// digest 字段在头部中的偏移。
pub const DIGEST_OFFSET: usize = 40;
/// 映像大小上限（64 MiB）。
pub const MAX_IMAGE: u32 = 64 << 20;
/// 段目录项数上限。
pub const MAX_SECTIONS: u32 = 64;
/// 导出项数上限。
pub const MAX_EXPORTS: u32 = 1024;
/// 导出名长度上限。
pub const MAX_NAME: u32 = 128;

/// 种类：Native（原生代码）。
pub const KIND_NATIVE: u16 = 1;
/// 段标志：可读。
pub const FLAG_R: u32 = 1;
/// 段标志：可写。
pub const FLAG_W: u32 = 2;
/// 段标志：可执行。
pub const FLAG_X: u32 = 4;
/// 导出种类：C 调用约定的函数。
pub const EXPORT_FUNC: u32 = 1;
/// 重定位种类：写入「基址 + addend」（8 字节）。
pub const RELOC_RELATIVE64: u32 = 1;

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
}

impl SectionKind {
    const fn from_u32(v: u32) -> Option<SectionKind> {
        match v {
            1 => Some(SectionKind::Manifest),
            2 => Some(SectionKind::Segment),
            3 => Some(SectionKind::Exports),
            4 => Some(SectionKind::Relocs),
            _ => None,
        }
    }
}

/// 解析与校验错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JasoError {
    /// 文件短于头部或某个声明的长度。
    Truncated,
    /// 魔数不符。
    BadMagic,
    /// 格式版本不受支持。
    UnsupportedVersion(u16),
    /// 种类不受支持（v0 只有 Native）。
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
    /// 段目录越界或项数超限。
    BadSectionDir,
    /// 某段的内容越出文件。
    SectionOutOfFile,
    /// 未知的段种类。
    UnknownSection(u32),
    /// 不允许重复的段出现了多次。
    DuplicateSection(u32),
    /// 缺少清单段或映像段。
    MissingSection(u32),
    /// 映像大小为 0、未按页对齐或超限。
    BadImageSize,
    /// 映像段非法（未对齐、越界、标志非法、`mem_size < file_size`）。
    BadSegment,
    /// 映像段同时可写可执行。
    WriteExecute,
    /// 两个映像段占用了同一页。
    SegmentOverlap,
    /// 导出表格式非法（越界、名字非法或重复）。
    BadExports,
    /// 导出的值不在映像内或函数不在可执行段内。
    ExportOutOfRange,
    /// 重定位表格式非法或种类未知。
    BadReloc,
    /// 重定位目标越界、未对齐或落在可执行段内。
    RelocOutOfRange,
    /// 清单错误。
    Manifest(ManifestError),
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

/// 段目录项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Dir {
    kind: u32,
    flags: u32,
    file_offset: u32,
    file_size: u32,
    vaddr: u32,
    mem_size: u32,
    reserved: u64,
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
    /// 映像内偏移。
    pub value: u32,
    /// 种类（v0 只有 [`EXPORT_FUNC`]）。
    pub kind: u32,
}

/// 一个重定位项。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    /// 写入位置（映像内偏移）。
    pub offset: u32,
    /// 种类（v0 只有 [`RELOC_RELATIVE64`]）。
    pub kind: u32,
    /// 加数（映像内偏移）。
    pub addend: u64,
}

/// 校验通过的 `.jaso` 文件视图（只借用输入字节，不分配）。
#[derive(Debug, Clone, Copy)]
pub struct Image<'a> {
    bytes: &'a [u8],
    /// 指令集。
    pub arch: Arch,
    /// 装载阶段。
    pub stage: Stage,
    /// 装入后占用的字节数（页对齐）。
    pub image_size: u32,
    /// 文件的 SHA-256（已校验）。
    pub digest: [u8; 32],
    /// 清单。
    pub manifest: Manifest<'a>,
    section_count: u32,
    dir_offset: u32,
    exports: Option<Dir>,
    relocs: Option<Dir>,
}

fn is_symbol(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'$')
}

impl<'a> Image<'a> {
    /// 解析并完整校验一个 `.jaso` 文件。成功返回的视图中，所有偏移都已证明在界内。
    pub fn parse(bytes: &'a [u8]) -> Result<Image<'a>, JasoError> {
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
        let kind = u16_at(bytes, 10);
        if kind != KIND_NATIVE {
            return Err(JasoError::UnsupportedKind(kind));
        }
        let arch_v = u16_at(bytes, 12);
        let arch = Arch::from_u16(arch_v).ok_or(JasoError::UnknownArch(arch_v))?;
        let stage = Stage::from_u8(bytes[14]).ok_or(JasoError::UnknownStage(bytes[14]))?;
        if bytes[15] != 0 || u32_at(bytes, 16) as usize != HEADER_SIZE || u32_at(bytes, 36) != 0 || u64_at(bytes, 72) != 0 {
            return Err(JasoError::BadHeader);
        }
        let section_count = u32_at(bytes, 20);
        let dir_offset = u32_at(bytes, 24);
        if u32_at(bytes, 28) as usize != bytes.len() || bytes.len() > u32::MAX as usize {
            return Err(JasoError::LengthMismatch);
        }
        let image_size = u32_at(bytes, 32);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[DIGEST_OFFSET..DIGEST_OFFSET + 32]);
        if digest_of(bytes) != digest {
            return Err(JasoError::DigestMismatch);
        }
        if image_size == 0 || image_size % PAGE != 0 || image_size > MAX_IMAGE {
            return Err(JasoError::BadImageSize);
        }
        if section_count == 0 || section_count > MAX_SECTIONS || (dir_offset as usize) < HEADER_SIZE {
            return Err(JasoError::BadSectionDir);
        }
        let dir_end = (section_count as usize).checked_mul(SECTION_SIZE).and_then(|n| n.checked_add(dir_offset as usize));
        if dir_end.is_none_or(|e| e > bytes.len()) {
            return Err(JasoError::BadSectionDir);
        }

        let mut img = Image {
            bytes,
            arch,
            stage,
            image_size,
            digest,
            manifest: Manifest::empty(),
            section_count,
            dir_offset,
            exports: None,
            relocs: None,
        };
        let mut manifest: Option<Dir> = None;
        let mut segments = 0u32;
        for i in 0..section_count {
            let d = img.dir(i);
            let kind = SectionKind::from_u32(d.kind).ok_or(JasoError::UnknownSection(d.kind))?;
            if d.reserved != 0 || (kind != SectionKind::Segment && (d.flags != 0 || d.vaddr != 0 || d.mem_size != 0)) {
                return Err(JasoError::BadSectionDir);
            }
            let end = d.file_offset.checked_add(d.file_size).ok_or(JasoError::SectionOutOfFile)?;
            if end as usize > bytes.len() || (d.file_offset as usize) < HEADER_SIZE && d.file_size > 0 {
                return Err(JasoError::SectionOutOfFile);
            }
            let slot = match kind {
                SectionKind::Manifest => &mut manifest,
                SectionKind::Exports => &mut img.exports,
                SectionKind::Relocs => &mut img.relocs,
                SectionKind::Segment => {
                    img.check_segment(&d)?;
                    segments += 1;
                    continue;
                }
            };
            if slot.is_some() {
                return Err(JasoError::DuplicateSection(d.kind));
            }
            *slot = Some(d);
        }
        let manifest = manifest.ok_or(JasoError::MissingSection(SectionKind::Manifest as u32))?;
        if segments == 0 {
            return Err(JasoError::MissingSection(SectionKind::Segment as u32));
        }
        // 段之间不得共用页（两两比较；项数有上限）
        for i in 0..section_count {
            for j in i + 1..section_count {
                let (a, b) = (img.dir(i), img.dir(j));
                if a.kind == SectionKind::Segment as u32 && b.kind == SectionKind::Segment as u32 {
                    let (sa, sb) = (img.segment_of(&a).page_span(), img.segment_of(&b).page_span());
                    if sa.0 < sb.1 && sb.0 < sa.1 {
                        return Err(JasoError::SegmentOverlap);
                    }
                }
            }
        }
        let text = core::str::from_utf8(img.section_bytes(&manifest)).map_err(|_| JasoError::Manifest(ManifestError::NotUtf8))?;
        img.manifest = Manifest::parse(text).map_err(JasoError::Manifest)?;
        img.check_exports()?;
        img.check_relocs()?;
        Ok(img)
    }

    fn dir(&self, i: u32) -> Dir {
        let o = self.dir_offset as usize + i as usize * SECTION_SIZE;
        let b = self.bytes;
        Dir {
            kind: u32_at(b, o),
            flags: u32_at(b, o + 4),
            file_offset: u32_at(b, o + 8),
            file_size: u32_at(b, o + 12),
            vaddr: u32_at(b, o + 16),
            mem_size: u32_at(b, o + 20),
            reserved: u64_at(b, o + 24),
        }
    }

    fn section_bytes(&self, d: &Dir) -> &'a [u8] {
        &self.bytes[d.file_offset as usize..(d.file_offset + d.file_size) as usize]
    }

    fn segment_of(&self, d: &Dir) -> Segment<'a> {
        Segment { vaddr: d.vaddr, mem_size: d.mem_size, flags: d.flags, data: self.section_bytes(d) }
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
        let Some(d) = self.exports else { return Ok(()) };
        let b = self.section_bytes(&d);
        if b.len() < 4 {
            return Err(JasoError::BadExports);
        }
        let count = u32_at(b, 0);
        if count > MAX_EXPORTS || 4 + count as usize * EXPORT_SIZE > b.len() {
            return Err(JasoError::BadExports);
        }
        let names_start = 4 + count as usize * EXPORT_SIZE;
        for i in 0..count {
            let e = self.export_at(b, i).ok_or(JasoError::BadExports)?;
            let off = 4 + i as usize * EXPORT_SIZE;
            if (u32_at(b, off) as usize) < names_start {
                return Err(JasoError::BadExports);
            }
            if e.kind != EXPORT_FUNC {
                return Err(JasoError::BadExports);
            }
            if !self.in_segment(e.value as u64, 1, |f| f & FLAG_X != 0) {
                return Err(JasoError::ExportOutOfRange);
            }
            for j in 0..i {
                if self.export_at(b, j).is_some_and(|p| p.name == e.name) {
                    return Err(JasoError::BadExports);
                }
            }
        }
        Ok(())
    }

    fn export_at(&self, b: &'a [u8], i: u32) -> Option<Export<'a>> {
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

    fn check_relocs(&self) -> Result<(), JasoError> {
        let Some(d) = self.relocs else { return Ok(()) };
        let b = self.section_bytes(&d);
        if b.len() < 4 {
            return Err(JasoError::BadReloc);
        }
        let count = u32_at(b, 0) as usize;
        if count.checked_mul(RELOC_SIZE).and_then(|n| n.checked_add(4)) != Some(b.len()) {
            return Err(JasoError::BadReloc);
        }
        for r in self.relocs() {
            if r.kind != RELOC_RELATIVE64 {
                return Err(JasoError::BadReloc);
            }
            if r.offset % 8 != 0 || r.addend >= self.image_size as u64 || !self.in_segment(r.offset as u64, 8, |f| f & FLAG_X == 0) {
                return Err(JasoError::RelocOutOfRange);
            }
        }
        Ok(())
    }

    /// 全部映像段。
    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        (0..self.section_count).map(|i| self.dir(i)).filter(|d| d.kind == SectionKind::Segment as u32).map(|d| self.segment_of(&d))
    }

    /// 全部导出项。
    pub fn exports(&self) -> impl Iterator<Item = Export<'a>> + '_ {
        let b = self.exports.map(|d| self.section_bytes(&d)).unwrap_or(&[]);
        let n = if b.len() >= 4 { u32_at(b, 0) } else { 0 };
        (0..n).filter_map(move |i| self.export_at(b, i))
    }

    /// 按名字查导出项。
    pub fn export(&self, name: &str) -> Option<Export<'a>> {
        self.exports().find(|e| e.name == name)
    }

    /// 全部重定位项。
    pub fn relocs(&self) -> impl Iterator<Item = Reloc> + '_ {
        let b = self.relocs.map(|d| self.section_bytes(&d)).unwrap_or(&[]);
        let n = if b.len() >= 4 { u32_at(b, 0) } else { 0 };
        (0..n).map(move |i| {
            let o = 4 + i as usize * RELOC_SIZE;
            Reloc { offset: u32_at(b, o), kind: u32_at(b, o + 4), addend: u64_at(b, o + 8) }
        })
    }

    /// 文件的原始字节。
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// 宿主接口表 v0：装载器在调用模块的 `jaso_init` 时传入。
///
/// 模块**不按名字导入**任何宿主符号——宿主能力只经这张显式的表提供，表头带版本与长度，
/// 日后增加函数只在末尾追加（`size` 随之变大），旧模块按自己认识的长度读取。
/// 清单中 `core.host = jaso.host.v0` 表示模块需要这张表。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HostV0 {
    /// 表版本（v0 = 0）。
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

/// 宿主接口表 v0 的名字（清单 `core.host` 的取值）。
pub const HOST_V0: &str = "jaso.host.v0";
/// 模块初始化导出的名字：`extern "C" fn(host: *const HostV0) -> i32`，返回 0 表示成功。
pub const INIT_SYMBOL: &str = "jaso_init";
/// 本实现支持的模块调用约定（清单 `core.abi` 的取值）：C 调用约定、v0。
pub const ABI_C_V0: &str = "c.v0";

#[cfg(test)]
mod tests;
