//! 构建 `.jaso` 文件（format 1）：按格式写出各段、（可选）以发布者密钥签名、计算完整性摘要，最后用解析器自检一遍。
//! Builds (and optionally signs) a format 1 `.jaso` file and validates the result with the parser.
//!
//! beta 的写入方每个文件只产出**一个**镜像（读取方须接受至多 8 个）。
//!
//! 签名只在宿主打包侧发生（`sign` 特性）；装载侧只需要 [`crate::trust`] 的验签。

use alloc::vec::Vec;

use crate::platform::PLATFORM_RECORD;
use crate::{
    digest_of, Arch, FloatAbi, ImageKind, Jaso, JasoError, Manifest, ModuleKind, SectionKind, Stage, Target, ABI_C_V1, CODE_JVM_CLASSES,
    DIGEST_OFFSET, EXPORT_FUNC, EXPORT_MANAGED, EXPORT_SIZE, EXT_CRITICAL, FORMAT_VERSION, HEADER_SIZE, IMAGE_ENTRY_SIZE, MAGIC, PAGE,
    RELOC_RELATIVE32, RELOC_RELATIVE64, RELOC_SIZE, SECTION_SIZE,
};
#[cfg(feature = "sign")]
use crate::{signed_digest_of, signed_message, SIGNATURE_SIZE, SIGNATURE_VALUE_OFFSET, SIG_ED25519};

/// 发布者签名密钥（Ed25519）：只在宿主打包侧使用。
/// A publisher signing key (Ed25519), used on the packing host only.
#[cfg(feature = "sign")]
pub struct Signer {
    key: ed25519_dalek::SigningKey,
}

#[cfg(feature = "sign")]
impl Signer {
    /// 由 32 字节种子（RFC 8032 的私钥）建立。
    /// Builds a signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Signer {
        Signer { key: ed25519_dalek::SigningKey::from_bytes(seed) }
    }

    /// 对应的公钥（写进受信发布者表）。
    /// The matching public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// 对消息签名。
    /// Signs a message.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.key.sign(message).to_bytes()
    }
}

/// 构建输入中的一个映像段。
#[derive(Debug, Clone)]
pub struct SegmentIn {
    /// 相对装入基址的偏移（页对齐）。
    pub vaddr: u32,
    /// 装入后占用的字节数。
    pub mem_size: u32,
    /// 权限标志。
    pub flags: u32,
    /// 文件中的内容。
    pub data: Vec<u8>,
}

/// 构建输入中的平台记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformIn {
    /// 指令集；托管为 `None`。指针宽度由它决定。
    pub isa: Option<Arch>,
    /// 指令集扩展记号（逗号分隔，可为空）。
    pub isa_ext: Vec<u8>,
    /// 浮点调用约定。
    pub float_abi: FloatAbi,
    /// 目标运行环境。
    pub target: Target,
    /// 调用约定名；`None` 取清单的 `core.abi`。
    pub abi: Option<Vec<u8>>,
}

impl PlatformIn {
    /// jasper-os 原生平台：该指令集、无扩展、软浮点、调用约定取清单。
    pub fn jasper_os(arch: Arch) -> PlatformIn {
        PlatformIn { isa: Some(arch), isa_ext: Vec::new(), float_abi: FloatAbi::Soft, target: Target::JasperOs, abi: None }
    }

    /// JVM 托管平台：调用约定取清单（如 `jvm.52`）。
    pub fn jvm() -> PlatformIn {
        PlatformIn { isa: None, isa_ext: Vec::new(), float_abi: FloatAbi::None, target: Target::Jvm, abi: None }
    }
}

/// 构建输入中的扩展段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionIn {
    /// 名字。
    pub name: Vec<u8>,
    /// 版本。
    pub version: u32,
    /// 关键标志。
    pub critical: bool,
    /// 内容。
    pub content: Vec<u8>,
}

/// `.jaso` 构建器（单镜像）。
#[derive(Debug, Clone)]
pub struct Builder {
    /// 模块种类。
    pub kind: ModuleKind,
    /// 装载阶段（同时写入头部；清单的 `core.stage` 须与它一致）。
    pub stage: Stage,
    /// 平台记录。
    pub platform: PlatformIn,
    /// 清单文本。
    pub manifest: Vec<u8>,
    /// 映像段（原生）。
    pub segments: Vec<SegmentIn>,
    /// 导出：(名字, 映像内偏移)；原生为 C 调用约定的函数，托管的偏移写 0。
    pub exports: Vec<(Vec<u8>, u32)>,
    /// 重定位：(写入位置, 加数)，种类按指针宽度。
    pub relocs: Vec<(u32, u64)>,
    /// 托管代码段的载荷（托管；载体为 JVM class 归档）。
    pub code: Option<Vec<u8>>,
    /// 扩展段（按此顺序写出）。
    pub extensions: Vec<ExtensionIn>,
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_u64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put_padded(v: &mut Vec<u8>, s: &[u8], width: usize) {
    let n = s.len().min(width);
    v.extend_from_slice(&s[..n]);
    v.resize(v.len() + width - n, 0);
}

/// 一个待写出的段：(种类, 标志, vaddr, mem_size, 内容)。
type Body = (u32, u32, u32, u32, Vec<u8>);

impl Builder {
    /// jasper-os 原生模块的构建输入（平台记录取 [`PlatformIn::jasper_os`]，其余为空）。
    pub fn native(arch: Arch, stage: Stage, manifest: &[u8]) -> Builder {
        Builder {
            kind: ModuleKind::Native,
            stage,
            platform: PlatformIn::jasper_os(arch),
            manifest: manifest.to_vec(),
            segments: Vec::new(),
            exports: Vec::new(),
            relocs: Vec::new(),
            code: None,
            extensions: Vec::new(),
        }
    }

    /// 由已校验文件的第 `image` 个镜像还原出构建输入（清单、平台、各段、导出、重定位、扩展；不含签名）——用于重新打包或重新签名。
    /// Recovers the build inputs of one image of a parsed file (signature excluded).
    pub fn from_file(f: &Jaso<'_>, image: u32) -> Option<Builder> {
        let im = f.image(image)?;
        let p = im.platform;
        Some(Builder {
            kind: f.kind,
            stage: f.stage,
            platform: PlatformIn {
                isa: p.isa,
                isa_ext: p.isa_ext.as_bytes().to_vec(),
                float_abi: p.float_abi,
                target: p.target,
                abi: Some(p.abi.as_bytes().to_vec()),
            },
            manifest: f.manifest.text().as_bytes().to_vec(),
            segments: im.segments().map(|s| SegmentIn { vaddr: s.vaddr, mem_size: s.mem_size, flags: s.flags, data: s.data.to_vec() }).collect(),
            exports: im.exports().map(|e| (e.name.as_bytes().to_vec(), e.value)).collect(),
            relocs: im.relocs().map(|r| (r.offset, r.addend)).collect(),
            code: im.code().map(|c| c.payload.to_vec()),
            extensions: f
                .extensions()
                .map(|e| ExtensionIn { name: e.name.as_bytes().to_vec(), version: e.version, critical: e.critical, content: e.content.to_vec() })
                .collect(),
        })
    }

    /// 映像大小：各段末端按页向上取整后的最大值（托管为 0）。
    pub fn image_size(&self) -> u32 {
        self.segments.iter().map(|s| s.vaddr.saturating_add(s.mem_size.div_ceil(PAGE).saturating_mul(PAGE))).max().unwrap_or(0)
    }

    /// 写出未签名的文件并自检；任何不满足格式约束的输入都以解析器给出的错误返回。
    pub fn finish(&self) -> Result<Vec<u8>, JasoError> {
        let out = self.layout(false)?;
        Jaso::parse(&out)?;
        Ok(out)
    }

    /// 写出以 `signer` 签名的文件并自检：签名段放在文件末尾，先签名、再计算完整性摘要。
    /// 清单应声明 `core.publisher`，否则装载侧的信任策略会拒绝（这里不替调用者决定发布者名）。
    /// Writes a file signed by `signer` and validates it.
    #[cfg(feature = "sign")]
    pub fn finish_signed(&self, signer: &Signer) -> Result<Vec<u8>, JasoError> {
        let mut out = self.layout(true)?;
        let sig_off = out.len() - SIGNATURE_SIZE;
        out[sig_off..sig_off + 4].copy_from_slice(&SIG_ED25519.to_le_bytes());
        out[sig_off + 8..sig_off + 40].copy_from_slice(&signer.public_key());
        let value = signer.sign(&signed_message(&signed_digest_of(&out, sig_off)));
        out[sig_off + SIGNATURE_VALUE_OFFSET..].copy_from_slice(&value);
        let d = digest_of(&out);
        out[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
        Jaso::parse(&out)?;
        Ok(out)
    }

    fn platform_record(&self) -> Vec<u8> {
        let p = &self.platform;
        let abi = match &p.abi {
            Some(a) => a.clone(),
            None => core::str::from_utf8(&self.manifest)
                .ok()
                .and_then(|t| Manifest::parse(t).ok())
                .map_or_else(|| ABI_C_V1.as_bytes().to_vec(), |m| m.abi.as_bytes().to_vec()),
        };
        let mut r = Vec::with_capacity(PLATFORM_RECORD);
        put_u16(&mut r, p.isa.map_or(0, |a| a as u16));
        r.push(p.isa.map_or(0, |a| a.pointer_bytes() as u8));
        r.push(p.float_abi as u8);
        put_u16(&mut r, p.target as u16);
        put_u16(&mut r, 0);
        put_padded(&mut r, &p.isa_ext, 32);
        put_padded(&mut r, &abi, 16);
        put_u64(&mut r, 0);
        r
    }

    fn image_kind(&self) -> ImageKind {
        if self.platform.isa.is_none() {
            ImageKind::Managed
        } else {
            ImageKind::Native
        }
    }

    /// 镜像认领的各段：映像段、导出表、重定位表或代码段。
    fn image_bodies(&self) -> Vec<Body> {
        let mut bodies = Vec::new();
        for s in &self.segments {
            bodies.push((SectionKind::Segment as u32, s.flags, s.vaddr, s.mem_size, s.data.clone()));
        }
        if let Some(code) = &self.code {
            let mut t = Vec::with_capacity(8 + code.len());
            put_u32(&mut t, CODE_JVM_CLASSES);
            put_u32(&mut t, 0);
            t.extend_from_slice(code);
            bodies.push((SectionKind::Code as u32, 0, 0, 0, t));
        }
        if !self.exports.is_empty() {
            let kind = if self.image_kind() == ImageKind::Managed { EXPORT_MANAGED } else { EXPORT_FUNC };
            let mut t = Vec::new();
            put_u32(&mut t, self.exports.len() as u32);
            let mut name_off = 4 + self.exports.len() * EXPORT_SIZE;
            for (name, value) in &self.exports {
                put_u32(&mut t, name_off as u32);
                put_u32(&mut t, name.len() as u32);
                put_u32(&mut t, *value);
                put_u32(&mut t, kind);
                name_off += name.len();
            }
            for (name, _) in &self.exports {
                t.extend_from_slice(name);
            }
            bodies.push((SectionKind::Exports as u32, 0, 0, 0, t));
        }
        if !self.relocs.is_empty() {
            let kind = if self.platform.isa.is_some_and(|a| a.pointer_bytes() == 4) { RELOC_RELATIVE32 } else { RELOC_RELATIVE64 };
            let mut t = Vec::with_capacity(4 + self.relocs.len() * RELOC_SIZE);
            put_u32(&mut t, self.relocs.len() as u32);
            for (offset, addend) in &self.relocs {
                put_u32(&mut t, *offset);
                put_u32(&mut t, kind);
                put_u64(&mut t, *addend);
            }
            bodies.push((SectionKind::Relocs as u32, 0, 0, 0, t));
        }
        bodies
    }

    /// 排布各段并回填长度与完整性摘要；`signature` 为真时在末尾留出全零的签名段（由调用者填写后重算摘要）。
    ///
    /// 目录顺序：清单、平台、镜像索引、镜像 0 认领的段、扩展段、签名段。
    fn layout(&self, signature: bool) -> Result<Vec<u8>, JasoError> {
        let mut bodies: Vec<Body> = Vec::new();
        bodies.push((SectionKind::Manifest as u32, 0, 0, 0, self.manifest.clone()));
        let mut platforms = Vec::new();
        put_u32(&mut platforms, 1);
        put_u32(&mut platforms, 0);
        platforms.extend_from_slice(&self.platform_record());
        bodies.push((SectionKind::Platform as u32, 0, 0, 0, platforms));
        let image = self.image_bodies();
        let first = bodies.len() as u32 + 1;
        let mut index = Vec::with_capacity(8 + IMAGE_ENTRY_SIZE);
        put_u32(&mut index, 1);
        put_u32(&mut index, 0);
        put_u16(&mut index, self.image_kind() as u16);
        put_u16(&mut index, 0);
        put_u32(&mut index, first);
        put_u32(&mut index, image.len() as u32);
        put_u32(&mut index, if self.image_kind() == ImageKind::Native { self.image_size() } else { 0 });
        index.resize(8 + IMAGE_ENTRY_SIZE, 0);
        bodies.push((SectionKind::Images as u32, 0, 0, 0, index));
        bodies.extend(image);
        for e in &self.extensions {
            let mut t = Vec::new();
            put_u32(&mut t, e.version);
            put_u16(&mut t, e.name.len() as u16);
            put_u16(&mut t, 0);
            t.extend_from_slice(&e.name);
            t.resize(t.len().next_multiple_of(8), 0);
            t.extend_from_slice(&e.content);
            bodies.push((SectionKind::Ext as u32, if e.critical { EXT_CRITICAL } else { 0 }, 0, 0, t));
        }
        if signature {
            bodies.push((SectionKind::Signature as u32, 0, 0, 0, alloc::vec![0u8; crate::SIGNATURE_SIZE]));
        }

        let dir_offset = HEADER_SIZE;
        let mut offset = dir_offset + bodies.len() * SECTION_SIZE;
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        put_u16(&mut out, FORMAT_VERSION);
        put_u16(&mut out, self.kind as u16);
        put_u16(&mut out, self.platform.isa.map_or(0, |a| a as u16));
        out.push(self.stage as u8);
        out.push(0);
        put_u32(&mut out, HEADER_SIZE as u32);
        put_u32(&mut out, bodies.len() as u32);
        put_u32(&mut out, dir_offset as u32);
        put_u32(&mut out, 0); // file_len：最后回填
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        out.extend_from_slice(&[0u8; 32]); // digest：最后回填
        put_u64(&mut out, 0);
        debug_assert_eq!(out.len(), HEADER_SIZE);
        for (kind, flags, vaddr, mem_size, bytes) in &bodies {
            put_u32(&mut out, *kind);
            put_u32(&mut out, *flags);
            put_u32(&mut out, offset as u32);
            put_u32(&mut out, bytes.len() as u32);
            put_u32(&mut out, *vaddr);
            put_u32(&mut out, *mem_size);
            put_u64(&mut out, 0);
            offset += bytes.len();
        }
        for (_, _, _, _, bytes) in &bodies {
            out.extend_from_slice(bytes);
        }
        let len = u32::try_from(out.len()).map_err(|_| JasoError::LengthMismatch)?;
        out[28..32].copy_from_slice(&len.to_le_bytes());
        let d = digest_of(&out);
        out[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
        Ok(out)
    }
}
