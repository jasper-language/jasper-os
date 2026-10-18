//! 构建 `.jaso` 文件：按格式写出各段、（可选）以发布者密钥签名、计算完整性摘要，最后用解析器自检一遍。
//! Builds (and optionally signs) a `.jaso` file and validates the result with the parser.
//!
//! 签名只在宿主打包侧发生（`sign` 特性）；装载侧只需要 [`crate::trust`] 的验签。

use alloc::vec::Vec;

use crate::{
    digest_of, Arch, Image, JasoError, SectionKind, Stage, DIGEST_OFFSET, EXPORT_FUNC, EXPORT_SIZE, FORMAT_VERSION, HEADER_SIZE,
    KIND_NATIVE, MAGIC, PAGE, RELOC_SIZE, SECTION_SIZE,
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

/// `.jaso` 构建器。
#[derive(Debug, Clone)]
pub struct Builder {
    /// 指令集。
    pub arch: Arch,
    /// 装载阶段。
    pub stage: Stage,
    /// 清单文本。
    pub manifest: Vec<u8>,
    /// 映像段。
    pub segments: Vec<SegmentIn>,
    /// 导出：(名字, 映像内偏移)，都是 C 调用约定的函数。
    pub exports: Vec<(Vec<u8>, u32)>,
    /// 重定位：(写入位置, 加数)，都是 RELATIVE64。
    pub relocs: Vec<(u32, u64)>,
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

impl Builder {
    /// 由已校验的文件还原出构建输入（清单、各段、导出、重定位；不含签名）——用于重新打包或重新签名。
    /// Recovers the build inputs from a parsed file (signature excluded).
    pub fn from_image(img: &Image<'_>) -> Builder {
        Builder {
            arch: img.arch,
            stage: img.stage,
            manifest: img.manifest.text().as_bytes().to_vec(),
            segments: img.segments().map(|s| SegmentIn { vaddr: s.vaddr, mem_size: s.mem_size, flags: s.flags, data: s.data.to_vec() }).collect(),
            exports: img.exports().map(|e| (e.name.as_bytes().to_vec(), e.value)).collect(),
            relocs: img.relocs().map(|r| (r.offset, r.addend)).collect(),
        }
    }

    /// 映像大小：各段末端按页向上取整后的最大值。
    pub fn image_size(&self) -> u32 {
        self.segments.iter().map(|s| s.vaddr.saturating_add(s.mem_size.div_ceil(PAGE).saturating_mul(PAGE))).max().unwrap_or(0)
    }

    /// 写出未签名的文件并自检；任何不满足格式约束的输入都以解析器给出的错误返回。
    pub fn finish(&self) -> Result<Vec<u8>, JasoError> {
        let out = self.layout(false)?;
        Image::parse(&out)?;
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
        Image::parse(&out)?;
        Ok(out)
    }

    /// 排布各段并回填长度与完整性摘要；`signature` 为真时在末尾留出全零的签名段（由调用者填写后重算摘要）。
    fn layout(&self, signature: bool) -> Result<Vec<u8>, JasoError> {
        // 各段内容：清单、映像段、导出表、重定位表（依次排在段目录之后）
        let mut bodies: Vec<(u32, u32, u32, u32, Vec<u8>)> = Vec::new(); // (kind, flags, vaddr, mem_size, bytes)
        bodies.push((SectionKind::Manifest as u32, 0, 0, 0, self.manifest.clone()));
        for s in &self.segments {
            bodies.push((SectionKind::Segment as u32, s.flags, s.vaddr, s.mem_size, s.data.clone()));
        }
        if !self.exports.is_empty() {
            let mut t = Vec::new();
            put_u32(&mut t, self.exports.len() as u32);
            let mut name_off = 4 + self.exports.len() * EXPORT_SIZE;
            for (name, value) in &self.exports {
                put_u32(&mut t, name_off as u32);
                put_u32(&mut t, name.len() as u32);
                put_u32(&mut t, *value);
                put_u32(&mut t, EXPORT_FUNC);
                name_off += name.len();
            }
            for (name, _) in &self.exports {
                t.extend_from_slice(name);
            }
            bodies.push((SectionKind::Exports as u32, 0, 0, 0, t));
        }
        if !self.relocs.is_empty() {
            let mut t = Vec::with_capacity(4 + self.relocs.len() * RELOC_SIZE);
            put_u32(&mut t, self.relocs.len() as u32);
            for (offset, addend) in &self.relocs {
                put_u32(&mut t, *offset);
                put_u32(&mut t, self.arch.relative_reloc());
                put_u64(&mut t, *addend);
            }
            bodies.push((SectionKind::Relocs as u32, 0, 0, 0, t));
        }
        if signature {
            bodies.push((SectionKind::Signature as u32, 0, 0, 0, alloc::vec![0u8; crate::SIGNATURE_SIZE]));
        }

        let dir_offset = HEADER_SIZE;
        let mut offset = dir_offset + bodies.len() * SECTION_SIZE;
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        put_u16(&mut out, FORMAT_VERSION);
        put_u16(&mut out, KIND_NATIVE);
        put_u16(&mut out, self.arch as u16);
        out.push(self.stage as u8);
        out.push(0);
        put_u32(&mut out, HEADER_SIZE as u32);
        put_u32(&mut out, bodies.len() as u32);
        put_u32(&mut out, dir_offset as u32);
        put_u32(&mut out, 0); // file_len：最后回填
        put_u32(&mut out, self.image_size());
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
