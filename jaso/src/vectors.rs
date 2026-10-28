//! 一致性向量的生成（SPEC §14）：`jasopack vectors <目录>` 用它重建仓库的 `jaso/vectors/`，宿主测试用它逐字节比对。
//! Generates the conformance vectors of SPEC §14.
//!
//! 每个向量是 (名字, 文件字节, 期望行)；期望行是**独立写下**的（不由判定函数算出），由宿主测试与 `jasopack vectors`
//! 用 [`crate::conformance::check`] 复核。合法向量都用开发用发布者签名；非法向量从合法文件出发，只引入一处违例
//! （另有几个「两处违例、报告先查到的那处」的顺序向量）。全部输入固定，Ed25519 签名是确定性的，所以重建结果逐字节不变。

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::build::{Builder, ExtensionIn, PlatformIn, SegmentIn, Signer};
use crate::{
    digest_of, signed_digest_of, signed_message, Arch, FloatAbi, ModuleKind, SectionKind, Stage, DIGEST_OFFSET, EXPORT_MANAGED,
    EXT_JASPER_IMPORT, FLAG_R, FLAG_W, FLAG_X, HEADER_SIZE, PAGE, RELOC_RELATIVE32, SECTION_SIZE, SIGNATURE_SIZE, SIGNATURE_VALUE_OFFSET,
    SIG_ED25519,
};

/// 一个向量。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector {
    /// 文件名（不含扩展名）。
    pub name: &'static str,
    /// `.jaso` 内容。
    pub bytes: Vec<u8>,
    /// `.expect` 的内容（一行，不含换行）：`ok` 或码名。
    pub expect: &'static str,
}

/// 与向量一同公开的开发用公钥文件名（内容为 64 个小写十六进制字符加换行）。
pub const DEV_KEY_FILE: &str = "jasper.dev.pub";

/// 不受信任的签名密钥（种子由公开字符串派生；只用于 `trust.key` 向量）。
fn untrusted_signer() -> Signer {
    crate::pack::signer_from_phrase(b"jaso conformance vectors: untrusted key")
}

/// 公钥文件的内容。
pub fn dev_key_text(key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(65);
    for b in key {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 15) as u32, 16).unwrap_or('0'));
    }
    s.push('\n');
    s
}

const MANIFEST: &str = "# conformance vector\ncore.name = jaso-demo\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\n\
core.publisher = jasper.dev\ncore.host = jaso.host.v1\ncore.requires = log, alloc\ncore.exports = jaso_init, f_one\n";

const MANAGED_MANIFEST: &str = "core.name = jaso-jvm\ncore.version = 0.3.0\ncore.abi = jvm.52\ncore.stage = runtime\n\
core.publisher = jasper.dev\ncore.exports = demo.Main.run\n";

/// 原生基准：目录 0 清单、1 平台、2 镜像索引、3 只读段、4 代码段（R+X）、5 数据段（R+W）、6 导出、7 重定位、（签名后）8 签名。
fn native_builder(isa: Arch) -> Builder {
    let mut b = Builder::native(isa, Stage::Runtime, MANIFEST.as_bytes());
    b.platform.float_abi = FloatAbi::Hard;
    b.segments = vec![
        SegmentIn { vaddr: 0, mem_size: 32, flags: FLAG_R, data: b"jaso conformance read-only data\0".to_vec() },
        SegmentIn { vaddr: PAGE, mem_size: 16, flags: FLAG_R | FLAG_X, data: vec![0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90] },
        SegmentIn { vaddr: 2 * PAGE, mem_size: PAGE, flags: FLAG_R | FLAG_W, data: vec![0; 16] },
    ];
    b.exports = vec![(b"jaso_init".to_vec(), PAGE), (b"f_one".to_vec(), PAGE + 8)];
    b.relocs = vec![(2 * PAGE, 0x10), (2 * PAGE + 8, PAGE as u64)];
    b
}

/// 托管基准：目录 0 清单、1 平台、2 镜像索引、3 代码段、4 导出、5 签名。
fn managed_builder() -> Builder {
    let mut b = Builder::native(Arch::X86_64, Stage::Runtime, MANAGED_MANIFEST.as_bytes());
    b.kind = ModuleKind::Managed;
    b.platform = PlatformIn::jvm();
    b.code = Some(b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec()); // 空 ZIP 归档（只有中央目录结尾记录）
    b.exports = vec![(b"demo.Main.run".to_vec(), 0)];
    b
}

fn import_ext() -> ExtensionIn {
    ExtensionIn { name: EXT_JASPER_IMPORT.as_bytes().to_vec(), version: 1, critical: true, content: b"fn f_one(): Unit".to_vec() }
}

/// 一个段：(种类, 标志, vaddr, mem_size, 内容)。
#[derive(Clone)]
struct Body {
    kind: u32,
    flags: u32,
    vaddr: u32,
    mem: u32,
    data: Vec<u8>,
}

fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// 拆出合法文件的头部与各段（按目录顺序）。
fn split(file: &[u8]) -> ([u8; HEADER_SIZE], Vec<Body>) {
    let mut head = [0u8; HEADER_SIZE];
    head.copy_from_slice(&file[..HEADER_SIZE]);
    let n = get32(file, 20) as usize;
    let bodies = (0..n)
        .map(|i| {
            let d = HEADER_SIZE + i * SECTION_SIZE;
            let (off, len) = (get32(file, d + 8) as usize, get32(file, d + 12) as usize);
            Body { kind: get32(file, d), flags: get32(file, d + 4), vaddr: get32(file, d + 16), mem: get32(file, d + 20), data: file[off..off + len].to_vec() }
        })
        .collect();
    (head, bodies)
}

/// 按头部模板与各段重新排布：目录紧跟头部，内容按目录顺序；去掉原有签名段，给了 `signer` 就在末尾签名；最后回填长度与完整性摘要。
/// 不做任何校验——非法向量正是靠它写出来的。
fn emit(head: &[u8; HEADER_SIZE], bodies: &[Body], signer: Option<&Signer>) -> Vec<u8> {
    let mut bodies: Vec<Body> = bodies.iter().filter(|b| b.kind != SectionKind::Signature as u32).cloned().collect();
    if signer.is_some() {
        bodies.push(Body { kind: SectionKind::Signature as u32, flags: 0, vaddr: 0, mem: 0, data: vec![0; SIGNATURE_SIZE] });
    }
    let mut out = head.to_vec();
    put32(&mut out, 20, bodies.len() as u32);
    put32(&mut out, 24, HEADER_SIZE as u32);
    let mut off = HEADER_SIZE + bodies.len() * SECTION_SIZE;
    for b in &bodies {
        for v in [b.kind, b.flags, off as u32, b.data.len() as u32, b.vaddr, b.mem, 0, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        off += b.data.len();
    }
    for b in &bodies {
        out.extend_from_slice(&b.data);
    }
    let len = out.len() as u32;
    put32(&mut out, 28, len);
    if let Some(s) = signer {
        let sig = out.len() - SIGNATURE_SIZE;
        put32(&mut out, sig, SIG_ED25519);
        out[sig + 8..sig + 40].copy_from_slice(&s.public_key());
        let value = s.sign(&signed_message(&signed_digest_of(&out, sig)));
        out[sig + SIGNATURE_VALUE_OFFSET..].copy_from_slice(&value);
    }
    digest_fix(&mut out);
    out
}

fn digest_fix(b: &mut [u8]) {
    let d = digest_of(b);
    b[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
}

/// 改写后回填完整性摘要（签名不重算：只用于结构违例，或有意让签名失效）。
fn edit(good: &[u8], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut b = good.to_vec();
    f(&mut b);
    digest_fix(&mut b);
    b
}

/// 改写目录第 `i` 项的第 `field` 个 u32（kind=0 flags=1 off=2 size=3 vaddr=4 mem=5）。
fn dir(good: &[u8], i: usize, field: usize, v: u32) -> Vec<u8> {
    edit(good, |b| put32(b, HEADER_SIZE + i * SECTION_SIZE + field * 4, v))
}

/// 改写目录第 `i` 项内容中偏移 `at` 处的一个 u32。
fn content32(good: &[u8], i: usize, at: usize, v: u32) -> Vec<u8> {
    edit(good, |b| {
        let o = get32(b, HEADER_SIZE + i * SECTION_SIZE + 8) as usize + at;
        put32(b, o, v)
    })
}

/// 换掉清单后重新排布并签名。
fn remanifest(good: &[u8], text: &[u8], signer: &Signer) -> Vec<u8> {
    let (head, mut bodies) = split(good);
    bodies[0].data = text.to_vec();
    emit(&head, &bodies, Some(signer))
}

/// 对清单文本做一次替换（`from` 必须出现）。
fn replaced(from: &str, to: &str) -> Vec<u8> {
    assert!(MANIFEST.contains(from), "{from}");
    MANIFEST.replacen(from, to, 1).into_bytes()
}

/// 两个原生镜像（依次为 `first`、`second` 指令集，各自一条平台记录），头部 `arch` = any，签名。
fn two_images(first: Arch, second: Arch, signer: &Signer) -> Vec<u8> {
    let a = native_builder(first).finish().expect("native image");
    let b = native_builder(second).finish().expect("native image");
    let (mut head, ab) = split(&a);
    let (_, bb) = split(&b);
    let image = 3..8;
    let mut bodies: Vec<Body> = ab[..3].to_vec();
    let mut platforms = vec![0u8; 8];
    put32(&mut platforms, 0, 2);
    platforms.extend_from_slice(&ab[1].data[8..72]);
    platforms.extend_from_slice(&bb[1].data[8..72]);
    bodies[1].data = platforms;
    let mut index = ab[2].data.clone();
    put32(&mut index, 0, 2);
    let mut e2 = index[8..40].to_vec();
    e2[2] = 1; // 平台记录 1
    put32(&mut e2, 4, 8); // 认领目录 8–12
    index.extend_from_slice(&e2);
    bodies[2].data = index;
    bodies.extend_from_slice(&ab[image.clone()]);
    bodies.extend_from_slice(&bb[image]);
    head[12] = 0;
    head[13] = 0;
    emit(&head, &bodies, Some(signer))
}

/// 全部向量（按名字排序）。`dev` 是开发用发布者的签名密钥（[`crate::pack::development_signer`]）。
pub fn all(dev: &Signer) -> Vec<Vector> {
    let native = native_builder(Arch::X86_64).finish_signed(dev).expect("ok-native");
    let managed = managed_builder().finish_signed(dev).expect("ok-managed");
    let mut v: Vec<Vector> = Vec::new();
    let mut add = |name: &'static str, bytes: Vec<u8>, expect: &'static str| v.push(Vector { name, bytes, expect });

    // —— 合法 ——
    add("ok-native", native.clone(), "ok");
    add("ok-managed", managed.clone(), "ok");
    let mut h = native_builder(Arch::X86_64);
    h.kind = ModuleKind::Hybrid;
    h.extensions = vec![import_ext()];
    add("ok-hybrid", h.finish_signed(dev).expect("ok-hybrid"), "ok");
    add("ok-multi-image", two_images(Arch::X86_64, Arch::Aarch64, dev), "ok");
    add("ok-multi-image-second", two_images(Arch::Aarch64, Arch::X86_64, dev), "ok");
    let mut u = native_builder(Arch::X86_64);
    u.extensions = vec![ExtensionIn { name: b"ui.layout".to_vec(), version: 3, critical: false, content: vec![1, 2, 3] }];
    add("ok-unknown-noncritical-ext", u.finish_signed(dev).expect("ok-unknown-ext"), "ok");
    let deps = "core.depends = jaso-base@>=1.0,<2.0\ncore.runtime = >=0.1,<0.2\n";
    add("ok-depends-runtime", remanifest(&native, &[MANIFEST.as_bytes(), deps.as_bytes()].concat(), dev), "ok");
    let (mut head, bodies) = split(&native);
    head[12] = 0;
    add("ok-arch-any", emit(&head, &bodies, Some(dev)), "ok");

    // —— 头部（§3）——
    add("bad-format-truncated", native[..HEADER_SIZE - 1].to_vec(), "format.truncated");
    add("bad-format-magic", edit(&native, |b| b[1] = b'j'), "format.magic");
    add("bad-format-header", edit(&native, |b| b[16] = 81), "format.header");
    add("bad-format-length", edit(&native, |b| b.extend_from_slice(&[0; 8])), "format.length");
    add("bad-format-digest", { let mut b = native.clone(); b[DIGEST_OFFSET] ^= 1; b }, "format.digest");
    add("bad-format-kind", edit(&native, |b| b[10] = 4), "format.kind");
    add("bad-format-arch", edit(&native, |b| b[12] = 9), "format.arch");
    add("bad-format-stage", edit(&native, |b| b[14] = 7), "format.stage");
    add("bad-version-unsupported", edit(&native, |b| b[8] = 0), "version.unsupported");
    // —— 段目录（§5）——
    add("bad-section-dir", edit(&native, |b| put32(b, 20, 0)), "section.dir");
    add("bad-section-bounds", dir(&native, 3, 3, u32::MAX), "section.bounds");
    add("bad-section-unknown", dir(&native, 3, 0, 10), "section.unknown");
    add("bad-section-duplicate", dir(&native, 6, 0, SectionKind::Manifest as u32), "section.duplicate");
    add("bad-section-missing", dir(&native, 1, 0, SectionKind::Segment as u32), "section.missing");
    // —— 平台与镜像索引（§6）——
    add("bad-platform-malformed", edit(&native, |b| { let o = get32(b, HEADER_SIZE + SECTION_SIZE + 8) as usize + 8 + 3; b[o] = 3 }), "platform.malformed");
    add("bad-platform-arch", edit(&native, |b| b[12] = Arch::Aarch64 as u8), "platform.arch");
    add("bad-image-index", content32(&native, 2, 0, 0), "image.index");
    add("bad-image-kind", edit(&native, |b| b[10] = ModuleKind::Managed as u8), "image.kind");
    add("bad-image-size", content32(&native, 2, 8 + 12, PAGE + 1), "image.size");
    // —— 原生镜像内容（§7）——
    add("bad-image-segment", dir(&native, 3, 1, FLAG_W), "image.segment");
    add("bad-image-wx", dir(&native, 5, 1, FLAG_R | FLAG_W | FLAG_X), "image.wx");
    add("bad-image-overlap", dir(&native, 5, 4, PAGE), "image.overlap");
    add("bad-image-exports", content32(&native, 6, 4 + 12, EXPORT_MANAGED), "image.exports");
    add("bad-image-export-range", content32(&native, 6, 4 + 8, 0), "image.export_range");
    add("bad-image-exports-mismatch", remanifest(&native, &replaced("jaso_init, f_one", "jaso_init, f_one, f_two"), dev), "image.exports_mismatch");
    add("bad-image-reloc", content32(&native, 7, 4 + 4, RELOC_RELATIVE32), "image.reloc");
    add("bad-image-reloc-range", content32(&native, 7, 4, PAGE), "image.reloc_range");
    // —— 托管镜像内容（§8）——
    add("bad-image-code", content32(&managed, 3, 0, 2), "image.code");
    // —— 签名段（§10）——
    add("bad-signature-section", content32(&native, 8, 0, 2), "signature.section");
    // —— 清单（§11）——
    add("bad-manifest-utf8", remanifest(&native, &[MANIFEST.as_bytes(), b"x.note = \xFF\n"].concat(), dev), "manifest.utf8");
    add("bad-manifest-line", remanifest(&native, &replaced("core.host", "just text\ncore.host"), dev), "manifest.line");
    add("bad-manifest-key", remanifest(&native, &replaced("core.host", "core.color = red\ncore.host"), dev), "manifest.key");
    add("bad-manifest-missing", remanifest(&native, &replaced("core.version = 1.0.0\n", ""), dev), "manifest.missing");
    add("bad-manifest-duplicate", remanifest(&native, &replaced("core.host", "core.name = jaso-other\ncore.host"), dev), "manifest.duplicate");
    add("bad-manifest-value", remanifest(&native, &replaced("core.version = 1.0.0", "core.version = 1.0"), dev), "manifest.value");
    let many: String = (0..33).map(|i| alloc::format!("core.requires = cap{i}\n")).collect();
    add("bad-manifest-limit", remanifest(&native, &[MANIFEST.as_bytes(), many.as_bytes()].concat(), dev), "manifest.limit");
    add("bad-manifest-stage", remanifest(&native, &replaced("core.stage = runtime", "core.stage = boot"), dev), "manifest.stage");
    add("bad-platform-abi", remanifest(&native, &replaced("core.abi = c.v1", "core.abi = c.v2"), dev), "platform.abi");
    // —— 扩展段（§9）——
    let ext = |e: ExtensionIn| {
        let (head, mut bodies) = split(&native);
        let mut t = Vec::new();
        t.extend_from_slice(&e.version.to_le_bytes());
        t.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        t.extend_from_slice(&[0, 0]);
        t.extend_from_slice(&e.name);
        t.resize(t.len().next_multiple_of(8), 0);
        t.extend_from_slice(&e.content);
        bodies.insert(8, Body { kind: SectionKind::Ext as u32, flags: e.critical as u32, vaddr: 0, mem: 0, data: t });
        emit(&head, &bodies, Some(dev))
    };
    add("bad-extension-malformed", ext(ExtensionIn { name: b"nodot".to_vec(), version: 1, critical: false, content: vec![] }), "extension.malformed");
    add("bad-extension-critical", ext(ExtensionIn { name: b"ui.layout".to_vec(), version: 1, critical: true, content: vec![] }), "extension.critical");
    let (head, mut bodies) = split(&ext(import_ext()));
    let second = bodies[8].clone();
    bodies.insert(9, second);
    add("bad-extension-duplicate", emit(&head, &bodies, Some(dev)), "extension.duplicate");
    let (mut head, bodies) = split(&native);
    head[10] = ModuleKind::Hybrid as u8;
    add("bad-extension-required", emit(&head, &bodies, Some(dev)), "extension.required");

    // —— 装载（§12.2 第 2–6 步，需一致性上下文）——
    add("load-platform-mismatch", native_builder(Arch::Aarch64).finish_signed(dev).expect("aarch64"), "platform.mismatch");
    let mut soft = native_builder(Arch::X86_64);
    soft.platform.float_abi = FloatAbi::Soft;
    add("load-platform-mismatch-float-abi", soft.finish_signed(dev).expect("soft"), "platform.mismatch");
    add("load-signature-invalid", edit(&native, |b| { let o = get32(b, HEADER_SIZE + 4 * SECTION_SIZE + 8) as usize; b[o] = 0xCC }), "signature.invalid");
    add("load-trust-unsigned", native_builder(Arch::X86_64).finish().expect("unsigned"), "trust.unsigned");
    add("load-trust-publisher", remanifest(&native, &replaced("core.publisher = jasper.dev", "core.publisher = other.dev"), dev), "trust.publisher");
    add("load-trust-publisher-missing", remanifest(&native, &replaced("core.publisher = jasper.dev\n", ""), dev), "trust.publisher");
    add("load-trust-key", remanifest(&native, MANIFEST.as_bytes(), &untrusted_signer()), "trust.key");
    add("load-trust-namespace", remanifest(&native, &replaced("core.name = jaso-demo", "core.name = demo-mod"), dev), "trust.namespace");
    add("load-capability-denied", remanifest(&native, &replaced("core.requires = log, alloc", "core.requires = log, net"), dev), "capability.denied");
    add("load-dependency-unsatisfied", remanifest(&native, &[MANIFEST.as_bytes(), b"core.depends = jaso-base@>=2.0"].concat(), dev), "dependency.unsatisfied");
    add("load-dependency-missing", remanifest(&native, &[MANIFEST.as_bytes(), b"core.depends = jaso-absent"].concat(), dev), "dependency.unsatisfied");
    add("load-dependency-runtime", remanifest(&native, &[MANIFEST.as_bytes(), b"core.runtime = >=0.2"].concat(), dev), "dependency.runtime");

    // —— 顺序：两处违例，报告先查到的那处（§12.1）——
    add("order-version-before-kind", edit(&native, |b| (b[8], b[10]) = (5, 9)), "version.unsupported");
    add("order-length-before-digest", { let mut b = native.clone(); b.push(0); b }, "format.length");
    add("order-manifest-before-exports", remanifest(&native, &replaced("jaso_init, f_one", "jaso_init, f_one, f_two\ncore.lifecycle = forever"), dev), "manifest.value");
    add("order-structure-before-trust", dir(&native_builder(Arch::X86_64).finish().expect("unsigned"), 5, 1, FLAG_R | FLAG_W | FLAG_X), "image.wx");
    add("order-trust-before-platform", native_builder(Arch::Aarch64).finish().expect("unsigned aarch64"), "trust.unsigned");
    add("order-platform-before-capability", remanifest(&native_builder(Arch::Aarch64).finish_signed(dev).expect("aarch64"), &replaced("log, alloc", "log, net"), dev), "platform.mismatch");

    v.sort_by(|a, b| a.name.cmp(b.name));
    v
}
