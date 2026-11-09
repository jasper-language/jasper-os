//! 宿主测试：构建 → 解析往返、每一类拒绝（按 SPEC §12.1 的顺序给出第一处违例）、清单规则、平台选择、
//! 扩展段、托管与混合种类、错误码表、format 0 迁移、随机变异输入不 panic。

extern crate std;

use std::string::String;
use std::vec;
use std::vec::Vec;

use crate::build::{Builder, ExtensionIn, MultiBuilder, PlatformIn, SegmentIn};
use crate::*;

const MANIFEST: &str = "# 测试模块\ncore.name = demo.mod\ncore.version = 1.2.3\ncore.abi = c.v1\ncore.stage = runtime\ncore.host = jaso.host.v1\n\
core.requires = system.console.write, system.memory.map\ncore.requires = system.time.now\nweb.route = /x\ncore.exports = f_one, f_two\n";

/// 段目录：0 清单、1 平台、2 镜像索引、3–5 映像段、6 导出、7 重定位。
fn sample() -> Builder {
    let mut b = Builder::native(Arch::X86_64, Stage::Runtime, MANIFEST.as_bytes());
    b.segments = vec![
        SegmentIn { vaddr: 0, mem_size: 100, flags: FLAG_R, data: vec![7; 100] },
        SegmentIn { vaddr: PAGE, mem_size: 64, flags: FLAG_R | FLAG_X, data: vec![0xC3; 64] },
        SegmentIn { vaddr: 2 * PAGE, mem_size: 2 * PAGE + 1, flags: FLAG_R | FLAG_W, data: vec![0; 16] },
    ];
    b.exports = vec![(b"f_one".to_vec(), PAGE), (b"f_two".to_vec(), PAGE + 8)];
    b.relocs = vec![(2 * PAGE, 0x10), (2 * PAGE + 8, PAGE as u64)];
    b
}

const MANAGED_MANIFEST: &str = "core.name = demo.jvm\ncore.version = 0.1.0\ncore.abi = jvm.52\ncore.stage = runtime\ncore.exports = demo.Main.run\n";

fn managed() -> Builder {
    let mut b = Builder::native(Arch::X86_64, Stage::Runtime, MANAGED_MANIFEST.as_bytes());
    b.kind = ModuleKind::Managed;
    b.platform = PlatformIn::jvm();
    b.code = Some(b"PK\x03\x04 class archive".to_vec());
    b.exports = vec![(b"demo.Main.run".to_vec(), 0)];
    b
}

fn import_ext() -> ExtensionIn {
    ExtensionIn { name: EXT_JASPER_IMPORT.as_bytes().to_vec(), version: 1, critical: true, content: b"fn f_one()".to_vec() }
}

fn hybrid() -> Builder {
    let mut b = sample();
    b.kind = ModuleKind::Hybrid;
    b.extensions = vec![import_ext()];
    b
}

fn digest_fix(b: &mut [u8]) {
    let d = digest_of(b);
    b[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
}

fn parse_err(b: &[u8]) -> JasoError {
    Jaso::parse(b).unwrap_err()
}

/// 改写后回填摘要再解析。
fn edit(good: &[u8], f: impl FnOnce(&mut Vec<u8>)) -> JasoError {
    let mut b = good.to_vec();
    f(&mut b);
    digest_fix(&mut b);
    parse_err(&b)
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// 段目录第 `i` 项的内容起点。
fn section_offset(b: &[u8], i: usize) -> usize {
    get32(b, HEADER_SIZE + i * SECTION_SIZE + 8) as usize
}

/// 修改段目录第 `i` 项的第 `field` 个 u32（kind=0 flags=1 off=2 size=3 vaddr=4 mem=5）。
fn with_dir(good: &[u8], i: usize, field: usize, v: u32) -> JasoError {
    edit(good, |b| put32(b, HEADER_SIZE + i * SECTION_SIZE + field * 4, v))
}

/// 修改第 `i` 项段内容中偏移 `at` 处的一个字节。
fn with_byte(good: &[u8], i: usize, at: usize, v: u8) -> JasoError {
    edit(good, |b| {
        let o = section_offset(b, i) + at;
        b[o] = v;
    })
}

#[test]
fn roundtrip() {
    let bytes = sample().finish().expect("build");
    let f = Jaso::parse(&bytes).expect("parse");
    assert_eq!((f.kind, f.arch, f.stage), (ModuleKind::Native, Some(Arch::X86_64), Stage::Runtime));
    assert_eq!(f.manifest.name, "demo.mod");
    assert_eq!(f.manifest.version, (1, 2, 3));
    assert_eq!(f.manifest.host, Some(HOST_V1));
    assert_eq!(f.manifest.lifecycle, Lifecycle::Plugin);
    let req: Vec<&str> = f.manifest.requires().collect();
    assert_eq!(req, ["system.console.write", "system.memory.map", "system.time.now"]);
    assert_eq!(f.manifest.extension("web.route"), Some("/x"));
    assert_eq!(f.images().count(), 1);
    let img = f.image(0).unwrap();
    assert_eq!((img.kind, img.image_size), (ImageKind::Native, 5 * PAGE));
    assert_eq!(img.platform.isa, Some(Arch::X86_64));
    assert_eq!((img.platform.pointer_bytes, img.platform.float_abi, img.platform.target), (8, FloatAbi::Soft, Target::JasperOs));
    assert_eq!((img.platform.abi, img.platform.isa_ext), ("c.v1", ""));
    assert_eq!(img.segments().count(), 3);
    assert_eq!(img.export("f_two").map(|e| e.value), Some(PAGE + 8));
    assert!(img.export("missing").is_none());
    assert_eq!(img.relocs().count(), 2);
    assert!(img.code().is_none());
    assert!(f.image(1).is_none());
    assert_eq!(f.extensions().count(), 0);
    // 由文件还原构建输入再写出：逐字节一致
    assert_eq!(Builder::from_file(&f, 0).unwrap().finish().unwrap(), bytes);
}

#[test]
fn any_changed_byte_breaks_the_digest() {
    let bytes = sample().finish().unwrap();
    for i in (0..bytes.len()).filter(|i| !(DIGEST_OFFSET..DIGEST_OFFSET + 32).contains(i)) {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(Jaso::parse(&b).is_err(), "改动第 {} 字节后仍通过", i);
    }
    let mut b = bytes.clone();
    b[DIGEST_OFFSET] ^= 0x80;
    assert_eq!(parse_err(&b), JasoError::DigestMismatch);
}

#[test]
fn header_rejections() {
    let good = sample().finish().unwrap();
    assert_eq!(parse_err(&good[..HEADER_SIZE - 1]), JasoError::Truncated);
    let set = |f: &dyn Fn(&mut Vec<u8>)| edit(&good, f);
    assert_eq!(set(&|b| b[0] = 0), JasoError::BadMagic);
    assert_eq!(set(&|b| b[8] = 0), JasoError::UnsupportedVersion(0));
    assert_eq!(set(&|b| b[8] = 2), JasoError::UnsupportedVersion(2));
    assert_eq!(set(&|b| b[10] = 4), JasoError::UnsupportedKind(4));
    assert_eq!(set(&|b| b[12] = 9), JasoError::UnknownArch(9));
    assert_eq!(set(&|b| b[14] = 7), JasoError::UnknownStage(7));
    assert_eq!(set(&|b| b[15] = 1), JasoError::BadHeader);
    assert_eq!(set(&|b| b[16] = 81), JasoError::BadHeader);
    assert_eq!(set(&|b| b[32] = 1), JasoError::BadHeader); // format 0 的映像大小位置现为保留
    assert_eq!(set(&|b| b[36] = 1), JasoError::BadHeader);
    assert_eq!(set(&|b| b[72] = 1), JasoError::BadHeader);
    assert_eq!(set(&|b| b.push(0)), JasoError::LengthMismatch);
    // 先后顺序：版本先于种类，种类先于指令集
    assert_eq!(set(&|b| (b[8], b[10], b[12]) = (5, 9, 9)), JasoError::UnsupportedVersion(5));
    assert_eq!(set(&|b| (b[10], b[12]) = (9, 9)), JasoError::UnsupportedKind(9));
    // 段目录位置与项数
    assert_eq!(set(&|b| put32(b, 20, 0)), JasoError::BadSectionDir);
    assert_eq!(set(&|b| put32(b, 20, 65)), JasoError::BadSectionDir);
    assert_eq!(set(&|b| put32(b, 24, 8)), JasoError::BadSectionDir);
    assert_eq!(set(&|b| put32(b, 24, u32::MAX - 4)), JasoError::BadSectionDir);
}

#[test]
fn section_rejections() {
    let good = sample().finish().unwrap();
    assert_eq!(with_dir(&good, 0, 0, 10), JasoError::UnknownSection(10));
    assert_eq!(with_dir(&good, 0, 0, 0), JasoError::UnknownSection(0));
    assert_eq!(with_dir(&good, 0, 1, 1), JasoError::BadSectionDir); // 清单的 flags 必须为 0
    assert_eq!(with_dir(&good, 1, 4, 1), JasoError::BadSectionDir); // 平台段的 vaddr 必须为 0
    assert_eq!(edit(&good, |b| b[HEADER_SIZE + 31] = 1), JasoError::BadSectionDir); // 目录保留字段
    assert_eq!(with_dir(&good, 3, 3, u32::MAX), JasoError::SectionOutOfFile);
    assert_eq!(with_dir(&good, 3, 2, 4), JasoError::SectionOutOfFile);
    assert_eq!(with_dir(&good, 6, 0, 1), JasoError::DuplicateSection(1)); // 第二个清单
    assert_eq!(with_dir(&good, 6, 0, 6), JasoError::DuplicateSection(6)); // 第二个平台段
    assert_eq!(with_dir(&good, 6, 0, 5), JasoError::ImageIndex); // 属于文件的签名段落在镜像区间内：段归属先于签名布局检查
    // 缺必需段：清单、平台、镜像索引
    assert_eq!(with_dir(&good, 0, 0, 2), JasoError::MissingSection(1));
    assert_eq!(edit(&good, |b| put32(b, HEADER_SIZE + SECTION_SIZE, 2)), JasoError::MissingSection(6));
    assert_eq!(edit(&good, |b| put32(b, HEADER_SIZE + 2 * SECTION_SIZE, 2)), JasoError::MissingSection(7));
    // 未知种类先于后面各项的任何检查
    assert_eq!(edit(&good, |b| {
        put32(b, HEADER_SIZE + 4, 1);
        put32(b, HEADER_SIZE + 7 * SECTION_SIZE, 99);
    }), JasoError::BadSectionDir);
}

#[test]
fn segment_rejections() {
    let good = sample().finish().unwrap();
    assert_eq!(with_dir(&good, 3, 1, FLAG_W), JasoError::BadSegment); // 不可读
    assert_eq!(with_dir(&good, 3, 1, 8 | FLAG_R), JasoError::BadSegment); // 未知标志
    assert_eq!(with_dir(&good, 4, 1, FLAG_R | FLAG_W | FLAG_X), JasoError::WriteExecute);
    assert_eq!(with_dir(&good, 5, 4, 2 * PAGE + 1), JasoError::BadSegment); // 未对齐
    assert_eq!(with_dir(&good, 5, 5, 0), JasoError::BadSegment); // mem_size 为 0
    assert_eq!(with_dir(&good, 5, 5, 1), JasoError::BadSegment); // mem_size < file_size
    assert_eq!(with_dir(&good, 5, 4, PAGE), JasoError::SegmentOverlap);
    assert_eq!(with_dir(&good, 5, 4, 4 * PAGE), JasoError::BadSegment); // 越出映像
}

#[test]
fn platform_rejections() {
    let good = sample().finish().unwrap();
    let p = |at: usize, v: u8| with_byte(&good, 1, at, v);
    assert_eq!(p(0, 0), JasoError::PlatformMalformed); // count = 0
    assert_eq!(p(0, 17), JasoError::PlatformMalformed); // count > 16
    assert_eq!(p(4, 1), JasoError::PlatformMalformed); // 保留
    let r = 8; // 第一条记录
    assert_eq!(p(r, 9), JasoError::PlatformMalformed); // 未知 isa
    assert_eq!(p(r + 2, 4), JasoError::PlatformMalformed); // x86_64 的指针宽度不是 4
    assert_eq!(p(r + 3, 0), JasoError::PlatformMalformed); // 原生平台 float_abi = none
    assert_eq!(p(r + 3, 3), JasoError::PlatformMalformed); // 未知 float_abi
    assert_eq!(p(r + 4, 2), JasoError::PlatformMalformed); // 原生 isa 配 jvm
    assert_eq!(p(r + 4, 4), JasoError::PlatformMalformed); // 未知 target
    assert_eq!(p(r + 6, 1), JasoError::PlatformMalformed);
    assert_eq!(p(r + 8, b'A'), JasoError::PlatformMalformed); // isa_ext 字符集
    assert_eq!(p(r + 8, b','), JasoError::PlatformMalformed); // 空记号
    assert_eq!(p(r + 40, 0), JasoError::PlatformMalformed); // abi 为空
    assert_eq!(p(r + 46, b'x'), JasoError::PlatformMalformed); // 零字节之后又出现非零
    assert_eq!(p(r + 63, 1), JasoError::PlatformMalformed);
    // 平台段长度不是 8 + 64 × count
    assert_eq!(with_dir(&good, 1, 3, 8 + 63), JasoError::PlatformMalformed);
    let mut b = sample();
    b.platform.isa_ext = b"m,a,m".to_vec(); // 重复记号
    assert_eq!(b.finish().unwrap_err(), JasoError::PlatformMalformed);
    let mut b = sample();
    b.platform.isa_ext = b"i,m,a,c".to_vec();
    assert!(b.finish().is_ok());
    // 头部 arch 与平台记录不一致
    assert_eq!(edit(&good, |b| b[12] = Arch::Aarch64 as u8), JasoError::PlatformArch);
}

#[test]
fn arch_any_accepted() {
    let mut b = sample().finish().unwrap();
    b[12] = 0;
    digest_fix(&mut b);
    assert_eq!(Jaso::parse(&b).unwrap().arch, None);
}

#[test]
fn image_index_rejections() {
    let good = sample().finish().unwrap();
    let e = |at: usize, v: u32| edit(&good, |b| { let o = section_offset(b, 2) + at; put32(b, o, v) });
    assert_eq!(e(0, 0), JasoError::ImageIndex); // count = 0
    assert_eq!(e(0, 9), JasoError::ImageIndex);
    assert_eq!(e(4, 1), JasoError::ImageIndex);
    assert_eq!(e(8, 3), JasoError::ImageIndex); // 未知镜像种类
    assert_eq!(e(8, 1 | 1 << 16), JasoError::ImageIndex); // 平台下标越界
    assert_eq!(e(12, 4), JasoError::ImageIndex); // 区间起点偏移：清单之后的段落在区间外
    assert_eq!(e(12, 2), JasoError::ImageIndex); // 区间包含镜像索引段本身
    assert_eq!(e(16, 0), JasoError::ImageIndex); // 区间为空
    assert_eq!(e(16, 99), JasoError::ImageIndex); // 区间越出目录
    assert_eq!(e(24, 1), JasoError::ImageIndex); // 保留
    assert_eq!(e(20, PAGE + 1), JasoError::BadImageSize);
    assert_eq!(e(20, 0), JasoError::BadImageSize);
    assert_eq!(e(20, MAX_IMAGE + PAGE), JasoError::BadImageSize);
    assert_eq!(e(20, 2 * PAGE), JasoError::BadSegment); // 映像大小比段所需的小
    // 镜像索引长度不是 8 + 32 × count
    assert_eq!(with_dir(&good, 2, 3, 8 + 33), JasoError::ImageIndex);
    // 原生模块里出现托管种类的镜像：平台与种类先不一致（isa ≠ 0）
    assert_eq!(e(8, 2), JasoError::ImageIndex);
    // 没有映像段的原生镜像
    let mut b = sample();
    b.segments.clear();
    b.exports.clear();
    b.relocs.clear();
    b.manifest = MANIFEST.replace("core.exports = f_one, f_two\n", "").into_bytes();
    assert_eq!(b.finish().unwrap_err(), JasoError::ImageIndex);
    // 原生镜像里出现代码段
    let mut b = sample();
    b.code = Some(vec![1]);
    assert_eq!(b.finish().unwrap_err(), JasoError::ImageIndex);
    // 托管模块种类配原生镜像
    let mut b = sample();
    b.kind = ModuleKind::Managed;
    assert_eq!(b.finish().unwrap_err(), JasoError::ImageKindNotAllowed);
}

#[test]
fn exports_must_match_manifest() {
    let mut b = sample();
    b.exports.pop();
    assert_eq!(b.finish().unwrap_err(), JasoError::ExportsMismatch);
    let mut b = sample();
    b.exports.push((b"f_three".to_vec(), PAGE + 16));
    assert_eq!(b.finish().unwrap_err(), JasoError::ExportsMismatch);
    let mut b = sample();
    b.manifest = MANIFEST.replace("core.exports = f_one, f_two", "core.exports = f_one, f_one").into_bytes();
    assert_eq!(b.finish().unwrap_err(), JasoError::ExportsMismatch);
    let bytes = sample().finish().unwrap();
    assert_eq!(Jaso::parse(&bytes).unwrap().manifest.exports().collect::<Vec<_>>(), ["f_one", "f_two"]);
}

#[test]
fn export_and_reloc_rejections() {
    let mut b = sample();
    b.exports.push((b"f_one".to_vec(), PAGE));
    assert_eq!(b.finish().unwrap_err(), JasoError::BadExports);
    let mut b = sample();
    b.exports[0].0 = b"bad name".to_vec();
    assert_eq!(b.finish().unwrap_err(), JasoError::BadExports);
    let mut b = sample();
    b.exports[0].1 = 0;
    assert_eq!(b.finish().unwrap_err(), JasoError::ExportOutOfRange);
    let mut b = sample();
    b.exports[0].1 = 99 * PAGE;
    assert_eq!(b.finish().unwrap_err(), JasoError::ExportOutOfRange);
    let good = sample().finish().unwrap();
    assert_eq!(with_byte(&good, 6, 4 + 12, EXPORT_MANAGED as u8), JasoError::BadExports); // 原生镜像里的托管导出
    let mut b = sample();
    b.relocs[0].0 = PAGE;
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    let mut b = sample();
    b.relocs[0].0 = 2 * PAGE + 4;
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    let mut b = sample();
    b.relocs[0].1 = 5 * PAGE as u64;
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    let mut b = sample();
    b.relocs[0].0 = 5 * PAGE - 4;
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    assert_eq!(with_byte(&good, 7, 4 + 4, RELOC_RELATIVE32 as u8), JasoError::BadReloc);
    assert_eq!(with_dir(&good, 7, 3, 4 + 15), JasoError::BadReloc);
    let f = Jaso::parse(&good).unwrap();
    assert_eq!(f.image(0).unwrap().relocs().next().map(|r| r.kind), Some(RELOC_RELATIVE64));
}

#[test]
fn reloc_width_follows_platform() {
    let mut b = sample();
    b.platform.isa = Some(Arch::Riscv32);
    b.relocs = vec![(2 * PAGE + 4, 0x10)];
    let ok = b.finish().unwrap();
    let f = Jaso::parse(&ok).unwrap();
    assert_eq!(f.image(0).unwrap().relocs().next().map(|r| r.kind), Some(RELOC_RELATIVE32));
    assert_eq!(with_byte(&ok, 7, 4 + 4, RELOC_RELATIVE64 as u8), JasoError::BadReloc);
    let mut b = sample();
    b.relocs = vec![(2 * PAGE + 4, 0x10)];
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    let mut b = sample();
    b.platform.isa = Some(Arch::Riscv32);
    b.relocs = vec![(5 * PAGE - 2, 0x10)];
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
}

#[test]
fn manifest_rules() {
    let p = Manifest::parse;
    const BASE: &str = "core.name = a\ncore.version = 0.0.1\ncore.abi = c.v1\ncore.stage = boot\n";
    let m = p(BASE).unwrap();
    assert_eq!((m.stage, m.lifecycle, m.runtime), (Stage::Boot, Lifecycle::Plugin, None));
    assert_eq!(p("core.version = 0.0.1\ncore.abi = c.v1").unwrap_err(), ManifestError::Missing("core.name"));
    assert_eq!(p("core.name = a\ncore.abi = c.v1").unwrap_err(), ManifestError::Missing("core.version"));
    assert_eq!(p("core.name = a\ncore.version = 1.0.0").unwrap_err(), ManifestError::Missing("core.abi"));
    assert_eq!(p("core.name = a\ncore.version = 1.0.0\ncore.abi = c.v1").unwrap_err(), ManifestError::Missing("core.stage"));
    assert_eq!(p("core.name = A\n").unwrap_err(), ManifestError::BadValue(1));
    assert_eq!(p("core.name = a\ncore.name = b\n").unwrap_err(), ManifestError::Duplicate(2));
    assert_eq!(p("core.name = a\ncore.version = 1.2\n").unwrap_err(), ManifestError::BadValue(2));
    assert_eq!(p("core.name = a\ncore.version = 1.2.3.4\n").unwrap_err(), ManifestError::BadValue(2));
    assert_eq!(p("core.name = a\ncore.version = 1.-2.3\n").unwrap_err(), ManifestError::BadValue(2));
    assert_eq!(p("core.version = 1234567890.0.0\n").unwrap_err(), ManifestError::BadValue(1));
    assert_eq!(p("core.abi = c.v1.too.long.name\n").unwrap_err(), ManifestError::BadValue(1)); // > 16 字节
    assert_eq!(p("core.stage = later\n").unwrap_err(), ManifestError::BadValue(1));
    assert_eq!(p("core.stage = boot\ncore.stage = boot\n").unwrap_err(), ManifestError::Duplicate(2));
    assert_eq!(p("core.lifecycle = forever\n").unwrap_err(), ManifestError::BadValue(1));
    assert_eq!(p("core.description = x\ncore.description = y\n").unwrap_err(), ManifestError::Duplicate(2));
    assert_eq!(p("core.color = red\n").unwrap_err(), ManifestError::BadKey(1));
    assert_eq!(p("nonamespace = 1\n").unwrap_err(), ManifestError::BadKey(1));
    assert_eq!(p("just text\n").unwrap_err(), ManifestError::BadLine(1));
    assert_eq!(p("core.requires = ok, Not_Ok\n").unwrap_err(), ManifestError::BadValue(1));
    assert_eq!(p("core.exports = bad name\n").unwrap_err(), ManifestError::BadValue(1));
    let many: String = (0..33).map(|i| std::format!("core.requires = cap{}\n", i)).collect();
    assert_eq!(p(&many).unwrap_err(), ManifestError::Limit(33));
    // 先报告第一处出错的行，各行合法后才检查缺失
    assert_eq!(p("core.name = A\njunk\n").unwrap_err(), ManifestError::BadValue(1));
    let text = std::format!("{}core.lifecycle = system\nx.k = v\n", BASE);
    let m = p(&text).unwrap();
    assert_eq!((m.lifecycle, m.extension("x.k"), m.extension("core.name")), (Lifecycle::System, Some("v"), None));
    assert_eq!(m.requires().count(), 0);
}

#[test]
fn version_ranges_and_dependencies() {
    let r = VersionRange::parse(">=0.1,<0.2").unwrap();
    assert!(r.contains((0, 1, 0)) && r.contains((0, 1, 99)) && !r.contains((0, 2, 0)) && !r.contains((0, 0, 9)));
    assert!(VersionRange::parse("=1.2.3").unwrap().contains((1, 2, 3)));
    assert!(!VersionRange::parse(">1.2").unwrap().contains((1, 2, 0)));
    assert!(VersionRange::parse("<=1.2").unwrap().contains((1, 2, 0)));
    for bad in ["", "1.2", ">= 1.2", ">=1", ">=1.2.3.4", ">=a.b", ">=1.0,", ">=1,<2,>3,<4,=5", "~1.0"] {
        assert!(VersionRange::parse(bad).is_none(), "{:?}", bad);
    }
    assert!(VersionRange::parse(">=1.0,<2.0,>1.1,<1.9").is_some()); // 恰好 4 个
    const BASE: &str = "core.name = a\ncore.version = 0.0.1\ncore.abi = c.v1\ncore.stage = runtime\n";
    // 只取错误（不借用临时文本）
    let p = |extra: &str| Manifest::parse(&std::format!("{}{}", BASE, extra)).map(|_| ());
    let text = std::format!("{}core.depends = jaso-log@>=1.0,<2.0, jaso-fmt\ncore.depends = jaso-x@=0.3\ncore.runtime = >=0.1,<0.2\n", BASE);
    let m = Manifest::parse(&text).unwrap();
    let d: Vec<_> = m.depends().collect();
    assert_eq!(d.iter().map(|d| d.name).collect::<Vec<_>>(), ["jaso-log", "jaso-fmt", "jaso-x"]);
    assert!(d[0].range.unwrap().contains((1, 5, 0)) && !d[0].range.unwrap().contains((2, 0, 0)));
    assert_eq!(d[1].range, None);
    assert!(m.runtime.unwrap().contains((0, 1, 0)));
    assert_eq!(p("core.depends = a, a\n").unwrap_err(), ManifestError::Duplicate(5));
    assert_eq!(p("core.depends = a\ncore.depends = b@>1.0, a\n").unwrap_err(), ManifestError::Duplicate(6));
    for bad in ["core.depends = \n", "core.depends = a,\n", "core.depends = >=1.0\n", "core.depends = a, >=1.0\n", "core.depends = A\n", "core.depends = a@1.0\n"] {
        assert_eq!(p(bad).unwrap_err(), ManifestError::BadValue(5), "{:?}", bad);
    }
    assert_eq!(p("core.runtime = 0.1\n").unwrap_err(), ManifestError::BadValue(5));
    assert_eq!(p("core.runtime = >=0.1\ncore.runtime = >=0.1\n").unwrap_err(), ManifestError::Duplicate(6));
    let many: String = (0..33).map(|i| std::format!("core.depends = m{}\n", i)).collect();
    assert_eq!(p(&many).unwrap_err(), ManifestError::Limit(37));
    depends_uniqueness_window(&p);
}

/// 重名只在前 32 项内检查，超出上限的项仍校验取值（SPEC §12.1）。
fn depends_uniqueness_window(p: &dyn Fn(&str) -> Result<(), ManifestError>) {
    let line = |names: &[String]| std::format!("core.depends = {}\n", names.join(", "));
    let mut names: Vec<String> = (0..32).map(|i| std::format!("m{}", i)).collect();
    assert_eq!(p(&line(&names)), Ok(()));
    // 第 32 项与第 1 项重名：仍在窗口内
    names[31] = "m0".into();
    assert_eq!(p(&line(&names)), Err(ManifestError::Duplicate(5)));
    names[31] = "m31".into();
    // 第 33 项超出上限：即使重名也只报上限
    names.push("m0".into());
    assert_eq!(p(&line(&names)), Err(ManifestError::Limit(5)));
    // 超出上限的行里，后面的坏项优先于上限
    names.push("BAD".into());
    assert_eq!(p(&line(&names)), Err(ManifestError::BadValue(5)));
}

/// 回归：一行百万项的未验证清单必须线性解析完（旧实现按项重扫，这里要跑数小时）。
#[test]
fn depends_scan_is_linear_in_entries() {
    let names: Vec<String> = (0..1_000_000).map(|i| std::format!("m{}", i)).collect();
    let text = std::format!("{}core.depends = {}\n", "core.name = a\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\n", names.join(","));
    assert_eq!(Manifest::parse(&text).unwrap_err(), ManifestError::Limit(5));
}

#[test]
fn manifest_cross_checks() {
    // core.stage 与头部不符
    let mut b = sample();
    b.manifest = MANIFEST.replace("core.stage = runtime", "core.stage = boot").into_bytes();
    assert_eq!(b.finish().unwrap_err(), JasoError::ManifestStage);
    // core.abi 与平台记录不符
    let mut b = sample();
    b.platform.abi = Some(b"c.v2".to_vec());
    assert_eq!(b.finish().unwrap_err(), JasoError::PlatformAbi);
    // 清单不是 UTF-8
    let mut b = sample();
    b.manifest = vec![0xFF, 0xFE];
    assert_eq!(b.finish().unwrap_err(), JasoError::Manifest(ManifestError::NotUtf8));
    // 清单错误先于导出声明
    let mut b = sample();
    b.manifest = MANIFEST.replace("core.version = 1.2.3", "core.version = x").into_bytes();
    b.exports.pop();
    assert_eq!(b.finish().unwrap_err(), JasoError::Manifest(ManifestError::BadValue(3)));
}

#[test]
fn extensions() {
    // 未知非关键扩展：跳过但保留
    let mut b = sample();
    b.extensions = vec![ExtensionIn { name: b"ui.layout".to_vec(), version: 3, critical: false, content: vec![1, 2, 3] }];
    let ok = b.finish().unwrap();
    let f = Jaso::parse(&ok).unwrap();
    let e = f.extensions().next().unwrap();
    assert_eq!((e.name, e.version, e.critical, e.content, e.is_known()), ("ui.layout", 3, false, &[1u8, 2, 3][..], false));
    assert_eq!(Builder::from_file(&f, 0).unwrap().finish().unwrap(), ok);
    // 未知关键扩展
    b.extensions[0].critical = true;
    assert_eq!(b.finish().unwrap_err(), JasoError::ExtensionCritical);
    // 已知名字的未知版本：非关键跳过、关键拒绝
    let mut b = sample();
    b.extensions = vec![ExtensionIn { version: 2, critical: false, ..import_ext() }];
    assert!(b.finish().is_ok());
    b.extensions[0].critical = true;
    assert_eq!(b.finish().unwrap_err(), JasoError::ExtensionCritical);
    // 保留名的关键标志不对
    let mut b = sample();
    b.extensions = vec![ExtensionIn { critical: false, ..import_ext() }];
    assert_eq!(b.finish().unwrap_err(), JasoError::ExtensionMalformed);
    let mut b = sample();
    b.extensions = vec![ExtensionIn { name: EXT_JASPER_SOURCE.as_bytes().to_vec(), version: 1, critical: true, content: vec![] }];
    assert_eq!(b.finish().unwrap_err(), JasoError::ExtensionMalformed);
    // 同名
    let mut b = sample();
    b.extensions = vec![import_ext(), ExtensionIn { version: 7, critical: false, ..import_ext() }];
    assert_eq!(b.finish().unwrap_err(), JasoError::ExtensionDuplicate);
    // 布局：名字无 '.'、字符集、长度、版本 0、填充非零、目录 flags 的其它位
    for (name, version) in [(&b"nodot"[..], 1), (b"Up.case", 1), (b"", 1), (&[b'a'; 65][..], 1), (b"ok.name", 0)] {
        let mut b = sample();
        b.extensions = vec![ExtensionIn { name: name.to_vec(), version, critical: false, content: vec![] }];
        assert_eq!(b.finish().unwrap_err(), JasoError::ExtensionMalformed, "{:?}", name);
    }
    let mut b = sample();
    b.extensions = vec![ExtensionIn { name: b"ab.c".to_vec(), version: 1, critical: false, content: vec![] }];
    let ok = b.finish().unwrap();
    assert_eq!(with_byte(&ok, 8, 8 + 4, 1), JasoError::ExtensionMalformed); // 填充
    assert_eq!(with_byte(&ok, 8, 6, 1), JasoError::ExtensionMalformed); // 保留
    assert_eq!(with_dir(&ok, 8, 1, 2), JasoError::BadSectionDir);
    assert_eq!(with_dir(&ok, 8, 3, 7), JasoError::ExtensionMalformed); // 短于头部
}

#[test]
fn source_extension_v1_envelope_is_validated_and_decoded() {
    let text = b"module source_demo\n";
    let content = crate::source::encode(
        crate::source::LANGUAGE_JASPER,
        crate::source::COMPRESSION_NONE,
        text.len() as u32,
        text,
    )
    .unwrap();
    let mut b = sample();
    b.extensions = vec![ExtensionIn {
        name: EXT_JASPER_SOURCE.as_bytes().to_vec(),
        version: 1,
        critical: false,
        content,
    }];
    let bytes = b.finish().unwrap();
    let file = Jaso::parse(&bytes).unwrap();
    let source = file.source_v1().unwrap();
    assert_eq!(source.language(), crate::source::LANGUAGE_JASPER);
    assert_eq!(
        source.decode(|_, _| None).unwrap().as_bytes(),
        text,
        "uncompressed source must be borrowed from the container"
    );

    let mut broken = bytes.clone();
    let ext = Jaso::parse(&bytes)
        .unwrap()
        .extension(EXT_JASPER_SOURCE, 1)
        .unwrap();
    let at = ext.content.as_ptr() as usize - bytes.as_ptr() as usize;
    broken[at] ^= 1;
    let digest = crate::digest_of(&broken);
    broken[crate::DIGEST_OFFSET..crate::DIGEST_OFFSET + 32].copy_from_slice(&digest);
    assert_eq!(
        Jaso::parse(&broken).unwrap_err(),
        JasoError::ExtensionMalformed
    );
}

#[test]
fn hybrid_requires_jasper_import() {
    let ok = hybrid().finish().unwrap();
    let f = Jaso::parse(&ok).unwrap();
    assert_eq!(f.kind, ModuleKind::Hybrid);
    assert_eq!(f.extension(EXT_JASPER_IMPORT, 1).map(|e| e.content), Some(&b"fn f_one()"[..]));
    let mut b = hybrid();
    b.extensions.clear();
    assert_eq!(b.finish().unwrap_err(), JasoError::ExtensionRequired);
    // 原生文件也可以带 jasper.import（非必需）
    let mut b = sample();
    b.extensions = vec![import_ext()];
    assert!(b.finish().is_ok());
}

#[test]
fn managed_images() {
    let ok = managed().finish().unwrap();
    let f = Jaso::parse(&ok).unwrap();
    assert_eq!((f.kind, f.arch), (ModuleKind::Managed, None));
    let img = f.image(0).unwrap();
    assert_eq!((img.kind, img.image_size, img.platform.isa, img.platform.target), (ImageKind::Managed, 0, None, Target::Jvm));
    assert_eq!(img.code().map(|c| (c.format, c.payload)), Some((CODE_JVM_CLASSES, &b"PK\x03\x04 class archive"[..])));
    assert_eq!(img.export("demo.Main.run").map(|e| (e.kind, e.value)), Some((EXPORT_MANAGED, 0)));
    assert_eq!(Builder::from_file(&f, 0).unwrap().finish().unwrap(), ok);
    // 目录：0 清单、1 平台、2 镜像索引、3 代码段、4 导出
    assert_eq!(with_byte(&ok, 3, 0, 2), JasoError::BadCode);
    assert_eq!(with_byte(&ok, 3, 4, 1), JasoError::BadCode);
    assert_eq!(with_dir(&ok, 3, 3, 8), JasoError::BadCode); // 载荷为空
    assert_eq!(with_byte(&ok, 4, 4 + 8, 1), JasoError::BadExports); // value ≠ 0
    assert_eq!(with_byte(&ok, 4, 4 + 12, EXPORT_FUNC as u8), JasoError::BadExports);
    assert_eq!(edit(&ok, |b| { let o = section_offset(b, 2) + 20; put32(b, o, PAGE) }), JasoError::BadImageSize);
    assert_eq!(edit(&ok, |b| b[12] = 1), JasoError::PlatformArch); // 头部指令集 ≠ any
    // 托管镜像里不得有映像段
    let mut b = managed();
    b.segments = vec![SegmentIn { vaddr: 0, mem_size: 1, flags: FLAG_R, data: vec![0] }];
    assert_eq!(b.finish().unwrap_err(), JasoError::ImageIndex);
    // 没有代码段
    let mut b = managed();
    b.code = None;
    assert_eq!(b.finish().unwrap_err(), JasoError::ImageIndex);
}

/// 两个镜像：手工在单镜像文件后追加第二个镜像的段与索引项，验证读取器兼容这一历史构造。
fn two_images(second: Arch) -> Vec<u8> {
    let one = sample().finish().unwrap();
    let f = Jaso::parse(&one).unwrap();
    let mut b = Builder::from_file(&f, 0).unwrap();
    b.platform.isa = Some(second);
    let other = b.finish().unwrap();
    // 第二个文件的平台记录与镜像段（3–7）搬进第一个文件
    let count = get32(&one, 20) as usize;
    let rec = |file: &[u8]| file[section_offset(file, 1) + 8..section_offset(file, 1) + 8 + 64].to_vec();
    let mut bodies: Vec<(Vec<u8>, Vec<u8>)> = Vec::new(); // (目录项, 内容)
    let take = |file: &[u8], i: usize| {
        let d = file[HEADER_SIZE + i * SECTION_SIZE..HEADER_SIZE + (i + 1) * SECTION_SIZE].to_vec();
        let (o, n) = (get32(&d, 8) as usize, get32(&d, 12) as usize);
        (d, file[o..o + n].to_vec())
    };
    for i in 0..count {
        bodies.push(take(&one, i));
    }
    let mut platforms = vec![0u8; 8];
    put32(&mut platforms, 0, 2);
    platforms.extend(rec(&one));
    platforms.extend(rec(&other));
    bodies[1].1 = platforms;
    let mut index = bodies[2].1.clone();
    put32(&mut index, 0, 2);
    let mut e2 = index[8..40].to_vec();
    e2[2] = 1; // 平台 1
    put32(&mut e2, 4, count as u32);
    put32(&mut e2, 8, 5);
    index.extend(e2);
    bodies[2].1 = index;
    for i in 3..8 {
        bodies.push(take(&other, i));
    }
    let mut out = one[..HEADER_SIZE].to_vec();
    put32(&mut out, 20, bodies.len() as u32);
    let mut off = HEADER_SIZE + bodies.len() * SECTION_SIZE;
    for (d, c) in &bodies {
        let mut d = d.clone();
        put32(&mut d, 8, off as u32);
        put32(&mut d, 12, c.len() as u32);
        out.extend(d);
        off += c.len();
    }
    for (_, c) in &bodies {
        out.extend(c);
    }
    out[12] = 0; // 两种指令集：any
    let n = out.len() as u32;
    put32(&mut out, 28, n);
    digest_fix(&mut out);
    out
}

#[test]
fn multiple_images_and_selection() {
    let two = two_images(Arch::Aarch64);
    let f = Jaso::parse(&two).expect("双镜像文件应合法");
    assert_eq!(f.images().count(), 2);
    let host = |isa| HostPlatform { isa: Some(isa), isa_ext: &[], target: Target::JasperOs, pointer_bytes: 8, float_abi: FloatAbi::Soft, abi: ABI_C_V1 };
    assert_eq!(f.select(&host(Arch::X86_64)).unwrap().index, 0);
    assert_eq!(f.select(&host(Arch::Aarch64)).unwrap().index, 1);
    // 都不符：报告镜像 0 的第一个不符字段
    let m = f.select(&host(Arch::Riscv64)).unwrap_err();
    assert_eq!((m.field, m.expected.as_str(), m.actual.as_str()), (PlatformField::Isa, "riscv64", "x86_64"));
    // 头部 arch 指定为其中一种：另一个镜像与之不符
    assert_eq!(edit(&two, |b| b[12] = 1), JasoError::PlatformArch);
    // 两个镜像引用同一平台记录但映像大小不同：选择会有歧义
    assert_eq!(edit(&two, |b| {
        let o = section_offset(b, 2) + 8 + 32;
        b[o + 2] = 0;
        put32(b, o + 12, 6 * PAGE);
    }), JasoError::ImageIndex);
    // 区间重叠
    assert_eq!(edit(&two, |b| { let o = section_offset(b, 2) + 8 + 32 + 4; put32(b, o, 4) }), JasoError::ImageIndex);
}

#[test]
fn multi_image_builder_writes_selects_and_preserves_all_images() {
    let mut multi = MultiBuilder::native(Stage::Runtime, MANIFEST.as_bytes());
    for arch in [Arch::X86_64, Arch::Aarch64, Arch::Riscv64, Arch::Riscv32] {
        let mut image = sample();
        image.platform = PlatformIn::jasper_os(arch);
        multi.push_image(image).unwrap();
    }
    let bytes = multi.finish().expect("four-image container");
    let file = Jaso::parse(&bytes).expect("parse four-image container");
    assert_eq!(file.images().count(), 4);
    assert_eq!(file.arch, None);
    for arch in [Arch::X86_64, Arch::Aarch64, Arch::Riscv64, Arch::Riscv32] {
        let host = HostPlatform {
            isa: Some(arch),
            isa_ext: &[],
            target: Target::JasperOs,
            pointer_bytes: arch.pointer_bytes() as u8,
            float_abi: FloatAbi::Soft,
            abi: ABI_C_V1,
        };
        assert_eq!(file.select(&host).unwrap().platform.isa, Some(arch));
    }
    assert_eq!(
        MultiBuilder::from_file(&file).unwrap().finish().unwrap(),
        bytes,
        "parsed containers must round-trip without losing images"
    );
}

#[test]
fn multi_image_builder_rejects_mixed_manifest_and_section_budget() {
    let mut multi = MultiBuilder::native(Stage::Runtime, MANIFEST.as_bytes());
    multi.push_image(sample()).unwrap();
    let mut different = sample();
    different.manifest = MANAGED_MANIFEST.as_bytes().to_vec();
    assert_eq!(multi.push_image(different), Err(JasoError::ImageIndex));

    let mut image = sample();
    image.platform.isa = Some(Arch::Aarch64);
    multi.push_image(image).unwrap();
    let mut too_many = MultiBuilder::native(Stage::Runtime, MANIFEST.as_bytes());
    for _ in 0..MAX_IMAGES {
        too_many.push_image(sample()).unwrap();
    }
    assert_eq!(too_many.push_image(sample()), Err(JasoError::ImageIndex));
}

#[test]
fn multi_image_resign_and_hybrid_keep_every_image() {
    let mut multi = MultiBuilder::native(Stage::Runtime, MANIFEST.as_bytes());
    for arch in [Arch::X86_64, Arch::Aarch64, Arch::Riscv64, Arch::Riscv32] {
        let mut image = sample();
        image.platform = PlatformIn::jasper_os(arch);
        multi.push_image(image).unwrap();
    }
    let bytes = multi.finish().unwrap();
    let signer = crate::pack::signer_from_phrase(b"multi-image-test");
    let signed = crate::pack::sign(&bytes, &signer).unwrap();
    let parsed = Jaso::parse(&signed).unwrap();
    assert_eq!(parsed.images().count(), 4);
    assert!(parsed.signature().is_some());

    let hybrid = crate::pack::to_hybrid(&bytes, b"fn f_one(): Unit\nfn f_two(): Unit\n").unwrap();
    let parsed = Jaso::parse(&hybrid).unwrap();
    assert_eq!(parsed.kind, ModuleKind::Hybrid);
    assert_eq!(parsed.images().count(), 4);
    assert!(parsed.extension(EXT_JASPER_IMPORT, 1).is_some());
}

#[test]
fn platform_mismatch_field_order() {
    let ok = sample().finish().unwrap();
    let f = Jaso::parse(&ok).unwrap();
    let base = HostPlatform { isa: Some(Arch::X86_64), isa_ext: &[], target: Target::JasperOs, pointer_bytes: 8, float_abi: FloatAbi::Soft, abi: ABI_C_V1 };
    assert!(f.select(&base).is_ok());
    let field = |h: HostPlatform<'_>| f.select(&h).unwrap_err().field;
    assert_eq!(field(HostPlatform { target: Target::Host, ..base }), PlatformField::Target);
    assert_eq!(field(HostPlatform { abi: "c.v0", ..base }), PlatformField::Abi);
    assert_eq!(field(HostPlatform { float_abi: FloatAbi::Hard, ..base }), PlatformField::FloatAbi);
    assert_eq!(field(HostPlatform { pointer_bytes: 4, ..base }), PlatformField::PointerBytes);
    assert_eq!(field(HostPlatform { isa: None, target: Target::Host, ..base }), PlatformField::Isa);
    // isa_ext：文件要求的每个记号宿主都必须有
    let mut b = sample();
    b.platform.isa_ext = b"avx2,bmi2".to_vec();
    let ext = b.finish().unwrap();
    let f = Jaso::parse(&ext).unwrap();
    let m = f.select(&HostPlatform { isa_ext: &["avx2"], ..base }).unwrap_err();
    assert_eq!((m.field, m.actual.as_str()), (PlatformField::IsaExt, "bmi2"));
    assert!(f.select(&HostPlatform { isa_ext: &["bmi2", "sse4", "avx2"], ..base }).is_ok());
    assert_eq!(HostPlatform::jasper_os_native().map(|h| (h.target, h.float_abi, h.abi)), Some((Target::JasperOs, FloatAbi::Soft, ABI_C_V1)));
}

#[test]
fn error_code_table() {
    assert_eq!(ErrorCode::ALL.len(), 52);
    for (i, c) in ErrorCode::ALL.iter().enumerate() {
        assert_eq!(ErrorCode::from_name(c.name()), Some(*c));
        assert_eq!(ErrorCode::from_number(c.number()), Some(*c));
        assert!(ErrorCode::ALL[..i].iter().all(|p| p.number() < c.number() && p.name() != c.name()));
        assert!(c.name().contains('.'));
    }
    assert_eq!(ErrorCode::ALL.iter().filter(|c| c.is_load()).count(), 10);
    assert_eq!(JasoError::WriteExecute.code().name(), "image.wx");
    assert_eq!(JasoError::Manifest(ManifestError::Limit(3)).code().number(), 407);
    assert_eq!(crate::trust::TrustError::UnknownPublisher.code(), ErrorCode::TrustPublisher);
    // 静态错误都不是 load 类
    for e in [JasoError::Truncated, JasoError::PlatformAbi, JasoError::ExtensionRequired, JasoError::BadSignatureSection] {
        assert!(!e.code().is_load());
    }
}

/// 一个 format 0 文件：按 format 0 布局手工写出（format 0 头部偏移 32 为映像大小）。
fn format0() -> Vec<u8> {
    let m = b"core.name = old.mod\ncore.version = 0.1.0\ncore.abi = c.v0\ncore.exports = f_one\n".to_vec();
    let mut exports = vec![0u8; 4 + 16];
    put32(&mut exports, 0, 1);
    put32(&mut exports, 4, 20);
    put32(&mut exports, 8, 5);
    put32(&mut exports, 12, PAGE);
    put32(&mut exports, 16, EXPORT_FUNC);
    exports.extend_from_slice(b"f_one");
    let bodies: [(u32, u32, u32, u32, Vec<u8>); 3] =
        [(1, 0, 0, 0, m), (2, FLAG_R | FLAG_X, PAGE, 16, vec![0xC3; 16]), (3, 0, 0, 0, exports)];
    let mut out = vec![0u8; HEADER_SIZE];
    out[..8].copy_from_slice(&MAGIC);
    (out[10], out[12], out[14]) = (1, 1, Stage::Boot as u8);
    put32(&mut out, 16, HEADER_SIZE as u32);
    put32(&mut out, 20, 3);
    put32(&mut out, 24, HEADER_SIZE as u32);
    put32(&mut out, 32, 2 * PAGE);
    let mut off = HEADER_SIZE + 3 * SECTION_SIZE;
    for (k, fl, va, mem, c) in &bodies {
        let mut d = vec![0u8; SECTION_SIZE];
        for (i, v) in [*k, *fl, off as u32, c.len() as u32, *va, *mem].into_iter().enumerate() {
            put32(&mut d, i * 4, v);
        }
        out.extend(d);
        off += c.len();
    }
    for (.., c) in &bodies {
        out.extend(c);
    }
    let n = out.len() as u32;
    put32(&mut out, 28, n);
    digest_fix(&mut out);
    out
}

#[test]
fn migrate_format0() {
    let old = format0();
    assert_eq!(parse_err(&old), JasoError::UnsupportedVersion(0));
    let new = crate::migrate::from_v0(&old).unwrap();
    let f = Jaso::parse(&new).unwrap();
    assert_eq!((f.stage, f.manifest.stage, f.manifest.name, f.manifest.abi), (Stage::Boot, Stage::Boot, "old.mod", "c.v0"));
    let img = f.image(0).unwrap();
    assert_eq!((img.image_size, img.platform.abi), (2 * PAGE, "c.v0"));
    assert_eq!(img.export("f_one").map(|e| e.value), Some(PAGE));
    // 旧调用约定原样保留：只认 c.v1 的宿主按 abi 不符拒绝
    let native = HostPlatform { isa: Some(Arch::X86_64), isa_ext: &[], target: Target::JasperOs, pointer_bytes: 8, float_abi: FloatAbi::Soft, abi: ABI_C_V1 };
    assert_eq!(f.select(&native).unwrap_err().field, PlatformField::Abi);
    // format 1 文件、损坏的 format 0 文件不能迁移
    use crate::migrate::MigrateError;
    assert!(matches!(crate::migrate::from_v0(&new), Err(MigrateError::NotFormat0(_))));
    let mut bad = old.clone();
    bad[100] ^= 1;
    assert!(matches!(crate::migrate::from_v0(&bad), Err(MigrateError::NotFormat0(_))));
    for cut in [0, 10, HEADER_SIZE, old.len() - 1] {
        assert!(crate::migrate::from_v0(&old[..cut]).is_err());
    }
}

#[test]
fn arch_and_stage_names() {
    for a in [Arch::X86_64, Arch::Aarch64, Arch::Riscv64, Arch::Riscv32] {
        assert_eq!(Arch::from_name(a.name()), Some(a));
        assert_eq!(Arch::from_u16(a as u16), Some(a));
    }
    for s in [Stage::Runtime, Stage::Boot, Stage::Build] {
        assert_eq!(Stage::from_name(s.name()), Some(s));
    }
    assert_eq!(Arch::from_name("mips"), None);
    assert_eq!(Arch::from_u16(0), None);
}

/// 随机变异：对合法文件随机改写、截断、追加（部分样本回填正确摘要，绕过完整性检查去考验结构校验），
/// 解析器必须给出 Ok 或 Err，绝不 panic；通过校验的结果其迭代器也不得越界。
#[test]
fn random_mutations_never_panic() {
    let seeds = [sample().finish().unwrap(), managed().finish().unwrap(), hybrid().finish().unwrap(), two_images(Arch::Aarch64)];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut accepted = 0;
    let host = HostPlatform::jasper_os_native().unwrap();
    for round in 0..40_000 {
        let mut b = seeds[round % seeds.len()].clone();
        let edits = 1 + next() % 6;
        for _ in 0..edits {
            let r = next();
            match r % 4 {
                0 | 1 => {
                    let i = (next() as usize) % b.len();
                    b[i] = next() as u8;
                }
                2 => {
                    let n = (next() as usize) % b.len();
                    b.truncate(n.max(1));
                }
                _ => b.extend_from_slice(&next().to_le_bytes()),
            }
        }
        if round % 2 == 0 && b.len() >= HEADER_SIZE {
            let n = b.len() as u32;
            if round % 4 == 0 {
                put32(&mut b, 28, n);
            }
            digest_fix(&mut b);
        }
        if let Ok(f) = Jaso::parse(&b) {
            accepted += 1;
            for img in f.images() {
                let _ = img.segments().map(|s| s.data.len()).sum::<usize>();
                let _ = img.exports().count();
                let _ = img.relocs().count();
                let _ = img.code().map(|c| c.payload.len());
            }
            let _ = f.extensions().count();
            let _ = f.select(&host);
            let _ = f.manifest.requires().count() + f.manifest.depends().count();
        }
    }
    assert!(accepted < 4000, "accepted={}", accepted);
}
