//! 宿主测试：构建 → 解析往返、每一类拒绝、清单规则、随机变异输入不 panic。

extern crate std;

use std::vec;
use std::vec::Vec;

use crate::build::{Builder, SegmentIn};
use crate::*;

const MANIFEST: &str = "# 测试模块\ncore.name = demo.mod\ncore.version = 1.2.3\ncore.abi = c.v0\ncore.host = jaso.host.v0\n\
core.requires = system.console.write, system.memory.map\ncore.requires = system.time.now\nweb.route = /x\n";

fn sample() -> Builder {
    Builder {
        arch: Arch::X86_64,
        stage: Stage::Runtime,
        manifest: MANIFEST.as_bytes().to_vec(),
        segments: vec![
            SegmentIn { vaddr: 0, mem_size: 100, flags: FLAG_R, data: vec![7; 100] },
            SegmentIn { vaddr: PAGE, mem_size: 64, flags: FLAG_R | FLAG_X, data: vec![0xC3; 64] },
            SegmentIn { vaddr: 2 * PAGE, mem_size: 2 * PAGE + 1, flags: FLAG_R | FLAG_W, data: vec![0; 16] },
        ],
        exports: vec![(b"f_one".to_vec(), PAGE), (b"f_two".to_vec(), PAGE + 8)],
        relocs: vec![(2 * PAGE, 0x10), (2 * PAGE + 8, PAGE as u64)],
    }
}

fn digest_fix(b: &mut [u8]) {
    let d = digest_of(b);
    b[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
}

#[test]
fn roundtrip() {
    let bytes = sample().finish().expect("build");
    let img = Image::parse(&bytes).expect("parse");
    assert_eq!(img.arch, Arch::X86_64);
    assert_eq!(img.stage, Stage::Runtime);
    assert_eq!(img.image_size, 5 * PAGE);
    assert_eq!(img.manifest.name, "demo.mod");
    assert_eq!(img.manifest.version, (1, 2, 3));
    assert_eq!(img.manifest.host, Some(HOST_V0));
    let req: Vec<&str> = img.manifest.requires().collect();
    assert_eq!(req, ["system.console.write", "system.memory.map", "system.time.now"]);
    assert_eq!(img.manifest.extension("web.route"), Some("/x"));
    assert_eq!(img.segments().count(), 3);
    assert_eq!(img.export("f_two").map(|e| e.value), Some(PAGE + 8));
    assert!(img.export("missing").is_none());
    assert_eq!(img.relocs().count(), 2);
}

#[test]
fn any_changed_byte_breaks_the_digest() {
    let bytes = sample().finish().unwrap();
    for i in (0..bytes.len()).filter(|i| !(DIGEST_OFFSET..DIGEST_OFFSET + 32).contains(i)) {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(Image::parse(&b).is_err(), "改动第 {} 字节后仍通过", i);
    }
    // 只改摘要本身也被发现
    let mut b = bytes.clone();
    b[DIGEST_OFFSET] ^= 0x80;
    assert_eq!(Image::parse(&b).unwrap_err(), JasoError::DigestMismatch);
}

#[test]
fn header_rejections() {
    let good = sample().finish().unwrap();
    let mut b = good.clone();
    b.truncate(HEADER_SIZE - 1);
    assert_eq!(Image::parse(&b).unwrap_err(), JasoError::Truncated);
    let set = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = good.clone();
        f(&mut b);
        digest_fix(&mut b);
        Image::parse(&b).unwrap_err()
    };
    assert_eq!(set(&|b| b[0] = 0), JasoError::BadMagic);
    assert_eq!(set(&|b| b[8] = 1), JasoError::UnsupportedVersion(1));
    assert_eq!(set(&|b| b[10] = 2), JasoError::UnsupportedKind(2));
    assert_eq!(set(&|b| b[12] = 9), JasoError::UnknownArch(9));
    assert_eq!(set(&|b| b[14] = 7), JasoError::UnknownStage(7));
    assert_eq!(set(&|b| b[15] = 1), JasoError::BadHeader);
    assert_eq!(set(&|b| b[16] = 81), JasoError::BadHeader);
    assert_eq!(set(&|b| b[72] = 1), JasoError::BadHeader);
    assert_eq!(set(&|b| b.push(0)), JasoError::LengthMismatch);
    assert_eq!(set(&|b| b[32..36].copy_from_slice(&(PAGE + 1).to_le_bytes())), JasoError::BadImageSize);
    assert_eq!(set(&|b| b[32..36].copy_from_slice(&(MAX_IMAGE + PAGE).to_le_bytes())), JasoError::BadImageSize);
    assert_eq!(set(&|b| b[20..24].copy_from_slice(&1000u32.to_le_bytes())), JasoError::BadSectionDir);
    assert_eq!(set(&|b| b[24..28].copy_from_slice(&8u32.to_le_bytes())), JasoError::BadSectionDir);
    // 映像大小比段所需的小
    assert_eq!(set(&|b| b[32..36].copy_from_slice(&(2 * PAGE).to_le_bytes())), JasoError::BadSegment);
}

/// 修改段目录第 `i` 项的第 `field` 个 u32（kind=0 flags=1 off=2 size=3 vaddr=4 mem=5）。
fn with_dir(good: &[u8], i: usize, field: usize, v: u32) -> JasoError {
    let mut b = good.to_vec();
    let o = HEADER_SIZE + i * SECTION_SIZE + field * 4;
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    digest_fix(&mut b);
    Image::parse(&b).unwrap_err()
}

#[test]
fn section_rejections() {
    let good = sample().finish().unwrap();
    // 段目录顺序：0 清单、1–3 映像段、4 导出、5 重定位
    assert_eq!(with_dir(&good, 0, 0, 9), JasoError::UnknownSection(9));
    assert_eq!(with_dir(&good, 0, 1, 1), JasoError::BadSectionDir);
    assert_eq!(with_dir(&good, 4, 0, 1), JasoError::DuplicateSection(1));
    assert_eq!(with_dir(&good, 0, 0, 3), JasoError::DuplicateSection(3));
    assert_eq!(with_dir(&good, 2, 3, u32::MAX), JasoError::SectionOutOfFile);
    assert_eq!(with_dir(&good, 2, 2, 4), JasoError::SectionOutOfFile);
    assert_eq!(with_dir(&good, 1, 1, FLAG_W), JasoError::BadSegment); // 不可读
    assert_eq!(with_dir(&good, 1, 1, 8 | FLAG_R), JasoError::BadSegment); // 未知标志
    assert_eq!(with_dir(&good, 2, 1, FLAG_R | FLAG_W | FLAG_X), JasoError::WriteExecute);
    assert_eq!(with_dir(&good, 2, 4, 1), JasoError::BadSegment); // 未对齐
    assert_eq!(with_dir(&good, 2, 5, 0), JasoError::BadSegment); // mem_size 为 0
    assert_eq!(with_dir(&good, 2, 5, 1), JasoError::BadSegment); // mem_size < file_size
    assert_eq!(with_dir(&good, 2, 4, 0), JasoError::SegmentOverlap);
    assert_eq!(with_dir(&good, 3, 4, 4 * PAGE), JasoError::BadSegment); // 越出映像
    let mut no_seg = sample();
    no_seg.segments.clear();
    no_seg.exports.clear();
    no_seg.relocs.clear();
    // 没有映像段时映像大小为 0：先在大小检查上被拒
    assert_eq!(no_seg.finish().unwrap_err(), JasoError::BadImageSize);
}

#[test]
fn export_and_reloc_rejections() {
    let mut b = sample();
    b.exports.push((b"f_one".to_vec(), PAGE));
    assert_eq!(b.finish().unwrap_err(), JasoError::BadExports); // 重名
    let mut b = sample();
    b.exports[0].0 = b"bad name".to_vec();
    assert_eq!(b.finish().unwrap_err(), JasoError::BadExports);
    let mut b = sample();
    b.exports[0].1 = 0; // 只读段，不是可执行段
    assert_eq!(b.finish().unwrap_err(), JasoError::ExportOutOfRange);
    let mut b = sample();
    b.exports[0].1 = 99 * PAGE;
    assert_eq!(b.finish().unwrap_err(), JasoError::ExportOutOfRange);
    let mut b = sample();
    b.relocs[0].0 = PAGE; // 可执行段
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    let mut b = sample();
    b.relocs[0].0 = 2 * PAGE + 4; // 未对齐
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    let mut b = sample();
    b.relocs[0].1 = 5 * PAGE as u64; // 加数越出映像
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    let mut b = sample();
    b.relocs[0].0 = 5 * PAGE - 4; // 写入越出映像末端
    assert_eq!(b.finish().unwrap_err(), JasoError::RelocOutOfRange);
    // 重定位种类不是 RELATIVE64
    let good = sample().finish().unwrap();
    let img = Image::parse(&good).unwrap();
    let reloc_dir = HEADER_SIZE + 5 * SECTION_SIZE;
    let off = u32::from_le_bytes(good[reloc_dir + 8..reloc_dir + 12].try_into().unwrap()) as usize;
    let mut bad = good.clone();
    bad[off + 4 + 4] = 2;
    digest_fix(&mut bad);
    assert_eq!(Image::parse(&bad).unwrap_err(), JasoError::BadReloc);
    assert_eq!(img.relocs().next().map(|r| r.kind), Some(RELOC_RELATIVE64));
}

#[test]
fn manifest_rules() {
    let p = Manifest::parse;
    assert!(p("core.name = a\ncore.version = 0.0.1\ncore.abi = c.v0\n").is_ok());
    assert_eq!(p("core.version = 0.0.1\ncore.abi = c.v0").unwrap_err(), ManifestError::Missing("core.name"));
    assert_eq!(p("core.name = a\ncore.abi = c.v0").unwrap_err(), ManifestError::Missing("core.version"));
    assert_eq!(p("core.name = a\ncore.version = 1.0.0").unwrap_err(), ManifestError::Missing("core.abi"));
    assert_eq!(p("core.name = A\n").unwrap_err(), ManifestError::BadValue(1));
    assert_eq!(p("core.name = a\ncore.name = b\n").unwrap_err(), ManifestError::Duplicate(2));
    assert_eq!(p("core.name = a\ncore.version = 1.2\n").unwrap_err(), ManifestError::BadValue(2));
    assert_eq!(p("core.name = a\ncore.version = 1.2.3.4\n").unwrap_err(), ManifestError::BadValue(2));
    assert_eq!(p("core.name = a\ncore.version = 1.-2.3\n").unwrap_err(), ManifestError::BadValue(2));
    assert_eq!(p("core.color = red\n").unwrap_err(), ManifestError::BadKey(1));
    assert_eq!(p("nonamespace = 1\n").unwrap_err(), ManifestError::BadKey(1));
    assert_eq!(p("just text\n").unwrap_err(), ManifestError::BadLine(1));
    assert_eq!(p("core.requires = ok, Not_Ok\n").unwrap_err(), ManifestError::BadValue(1));
    let many: std::string::String = (0..33).map(|i| std::format!("core.requires = cap{}\n", i)).collect();
    assert_eq!(p(&many).unwrap_err(), ManifestError::TooManyRequires);
    let m = p("core.name = a\ncore.version = 1.0.0\ncore.abi = c.v0\nx.k = v\n").unwrap();
    assert_eq!(m.extension("x.k"), Some("v"));
    assert_eq!(m.extension("core.name"), None);
    assert_eq!(m.requires().count(), 0);
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
}

/// 随机变异：对合法文件随机改写、截断、追加（部分样本回填正确摘要，绕过完整性检查去考验结构校验），
/// 解析器必须给出 Ok 或 Err，绝不 panic；通过校验的结果其迭代器也不得越界。
#[test]
fn random_mutations_never_panic() {
    let good = sample().finish().unwrap();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut accepted = 0;
    for round in 0..20_000 {
        let mut b = good.clone();
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
            digest_fix(&mut b);
        }
        if let Ok(img) = Image::parse(&b) {
            accepted += 1;
            let _ = img.segments().map(|s| s.data.len()).sum::<usize>();
            let _ = img.exports().count();
            let _ = img.relocs().count();
            let _ = img.manifest.requires().count();
        }
    }
    // 绝大多数变异应被拒绝；接受的必是与原文件等价的少数情形
    assert!(accepted < 2000, "accepted={}", accepted);
}
