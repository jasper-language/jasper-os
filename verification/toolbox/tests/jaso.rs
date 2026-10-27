//! `.jaso` format 1 的属性测试（Proptest，固定种子 + 收缩）：
//! * 随机合格输入构建 → 读取往返一致，由文件还原再写出逐字节相同；
//! * 对合格文件做任意改写并回填长度与摘要，读取只给出 Ok 或静态错误码，从不 panic；
//! * 版本区间与参考求值一致；依赖列表切分与生成时的结构一致。
//! `seed_fuzz_corpus` 把几份合格文件写进入库的 cargo-fuzz 种子目录 `fuzz/seeds/jaso_parse`（内容确定，可重复执行）。
use jaso::build::{Builder, ExtensionIn, PlatformIn, SegmentIn};
use jaso::{Arch, Jaso, Manifest, ModuleKind, Stage, VersionRange, DIGEST_OFFSET, FLAG_R, FLAG_W, FLAG_X, PAGE};
use proptest::prelude::*;

fn manifest(exports: &[String]) -> String {
    let mut m = String::from("core.name = jaso-prop\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\n");
    if !exports.is_empty() {
        m.push_str(&format!("core.exports = {}\n", exports.join(", ")));
    }
    m
}

/// 随机原生模块：1–4 个各占独立页的段（第一个段可执行），若干落在可执行段内的导出，若干落在可写段内的重定位。
fn native() -> impl Strategy<Value = Builder> {
    (1usize..5, proptest::collection::vec(0u32..64, 0..4), proptest::collection::vec(0u8..3, 4), any::<bool>()).prop_map(|(n, offs, kinds, ext)| {
        let mut segs = Vec::new();
        for i in 0..n {
            let flags = if i == 0 { FLAG_R | FLAG_X } else { [FLAG_R, FLAG_R | FLAG_W, FLAG_R | FLAG_W][kinds[i] as usize] };
            segs.push(SegmentIn { vaddr: 2 * i as u32 * PAGE, mem_size: PAGE + 8, flags, data: vec![i as u8; 64] });
        }
        let names: Vec<String> = offs.iter().enumerate().map(|(i, _)| format!("f{}", i)).collect();
        let mut b = Builder::native(Arch::X86_64, Stage::Runtime, manifest(&names).as_bytes());
        b.exports = names.iter().zip(&offs).map(|(name, o)| (name.as_bytes().to_vec(), o * 8)).collect();
        b.relocs = segs.iter().filter(|s| s.flags & FLAG_W != 0).map(|s| (s.vaddr, 0x10)).collect();
        b.segments = segs;
        if ext {
            b.extensions = vec![ExtensionIn { name: b"ui.layout".to_vec(), version: 2, critical: false, content: vec![9; 5] }];
        }
        b
    })
}

fn managed() -> Builder {
    let mut b = Builder::native(Arch::X86_64, Stage::Runtime, b"core.name = jaso-jvm\ncore.version = 0.1.0\ncore.abi = jvm.52\ncore.stage = runtime\n");
    b.kind = ModuleKind::Managed;
    b.platform = PlatformIn::jvm();
    b.code = Some(b"PK\x03\x04".to_vec());
    b
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn build_read_roundtrip(b in native()) {
        let bytes = b.finish().expect("随机合格输入应能构建");
        let f = Jaso::parse(&bytes).unwrap();
        let img = f.image(0).unwrap();
        prop_assert_eq!(img.segments().count(), b.segments.len());
        prop_assert_eq!(img.exports().count(), b.exports.len());
        prop_assert_eq!(img.relocs().count(), b.relocs.len());
        prop_assert_eq!(img.image_size, b.image_size());
        prop_assert_eq!(Builder::from_file(&f, 0).unwrap().finish().unwrap(), bytes);
    }

    #[test]
    fn edited_files_never_panic(b in native(), edits in proptest::collection::vec((any::<u16>(), any::<u8>()), 1..6)) {
        let mut bytes = b.finish().unwrap();
        for (at, v) in edits {
            let i = at as usize % bytes.len();
            bytes[i] = v;
        }
        let n = bytes.len() as u32;
        bytes[28..32].copy_from_slice(&n.to_le_bytes());
        let d = jaso::digest_of(&bytes);
        bytes[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
        match Jaso::parse(&bytes) {
            Ok(f) => {
                for img in f.images() {
                    prop_assert!(img.segments().all(|s| s.data.len() as u32 <= s.mem_size));
                }
            }
            Err(e) => prop_assert!(!e.code().is_load()),
        }
    }

    #[test]
    fn version_range_matches_reference(ops in proptest::collection::vec((0usize..5, 0u32..4, 0u32..4), 1..5), v in (0u32..4, 0u32..4, 0u32..4)) {
        const OPS: [&str; 5] = [">=", ">", "<=", "<", "="];
        let text: Vec<String> = ops.iter().map(|(o, a, b)| format!("{}{}.{}", OPS[*o], a, b)).collect();
        let r = VersionRange::parse(&text.join(",")).unwrap();
        let want = ops.iter().all(|&(o, a, b)| {
            let w = (a, b, 0);
            match o { 0 => v >= w, 1 => v > w, 2 => v <= w, 3 => v < w, _ => v == w }
        });
        prop_assert_eq!(r.contains(v), want);
    }

    #[test]
    fn dependency_lists_split_as_written(deps in proptest::collection::vec(proptest::option::of((0u32..9, 1u32..9)), 1..6)) {
        let items: Vec<String> = deps.iter().enumerate().map(|(i, d)| match d {
            Some((a, b)) => format!("jaso-d{}@>={}.0,<{}.0", i, a, a + b),
            None => format!("jaso-d{}", i),
        }).collect();
        let text = format!("core.name = a\ncore.version = 1.0.0\ncore.abi = c.v1\ncore.stage = runtime\ncore.depends = {}\n", items.join(", "));
        let m = Manifest::parse(&text).unwrap();
        let got: Vec<_> = m.depends().collect();
        prop_assert_eq!(got.len(), deps.len());
        for (i, (g, d)) in got.iter().zip(&deps).enumerate() {
            prop_assert_eq!(g.name, format!("jaso-d{}", i));
            prop_assert_eq!(g.range.is_some(), d.is_some());
            if let (Some(r), Some((a, b))) = (g.range, d) {
                prop_assert!(r.contains((*a, 0, 0)) && !r.contains((a + b, 0, 0)));
            }
        }
    }
}

#[test]
fn managed_roundtrip() {
    let bytes = managed().finish().unwrap();
    let f = Jaso::parse(&bytes).unwrap();
    assert_eq!(f.image(0).unwrap().code().map(|c| c.payload), Some(&b"PK\x03\x04"[..]));
}

#[test]
fn seed_fuzz_corpus() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/jaso_parse");
    std::fs::create_dir_all(&dir).unwrap();
    let mut b = Builder::native(Arch::X86_64, Stage::Runtime, manifest(&["f0".into()]).as_bytes());
    b.segments = vec![
        SegmentIn { vaddr: 0, mem_size: 64, flags: FLAG_R | FLAG_X, data: vec![0xC3; 64] },
        SegmentIn { vaddr: PAGE, mem_size: 16, flags: FLAG_R | FLAG_W, data: vec![0; 16] },
    ];
    b.exports = vec![(b"f0".to_vec(), 0)];
    b.relocs = vec![(PAGE, 8)];
    let native = b.finish().unwrap();
    b.kind = ModuleKind::Hybrid;
    b.extensions = vec![ExtensionIn { name: b"jasper.import".to_vec(), version: 1, critical: true, content: b"f0".to_vec() }];
    let hybrid = b.finish().unwrap();
    for (name, bytes) in [("native.jaso", native), ("hybrid.jaso", hybrid), ("managed.jaso", managed().finish().unwrap())] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}
