//! 一致性向量（SPEC §14）：仓库中的 `jaso/vectors/` 与生成器逐字节一致，每个文件的判定结果与 `.expect` 一致，
//! 且全部错误码与 `ok` 都至少有一个向量。

extern crate std;

use std::collections::BTreeSet;
use std::string::String;
use std::vec::Vec;

use crate::code::ErrorCode;
use crate::conformance::{check, expect_line};
use crate::vectors::{all, dev_key_text, DEV_KEY_FILE};

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

fn parse_key(text: &str) -> [u8; 32] {
    let t = text.trim_end_matches('\n');
    assert_eq!(t.len(), 64, "公钥文件应为 64 个十六进制字符");
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).expect("十六进制");
    }
    k
}

#[test]
fn checked_in_vectors_match_the_generator() {
    let dev = crate::pack::development_signer();
    let key = dev.public_key();
    let d = dir();
    let pub_text = std::fs::read_to_string(d.join(DEV_KEY_FILE)).expect("jasper.dev.pub（运行 jaso/vectors/regen.sh 重建）");
    assert_eq!(pub_text, dev_key_text(&key));
    let gen = all(&dev);
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for e in std::fs::read_dir(&d).expect("vectors 目录").flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) == Some("jaso") {
            on_disk.insert(p.file_stem().unwrap().to_str().unwrap().into());
        }
    }
    let names: BTreeSet<String> = gen.iter().map(|v| v.name.into()).collect();
    assert_eq!(on_disk, names, "仓库中的向量与生成器不一致：运行 jaso/vectors/regen.sh");
    for v in &gen {
        let bytes = std::fs::read(d.join(std::format!("{}.jaso", v.name))).unwrap();
        assert!(bytes == v.bytes, "{}.jaso 与生成器不一致", v.name);
        let expect = std::fs::read_to_string(d.join(std::format!("{}.expect", v.name))).unwrap();
        assert_eq!(expect, std::format!("{}\n", v.expect), "{}.expect", v.name);
    }
}

#[test]
fn every_vector_yields_its_expected_line() {
    let d = dir();
    let key = parse_key(&std::fs::read_to_string(d.join(DEV_KEY_FILE)).unwrap());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut n = 0;
    for e in std::fs::read_dir(&d).unwrap().flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("jaso") {
            continue;
        }
        let bytes = std::fs::read(&p).unwrap();
        let expect = std::fs::read_to_string(p.with_extension("expect")).unwrap();
        let got = expect_line(check(&bytes, key));
        assert_eq!(std::format!("{}\n", got), expect, "{}", p.display());
        seen.insert(got.into());
        n += 1;
    }
    assert!(n >= 20, "向量数 {} < 20", n);
    let missing: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.name()).filter(|c| !seen.contains(*c)).collect();
    assert!(missing.is_empty(), "没有向量覆盖：{:?}", missing);
    assert!(seen.contains("ok"));
}

#[test]
fn every_expect_line_is_ok_or_a_known_code() {
    let dev = crate::pack::development_signer();
    for v in all(&dev) {
        assert!(v.expect == "ok" || ErrorCode::from_name(v.expect).is_some(), "{}: {}", v.name, v.expect);
    }
}

#[test]
fn a_bad_trust_key_never_admits() {
    // 公钥不是合法曲线点（全 0xFF 解压失败）：配置错误一律拒绝，不 panic
    let dev = crate::pack::development_signer();
    let ok = all(&dev).into_iter().find(|v| v.name == "ok-native").unwrap();
    assert_eq!(check(&ok.bytes, [0xFF; 32]), Err(ErrorCode::TrustKey));
    // 换成另一把合法公钥：发布者已知、签名公钥不符
    let other = crate::pack::signer_from_phrase(b"another key").public_key();
    assert_eq!(check(&ok.bytes, other), Err(ErrorCode::TrustKey));
}
