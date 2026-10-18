//! 宿主测试：发布者签名与信任策略——签名往返、RFC 8032 已知答案，以及篡改字节、替换签名、换发布者、
//! 重签他人模块、未知发布者、未签名、签名段格式等各类拒绝；随机篡改（含重算完整性摘要）从不被接受。

extern crate std;

use std::vec;
use std::vec::Vec;

use crate::build::{Builder, SegmentIn, Signer};
use crate::trust::{PolicyError, Provenance, Publisher, TrustError, TrustMode, TrustPolicy};
use crate::*;

const BASE_MANIFEST: &str = "core.name = demo.mod\ncore.version = 1.0.0\ncore.abi = c.v0\ncore.exports = f_one\n";

fn manifest(publisher: Option<&str>) -> Vec<u8> {
    let mut m = BASE_MANIFEST.as_bytes().to_vec();
    if let Some(p) = publisher {
        m.extend_from_slice(std::format!("core.publisher = {}\n", p).as_bytes());
    }
    m
}

fn builder(publisher: Option<&str>) -> Builder {
    Builder {
        arch: Arch::X86_64,
        stage: Stage::Runtime,
        manifest: manifest(publisher),
        segments: vec![
            SegmentIn { vaddr: 0, mem_size: 64, flags: FLAG_R, data: vec![5; 64] },
            SegmentIn { vaddr: PAGE, mem_size: 32, flags: FLAG_R | FLAG_X, data: vec![0xC3; 32] },
        ],
        exports: vec![(b"f_one".to_vec(), PAGE)],
        relocs: vec![(0, 0x10)],
    }
}

fn seed(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn signer_a() -> Signer {
    Signer::from_seed(&seed(0xA1))
}

fn signer_b() -> Signer {
    Signer::from_seed(&seed(0xB2))
}

/// 两个受信发布者：pub.a 管 `demo.` 命名空间，pub.b 管 `other.` 命名空间。
fn publishers() -> [Publisher<'static>; 2] {
    [
        Publisher { name: "pub.a", namespace: "demo.", key: signer_a().public_key() },
        Publisher { name: "pub.b", namespace: "other.", key: signer_b().public_key() },
    ]
}

fn verify_with(bytes: &[u8], mode: TrustMode) -> Result<Provenance<'static>, TrustError> {
    let table: &'static [Publisher<'static>] = std::boxed::Box::leak(std::boxed::Box::new(publishers()));
    let policy = TrustPolicy::new(table, mode).expect("策略应合法");
    let img = Image::parse(bytes).expect("格式应合法");
    policy.verify(&img)
}

fn verify(bytes: &[u8]) -> Result<Provenance<'static>, TrustError> {
    verify_with(bytes, TrustMode::Enforce)
}

fn digest_fix(b: &mut [u8]) {
    let d = digest_of(b);
    b[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn rfc8032_test_1() {
    // RFC 8032 §7.1 TEST 1：空消息
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    let s = Signer::from_seed(&sk);
    assert_eq!(s.public_key().to_vec(), hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    let want = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    assert_eq!(s.sign(b"").to_vec(), want);
}

#[test]
fn signed_roundtrip() {
    let bytes = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let img = Image::parse(&bytes).unwrap();
    let sig = img.signature().expect("应有签名段");
    assert_eq!(sig.scheme, SIG_ED25519);
    assert_eq!(sig.publisher_key, signer_a().public_key());
    assert_eq!(sig.file_offset as usize + SIGNATURE_SIZE, bytes.len());
    assert_eq!(img.manifest.publisher, Some("pub.a"));
    assert_eq!(verify(&bytes), Ok(Provenance::Signed { publisher: "pub.a" }));
    // 开发模式下签名模块同样按发布者通过
    assert_eq!(verify_with(&bytes, TrustMode::Development), Ok(Provenance::Signed { publisher: "pub.a" }));
    // 从文件还原再签名，得到逐字节相同的结果（Ed25519 签名是确定性的）
    assert_eq!(Builder::from_image(&img).finish_signed(&signer_a()).unwrap(), bytes);
    // 未签名文件没有签名段
    let plain = builder(Some("pub.a")).finish().unwrap();
    assert!(Image::parse(&plain).unwrap().signature().is_none());
}

#[test]
fn unsigned_rejected_unless_development() {
    let plain = builder(Some("pub.a")).finish().unwrap();
    assert_eq!(verify(&plain), Err(TrustError::Unsigned));
    assert_eq!(verify_with(&plain, TrustMode::Development), Ok(Provenance::UnsignedDevelopment));
    let anon = builder(None).finish().unwrap();
    assert_eq!(verify(&anon), Err(TrustError::Unsigned));
}

#[test]
fn tampered_bytes_rejected() {
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let sig_off = good.len() - SIGNATURE_SIZE;
    let img = Image::parse(&good).unwrap();
    // 映像段内容中的每个字节：不重算摘要 ⇒ 完整性校验拒绝；重算摘要 ⇒ 验签拒绝
    let seg_start = img.segments().next().unwrap().data.as_ptr() as usize - good.as_ptr() as usize;
    for i in seg_start..sig_off {
        let mut t = good.clone();
        t[i] ^= 0x40;
        assert_eq!(Image::parse(&t).err(), Some(JasoError::DigestMismatch), "byte {}", i);
        digest_fix(&mut t);
        if Image::parse(&t).is_ok() {
            assert!(verify(&t).is_err(), "篡改字节 {} 后仍被接受", i);
        }
    }
}

#[test]
fn replaced_signature_rejected() {
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let value = good.len() - 64;
    // 翻转签名值的任一位
    for i in [value, value + 31, value + 32, good.len() - 1] {
        let mut t = good.clone();
        t[i] ^= 0x01;
        digest_fix(&mut t);
        assert_eq!(verify(&t), Err(TrustError::BadSignature), "sig byte {}", i);
    }
    // 换成同一发布者为另一份内容签的合法签名值
    let mut other = builder(Some("pub.a"));
    other.segments[0].data[0] ^= 1;
    let other = other.finish_signed(&signer_a()).unwrap();
    let mut t = good.clone();
    t[value..].copy_from_slice(&other[other.len() - 64..]);
    digest_fix(&mut t);
    assert_eq!(verify(&t), Err(TrustError::BadSignature));
    // 全零签名值
    let mut t = good.clone();
    t[value..].fill(0);
    digest_fix(&mut t);
    assert_eq!(verify(&t), Err(TrustError::BadSignature));
}

#[test]
fn swapped_publisher_rejected() {
    // 清单改称另一个受信发布者（签名仍是 A 的）：公钥对不上
    let a_signed_claims_b = builder(Some("pub.b")).finish_signed(&signer_a()).unwrap();
    assert_eq!(verify(&a_signed_claims_b), Err(TrustError::KeyMismatch));
    // 只把签名段里的公钥换成 B 的（清单仍称 pub.a）：与 pub.a 的受信公钥不一致
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let mut t = good.clone();
    let key_off = good.len() - SIGNATURE_SIZE + 8;
    t[key_off..key_off + 32].copy_from_slice(&signer_b().public_key());
    digest_fix(&mut t);
    assert_eq!(verify(&t), Err(TrustError::KeyMismatch));
    // 同时把清单改成 pub.b：公钥一致，但模块名不在 pub.b 的命名空间
    let mut swapped = builder(Some("pub.b"));
    swapped.manifest = manifest(Some("pub.b"));
    let mut t = swapped.finish_signed(&signer_a()).unwrap();
    let key_off = t.len() - SIGNATURE_SIZE + 8;
    t[key_off..key_off + 32].copy_from_slice(&signer_b().public_key());
    digest_fix(&mut t);
    assert_eq!(verify(&t), Err(TrustError::OutOfNamespace));
}

#[test]
fn resigning_someone_elses_module_rejected() {
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let img = Image::parse(&good).unwrap();
    // B 拿 A 的模块原样重签（仍声称 pub.a）：公钥不是 A 的
    let resigned = Builder::from_image(&img).finish_signed(&signer_b()).unwrap();
    assert_eq!(verify(&resigned), Err(TrustError::KeyMismatch));
    // B 重签并改称自己（pub.b）：B 无权签发 `demo.` 命名空间下的模块名
    let mut claim = Builder::from_image(&img);
    claim.manifest = manifest(Some("pub.b"));
    let claimed = claim.finish_signed(&signer_b()).unwrap();
    assert_eq!(verify(&claimed), Err(TrustError::OutOfNamespace));
    // 不在表中的密钥签名、声称不在表中的发布者
    let stranger = Signer::from_seed(&seed(0x33));
    let mut unknown = Builder::from_image(&img);
    unknown.manifest = manifest(Some("pub.unknown"));
    assert_eq!(verify(&unknown.finish_signed(&stranger).unwrap()), Err(TrustError::UnknownPublisher));
    // 签名了却不声明发布者
    assert_eq!(verify(&builder(None).finish_signed(&signer_a()).unwrap()), Err(TrustError::MissingPublisher));
}

#[test]
fn development_mode_still_rejects_bad_signatures() {
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let mut t = good.clone();
    let n = t.len();
    t[n - 1] ^= 0x80;
    digest_fix(&mut t);
    assert_eq!(verify_with(&t, TrustMode::Development), Err(TrustError::BadSignature));
    let resigned = Builder::from_image(&Image::parse(&good).unwrap()).finish_signed(&signer_b()).unwrap();
    assert_eq!(verify_with(&resigned, TrustMode::Development), Err(TrustError::KeyMismatch));
}

#[test]
fn signature_section_format() {
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let sig_off = good.len() - SIGNATURE_SIZE;
    // 未知算法、保留字段非 0
    for (at, v) in [(sig_off, 2u32), (sig_off + 4, 1u32)] {
        let mut t = good.clone();
        t[at..at + 4].copy_from_slice(&v.to_le_bytes());
        digest_fix(&mut t);
        assert_eq!(Image::parse(&t).err(), Some(JasoError::BadSignatureSection));
    }
    // 签名段目录项：长度改短（不在文件末尾）、偏移前移与其它段重叠
    let dir_count = u32::from_le_bytes(good[20..24].try_into().unwrap()) as usize;
    let sig_dir = HEADER_SIZE + (dir_count - 1) * SECTION_SIZE;
    assert_eq!(u32::from_le_bytes(good[sig_dir..sig_dir + 4].try_into().unwrap()), 5);
    let mut t = good.clone();
    t[sig_dir + 12..sig_dir + 16].copy_from_slice(&((SIGNATURE_SIZE - 8) as u32).to_le_bytes());
    digest_fix(&mut t);
    assert_eq!(Image::parse(&t).err(), Some(JasoError::BadSignatureSection));
    let mut t = good.clone();
    t[sig_dir + 8..sig_dir + 12].copy_from_slice(&((sig_off - 8) as u32).to_le_bytes());
    digest_fix(&mut t);
    assert!(Image::parse(&t).is_err());
    // 签名段带了段标志
    let mut t = good.clone();
    t[sig_dir + 4..sig_dir + 8].copy_from_slice(&1u32.to_le_bytes());
    digest_fix(&mut t);
    assert_eq!(Image::parse(&t).err(), Some(JasoError::BadSectionDir));
}

#[test]
fn policy_construction_rules() {
    let a = signer_a().public_key();
    let dup = [Publisher { name: "p", namespace: "", key: a }, Publisher { name: "p", namespace: "x.", key: a }];
    assert_eq!(TrustPolicy::new(&dup, TrustMode::Enforce).err(), Some(PolicyError::DuplicatePublisher));
    let empty = [Publisher { name: "", namespace: "", key: a }];
    assert_eq!(TrustPolicy::new(&empty, TrustMode::Enforce).err(), Some(PolicyError::EmptyName));
    // 找一个不是合法曲线点的编码
    let bad = (0u8..=255)
        .map(|i| {
            let mut k = [0u8; 32];
            k[0] = i;
            k[31] = 0x7f;
            k
        })
        .find(|k| TrustPolicy::new(&[Publisher { name: "t", namespace: "", key: *k }], TrustMode::Enforce).is_err())
        .expect("应存在非法公钥编码");
    let bad = [Publisher { name: "t", namespace: "", key: bad }];
    assert_eq!(TrustPolicy::new(&bad, TrustMode::Enforce).err(), Some(PolicyError::BadKey));
    // 空表：任何签名模块都是未知发布者
    let none = TrustPolicy::new(&[], TrustMode::Enforce).unwrap();
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    assert_eq!(none.verify(&Image::parse(&good).unwrap()), Err(TrustError::UnknownPublisher));
    assert_eq!(none.mode(), TrustMode::Enforce);
    assert!(none.publishers().is_empty());
}

#[test]
fn random_tampering_never_accepted() {
    let good = builder(Some("pub.a")).finish_signed(&signer_a()).unwrap();
    let table = publishers();
    // 强制模式：变异可能把签名段从目录里「删掉」（变成未签名文件），这只能被强制模式拒绝
    let policy = TrustPolicy::new(&table, TrustMode::Enforce).unwrap();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut parsed = 0;
    for _ in 0..3000 {
        let mut t = good.clone();
        for _ in 0..1 + next() % 3 {
            let i = (next() % t.len() as u64) as usize;
            t[i] ^= 1 << (next() % 8);
        }
        digest_fix(&mut t);
        if t == good {
            continue;
        }
        if let Ok(img) = Image::parse(&t) {
            parsed += 1;
            // 结构仍合法的变体一律被信任策略拒绝
            assert!(policy.verify(&img).is_err(), "变异后仍被接受");
        }
    }
    assert!(parsed > 100, "变异样本中结构合法的太少：{}", parsed);
}

#[cfg(feature = "pack")]
#[test]
fn development_signer_and_resign() {
    use crate::trust::{DEVELOPMENT_NAMESPACE, DEVELOPMENT_PUBLISHER};
    let dev = crate::pack::development_signer();
    // 种子固定：两次得到同一把密钥；与「由短语派生」的其它密钥不同
    assert_eq!(dev.public_key(), crate::pack::development_signer().public_key());
    assert_ne!(dev.public_key(), crate::pack::signer_from_phrase(b"another phrase").public_key());
    let mut b = builder(Some(DEVELOPMENT_PUBLISHER));
    b.manifest = std::format!("core.name = jaso-x\ncore.version = 1.0.0\ncore.abi = c.v0\ncore.exports = f_one\ncore.publisher = {}\n", DEVELOPMENT_PUBLISHER)
        .into_bytes();
    let unsigned = b.finish().unwrap();
    let signed = crate::pack::sign(&unsigned, &dev).unwrap();
    let table = [Publisher { name: DEVELOPMENT_PUBLISHER, namespace: DEVELOPMENT_NAMESPACE, key: dev.public_key() }];
    let policy = TrustPolicy::new(&table, TrustMode::Enforce).unwrap();
    assert_eq!(policy.verify(&Image::parse(&signed).unwrap()), Ok(Provenance::Signed { publisher: DEVELOPMENT_PUBLISHER }));
    // 重新签名已签名的文件：替换签名段而不是追加第二个
    assert_eq!(crate::pack::sign(&signed, &dev).unwrap(), signed);
    // 输入不合法：原样报告解析错误，不产出文件
    let mut bad = unsigned.clone();
    bad[0] ^= 1;
    assert_eq!(crate::pack::sign(&bad, &dev).err(), Some(JasoError::BadMagic));
}
