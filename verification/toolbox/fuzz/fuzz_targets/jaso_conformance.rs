#![no_main]
//! `.jaso` 一致性判定（SPEC §14）：任意字节不 panic；结果为 ok 时文件必须通过结构读取且带开发用发布者的签名；
//! 结构读取失败时判定结果就是读取的错误码（load 类码只来自第 2–6 步）。另以「回填长度与摘要」的副本越过完整性检查。
use jaso::conformance::check;
use jaso::{Jaso, DIGEST_OFFSET, HEADER_SIZE};

fn exercise(b: &[u8], key: [u8; 32]) {
    let r = check(b, key);
    match Jaso::parse(b) {
        Err(e) => assert_eq!(r, Err(e.code())),
        Ok(f) => {
            if let Err(c) = r {
                assert!(c.is_load(), "结构合格的文件只能在装载步骤被拒绝");
            } else {
                assert_eq!(f.signature().map(|s| s.publisher_key), Some(key), "放行的文件必须由受信公钥签名");
            }
        }
    }
}

/// 与向量一同公开的开发用公钥（`jaso/vectors/jasper.dev.pub`，64 个十六进制字符）。
fn dev_key() -> [u8; 32] {
    let t = include_str!("../../../../jaso/vectors/jasper.dev.pub").trim();
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap();
    }
    k
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let key = dev_key();
    exercise(data, key);
    if data.len() >= HEADER_SIZE {
        let mut b = data.to_vec();
        b[..8].copy_from_slice(&jaso::MAGIC);
        (b[8], b[9]) = (1, 0);
        let n = b.len() as u32;
        b[28..32].copy_from_slice(&n.to_le_bytes());
        let d = jaso::digest_of(&b);
        b[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
        exercise(&b, key);
    }
});
