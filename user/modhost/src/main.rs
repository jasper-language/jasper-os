//! user-modhost：现有 Rust 库作为 `.jaso` 模块装载运行（验收用）。
//! Runs existing Rust libraries as `.jaso` modules.
//!
//! 四个模块同时装入，每个都用与 `user/libcheck`（直接链接这些库）相同的已知答案检查：
//! * jaso-sha2：FIPS 180 向量（含一百万个 `a`）、SHA-512
//! * jaso-crc：四种算法对 `123456789` 的校验值
//! * jaso-deflate：手工存储块、空输入 zlib 流、64 KiB 往返、改坏校验和被拒；缓冲所有权经 `buffer_free` 归还
//! * jaso-net：环回 TCP 回送
//!
//! 然后让模块串联：deflate 压缩的结果经 net 回送，回送内容的 SHA-256（sha2 模块）与原压缩结果一致、
//! 解压（deflate 模块）后与原文一致、CRC-32（crc 模块）与原文一致。最后全部卸载，映射消失。
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use jasper_rt::module::{Grant, Module, Publisher, TrustMode, TrustPolicy, DEVELOPMENT_NAMESPACE, DEVELOPMENT_PUBLISHER, STD_HOST};
use jasper_rt::{entry, mem, println, Error};

entry!(main);

static SHA2: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sha2.jaso"));
static CRC: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/crc.jaso"));
static DEFLATE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/deflate.jaso"));
static NET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/net.jaso"));
/// 受信发布者表：只信任构建期为这些模块签名的开发用发布者。
static PUBLISHERS: [Publisher<'static>; 1] = [Publisher {
    name: DEVELOPMENT_PUBLISHER,
    namespace: DEVELOPMENT_NAMESPACE,
    key: *include_bytes!(concat!(env!("OUT_DIR"), "/trust-dev.key")),
}];

type HashFn = unsafe extern "C" fn(*const u8, usize, *mut u8) -> i32;
type Crc32Fn = unsafe extern "C" fn(*const u8, usize) -> u32;
type Crc16Fn = unsafe extern "C" fn(*const u8, usize) -> u16;
type Crc64Fn = unsafe extern "C" fn(*const u8, usize) -> u64;
type CompressFn = unsafe extern "C" fn(*const u8, usize, u32, *mut *mut u8, *mut usize) -> i32;
type InflateFn = unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32;
type FreeFn = unsafe extern "C" fn(*mut u8, usize);
type EchoFn = unsafe extern "C" fn(*const u8, usize, *mut u8) -> i64;
type RoundsFn = extern "C" fn() -> u64;

struct Steps(u32);

impl Steps {
    fn check(&mut self, ok: bool) -> Result<(), u32> {
        self.0 += 1;
        if ok {
            Ok(())
        } else {
            Err(self.0)
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    let d = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0xFF,
    };
    s.as_bytes().chunks(2).map(|p| d(p[0]) << 4 | d(p[1])).collect()
}

/// 已装入的四个模块及其导出。
struct Libs {
    sha2: Module,
    crc: Module,
    deflate: Module,
    net: Module,
}

impl Libs {
    fn sha256(&self, data: &[u8]) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        // SAFETY：签名与模块导出一致；data 可读、out 可写 32 字节。
        let rc = unsafe { (self.sha2.function::<HashFn>("sha256")?.get())(data.as_ptr(), data.len(), out.as_mut_ptr()) };
        (rc == 0).then_some(out)
    }

    fn crc32(&self, data: &[u8]) -> Option<u32> {
        // SAFETY：签名与模块导出一致；data 可读。
        Some(unsafe { (self.crc.function::<Crc32Fn>("crc32_iso_hdlc")?.get())(data.as_ptr(), data.len()) })
    }

    /// 调用 deflate 模块的一个「输入 → 交出缓冲」函数，把结果复制出来并经 `buffer_free` 归还缓冲。
    fn deflate_call(&self, f: impl FnOnce(*mut *mut u8, *mut usize) -> i32) -> Result<Vec<u8>, i32> {
        let (mut p, mut n) = (core::ptr::null_mut::<u8>(), 0usize);
        let rc = f(&mut p, &mut n);
        if rc != 0 {
            return Err(rc);
        }
        // SAFETY：模块交出 (p, n)，在归还前只读一次。
        let v = unsafe { core::slice::from_raw_parts(p, n) }.to_vec();
        // SAFETY：签名与模块导出一致；(p, n) 由该模块交出、尚未归还。
        if let Some(free) = unsafe { self.deflate.function::<FreeFn>("buffer_free") } {
            unsafe { (free.get())(p, n) };
        }
        Ok(v)
    }

    fn compress(&self, data: &[u8], level: u32) -> Result<Vec<u8>, i32> {
        // SAFETY：签名与模块导出一致。
        let f = unsafe { self.deflate.function::<CompressFn>("zlib_compress") }.ok_or(-100)?.get();
        // SAFETY：data 可读；输出指针可写。
        self.deflate_call(|p, n| unsafe { f(data.as_ptr(), data.len(), level, p, n) })
    }

    fn inflate(&self, name: &str, data: &[u8]) -> Result<Vec<u8>, i32> {
        // SAFETY：签名与模块导出一致（zlib_decompress / inflate_raw 同型）。
        let f = unsafe { self.deflate.function::<InflateFn>(name) }.ok_or(-100)?.get();
        // SAFETY：data 可读；输出指针可写。
        self.deflate_call(|p, n| unsafe { f(data.as_ptr(), data.len(), p, n) })
    }

    fn echo(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut out = vec![0u8; data.len()];
        // SAFETY：签名与模块导出一致；data 可读、out 可写同样长度。
        let n = unsafe { (self.net.function::<EchoFn>("tcp_loopback_echo")?.get())(data.as_ptr(), data.len(), out.as_mut_ptr()) };
        (n == data.len() as i64).then_some(out)
    }
}

fn main(_: u64, _: u64) -> i32 {
    let mut s = Steps(0);
    match run(&mut s) {
        Ok(()) => {
            println!("modhost: ok checks={}", s.0);
            0
        }
        Err(step) => {
            println!("modhost: FAIL step={}", step);
            step as i32
        }
    }
}

fn run(s: &mut Steps) -> Result<(), u32> {
    let trust = TrustPolicy::new(&PUBLISHERS, TrustMode::Enforce).map_err(|_| 99u32)?;
    let grant = Grant { capabilities: &["system.console.write"], host: Some(&STD_HOST), trust: &trust };
    let load = |b: &[u8], s: &Steps| Module::load(b, grant).map_err(|_| 100 + s.0);
    let libs = Libs { sha2: load(SHA2, s)?, crc: load(CRC, s)?, deflate: load(DEFLATE, s)?, net: load(NET, s)? };
    let signed = [&libs.sha2, &libs.crc, &libs.deflate, &libs.net].iter().filter(|m| m.publisher() == Some(DEVELOPMENT_PUBLISHER)).count();
    s.check(signed == 4)?;
    println!("modhost: trusted publisher={} signed={}/4 mode=enforce", DEVELOPMENT_PUBLISHER, signed);
    println!(
        "modhost: loaded sha2={}B crc={}B deflate={}B net={}B pages={}+{}+{}+{}",
        SHA2.len(),
        CRC.len(),
        DEFLATE.len(),
        NET.len(),
        libs.sha2.pages(),
        libs.crc.pages(),
        libs.deflate.pages(),
        libs.net.pages()
    );

    // sha2
    let v256: [(&[u8], &str); 3] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ];
    for (msg, want) in v256 {
        s.check(libs.sha256(msg).map(|d| d.to_vec()) == Some(hex(want)))?;
    }
    let million = vec![b'a'; 1_000_000];
    s.check(libs.sha256(&million).map(|d| d.to_vec()) == Some(hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")))?;
    drop(million);
    let mut d512 = [0u8; 64];
    // SAFETY：签名与模块导出一致；out 可写 64 字节。
    let rc = unsafe { libs.sha2.function::<HashFn>("sha512") }.map(|f| unsafe { (f.get())(b"abc".as_ptr(), 3, d512.as_mut_ptr()) });
    s.check(rc == Some(0) && d512.to_vec() == hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))?;
    println!("modhost: module=jaso-sha2 vectors=5 ok=true");

    // crc
    let input = b"123456789";
    s.check(libs.crc32(input) == Some(0xCBF4_3926))?;
    // SAFETY：签名与模块导出一致；input 可读。
    unsafe {
        s.check(libs.crc.function::<Crc32Fn>("crc32_iscsi").map(|f| (f.get())(input.as_ptr(), 9)) == Some(0xE306_9283))?;
        s.check(libs.crc.function::<Crc16Fn>("crc16_ibm_sdlc").map(|f| (f.get())(input.as_ptr(), 9)) == Some(0x906E))?;
        s.check(libs.crc.function::<Crc64Fn>("crc64_ecma_182").map(|f| (f.get())(input.as_ptr(), 9)) == Some(0x6C40_DF5F_0B49_7347))?;
    }
    println!("modhost: module=jaso-crc algorithms=4 ok=true");

    // deflate
    let stored = [0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'];
    s.check(libs.inflate("inflate_raw", &stored).as_deref() == Ok(&b"hello"[..]))?;
    s.check(libs.inflate("zlib_decompress", &[0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]).map(|v| v.is_empty()) == Ok(true))?;
    let mut text = Vec::with_capacity(64 * 1024);
    while text.len() < 64 * 1024 {
        text.extend_from_slice("jasper-os 以 .jaso 模块运行 miniz_oxide；".as_bytes());
    }
    let packed = libs.compress(&text, 6).map_err(|_| 200 + s.0)?;
    s.check(packed.len() < text.len() / 10)?;
    s.check(libs.inflate("zlib_decompress", &packed).as_deref() == Ok(&text[..]))?;
    let mut bad = packed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    s.check(libs.inflate("zlib_decompress", &bad) == Err(-2))?;
    s.check(libs.compress(&text, 11) == Err(-1))?;
    println!("modhost: module=jaso-deflate in={} packed={} roundtrip=true corrupt_rejected=true", text.len(), packed.len());

    // net
    let payload: Vec<u8> = (0..32 * 1024).map(|i| (i * 7 % 251) as u8).collect();
    let echoed = libs.echo(&payload).ok_or(300 + s.0)?;
    s.check(echoed == payload)?;
    // SAFETY：签名与模块导出一致。
    let rounds = unsafe { libs.net.function::<RoundsFn>("last_rounds") }.map(|f| (f.get())()).unwrap_or(0);
    s.check(rounds > 0)?;
    println!("modhost: module=jaso-net tcp_loopback bytes={} echoed=true rounds={}", payload.len(), rounds);

    // 串联：压缩 → 经 TCP 回送 → 摘要一致 → 解压回原文 → CRC 一致
    let through = libs.echo(&packed).ok_or(400 + s.0)?;
    s.check(libs.sha256(&through).is_some() && libs.sha256(&through) == libs.sha256(&packed))?;
    let restored = libs.inflate("zlib_decompress", &through).map_err(|_| 400 + s.0)?;
    s.check(libs.crc32(&restored) == libs.crc32(&text) && restored == text)?;
    println!("modhost: pipeline deflate->net->sha2->deflate->crc ok=true crc32={:#010x}", libs.crc32(&text).unwrap_or(0));

    // 卸载全部：映射消失
    let bases = [libs.sha2.base(), libs.crc.base(), libs.deflate.base(), libs.net.base()];
    drop(libs);
    s.check(bases.iter().all(|&b| mem::unmap(b, 1) == Err(Error::MEMORY_INVALID_ADDRESS)))?;
    println!("modhost: unloaded modules=4");
    Ok(())
}
