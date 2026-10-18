//! user-libcheck：现有 Rust 库在 jasper-os 用户态的可移植性验收。
//! Portability check: existing Rust crates running in jasper-os user space on top of jasper-rt.
//!
//! 每个库都用公开的已知答案（标准测试向量）或可独立验证的往返来检查；任何一步不符即以该步编号退出。
//!
//! # 可移植性清单（本程序实测的结论）
//! | 库（版本） | 需要 | 不需要 | 备注 |
//! |---|---|---|---|
//! | sha2 0.11.1 | `core` | alloc、线程、TLS、时间、随机数 | x86_64 上默认会在运行时选 SHA-NI（SSE）实现；内核尚不保存 SIMD 寄存器，故以 `sha2_backend="soft"` 强制纯软件后端 |
//! | crc 3.4.0 | `core` | alloc、线程、TLS、时间 | 查表在编译期生成 |
//! | miniz_oxide 0.9.1 | `core` + `alloc`（`with-alloc`） | 线程、TLS、时间 | 输出缓冲按需增长，依赖堆 |
//! | smoltcp 0.14.0 | `core` + `alloc`（套接字缓冲、环回设备队列） | 线程、TLS | 不读系统时钟：时间由调用者以 `Instant` 传入；本程序用确定性的虚拟时钟 |
//!
//! 共同点：全部 `no_std`、不需要线程局部存储与操作系统线程；浮点只在软件实现中出现（目标为软浮点）。
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use jasper_rt::{entry, println};

entry!(main);

/// 检查计数器：失败时以步骤编号退出。
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

fn main(_role: u64, _arg: u64) -> i32 {
    let mut s = Steps(0);
    let r = sha2_kat(&mut s).and_then(|_| crc_kat(&mut s)).and_then(|_| deflate_kat(&mut s)).and_then(|_| tcp_loopback(&mut s));
    match r {
        Ok(()) => {
            println!("libcheck: ok checks={}", s.0);
            0
        }
        Err(step) => {
            println!("libcheck: FAIL step={}", step);
            step as i32
        }
    }
}

/// 十六进制串 → 字节。
fn hex(s: &str) -> Vec<u8> {
    let d = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0xFF,
    };
    s.as_bytes().chunks(2).map(|p| d(p[0]) << 4 | d(p[1])).collect()
}

/// SHA-256 / SHA-512：FIPS 180 的标准测试向量（含一百万个 'a'）。
fn sha2_kat(s: &mut Steps) -> Result<(), u32> {
    use sha2::{Digest, Sha256, Sha512};
    let v256: [(&[u8], &str); 3] = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (msg, want) in v256 {
        s.check(Sha256::digest(msg).as_slice() == hex(want).as_slice())?;
    }
    // 一百万个 'a'，分块喂入（同时检验增量接口）
    let mut h = Sha256::new();
    let block = [b'a'; 1000];
    for _ in 0..1000 {
        h.update(block);
    }
    s.check(h.finalize().as_slice() == hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0").as_slice())?;
    let want512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    s.check(Sha512::digest(b"abc").as_slice() == hex(want512).as_slice())?;
    println!("libcheck: lib=sha2 version=0.11.1 backend=soft vectors=5 ok=true");
    Ok(())
}

/// CRC：各算法目录中的「123456789」校验值。
fn crc_kat(s: &mut Steps) -> Result<(), u32> {
    use crc::{Crc, CRC_16_IBM_SDLC, CRC_32_ISCSI, CRC_32_ISO_HDLC, CRC_64_ECMA_182};
    let input = b"123456789";
    s.check(Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(input) == 0xCBF4_3926)?;
    s.check(Crc::<u32>::new(&CRC_32_ISCSI).checksum(input) == 0xE306_9283)?;
    s.check(Crc::<u16>::new(&CRC_16_IBM_SDLC).checksum(input) == 0x906E)?;
    s.check(Crc::<u64>::new(&CRC_64_ECMA_182).checksum(input) == 0x6C40_DF5F_0B49_7347)?;
    // 增量计算与一次计算一致
    let c = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut d = c.digest();
    d.update(b"1234");
    d.update(b"56789");
    s.check(d.finalize() == 0xCBF4_3926)?;
    println!("libcheck: lib=crc version=3.4.0 algorithms=4 ok=true");
    Ok(())
}

/// DEFLATE / zlib：手工构造的存储块、空输入的标准 zlib 流、压缩 → 解压往返（含压缩率）、损坏输入被拒。
fn deflate_kat(s: &mut Steps) -> Result<(), u32> {
    use miniz_oxide::deflate::compress_to_vec_zlib;
    use miniz_oxide::inflate::{decompress_to_vec, decompress_to_vec_zlib};
    // 原始 DEFLATE 存储块：BFINAL=1、BTYPE=00，LEN=5、NLEN=!5，随后 5 个原样字节
    let stored = [0x01, 0x05, 0x00, 0xFA, 0xFF, b'h', b'e', b'l', b'l', b'o'];
    s.check(decompress_to_vec(&stored).is_ok_and(|v| v == b"hello"))?;
    // 空输入的 zlib 流（默认级别）：头 78 9C、空的固定哈夫曼块、Adler-32 = 1
    s.check(decompress_to_vec_zlib(&[0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]).is_ok_and(|v| v.is_empty()))?;
    // 往返：64 KiB 有规律的文本
    let mut text = Vec::with_capacity(64 * 1024);
    while text.len() < 64 * 1024 {
        text.extend_from_slice("jasper-os 用户态运行 miniz_oxide；".as_bytes());
    }
    let packed = compress_to_vec_zlib(&text, 6);
    s.check(packed.len() < text.len() / 10)?;
    s.check(decompress_to_vec_zlib(&packed).is_ok_and(|v| v == text))?;
    // 损坏的流：改坏 Adler-32 校验 ⇒ 解压报错而不是返回错误数据
    let mut bad = packed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xFF;
    s.check(decompress_to_vec_zlib(&bad).is_err())?;
    println!("libcheck: lib=miniz_oxide version=0.9.1 in={} packed={} roundtrip=true corrupt_rejected=true", text.len(), packed.len());
    Ok(())
}

/// smoltcp：环回设备上的一次 TCP 连接——客户端发 32 KiB，服务端原样回送；
/// 双方各自对收发的数据做 SHA-256，必须一致。时钟是确定性的虚拟时钟（每轮前进到协议栈要求的下一时刻）。
fn tcp_loopback(s: &mut Steps) -> Result<(), u32> {
    use sha2::{Digest, Sha256};
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::socket::tcp;
    use smoltcp::time::{Duration, Instant};
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

    const TOTAL: usize = 32 * 1024;
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i * 7 % 251) as u8).collect();

    let mut device = Loopback::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x6a73_7072_6f73; // 固定种子：初始序列号可复现
    let mut now = Instant::from_millis(0);
    let mut iface = Interface::new(config, &mut device, now);
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
    });
    let sock = || tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 8192]), tcp::SocketBuffer::new(vec![0; 8192]));
    let mut sockets = SocketSet::new(Vec::new());
    let server = sockets.add(sock());
    let client = sockets.add(sock());
    s.check(sockets.get_mut::<tcp::Socket>(server).listen(1234).is_ok())?;
    let cx = iface.context();
    s.check(sockets.get_mut::<tcp::Socket>(client).connect(cx, (IpAddress::v4(127, 0, 0, 1), 1234), 49152).is_ok())?;

    let (mut sent, mut echoed, mut got) = (0usize, 0usize, Vec::with_capacity(TOTAL));
    let mut pending: Vec<u8> = Vec::new(); // 服务端已收到、尚未回送的数据
    let mut rounds = 0u32;
    while got.len() < TOTAL && rounds < 200_000 {
        rounds += 1;
        iface.poll(now, &mut device, &mut sockets);
        {
            let c = sockets.get_mut::<tcp::Socket>(client);
            if c.can_send() && sent < TOTAL {
                sent += c.send_slice(&payload[sent..]).unwrap_or(0);
            }
            if c.can_recv() {
                let _ = c.recv(|b| {
                    got.extend_from_slice(b);
                    (b.len(), ())
                });
            }
        }
        {
            let sv = sockets.get_mut::<tcp::Socket>(server);
            if sv.can_recv() {
                let _ = sv.recv(|b| {
                    pending.extend_from_slice(b);
                    (b.len(), ())
                });
            }
            if sv.can_send() && !pending.is_empty() {
                let n = sv.send_slice(&pending).unwrap_or(0);
                pending.drain(..n);
                echoed += n;
            }
        }
        now += match iface.poll_delay(now, &sockets) {
            Some(d) if d > Duration::ZERO => d,
            _ => Duration::from_millis(1),
        };
    }
    s.check(sent == TOTAL && echoed == TOTAL && got.len() == TOTAL)?;
    s.check(Sha256::digest(&got) == Sha256::digest(&payload))?;
    // 有序关闭：客户端关闭后服务端看到对端关闭
    sockets.get_mut::<tcp::Socket>(client).close();
    for _ in 0..1000 {
        iface.poll(now, &mut device, &mut sockets);
        if !sockets.get_mut::<tcp::Socket>(server).may_recv() {
            break;
        }
        now += Duration::from_millis(1);
    }
    s.check(!sockets.get_mut::<tcp::Socket>(server).may_recv())?;
    println!(
        "libcheck: lib=smoltcp version=0.14.0 tcp_loopback bytes={} echoed={} sha256_match=true rounds={} virtual_ms={} peer_close_seen=true",
        got.len(),
        echoed,
        rounds,
        now.total_millis()
    );
    Ok(())
}
