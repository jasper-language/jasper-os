//! jaso-net：smoltcp 的 `.jaso` 模块封装。
//! The smoltcp crate as a `.jaso` module.
//!
//! | 导出 | 说明 |
//! |---|---|
//! | `tcp_loopback_echo(input, len, out)` | 在模块内的环回设备上建立一条 TCP 连接：客户端发出 `[input, input+len)`，服务端原样回送，客户端收到的写入 `out`；返回收到的字节数，失败为负数（-1 参数非法、-2 建连失败、-3 未在轮数上限内完成） |
//! | `last_rounds()` | 上一次 `tcp_loopback_echo` 的协议栈轮询轮数 |
//!
//! 时间由模块内确定性的虚拟时钟提供（每轮前进到协议栈要求的下一时刻），与系统时钟无关。
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use jaso_module as _;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

/// 单次回送的字节数上限。
const MAX_LEN: usize = 1 << 20;
/// 轮询轮数上限。
const MAX_ROUNDS: u64 = 1_000_000;

static ROUNDS: AtomicU64 = AtomicU64::new(0);

/// 环回 TCP 回送。
///
/// # Safety
/// `input` 可读 `len` 字节；`out` 可写 `len` 字节。
#[no_mangle]
pub unsafe extern "C" fn tcp_loopback_echo(input: *const u8, len: usize, out: *mut u8) -> i64 {
    if len == 0 || len > MAX_LEN {
        return -1;
    }
    let payload = core::slice::from_raw_parts(input, len);
    let mut device = Loopback::new(Medium::Ip);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x6a61_736f; // 固定种子：初始序列号可复现
    let mut now = Instant::from_millis(0);
    let mut iface = Interface::new(config, &mut device, now);
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
    });
    let sock = || tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 16384]), tcp::SocketBuffer::new(vec![0; 16384]));
    let mut sockets = SocketSet::new(Vec::new());
    let server = sockets.add(sock());
    let client = sockets.add(sock());
    if sockets.get_mut::<tcp::Socket>(server).listen(7).is_err() {
        return -2;
    }
    let cx = iface.context();
    if sockets.get_mut::<tcp::Socket>(client).connect(cx, (IpAddress::v4(127, 0, 0, 1), 7), 49153).is_err() {
        return -2;
    }
    let (mut sent, mut got) = (0usize, 0usize);
    let mut pending: Vec<u8> = Vec::new();
    let mut rounds = 0u64;
    while got < len && rounds < MAX_ROUNDS {
        rounds += 1;
        iface.poll(now, &mut device, &mut sockets);
        let c = sockets.get_mut::<tcp::Socket>(client);
        if c.can_send() && sent < len {
            sent += c.send_slice(&payload[sent..]).unwrap_or(0);
        }
        if c.can_recv() {
            let _ = c.recv(|b| {
                let n = b.len().min(len - got);
                core::ptr::copy_nonoverlapping(b.as_ptr(), out.add(got), n);
                got += n;
                (n, ())
            });
        }
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
        }
        now += match iface.poll_delay(now, &sockets) {
            Some(d) if d > Duration::ZERO => d,
            _ => Duration::from_millis(1),
        };
    }
    ROUNDS.store(rounds, Ordering::Relaxed);
    if got == len {
        got as i64
    } else {
        -3
    }
}

/// 上一次回送的轮询轮数。
#[no_mangle]
pub extern "C" fn last_rounds() -> u64 {
    ROUNDS.load(Ordering::Relaxed)
}
