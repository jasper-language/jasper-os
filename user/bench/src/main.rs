//! user-bench：用户态基准程序——系统调用往返、异步环提交→完成、Channel 消息往返。
//! User-space benchmarks: system-call round trip, ring submit-to-complete, channel message round trip.
//!
//! # 测什么
//! | 名称 | 一个样本 = |
//! |---|---|
//! | `syscall.roundtrip` | 一次 `time.now`（进入内核 → 分发 → 返回用户态） |
//! | `ring.submit_complete` | 一次 enter：提交一条 `time.now` 请求并等到它的完成记录被收取 |
//! | `ipc.roundtrip` | 端点 A 发 16 字节 → 端点 B 收 → B 原样发回 → A 收（同一线程，4 次系统调用） |
//!
//! 每项先预热 [`WARMUP`] 次，再采 [`ITERS`] 个样本；样本单位是周期计数器读数，入口参数 `arg` 是内核校准得到的
//! 每秒周期数，据此同时输出纳秒。统计口径（最近秩百分位）与内核侧基准共用同一实现。
//!
//! # 校验（失败即以步骤编号退出）
//! * 每个样本的结果都必须正确：时刻非负、完成记录的标签与请求 ID 对得上、收到的字节与发出的一致；
//! * 失败路径：未登记的异步操作被拒且不产生完成记录；缓冲区过小的接收被拒、消息仍留在队列且之后能完整收到；
//! * 没有样本被拒收（缓冲容量足够）。
#![no_std]
#![no_main]

use jasper_rt::channel;
use jasper_rt::ring::{Cqe, Ring, Sqe};
use jasper_rt::{entry, ids, println, time};
use kernel_core::bench::{Calibration, Samples, Summary};

entry!(main);

/// 每项的预热次数（不计入样本）。
const WARMUP: u32 = 16;
/// 每项的样本数。
const ITERS: u32 = 200;
/// 往返消息的长度。
const MSG: usize = 16;
/// 一个不存在的异步操作 ID（失败路径用）。
const BOGUS_OP: u32 = 0xFFFF_FFF0;

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

fn main(_role: u64, cycles_per_second: u64) -> i32 {
    let mut s = Steps(0);
    match run(&mut s, cycles_per_second) {
        Ok(()) => {
            println!("bench: user ok checks={}", s.0);
            0
        }
        Err(step) => {
            println!("bench: user FAIL step={}", step);
            step as i32
        }
    }
}

fn run(s: &mut Steps, cycles_per_second: u64) -> Result<(), u32> {
    let cal = Calibration::per_second(cycles_per_second);
    s.check(cal.is_some())?;
    let Some(cal) = cal else { return Err(s.0) };

    // ---- 系统调用往返 ----
    let mut samples = Samples::new();
    let mut ok = true;
    for i in 0..WARMUP + ITERS {
        let t0 = time::cycles();
        let now = time::now();
        let dt = time::cycles().wrapping_sub(t0);
        ok &= now > 0;
        if i >= WARMUP {
            samples.push(dt);
        }
    }
    s.check(ok)?;
    report(s, "syscall.roundtrip", &samples, &cal)?;

    // ---- 异步环：提交 → 完成（一次 enter）----
    let ring = Ring::create(8);
    s.check(ring.is_ok())?;
    let Ok(ring) = ring else { return Err(s.0) };
    let mut samples = Samples::new();
    let mut ok = true;
    for i in 0..WARMUP + ITERS {
        let tag = 0xB000 + i as u64;
        let sqe = Sqe { op: ids::SYSTEM_TIME_NOW as u32, flags: 0, user_tag: tag, arg0: 0, arg1: 0 };
        let mut id = [0u64; 1];
        let mut cq = [Cqe::default(); 1];
        let t0 = time::cycles();
        // SAFETY：time.now 不引用用户内存。
        let e = unsafe { ring.enter_raw(core::slice::from_ref(&sqe), &mut id, &mut cq, 1) };
        let dt = time::cycles().wrapping_sub(t0);
        ok &= matches!(e, Ok(x) if x.submitted == 1 && x.reaped == 1)
            && cq[0].user_tag == tag
            && cq[0].request_id == id[0]
            && cq[0].result > 0;
        if i >= WARMUP {
            samples.push(dt);
        }
    }
    s.check(ok)?;
    report(s, "ring.submit_complete", &samples, &cal)?;
    // 失败路径：未登记的操作被拒，且不产生任何完成记录
    let bad = Sqe { op: BOGUS_OP, flags: 0, user_tag: 1, arg0: 0, arg1: 0 };
    let mut id = [0u64; 1];
    let mut cq = [Cqe::default(); 1];
    // SAFETY：被拒的提交不会访问任何用户内存。
    let e = unsafe { ring.enter_raw(core::slice::from_ref(&bad), &mut id, &mut [], 0) };
    s.check(matches!(e, Ok(x) if x.submitted == 0 && x.first_error.is_some()) || e.is_err())?;
    // SAFETY：不提交任何记录。
    let left = unsafe { ring.enter_raw(&[], &mut [], &mut cq, 0) };
    s.check(matches!(left, Ok(x) if x.reaped == 0))?;
    println!("bench: user case=ring_refusal refused=true no_completion=true");

    // ---- Channel 消息往返 ----
    let pair = channel::pair();
    s.check(pair.is_ok())?;
    let Ok((a, b)) = pair else { return Err(s.0) };
    let mut samples = Samples::new();
    let mut ok = true;
    let mut buf = [0u8; MSG];
    for i in 0..WARMUP + ITERS {
        let msg = [(i & 0xFF) as u8; MSG];
        let t0 = time::cycles();
        let r = a.send(&msg).is_ok()
            && matches!(b.recv(&mut buf), Ok(r) if r.len == MSG)
            && b.send(&buf).is_ok()
            && matches!(a.recv(&mut buf), Ok(r) if r.len == MSG);
        let dt = time::cycles().wrapping_sub(t0);
        ok &= r && buf == msg;
        if i >= WARMUP {
            samples.push(dt);
        }
    }
    s.check(ok)?;
    report(s, "ipc.roundtrip", &samples, &cal)?;
    // 失败路径：缓冲区过小 ⇒ 被拒，消息留在队列；随后完整收到
    let msg = [0x5Au8; MSG];
    s.check(a.send(&msg).is_ok())?;
    let mut tiny = [0u8; MSG / 2];
    s.check(b.recv(&mut tiny).map(|r| r.len).err() == Some(jasper_rt::Error::CHANNEL_BUFFER_TOO_SMALL))?;
    s.check(tiny == [0u8; MSG / 2])?;
    let mut full = [0u8; MSG];
    s.check(matches!(b.recv(&mut full), Ok(r) if r.len == MSG) && full == msg)?;
    println!("bench: user case=ipc_refusal refused=true message_kept=true");
    Ok(())
}

/// 输出一项基准的汇总（周期 + 纳秒），并检查样本完整。
fn report(s: &mut Steps, name: &str, samples: &Samples, cal: &Calibration) -> Result<(), u32> {
    s.check(samples.len() == ITERS as usize && samples.rejected() == 0)?;
    let sum: Option<Summary> = samples.summary();
    s.check(sum.is_some())?;
    if let Some(m) = sum {
        println!(
            "bench: name={} iters={} min={} p50={} p99={} max={} mean={} unit=cycles p50_ns={} p99_ns={}",
            name,
            m.count,
            m.min,
            m.p50,
            m.p99,
            m.max,
            m.mean,
            cal.to_ns(m.p50),
            cal.to_ns(m.p99)
        );
    }
    Ok(())
}
