//! user-bench：用户态基准程序——系统调用往返、异步环提交→完成、Channel 消息往返。
//! User-space benchmarks: system-call round trip, ring submit-to-complete, channel message round trip.
//!
//! # 测什么
//! | 名称 | 一个样本 = |
//! |---|---|
//! | `syscall.roundtrip` | 一次 `time.now`（进入内核 → 分发 → 返回用户态） |
//! | `ring.submit_complete` | 一次 enter：提交一条 `time.now` 请求并等到它的完成记录被收取 |
//! | `ring.wait_complete` | 一次 enter：提交一条 1 tick 的 `time.wait` 并等到自然完成 |
//! | `ring.wait_cancel` | 提交一条长等待、同步取消，并收取取消终态 |
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

extern crate alloc;

use alloc::vec::Vec;
use jasper_rt::channel;
use jasper_rt::ring::{Cqe, Ring, Sqe};
use jasper_rt::{entry, ids, println, time};
use kernel_core::bench::{
    summarize, Calibration, HumanDuration, Summary, P9999_RECOMMENDED_SAMPLES,
    P99999_RECOMMENDED_SAMPLES, P999_RECOMMENDED_SAMPLES, P99_RECOMMENDED_SAMPLES,
};

entry!(main);

/// 每项的预热次数（不计入样本）。
const WARMUP: u32 = 16;
/// 每项的样本数。
const ITERS: usize = 1_000_000;
/// Sleep-bound paths also retain one million one-operation samples.
const WAIT_ITERS: usize = 1_000_000;
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
    let mut samples = Vec::with_capacity(ITERS);
    let mut ok = true;
    for i in 0..WARMUP as usize + ITERS {
        let t0 = time::cycles();
        let now = time::now();
        let dt = time::cycles().wrapping_sub(t0);
        ok &= now > 0;
        if i >= WARMUP as usize {
            samples.push(dt);
        }
        if (i + 1) % 100_000 == 0 {
            println!("bench: progress name=syscall.roundtrip samples={}", i + 1);
        }
    }
    s.check(ok)?;
    report(s, "syscall.roundtrip", &mut samples, &cal, ITERS)?;

    // ---- 异步环：提交 → 完成（一次 enter）----
    let ring = Ring::create(8);
    s.check(ring.is_ok())?;
    let Ok(ring) = ring else { return Err(s.0) };
    let mut samples = Vec::with_capacity(ITERS);
    let mut ok = true;
    for i in 0..WARMUP as usize + ITERS {
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
        if i >= WARMUP as usize {
            samples.push(dt);
        }
        if (i + 1) % 100_000 == 0 {
            println!("bench: progress name=ring.submit_complete samples={}", i + 1);
        }
    }
    s.check(ok)?;
    report(s, "ring.submit_complete", &mut samples, &cal, ITERS)?;

    // ---- 异步环：Wait 自然完成与取消（issue #5 第四片同口径）----
    let mut samples = Vec::with_capacity(WAIT_ITERS);
    let mut ok = true;
    for i in 0..WARMUP as usize + WAIT_ITERS {
        let tag = 0xB100 + i as u64;
        let sqe = Sqe {
            op: ids::SYSTEM_TIME_WAIT as u32,
            flags: 0,
            user_tag: tag,
            arg0: 1,
            arg1: 0,
        };
        let mut id = [0u64; 1];
        let mut cq = [Cqe::default(); 1];
        let t0 = time::cycles();
        // SAFETY：time.wait 不引用用户内存。
        let e = unsafe { ring.enter_raw(core::slice::from_ref(&sqe), &mut id, &mut cq, 1) };
        let dt = time::cycles().wrapping_sub(t0);
        ok &= matches!(e, Ok(x) if x.submitted == 1 && x.reaped == 1)
            && cq[0].user_tag == tag
            && cq[0].request_id == id[0]
            && cq[0].result == 0;
        if i >= WARMUP as usize {
            samples.push(dt);
        }
        if (i + 1) % 100_000 == 0 {
            println!("bench: progress name=ring.wait_complete samples={}", i + 1);
        }
    }
    s.check(ok)?;
    report(s, "ring.wait_complete", &mut samples, &cal, WAIT_ITERS)?;

    let mut samples = Vec::with_capacity(WAIT_ITERS);
    let mut ok = true;
    for i in 0..WARMUP as usize + WAIT_ITERS {
        let tag = 0xB200 + i as u64;
        let sqe = Sqe {
            op: ids::SYSTEM_TIME_WAIT as u32,
            flags: 0,
            user_tag: tag,
            arg0: 1 << 40,
            arg1: 0,
        };
        let mut id = [0u64; 1];
        let mut cq = [Cqe::default(); 1];
        let t0 = time::cycles();
        // SAFETY：time.wait 不引用用户内存；该请求在同一线程内立即取消并收取。
        let submit = unsafe { ring.enter_raw(core::slice::from_ref(&sqe), &mut id, &mut [], 0) };
        let cancelled = ring.cancel(id[0]).is_ok();
        // SAFETY：不提交新记录；取消后的完成记录必须在消费前保持对应请求有效。
        let reap = unsafe { ring.enter_raw(&[], &mut [], &mut cq, 1) };
        let dt = time::cycles().wrapping_sub(t0);
        ok &= matches!(submit, Ok(x) if x.submitted == 1)
            && cancelled
            && matches!(reap, Ok(x) if x.reaped == 1)
            && cq[0].user_tag == tag
            && cq[0].request_id == id[0]
            && cq[0].result == -(ids::SYSTEM_ASYNC_ERROR_CANCELLED as i64);
        if i >= WARMUP as usize {
            samples.push(dt);
        }
        if (i + 1) % 100_000 == 0 {
            println!("bench: progress name=ring.wait_cancel samples={}", i + 1);
        }
    }
    s.check(ok)?;
    report(s, "ring.wait_cancel", &mut samples, &cal, WAIT_ITERS)?;

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
    let mut samples = Vec::with_capacity(ITERS);
    let mut ok = true;
    let mut buf = [0u8; MSG];
    let mut reported_recv = false;
    for i in 0..WARMUP as usize + ITERS {
        let msg = [(i & 0xFF) as u8; MSG];
        let t0 = time::cycles();
        let sent = a.send(&msg);
        if let Err(error) = sent {
            if !reported_recv {
                println!("bench: send_error={} iteration={}", error, i);
                reported_recv = true;
            }
        }
        let r = if sent.is_ok() {
            match b.recv(&mut buf) {
                Ok(received) => {
                    let received_ok = received.len == MSG;
                    if !received_ok && !reported_recv {
                        println!("bench: receive_length={}", received.len);
                        reported_recv = true;
                    }
                    let received_bytes_ok = buf == msg;
                    if received_ok && !received_bytes_ok && !reported_recv {
                        println!("bench: receive_bytes");
                        reported_recv = true;
                    }
                    let echo = b.send(&buf);
                    if let Err(error) = echo {
                        if !reported_recv {
                            println!("bench: echo_error={}", error);
                            reported_recv = true;
                        }
                    }
                    let returned = if echo.is_ok() {
                        Some(a.recv(&mut buf))
                    } else {
                        None
                    };
                    if let Some(Err(error)) = returned {
                        if !reported_recv {
                            println!("bench: return_error={}", error);
                            reported_recv = true;
                        }
                    }
                    received_ok
                        && received_bytes_ok
                        && returned.is_some_and(|r| matches!(r, Ok(r) if r.len == MSG))
                        && buf == msg
                }
                Err(error) => {
                    if !reported_recv {
                        println!("bench: recv_error={}", error);
                        reported_recv = true;
                    }
                    false
                }
            }
        } else {
            false
        };
        let dt = time::cycles().wrapping_sub(t0);
        ok &= r && buf == msg;
        if i >= WARMUP as usize {
            samples.push(dt);
        }
        if (i + 1) % 100_000 == 0 {
            println!("bench: progress name=ipc.roundtrip samples={}", i + 1);
        }
    }
    s.check(ok)?;
    report(s, "ipc.roundtrip", &mut samples, &cal, ITERS)?;
    // 失败路径：缓冲区过小 ⇒ 被拒，消息留在队列；随后完整收到
    let msg = [0x5Au8; MSG];
    s.check(a.send(&msg).is_ok())?;
    let mut tiny = [0u8; MSG / 2];
    let tiny_result = b.recv(&mut tiny).map(|r| r.len);
    let tiny_error = tiny_result.as_ref().err().copied();
    if tiny_error != Some(jasper_rt::Error::CHANNEL_BUFFER_TOO_SMALL) {
        println!("bench: tiny_result={:?}", tiny_result);
    }
    s.check(tiny_error == Some(jasper_rt::Error::CHANNEL_BUFFER_TOO_SMALL))?;
    s.check(tiny == [0u8; MSG / 2])?;
    let mut full = [0u8; MSG];
    s.check(matches!(b.recv(&mut full), Ok(r) if r.len == MSG) && full == msg)?;
    println!("bench: user case=ipc_refusal refused=true message_kept=true");
    Ok(())
}

/// 输出一项基准的汇总（周期 + 纳秒），并检查样本完整。
fn report(
    s: &mut Steps,
    name: &str,
    samples: &mut [u64],
    cal: &Calibration,
    expected: usize,
) -> Result<(), u32> {
    s.check(samples.len() == expected)?;
    let sum: Option<Summary> = summarize(samples);
    s.check(sum.is_some())?;
    if let Some(m) = sum {
        let counts = cal.threshold_counts(samples);
        println!(
            "bench: name={} iters={} min={} p50={} p90={} p95={} p99={} p999={} p9999={} p99999={} max={} mean={} stddev={} unit=cycles p50_ns={} p99_ns={} p999_ns={} p9999_ns={} p99999_ns={} over_1us={} over_10us={} over_50us={} spike=unattributed",
            name,
            m.count,
            m.min,
            m.p50,
            m.p90,
            m.p95,
            m.p99,
            m.p999,
            m.p9999,
            m.p99999,
            m.max,
            m.mean,
            m.stddev,
            cal.to_ns(m.p50),
            cal.to_ns(m.p99),
            cal.to_ns(m.p999),
            cal.to_ns(m.p9999),
            cal.to_ns(m.p99999),
            counts.over_1us,
            counts.over_10us,
            counts.over_50us
        );
        let resolution_ns = 1_000_000_000u64.div_ceil(cal.cycles_per_second().max(1));
        let count = m.count as usize;
        let p99_confidence = confidence(count, P99_RECOMMENDED_SAMPLES);
        let p999_confidence = confidence(count, P999_RECOMMENDED_SAMPLES);
        let p9999_confidence = confidence(count, P9999_RECOMMENDED_SAMPLES);
        let p99999_confidence = confidence(count, P99999_RECOMMENDED_SAMPLES);
        println!(
            "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"metric\",\"source\":\"user\",\"name\":\"{}\",\"count\":{},\"min_ns\":{},\"mean_ns\":{},\"p50_ns\":{},\"p90_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"p9999_ns\":{},\"p99999_ns\":{},\"max_ns\":{},\"stddev_ns\":{},\"over_1us\":{},\"over_10us\":{},\"over_50us\":{},\"spike_cause\":\"{}\",\"resolution_ns\":{},\"p50_below_resolution\":{},\"p99_confidence\":\"{}\",\"p999_confidence\":\"{}\",\"p9999_confidence\":\"{}\",\"p99999_confidence\":\"{}\"}}",
            name,
            m.count,
            cal.to_ns(m.min),
            cal.to_ns(m.mean),
            cal.to_ns(m.p50),
            cal.to_ns(m.p90),
            cal.to_ns(m.p95),
            cal.to_ns(m.p99),
            cal.to_ns(m.p999),
            cal.to_ns(m.p9999),
            cal.to_ns(m.p99999),
            cal.to_ns(m.max),
            cal.to_ns(m.stddev),
            counts.over_1us,
            counts.over_10us,
            counts.over_50us,
            if counts.over_50us == 0 {
                "none"
            } else {
                "unattributed"
            },
            resolution_ns,
            m.p50 == 0,
            p99_confidence,
            p999_confidence,
            p9999_confidence,
            p99999_confidence
        );
        println!(
            "bench: {} n={} p50={} p99={} p999={} max={}",
            name,
            m.count,
            HumanDuration::new(m.p50, cal),
            HumanDuration::new(m.p99, cal),
            HumanDuration::new(m.p999, cal),
            HumanDuration::new(m.max, cal)
        );
        println!(
            "bench-result: {} N={} P50={} P99={} P999={}",
            name,
            m.count,
            HumanDuration::new(m.p50, cal),
            HumanDuration::new(m.p99, cal),
            HumanDuration::new(m.p999, cal)
        );
        println!(
            "bench-result: {} P99.99={} P99.999={} MAX={} >1us={} >10us={} >50us={} SPIKE={}",
            name,
            HumanDuration::new(m.p9999, cal),
            HumanDuration::new(m.p99999, cal),
            HumanDuration::new(m.max, cal),
            counts.over_1us,
            counts.over_10us,
            counts.over_50us,
            if counts.over_50us == 0 {
                "none"
            } else {
                "unattributed"
            }
        );
    }
    Ok(())
}

fn confidence(count: usize, recommended: usize) -> &'static str {
    if count >= recommended {
        "recommended"
    } else if count >= recommended / 10 {
        "low_tail_count"
    } else {
        "insufficient"
    }
}
