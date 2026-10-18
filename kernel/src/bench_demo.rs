//! 基准演练：在真实时钟与真实切换路径上测量内核关键路径的耗时，并据测量评估可调参数的取值。
//! Benchmark drill: times the kernel's hot paths on real hardware paths and evaluates tunables against a limit.
//!
//! # 测什么（一个样本 = 一次操作，单位为周期计数器读数，并按校准换算成纳秒）
//! | 名称 | 一个样本 = |
//! |---|---|
//! | `kernel.timer_irq` | 一次时钟中断从打断到返回的额外耗时（忙循环中包含 tick 变化的跨两轮读数间隔，减去关中断时同样间隔的中位耗时） |
//! | `sched.context_switch` | 两个内核任务互相让出时，平均每次任务切换的耗时 |
//! | `frame.alloc` / `frame.free` | 分配 / 释放一个物理页帧 |
//! | `heap.alloc_free_64` / `heap.alloc_free_4096` | 内核堆上分配并释放 64 / 4096 字节 |
//! | 用户程序 `user/bench` | 系统调用往返、异步环提交→完成、Channel 消息往返 |
//!
//! # 取值规则
//! 以 [`LIMIT_PPM`]（1%）为周期性开销预算，用 `kernel_core::bench::select` 评估：
//! * 时钟频率：每秒开销 = 中断成本 × 频率；预算内**最大**的候选即频率上界；
//! * 各档时间片：每片开销 = 一次切换成本 / 片长；预算内**最小**的候选即片长下界。
//!
//! 默认配置档（standard）的生效值必须落在预算内，否则本演练判失败；其它配置档照样测量并输出结论
//! （`gated=false`），但不据此判失败——它们是为别的目标（例如交互优先）有意用开销换响应的取舍，
//! 且已有配置档的取值不随测量改动。边界值只作为参考输出，是否改默认值由其它约束一起决定。
//!
//! # 局限
//! 在指令翻译型仿真器上，周期计数器与定时器都跟随宿主时间，绝对数字不代表真机，只适合同一环境下的相对比较。
//! 本演练不改变任何调度、等待、锁或 IPC 机制；中断与切换路径的测量在关闭时间片抢占、没有其它工作任务时进行。
//! 每个用例结束后检查空闲页帧、存活对象、清理队列、固定帧回到用例前的基线。

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kernel_core::bench::{quantum_overhead, select, timer_overhead, Calibration, Decision, Prefer, Samples, Summary};
use kernel_core::sync::SpinLock;

use crate::mm::{frame, heap};
use crate::proc::ProcState;
use crate::rt_demo::{baseline, rt_calls, run_program_arg};
use crate::task::TaskId;
use crate::{arch, config, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-BENCH-FAIL] {}", what);
    }
}

/// 失败断言数。
/// Number of failed checks.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 用户态基准程序 `user/bench` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_BENCH: &[u8] = include_bytes!(env!("JSR_USER_BENCH"));

/// 校准与中断成本测量各自持续的 tick 数。
const WINDOW_TICKS: u64 = 20;
/// 每项的预热次数（不计入样本）。
const WARMUP: u32 = 16;
/// 每项的样本数。
const ITERS: u32 = 200;
/// 测量循环本身耗时的读数次数（关中断）。
const LOOP_PROBE: u32 = 4096;
/// 周期性开销预算（百万分比）：1%。
const LIMIT_PPM: u64 = 10_000;
/// 时钟频率候选（Hz）。
const HZ_CANDIDATES: [u32; 4] = [100, 250, 500, 1000];
/// 时间片候选（tick）。
const QUANTUM_CANDIDATES: [u32; 4] = [1, 2, 4, 8];
/// 时间片参数名（与启动时的配置输出一致）。
const QUANTUM_NAMES: [&str; 4] = ["quantum.0", "quantum.1", "quantum.2", "quantum.3"];
/// 本演练的内核任务号起点（与其它演练的任务号不重叠）。
const TASK_ID_BASE: u64 = 9800;

/// 运行全部基准。演练期间关闭时间片抢占；结束时恢复进入前的设置与中断状态。
/// Run every benchmark; preemption is off during the drill and restored afterwards.
pub fn run() {
    let prev_preemption = sched::set_preemption(false);
    let was_enabled = arch::irq_save_disable();
    let start = baseline();
    let cal = calibrate();
    check(cal.is_some(), "周期计数器校准失败");
    if let Some(cal) = cal {
        let tick = timer_irq(&cal);
        let switch = context_switch(&cal);
        frames(&cal);
        heap_paths(&cal);
        user_program(&cal);
        if let (Some(tick), Some(switch)) = (tick, switch) {
            tuning(&cal, tick.p50, switch.p50);
        }
    }
    let end = baseline();
    check(end == start, "基准演练结束后资源未回到起点");
    arch::irq_restore(was_enabled);
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-BENCH] summary free_frames={}/{} objects={}/{} reclaimed={} checks={} failed={}",
        end.free_frames,
        start.free_frames,
        end.objects,
        start.objects,
        end == start,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 输出一项汇总：`[JSR-BENCH] name=<名> iters=… min=… p50=… p99=… max=… mean=… unit=cycles p50_ns=… p99_ns=…`。
fn report(name: &str, samples: &Samples, cal: &Calibration) -> Option<Summary> {
    let sum = samples.summary();
    check(sum.is_some() && samples.rejected() == 0, "基准样本缺失或被拒收");
    if let Some(m) = sum {
        kprintln!(
            "[JSR-BENCH] name={} iters={} min={} p50={} p99={} max={} mean={} unit=cycles p50_ns={} p99_ns={}",
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
    sum
}

/// 开中断等到下一个 tick 的边沿，返回边沿处的 tick 数。
fn next_tick_edge() -> u64 {
    let t = sched::timer_ticks();
    while sched::timer_ticks() == t {
        arch::wait_for_interrupt();
    }
    sched::timer_ticks()
}

// ---------------------------------------------------------------------------
// 校准
// ---------------------------------------------------------------------------

/// 在 [`WINDOW_TICKS`] 个 tick 内数周期计数器走了多少，得到每 tick 周期数。
fn calibrate() -> Option<Calibration> {
    let hz = config::ACTIVE.clock.timer_hz;
    let t0 = next_tick_edge();
    let c0 = arch::cycles();
    while sched::timer_ticks() < t0 + WINDOW_TICKS {
        arch::wait_for_interrupt();
    }
    let c1 = arch::cycles();
    arch::irq_disable();
    let cal = Calibration::new(c1.wrapping_sub(c0), WINDOW_TICKS, hz)?;
    kprintln!(
        "[JSR-BENCH] calibrate ticks={} cycles={} cycles_per_tick={} cycles_per_second={} timer_hz={}",
        WINDOW_TICKS,
        c1.wrapping_sub(c0),
        cal.cycles_per_tick(),
        cal.cycles_per_second(),
        hz
    );
    Some(cal)
}

// ---------------------------------------------------------------------------
// 时钟中断成本
// ---------------------------------------------------------------------------

/// 每次循环先读计数器 `a`、再读 tick 数 `t`。若第 i 次读到的 `t` 变了，时钟中断一定发生在
/// 第 i−1 次读 `t` 与第 i 次读 `t` 之间，必然落在 `(a[i-1], a[i+1])` 这段跨两轮的间隔里；
/// 用它减去「同样跨两轮、但关中断时」的中位耗时，即为一次中断的成本。
/// 每个 tick 恰好一个样本，不依赖「多大的缺口才算中断」的阈值（仿真器的偶发停顿不会被误计为中断）。
fn timer_irq(cal: &Calibration) -> Option<Summary> {
    // 关中断探测：跨两轮的间隔 a[i+1] − a[i-1]
    let mut probe = Samples::new();
    let (mut a1, mut a2) = (arch::cycles(), arch::cycles());
    for i in 0..LOOP_PROBE {
        let a = arch::cycles();
        black_box(sched::timer_ticks());
        if i % (LOOP_PROBE / 256) == 0 {
            probe.push(a.wrapping_sub(a2));
        }
        a2 = a1;
        a1 = a;
    }
    let Some(base) = probe.summary() else {
        check(false, "循环耗时探测没有样本");
        return None;
    };
    let mut irqs = Samples::new();
    let t0 = next_tick_edge();
    arch::irq_disable();
    let end = t0 + WINDOW_TICKS;
    let mut last = sched::timer_ticks();
    let mut prev = arch::cycles();
    // 上一轮发现 tick 变化时记下的 a[i-1]；下一轮读到 a[i+1] 后结算
    let mut pending: Option<u64> = None;
    arch::irq_enable();
    loop {
        let a = arch::cycles();
        if let Some(start) = pending.take() {
            irqs.push(a.wrapping_sub(start).saturating_sub(base.p50));
            if last >= end {
                break;
            }
        }
        let t = sched::timer_ticks();
        if t != last {
            pending = Some(prev);
            last = t;
        }
        prev = a;
    }
    arch::irq_disable();
    // 窗口内应恰好观察到 WINDOW_TICKS 次 tick 变化（每次变化只加 1：中断成本远小于一个 tick）
    let matched = irqs.len() as u64 == WINDOW_TICKS && last == end;
    check(matched, "时钟中断样本数与 tick 数不符");
    kprintln!(
        "[JSR-BENCH] probe span_p50={} span_max={} samples={} ticks={} matched={}",
        base.p50,
        base.max,
        irqs.len(),
        WINDOW_TICKS,
        matched
    );
    report("kernel.timer_irq", &irqs, cal)
}

// ---------------------------------------------------------------------------
// 上下文切换
// ---------------------------------------------------------------------------

static SWITCH_SAMPLES: SpinLock<Samples> = SpinLock::new(Samples::new());
static SWITCH_DONE: AtomicBool = AtomicBool::new(false);
/// 一次让出没有发生任何切换的次数（应为 0：总有另一个任务可运行）。
static SWITCH_NONE: AtomicU32 = AtomicU32::new(0);

/// 测量任务：每次让出前后读计数器，按期间发生的切换次数平摊。
fn switch_measurer() {
    for i in 0..WARMUP + ITERS {
        let n0 = sched::switch_count();
        let c0 = arch::cycles();
        sched::yield_now();
        let dt = arch::cycles().wrapping_sub(c0);
        let n = sched::switch_count() - n0;
        if n == 0 {
            SWITCH_NONE.fetch_add(1, Ordering::Relaxed);
        } else if i >= WARMUP {
            SWITCH_SAMPLES.lock().push(dt / n);
        }
    }
    SWITCH_DONE.store(true, Ordering::Relaxed);
}

/// 对手任务：一直让出，直到测量任务结束。
fn switch_partner() {
    while !SWITCH_DONE.load(Ordering::Relaxed) {
        sched::yield_now();
    }
}

fn context_switch(cal: &Calibration) -> Option<Summary> {
    let before = baseline();
    *SWITCH_SAMPLES.lock() = Samples::new();
    SWITCH_DONE.store(false, Ordering::Relaxed);
    SWITCH_NONE.store(0, Ordering::Relaxed);
    let a = sched::spawn(TaskId(TASK_ID_BASE + 1), "bench-switch-a", switch_measurer).is_ok();
    let b = sched::spawn(TaskId(TASK_ID_BASE + 2), "bench-switch-b", switch_partner).is_ok();
    check(a && b, "切换基准任务创建失败");
    sched::run();
    check(SWITCH_NONE.load(Ordering::Relaxed) == 0, "有可运行对手时让出却没有切换");
    let samples = SWITCH_SAMPLES.lock().clone();
    check(samples.len() == ITERS as usize, "切换样本数不足");
    let sum = report("sched.context_switch", &samples, cal);
    let after = baseline();
    check(after == before, "切换基准后资源未回到基线");
    sum
}

// ---------------------------------------------------------------------------
// 物理页帧
// ---------------------------------------------------------------------------

fn frames(cal: &Calibration) {
    let before = baseline();
    let mut alloc = Samples::new();
    let mut free = Samples::new();
    let mut ok = true;
    for i in 0..WARMUP + ITERS {
        let c0 = arch::cycles();
        let f = frame::allocate();
        let c1 = arch::cycles();
        let Ok(f) = f else {
            ok = false;
            break;
        };
        let r = frame::deallocate(f);
        let c2 = arch::cycles();
        ok &= r.is_ok();
        if i >= WARMUP {
            alloc.push(c1.wrapping_sub(c0));
            free.push(c2.wrapping_sub(c1));
        }
    }
    check(ok, "页帧分配/释放失败");
    report("frame.alloc", &alloc, cal);
    report("frame.free", &free, cal);
    // 失败路径：重复释放被拒，空闲帧数不变
    let refused = match frame::allocate() {
        Ok(f) => {
            let first = frame::deallocate(f).is_ok();
            let free_before = frame::free_frames();
            let second = frame::deallocate(f);
            first && second == Err(kernel_core::frame::FrameError::DoubleFree) && frame::free_frames() == free_before
        }
        Err(_) => false,
    };
    check(refused, "重复释放页帧未被拒绝或改动了空闲帧数");
    let after = baseline();
    check(after == before, "页帧基准后资源未回到基线");
    kprintln!("[JSR-BENCH] case=frame_refusal double_free_refused={} free_unchanged={} reclaimed={}", refused, refused, after == before);
}

// ---------------------------------------------------------------------------
// 内核堆
// ---------------------------------------------------------------------------

fn heap_paths(cal: &Calibration) {
    let before = baseline();
    let mut small = Samples::new();
    let mut page = Samples::new();
    for i in 0..WARMUP + ITERS {
        let c0 = arch::cycles();
        drop(black_box(Box::new([0u8; 64])));
        let c1 = arch::cycles();
        drop(black_box(Vec::<u8>::with_capacity(4096)));
        let c2 = arch::cycles();
        if i >= WARMUP {
            small.push(c1.wrapping_sub(c0));
            page.push(c2.wrapping_sub(c1));
        }
    }
    report("heap.alloc_free_64", &small, cal);
    report("heap.alloc_free_4096", &page, cal);
    // 失败路径：超出堆上限的申请被拒，堆的统计不变
    let stats_before = heap::stats();
    let mut v: Vec<u8> = Vec::new();
    let refused = v.try_reserve(config::ACTIVE.memory.heap_max as usize + 4096).is_err();
    let unchanged = heap::stats() == stats_before && v.capacity() == 0;
    check(refused && unchanged, "超大堆申请未被拒绝或改动了堆");
    let after = baseline();
    check(after == before, "堆基准后资源未回到基线");
    kprintln!("[JSR-BENCH] case=heap_refusal refused={} heap_unchanged={} reclaimed={}", refused, unchanged, after == before);
}

// ---------------------------------------------------------------------------
// 用户态基准
// ---------------------------------------------------------------------------

fn user_program(cal: &Calibration) {
    let before = baseline();
    let res = run_program_arg("bench", USER_BENCH, 0, cal.cycles_per_second(), rt_calls());
    let ok_exit = matches!(res, Some((Some(ProcState::Exited { code: 0 }), Some(0))));
    check(ok_exit, "user/bench 未以 0 退出");
    let after = baseline();
    check(after == before, "用户基准后资源未回到基线");
    kprintln!("[JSR-BENCH] case=user exit={:?} reclaimed={}", res.and_then(|r| r.1), after == before);
}

// ---------------------------------------------------------------------------
// 取值
// ---------------------------------------------------------------------------

/// 本次构建是否为默认配置档：只有默认档的生效值以开销预算判定成败。
fn gated() -> bool {
    config::ACTIVE.name == kernel_core::config::KernelConfig::STANDARD.name
}

fn print_decision(d: &Decision, prefer: &str) {
    kprintln!(
        "[JSR-BENCH] tune param={} current={} current_ppm={} limit_ppm={} within_limit={} gated={} prefer={} bound={:?} bound_ppm={:?}",
        d.param,
        d.current,
        d.current_ppm,
        d.limit_ppm,
        d.current_within_limit(),
        gated(),
        prefer,
        d.bound,
        d.bound_ppm
    );
}

fn tuning(cal: &Calibration, tick_cost: u64, switch_cost: u64) {
    let hz = select("timer_hz", config::ACTIVE.clock.timer_hz, &HZ_CANDIDATES, LIMIT_PPM, Prefer::Largest, |h| {
        timer_overhead(tick_cost, cal, h)
    });
    check(hz.is_ok(), "时钟频率取值失败");
    if let Ok(d) = hz {
        check(!gated() || d.current_within_limit(), "默认配置档的时钟频率超出开销预算");
        print_decision(&d, "largest");
    }
    for (i, name) in QUANTUM_NAMES.iter().enumerate() {
        let q = config::ACTIVE.sched.qos.quantum[i];
        let d = select(name, q, &QUANTUM_CANDIDATES, LIMIT_PPM, Prefer::Smallest, |q| quantum_overhead(switch_cost, cal, q));
        check(d.is_ok(), "时间片取值失败");
        if let Ok(d) = d {
            check(!gated() || d.current_within_limit(), "默认配置档的时间片超出开销预算");
            print_decision(&d, "smallest");
        }
    }
    // 失败路径：非法候选（0）被拒，不给出部分结论
    let bad = select("timer_hz", config::ACTIVE.clock.timer_hz, &[100, 0], LIMIT_PPM, Prefer::Largest, |h| timer_overhead(tick_cost, cal, h));
    check(bad.is_err(), "非法候选未被拒绝");
    kprintln!("[JSR-BENCH] case=tune_refusal invalid_candidate_refused={}", bad.is_err());
}
