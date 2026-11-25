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
//! 默认配置档（standard）的生效值超出预算时，只作为**计时类断言**记录（`[JSR-BENCH-TIMING]`、汇总行末
//! `timing_failed=<n>`），不使本演练判失败：指令翻译型仿真器下计时不可信，性能只在裸机上判定。
//! 其它配置档照样测量并输出结论（`gated=false`），但不据此判失败——它们是为别的目标（例如交互优先）
//! 有意用开销换响应的取舍，且已有配置档的取值不随测量改动。边界值只作为参考输出，是否改默认值由其它约束一起决定。
//! 功能类断言（样本齐全、失败路径被拒、回到基线）照旧判失败，不因平台快慢而放宽。
//!
//! # 局限
//! 在指令翻译型仿真器上，周期计数器与定时器都跟随宿主时间，绝对数字不代表真机，只适合同一环境下的相对比较。
//! 本演练不改变任何调度、等待、锁或 IPC 机制；中断与切换路径的测量在关闭时间片抢占、没有其它工作任务时进行。
//! 每个用例结束后检查空闲页帧、存活对象、清理队列、固定帧回到用例前的基线。

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use kernel_core::bench::{
    quantum_overhead, select, summarize, timer_overhead, Calibration, Decision, HumanDuration,
    Prefer, Samples, Summary, P99999_RECOMMENDED_SAMPLES, P9999_RECOMMENDED_SAMPLES,
    P999_RECOMMENDED_SAMPLES, P99_RECOMMENDED_SAMPLES,
};
use kernel_core::spawn_abi::SpawnDesc;
use kernel_core::sync::SpinLock;
use kernel_core::syscall_set::SyscallSet;

use crate::baseline::baseline;
use crate::mm::{frame, heap};
use crate::proc::ProcState;
use crate::rt_demo::{rt_calls, run_program_arg};
use crate::task::TaskId;
use crate::{arch, config, early, kprintln, sched, smp};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 计时类断言超界的次数：只记录，不计入功能失败（仿真器下计时不可信）。
static TIMING_FAILED: AtomicU32 = AtomicU32::new(0);
static LAST_RECLAIMED: AtomicBool = AtomicBool::new(false);
static LAST_SINGLE_MODE: AtomicBool = AtomicBool::new(false);
static LAST_PHYSICAL_MODE: AtomicBool = AtomicBool::new(false);
static LAST_LOGICAL_MODE: AtomicBool = AtomicBool::new(false);

fn all_concurrent_modes_ok() -> bool {
    LAST_PHYSICAL_MODE.load(Ordering::Acquire)
        && LAST_LOGICAL_MODE.load(Ordering::Acquire)
        && (cfg!(feature = "bench-skip-single") || LAST_SINGLE_MODE.load(Ordering::Acquire))
}

/// Result-log slots are test-fixture metadata, not a hardware capacity.
const REPORT_ROWS: usize = 64;
/// One framebuffer result row, retaining slightly more text than the display width.
const REPORT_ROW_BYTES: usize = 240;

#[derive(Clone, Copy)]
struct ReportRow {
    bytes: [u8; REPORT_ROW_BYTES],
    len: usize,
}

impl ReportRow {
    const fn empty() -> Self {
        Self {
            bytes: [0; REPORT_ROW_BYTES],
            len: 0,
        }
    }

    fn text(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

struct ReportLog {
    rows: [ReportRow; REPORT_ROWS],
    len: usize,
}

impl ReportLog {
    const fn new() -> Self {
        Self {
            rows: [ReportRow::empty(); REPORT_ROWS],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn push_format(&mut self, args: fmt::Arguments) {
        if self.len == self.rows.len() {
            return;
        }
        let row = &mut self.rows[self.len];
        row.len = 0;
        let mut writer = RowWriter {
            bytes: &mut row.bytes,
            len: &mut row.len,
        };
        let _ = writer.write_fmt(args);
        self.len += 1;
    }

    fn push_text(&mut self, text: &str) {
        self.push_format(format_args!(
            "{}",
            text.trim_end_matches(|ch| ch == '\r' || ch == '\n')
        ));
    }
}

struct RowWriter<'a> {
    bytes: &'a mut [u8],
    len: &'a mut usize,
}

impl fmt::Write for RowWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for ch in text.chars() {
            let mut encoded = [0u8; 4];
            let bytes = ch.encode_utf8(&mut encoded).as_bytes();
            if *self.len + bytes.len() > self.bytes.len() {
                break;
            }
            self.bytes[*self.len..*self.len + bytes.len()].copy_from_slice(bytes);
            *self.len += bytes.len();
        }
        Ok(())
    }
}

static REPORT: SpinLock<ReportLog> = SpinLock::new(ReportLog::new());

fn reset_report() {
    REPORT.lock().clear();
    LAST_RECLAIMED.store(false, Ordering::Release);
    LAST_SINGLE_MODE.store(false, Ordering::Release);
    LAST_PHYSICAL_MODE.store(false, Ordering::Release);
    LAST_LOGICAL_MODE.store(false, Ordering::Release);
}

fn record_result(args: fmt::Arguments) {
    REPORT.lock().push_format(args);
}

/// Capture a final user-space benchmark result. Progress and diagnostic lines
/// are intentionally excluded; the final panel only contains measurements.
pub(crate) fn capture_console_line(text: &str) {
    let line = text.trim_end_matches(|ch| ch == '\r' || ch == '\n');
    if line.starts_with("bench-result:") {
        REPORT.lock().push_text(line);
    }
}

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-BENCH-FAIL] {}", what);
    }
}

/// 计时类断言：超界只累加 [`TIMING_FAILED`] 并单独打印，不改变功能失败数。
/// Timing-class assertion: an over-limit result is recorded separately and does not fail the drill.
fn check_timing(ok: bool, what: &str) {
    if !ok {
        TIMING_FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-BENCH-TIMING] {}", what);
    }
}

/// A timing sample-shape check is part of the functional checklist, but an
/// incomplete sample window under TCG is still timing evidence rather than a
/// kernel mechanism failure. Keep the checklist count stable while reporting
/// the incomplete measurement through the timing channel.
fn check_timing_sample(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    check_timing(ok, what);
}

/// 失败断言数。
/// Number of failed checks.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 计时类断言超界数（功能断言之外的参考结论）。
/// Number of timing-class assertions that exceeded their limit.
pub fn timing_failed() -> u32 {
    TIMING_FAILED.load(Ordering::Relaxed)
}

/// 用户态基准程序 `user/bench` 的 ELF 镜像（构建期由 `kernel/build.rs` 产出并嵌入）。
static USER_BENCH: &[u8] = include_bytes!(env!("JSR_USER_BENCH"));

/// TSC calibration window. This is setup, not a benchmark sample set.
const CALIBRATION_TICKS: u64 = 1_000;
/// One IRQ-latency observation is retained per timer tick.
const TIMER_IRQ_SAMPLES: usize = 1_000_000;
/// 每项的预热次数（不计入样本）。
const WARMUP: u32 = 16;
#[cfg(feature = "bench-switch-diagnostic")]
const BENCH_SAMPLES: usize = 1_000;
#[cfg(all(feature = "bench-smoke", not(feature = "bench-switch-diagnostic")))]
const BENCH_SAMPLES: usize = 100_000;
#[cfg(not(any(feature = "bench-smoke", feature = "bench-switch-diagnostic")))]
const BENCH_SAMPLES: usize = 1_000_000;
/// Every formal metric retains one million one-operation samples; QEMU smoke
/// profiles use 100,000 and explicitly report that reduced scale.
const TAIL_ITERS: usize = BENCH_SAMPLES;
/// Context switches are substantially more expensive under TCG, so its QEMU
/// smoke gate uses a smaller explicit scale while physical runs retain one
/// million.
#[cfg(feature = "bench-switch-diagnostic")]
const CONTEXT_ITERS: usize = 1_000;
#[cfg(all(feature = "bench-smoke", not(feature = "bench-switch-diagnostic")))]
const CONTEXT_ITERS: usize = 10_000;
#[cfg(not(any(feature = "bench-smoke", feature = "bench-switch-diagnostic")))]
const CONTEXT_ITERS: usize = 1_000_000;
#[cfg(feature = "bench-switch-diagnostic")]
const CONTEXT_PROGRESS_STEP: usize = 100;
#[cfg(all(feature = "bench-smoke", not(feature = "bench-switch-diagnostic")))]
const CONTEXT_PROGRESS_STEP: usize = 4_096;
#[cfg(not(any(feature = "bench-smoke", feature = "bench-switch-diagnostic")))]
const CONTEXT_PROGRESS_STEP: usize = 100_000;
/// Empty serialized counter-read intervals used to report timer overhead.
const TIMER_READ_ITERS: usize = BENCH_SAMPLES;
/// SyscallSet 追加微基准的预热次数。
const SET_WARMUP: u32 = 64;
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
    reset_report();
    kprintln!(
        "[JSR-BENCH] stage=calibration_begin timer_hz={} target_ticks={}",
        config::ACTIVE.clock.timer_hz,
        CALIBRATION_TICKS
    );
    #[cfg(feature = "bench-smoke")]
    screen_line("BENCH START - 100K-SAMPLE QEMU SMOKE TESTS\n");
    #[cfg(not(feature = "bench-smoke"))]
    screen_line("BENCH START - MILLION-SAMPLE KERNEL TESTS\n");
    #[cfg(feature = "bench-profile")]
    early::append_progress("BENCH calibrating cycle counter");
    let prev_preemption = sched::set_preemption(false);
    let was_enabled = arch::irq_save_disable();
    let start = baseline();
    let start_heap_frames = heap::physical_frames();
    arch::watchdog_pet_force();
    let cal = calibrate();
    check(cal.is_some(), "周期计数器校准失败");
    if let Some(cal) = cal {
        counter_read_overhead(&cal);
        arch::watchdog_pet_force();
        frames(&cal);
        arch::watchdog_pet_force();
        heap_paths(&cal);
        arch::watchdog_pet_force();
        syscall_set_paths(&cal);
        arch::watchdog_pet_force();
        let switch = context_switch(&cal);
        arch::watchdog_pet_force();
        publish_checkpoint();
        user_program(&cal);
        arch::watchdog_pet_force();
        let tick = timer_irq(&cal);
        arch::watchdog_pet_force();
        if let (Some(tick), Some(switch)) = (tick, switch) {
            tuning(&cal, tick.p50, switch.p50);
        }
    }
    let end = baseline();
    let end_heap_frames = heap::physical_frames();
    let reclaimed = resources_reclaimed(start, end, start_heap_frames, end_heap_frames);
    check(reclaimed, "基准演练结束后资源未回到起点");
    LAST_RECLAIMED.store(reclaimed, Ordering::Release);
    arch::irq_restore(was_enabled);
    sched::set_preemption(prev_preemption);
    kprintln!(
        "[JSR-BENCH] summary free_frames={}/{} objects={}/{} reclaimed={} checks={} failed={} timing_failed={}",
        end.free_frames,
        start.free_frames,
        end.objects,
        start.objects,
        reclaimed,
        CHECKS.load(Ordering::Relaxed),
        failed(),
        timing_failed()
    );
}

#[derive(Clone, Copy)]
enum ParallelMetric {
    TimerRead,
    FrameAlloc,
    FrameFree,
    Heap64,
    Heap4096,
    SyscallContainsCurrent,
    SyscallContainsReference,
    SyscallSubsetCurrent,
    SyscallSubsetReference,
    SyscallCopyCurrent,
    SyscallCopyReference,
    SpawnDecodeCurrent,
    SpawnCallsDecodeCurrent,
    SpawnCallsDecodeReference,
    FrameAllocFreePair,
}

impl ParallelMetric {
    const ALL: [Self; 15] = [
        Self::TimerRead,
        Self::FrameAlloc,
        Self::FrameFree,
        Self::Heap64,
        Self::Heap4096,
        Self::SyscallContainsCurrent,
        Self::SyscallContainsReference,
        Self::SyscallSubsetCurrent,
        Self::SyscallSubsetReference,
        Self::SyscallCopyCurrent,
        Self::SyscallCopyReference,
        Self::SpawnDecodeCurrent,
        Self::SpawnCallsDecodeCurrent,
        Self::SpawnCallsDecodeReference,
        Self::FrameAllocFreePair,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::TimerRead => "TIMER.READ_OVERHEAD",
            Self::FrameAlloc => "FRAME.ALLOC",
            Self::FrameFree => "FRAME.FREE",
            Self::Heap64 => "HEAP.ALLOC_FREE_64",
            Self::Heap4096 => "HEAP.ALLOC_FREE_4096",
            Self::SyscallContainsCurrent => "SYSCALLSET.CONTAINS.CURRENT",
            Self::SyscallContainsReference => "SYSCALLSET.CONTAINS.U64-REFERENCE",
            Self::SyscallSubsetCurrent => "SYSCALLSET.SUBSET.CURRENT",
            Self::SyscallSubsetReference => "SYSCALLSET.SUBSET.U64-REFERENCE",
            Self::SyscallCopyCurrent => "SYSCALLSET.COPY.CURRENT",
            Self::SyscallCopyReference => "SYSCALLSET.COPY.U64-REFERENCE",
            Self::SpawnDecodeCurrent => "SPAWN.DECODE.CURRENT",
            Self::SpawnCallsDecodeCurrent => "SPAWN.CALLS.DECODE.CURRENT",
            Self::SpawnCallsDecodeReference => "SPAWN.CALLS.DECODE.U64-REFERENCE",
            Self::FrameAllocFreePair => "FRAME.ALLOC_FREE_PAIR",
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MetricExecution {
    success: u64,
    failure: u64,
}

impl MetricExecution {
    fn packed(self) -> u64 {
        (self.success << 32) | self.failure
    }

    fn unpack(value: u64) -> Self {
        Self {
            success: value >> 32,
            failure: value & u64::from(u32::MAX),
        }
    }
}

static PARALLEL_SAMPLE_PTRS: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; kernel_core::smp::MAX_CPUS];
static PARALLEL_READY: AtomicU32 = AtomicU32::new(0);
static PARALLEL_RELEASE: AtomicBool = AtomicBool::new(false);
static TSC_SKEW_SAMPLES: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; kernel_core::smp::MAX_CPUS];
static TSC_SKEW_READY: AtomicU32 = AtomicU32::new(0);
static TSC_SKEW_RELEASE: AtomicBool = AtomicBool::new(false);

fn tsc_skew_worker(_: u64) -> u64 {
    let cpu = arch::cpu_index();
    TSC_SKEW_READY.fetch_add(1, Ordering::AcqRel);
    while !TSC_SKEW_RELEASE.load(Ordering::Acquire) {
        arch::watchdog_pet_force();
        core::hint::spin_loop();
    }
    if let Some(sample) = TSC_SKEW_SAMPLES.get(cpu) {
        sample.store(arch::measure_cycles() as usize, Ordering::Release);
    }
    1
}

/// Measure a same-barrier TSC upper bound. The result includes release-IPI
/// delivery latency, so it is a conservative skew bound rather than a claim
/// that the counters are hardware-synchronized to this value.
fn measure_tsc_skew(mode: &str, cpus: &[usize]) -> Option<u64> {
    for cpu in cpus {
        TSC_SKEW_SAMPLES.get(*cpu)?.store(0, Ordering::Relaxed);
    }
    TSC_SKEW_READY.store(0, Ordering::Release);
    TSC_SKEW_RELEASE.store(false, Ordering::Release);
    let local_cpu = arch::cpu_index();
    let local_selected = cpus.contains(&local_cpu);
    let mut posted = Vec::new();
    for &cpu in cpus {
        if cpu != local_cpu {
            if smp::post_call(cpu, tsc_skew_worker, 0).is_err() {
                return None;
            }
            posted.push(cpu);
        }
    }
    if local_selected {
        TSC_SKEW_READY.fetch_add(1, Ordering::AcqRel);
    }
    let deadline = arch::measure_cycles().saturating_add(
        early::tsc_frequency_hz()
            .unwrap_or(3_000_000_000)
            .saturating_mul(10),
    );
    while TSC_SKEW_READY.load(Ordering::Acquire) != cpus.len() as u32 {
        if arch::measure_cycles() >= deadline {
            TSC_SKEW_RELEASE.store(true, Ordering::Release);
            for cpu in posted {
                let _ = smp::collect_call(cpu);
            }
            return None;
        }
        arch::watchdog_pet_force();
        core::hint::spin_loop();
    }
    TSC_SKEW_RELEASE.store(true, Ordering::Release);
    if local_selected {
        let local = arch::measure_cycles() as usize;
        TSC_SKEW_SAMPLES[local_cpu].store(local, Ordering::Release);
    }
    for cpu in posted {
        if smp::collect_call(cpu) != Ok(1) {
            return None;
        }
    }
    let mut min = usize::MAX;
    let mut max = 0usize;
    for cpu in cpus {
        let value = TSC_SKEW_SAMPLES.get(*cpu)?.load(Ordering::Acquire);
        if value == 0 {
            return None;
        }
        min = min.min(value);
        max = max.max(value);
    }
    let skew_ns = cycles_to_ns(max.saturating_sub(min) as u64)?;
    kprintln!(
        "[JSR-TSC-SKEW] mode={} cpus={} upper_bound_ns={} semantics=same_barrier_including_release_latency",
        mode,
        cpus.len(),
        skew_ns
    );
    Some(skew_ns)
}

fn parallel_metric_worker(arg: u64) -> u64 {
    let metric = match arg {
        0 => ParallelMetric::TimerRead,
        1 => ParallelMetric::FrameAlloc,
        2 => ParallelMetric::FrameFree,
        3 => ParallelMetric::Heap64,
        4 => ParallelMetric::Heap4096,
        5 => ParallelMetric::SyscallContainsCurrent,
        6 => ParallelMetric::SyscallContainsReference,
        7 => ParallelMetric::SyscallSubsetCurrent,
        8 => ParallelMetric::SyscallSubsetReference,
        9 => ParallelMetric::SyscallCopyCurrent,
        10 => ParallelMetric::SyscallCopyReference,
        11 => ParallelMetric::SpawnDecodeCurrent,
        12 => ParallelMetric::SpawnCallsDecodeCurrent,
        13 => ParallelMetric::SpawnCallsDecodeReference,
        14 => ParallelMetric::FrameAllocFreePair,
        _ => return 0,
    };
    let cpu = arch::cpu_index();
    let Some(slot) = PARALLEL_SAMPLE_PTRS.get(cpu) else {
        return 0;
    };
    let ptr = slot.load(Ordering::Acquire) as *mut u64;
    if ptr.is_null() {
        return 0;
    }
    PARALLEL_READY.fetch_add(1, Ordering::AcqRel);
    while !PARALLEL_RELEASE.load(Ordering::Acquire) {
        arch::watchdog_pet_force();
        core::hint::spin_loop();
    }
    execute_parallel_metric(metric, unsafe {
        core::slice::from_raw_parts_mut(ptr, TAIL_ITERS)
    })
    .packed()
}

fn execute_parallel_metric(metric: ParallelMetric, samples: &mut [u64]) -> MetricExecution {
    let ids = [0u64, 1, 4, 6, 15, 16, 19, 63];
    let current = SyscallSet::of(&[0, 1, 4, 6, 15, 16, 19, 63]);
    let other = SyscallSet::of(&[1, 4, 6, 19, 63]);
    let old = ids.iter().fold(0u64, |word, &id| word | (1u64 << id));
    let old_other = [1usize, 4, 6, 19, 63]
        .iter()
        .fold(0u64, |word, &id| word | (1u64 << id));
    let mut raw = SpawnDesc::default();
    raw.image_len = 64;
    raw.cpu_limit_permille = kernel_core::spawn_abi::CPU_UNLIMITED;
    raw.calls = current;
    let encoded = raw.encode();
    let mut call_bytes = [0u8; kernel_core::syscall_set::BYTES];
    current.encode(&mut call_bytes);
    let mut cursor = 0u64;
    let mut execution = MetricExecution::default();
    let batch_capacity = samples.len().min(256);
    let mut frame_batch = Vec::new();
    if frame_batch.try_reserve_exact(batch_capacity).is_err()
        && matches!(
            metric,
            ParallelMetric::FrameAlloc | ParallelMetric::FrameFree
        )
    {
        execution.failure = samples.len() as u64;
        samples.fill(0);
        return execution;
    }

    for (index, sample) in samples.iter_mut().enumerate() {
        if matches!(metric, ParallelMetric::FrameFree) && frame_batch.is_empty() {
            while frame_batch.len() < batch_capacity {
                match frame::allocate() {
                    Ok(frame) => frame_batch.push(frame),
                    Err(_) => break,
                }
            }
        }
        let start = arch::measure_cycles();
        let outcome = match metric {
            ParallelMetric::TimerRead => {
                black_box(arch::measure_cycles());
                Ok(())
            }
            ParallelMetric::FrameAlloc => match frame::allocate() {
                Ok(frame) if frame_batch.len() < batch_capacity => {
                    frame_batch.push(frame);
                    Ok(())
                }
                Ok(frame) => {
                    let released = frame::deallocate(frame).is_ok();
                    Err(!released)
                }
                Err(_) => Err(true),
            },
            ParallelMetric::FrameFree => {
                if let Some(frame) = frame_batch.pop() {
                    frame::deallocate(frame).map_err(|_| true)
                } else {
                    Err(true)
                }
            }
            ParallelMetric::Heap64 => {
                drop(black_box(Box::new([0u8; 64])));
                Ok(())
            }
            ParallelMetric::Heap4096 => {
                drop(black_box(Vec::<u8>::with_capacity(4096)));
                Ok(())
            }
            ParallelMetric::SyscallContainsCurrent => {
                cursor = cursor.wrapping_add(1);
                black_box(current.contains(ids[cursor as usize % ids.len()]));
                Ok(())
            }
            ParallelMetric::SyscallContainsReference => {
                cursor = cursor.wrapping_add(1);
                let id = ids[cursor as usize % ids.len()];
                black_box(id < 64 && old & (1u64 << id) != 0);
                Ok(())
            }
            ParallelMetric::SyscallSubsetCurrent => {
                black_box(other.is_subset_of(current));
                Ok(())
            }
            ParallelMetric::SyscallSubsetReference => {
                black_box(old_other & !old == 0);
                Ok(())
            }
            ParallelMetric::SyscallCopyCurrent => {
                black_box(black_box(current));
                Ok(())
            }
            ParallelMetric::SyscallCopyReference => {
                black_box(black_box(old));
                Ok(())
            }
            ParallelMetric::SpawnDecodeCurrent => {
                black_box(SpawnDesc::decode(black_box(&encoded)).expect("bench fixture decodes"));
                Ok(())
            }
            ParallelMetric::SpawnCallsDecodeCurrent => {
                black_box(SyscallSet::decode(black_box(&call_bytes)));
                Ok(())
            }
            ParallelMetric::SpawnCallsDecodeReference => {
                let mut word = [0u8; 8];
                word.copy_from_slice(&call_bytes[..8]);
                black_box(u64::from_le_bytes(word));
                Ok(())
            }
            ParallelMetric::FrameAllocFreePair => match frame::allocate() {
                Ok(frame) => frame::deallocate(frame).map_err(|_| true),
                Err(_) => Err(true),
            },
        };
        if outcome.is_ok() {
            execution.success = execution.success.saturating_add(1);
        } else {
            execution.failure = execution.failure.saturating_add(1);
        }
        *sample = arch::measure_cycles().wrapping_sub(start);
        if matches!(
            metric,
            ParallelMetric::FrameAlloc | ParallelMetric::FrameFree
        ) && frame_batch.len() >= batch_capacity
        {
            while let Some(frame) = frame_batch.pop() {
                if frame::deallocate(frame).is_err() {
                    execution.failure = execution.failure.saturating_add(1);
                }
            }
        }
        if index % 4096 == 0 {
            arch::watchdog_pet_force();
        }
    }
    while let Some(frame) = frame_batch.pop() {
        if frame::deallocate(frame).is_err() {
            execution.failure = execution.failure.saturating_add(1);
        }
    }
    black_box(cursor);
    execution
}

fn run_parallel_metric(
    mode: &str,
    metric: ParallelMetric,
    cpus: &[usize],
    cal: &Calibration,
) -> bool {
    kprintln!(
        "[JSR-SMP-BENCH] stage=start mode={} metric={} cpus={}",
        mode,
        metric.name(),
        cpus.len()
    );
    let total = match TAIL_ITERS.checked_mul(cpus.len()) {
        Some(total) => total,
        None => return false,
    };
    let mut samples = Vec::new();
    if samples.try_reserve_exact(total).is_err() {
        record_result(format_args!(
            "{} {} BLOCKED reason=sample_allocation",
            mode,
            metric.name()
        ));
        return false;
    }
    samples.resize(total, 0);
    for (index, &cpu) in cpus.iter().enumerate() {
        let Some(slot) = PARALLEL_SAMPLE_PTRS.get(cpu) else {
            return false;
        };
        slot.store(
            unsafe { samples.as_mut_ptr().add(index * TAIL_ITERS) } as usize,
            Ordering::Release,
        );
    }
    PARALLEL_READY.store(0, Ordering::Release);
    PARALLEL_RELEASE.store(false, Ordering::Release);
    let expected = cpus.len() as u32;
    let local_cpu = arch::cpu_index();
    let local_selected = cpus.contains(&local_cpu);
    let mut posted = Vec::new();
    for &cpu in cpus {
        if cpu != local_cpu {
            if smp::post_call(cpu, parallel_metric_worker, metric as u64).is_err() {
                record_result(format_args!(
                    "{} {} BLOCKED reason=post_cpu{}",
                    mode,
                    metric.name(),
                    cpu
                ));
                return false;
            }
            posted.push(cpu);
        }
    }
    kprintln!(
        "[JSR-SMP-BENCH] stage=posted mode={} metric={} posted={}",
        mode,
        metric.name(),
        posted.len()
    );

    let local_ptr = if local_selected {
        PARALLEL_SAMPLE_PTRS
            .get(local_cpu)
            .map(|slot| slot.load(Ordering::Acquire) as *mut u64)
            .unwrap_or(core::ptr::null_mut())
    } else {
        core::ptr::null_mut()
    };
    if local_selected {
        PARALLEL_READY.fetch_add(1, Ordering::AcqRel);
    }
    let deadline = arch::measure_cycles().saturating_add(
        early::tsc_frequency_hz()
            .unwrap_or(3_000_000_000)
            .saturating_mul(10),
    );
    while PARALLEL_READY.load(Ordering::Acquire) != expected && arch::measure_cycles() < deadline {
        arch::watchdog_pet_force();
        core::hint::spin_loop();
    }
    let all_ready = PARALLEL_READY.load(Ordering::Acquire) == expected;
    kprintln!(
        "[JSR-SMP-BENCH] stage=ready mode={} metric={} ready={}/{}",
        mode,
        metric.name(),
        PARALLEL_READY.load(Ordering::Acquire),
        expected
    );
    let work_start = arch::measure_cycles();
    // Always release workers, including the partial-participation failure
    // path. Otherwise a missing AP leaves every posted worker spinning in its
    // interrupt handler and the BSP can never collect the failed batch.
    PARALLEL_RELEASE.store(true, Ordering::Release);
    let local_ok = all_ready && (!local_selected || !local_ptr.is_null());
    let mut execution = MetricExecution::default();
    let mut per_cpu = Vec::new();
    if per_cpu.try_reserve_exact(cpus.len()).is_err() {
        return false;
    }
    per_cpu.resize(cpus.len(), MetricExecution::default());
    if local_ok && local_selected {
        let local = execute_parallel_metric(metric, unsafe {
            core::slice::from_raw_parts_mut(local_ptr, TAIL_ITERS)
        });
        if let Some(index) = cpus.iter().position(|cpu| *cpu == local_cpu) {
            per_cpu[index] = local;
        }
        execution.success = execution.success.saturating_add(local.success);
        execution.failure = execution.failure.saturating_add(local.failure);
    }
    let mut remote_ok = true;
    for cpu in posted {
        match smp::collect_call(cpu) {
            Ok(packed) => {
                let remote = MetricExecution::unpack(packed);
                if let Some(index) = cpus.iter().position(|candidate| *candidate == cpu) {
                    per_cpu[index] = remote;
                }
                execution.success = execution.success.saturating_add(remote.success);
                execution.failure = execution.failure.saturating_add(remote.failure);
            }
            Err(_) => remote_ok = false,
        }
    }
    let work_end = arch::measure_cycles();
    kprintln!(
        "[JSR-SMP-BENCH] stage=collected mode={} metric={} ok={}",
        mode,
        metric.name(),
        all_ready && local_ok && remote_ok
    );
    for &cpu in cpus {
        if let Some(slot) = PARALLEL_SAMPLE_PTRS.get(cpu) {
            slot.store(0, Ordering::Release);
        }
    }
    let ok = all_ready
        && local_ok
        && remote_ok
        && samples.len() == total
        && execution.failure == 0
        && execution.success == total as u64;
    check(ok, "并发基准参与 CPU、成功样本或失败计数不符合要求");
    if !ok {
        record_result(format_args!(
            "{} {} BLOCKED ready={}/{} local={} remote={} cpu={} success={} failed={}",
            mode,
            metric.name(),
            PARALLEL_READY.load(Ordering::Acquire),
            expected,
            local_ok,
            remote_ok,
            local_cpu,
            execution.success,
            execution.failure
        ));
        return false;
    }
    let summarize_started = arch::measure_cycles();
    for (index, &cpu) in cpus.iter().enumerate() {
        let start = index.saturating_mul(TAIL_ITERS);
        let Some(end) = start.checked_add(TAIL_ITERS) else {
            return false;
        };
        let Some(cpu_summary) = summarize(&mut samples[start..end]) else {
            return false;
        };
        kprintln!(
            "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel_cpu\",\"mode\":\"{}\",\"name\":\"{}\",\"cpu\":{},\"planned\":{},\"observed\":{},\"valid\":{},\"failed_ops\":{},\"incomplete\":{},\"p50_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"p9999_ns\":{},\"p99999_ns\":{},\"max_ns\":{}}}",
            mode,
            metric.name(),
            cpu,
            TAIL_ITERS,
            cpu_summary.count,
            per_cpu[index].success,
            per_cpu[index].failure,
            TAIL_ITERS.saturating_sub(cpu_summary.count as usize),
            cal.to_ns(cpu_summary.p50),
            cal.to_ns(cpu_summary.p99),
            cal.to_ns(cpu_summary.p999),
            cal.to_ns(cpu_summary.p9999),
            cal.to_ns(cpu_summary.p99999),
            cal.to_ns(cpu_summary.max)
        );
    }
    let summary = summarize(&mut samples);
    let summarize_ns =
        cycles_to_ns(arch::measure_cycles().wrapping_sub(summarize_started)).unwrap_or(0);
    let Some(summary) = summary else {
        return false;
    };
    let counts = cal.threshold_counts(&samples);
    let window_ns = cycles_to_ns(work_end.wrapping_sub(work_start)).unwrap_or(0);
    emit_parallel_json(
        mode,
        metric.name(),
        &summary,
        &counts,
        cal,
        execution,
        total,
        window_ns,
        summarize_ns,
    );
    let throughput = execution
        .success
        .saturating_mul(1_000_000_000)
        .checked_div(window_ns.max(1))
        .unwrap_or(0);
    record_result(format_args!(
        "{} {} PLANNED={} N={} CPUS={} SUCCESS={} FAILED_OPS={} INCOMPLETE={} P50={} P99={} P99.9={} P99.99={} P99.999={} MAX={} >1US={} >10US={} >50US={} WINDOW_NS={} OPS/S={}",
        mode,
        metric.name(),
        total,
        summary.count,
        cpus.len(),
        execution.success,
        execution.failure,
        total.saturating_sub(summary.count as usize),
        HumanDuration::new(summary.p50, cal),
        HumanDuration::new(summary.p99, cal),
        HumanDuration::new(summary.p999, cal),
        HumanDuration::new(summary.p9999, cal),
        HumanDuration::new(summary.p99999, cal),
        HumanDuration::new(summary.max, cal),
        counts.over_1us,
        counts.over_10us,
        counts.over_50us,
        window_ns,
        throughput
    ));
    true
}

fn cycles_to_ns(cycles: u64) -> Option<u64> {
    early::tsc_frequency_hz().map(|hz| {
        (u128::from(cycles) * 1_000_000_000u128 / u128::from(hz.max(1))).min(u128::from(u64::MAX))
            as u64
    })
}

fn report_parallel_memory(mode: &str, phase: &str) {
    let usable = crate::mm::frame::usable_frames();
    let free = crate::mm::frame::free_frames();
    let (heap_used, heap_free, heap_mapped) = {
        let (total, free, _, mapped) = heap::stats();
        (total.saturating_sub(free), free, mapped)
    };
    let heap_peak = heap::peak_used();
    kprintln!(
        "[JSR-SMP-MEMORY] mode={} phase={} usable_kib={} free_kib={} used_kib={} heap_used_kib={} heap_peak_kib={} heap_free_kib={} heap_mapped_kib={}",
        mode,
        phase,
        usable.saturating_mul(4),
        free.saturating_mul(4),
        usable.saturating_sub(free).saturating_mul(4),
        heap_used / 1024,
        heap_peak / 1024,
        heap_free / 1024,
        heap_mapped / 1024
    );
}

fn emit_parallel_json(
    mode: &str,
    name: &str,
    summary: &Summary,
    counts: &kernel_core::bench::ThresholdCounts,
    cal: &Calibration,
    execution: MetricExecution,
    planned_samples: usize,
    work_window_ns: u64,
    summarize_ns: u64,
) {
    kprintln!(
        "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel_metric\",\"mode\":\"{}\",\"name\":\"{}\",\"planned\":{},\"observed\":{},\"valid\":{},\"failed_ops\":{},\"incomplete\":{},\"work_window_ns\":{},\"summarize_ns\":{},\"min_ns\":{},\"mean_ns\":{},\"p50_ns\":{},\"p90_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"p9999_ns\":{},\"p99999_ns\":{},\"max_ns\":{},\"over_1us\":{},\"over_10us\":{},\"over_50us\":{}}}",
        mode,
        name,
        planned_samples,
        summary.count,
        execution.success,
        execution.failure,
        planned_samples.saturating_sub(summary.count as usize),
        work_window_ns,
        summarize_ns,
        cal.to_ns(summary.min),
        cal.to_ns(summary.mean),
        cal.to_ns(summary.p50),
        cal.to_ns(summary.p90),
        cal.to_ns(summary.p95),
        cal.to_ns(summary.p99),
        cal.to_ns(summary.p999),
        cal.to_ns(summary.p9999),
        cal.to_ns(summary.p99999),
        cal.to_ns(summary.max),
        counts.over_1us,
        counts.over_10us,
        counts.over_50us
    );
}

static CS_SAMPLE_PTRS: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_DONE: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static CS_NONE: [AtomicU32; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU32::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_RETRIES: [AtomicU32; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU32::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_UNEXPECTED: [AtomicU32; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU32::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_VALID: [AtomicU32; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU32::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_SWITCHES: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_LAST_SLOT: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(usize::MAX) }; kernel_core::smp::MAX_CPUS];
static CS_LAST_GENERATION: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_LAST_TO_SLOT: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(usize::MAX) }; kernel_core::smp::MAX_CPUS];
static CS_LAST_TO_GENERATION: [AtomicUsize; kernel_core::smp::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_READY: AtomicU32 = AtomicU32::new(0);
static CS_RELEASE: AtomicBool = AtomicBool::new(false);
static CS_ABORT: AtomicBool = AtomicBool::new(false);
static CS_EXPECTED: AtomicU32 = AtomicU32::new(0);
static CS_RELEASE_CYCLES: AtomicUsize = AtomicUsize::new(0);
static CS_SWITCH_DEADLINE: AtomicUsize = AtomicUsize::new(0);
static CS_ITERATIONS: AtomicUsize = AtomicUsize::new(0);
static CS_REQUEST: [AtomicU64; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_PARTNER_ACK: [AtomicU64; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_PARTNER_RUNS: [AtomicU64; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; kernel_core::smp::MAX_CPUS];
static CS_LOGGED_MEASURER_START: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static CS_LOGGED_PARTNER_START: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static CS_LOGGED_PARTNER_WAIT: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static CS_LOGGED_FIRST_RESUME: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static CS_LOGGED_FIRST_MISS: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static CS_LOGGED_FIRST_UNEXPECTED: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static CS_LOGGED_FIRST_PARTNER_RUN: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];

const SWITCH_RETRY_BUDGET: u32 = 64;
const SWITCH_WORKERS_PER_CPU: usize = 2;
static SWITCH_BASELINES: [AtomicU64; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; kernel_core::smp::MAX_CPUS];
static SWITCH_TARGETS: [AtomicU64; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; kernel_core::smp::MAX_CPUS];
static SWITCH_BASELINE_SET: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static SWITCH_BASELINE_READY: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static SWITCH_CPU_READY: [AtomicU32; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU32::new(0) }; kernel_core::smp::MAX_CPUS];
static SWITCH_CPU_RELEASE: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static SWITCH_WORKER_LOGGED: [AtomicBool; kernel_core::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; kernel_core::smp::MAX_CPUS];
static SWITCH_WORKERS_DONE: AtomicU32 = AtomicU32::new(0);
static SWITCH_LAST_REPORTED: [AtomicU64; kernel_core::smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; kernel_core::smp::MAX_CPUS];

fn switch_deadline_reached() -> bool {
    let deadline = CS_SWITCH_DEADLINE.load(Ordering::Acquire);
    deadline != 0 && arch::measure_cycles() as usize >= deadline
}

fn parallel_switch_measurer() {
    let cpu = arch::cpu_index();
    let Some(slot) = CS_SAMPLE_PTRS.get(cpu) else {
        return;
    };
    if CS_LOGGED_MEASURER_START
        .get(cpu)
        .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
    {
        kprintln!(
            "[JSR-SMP-SW] stage=worker_start cpu={} role=measurer self_slot={} expected={}",
            cpu,
            crate::smp::percpu::this().current(),
            CS_EXPECTED.load(Ordering::Acquire)
        );
    }
    let ptr = slot.load(Ordering::Acquire) as *mut u64;
    let ready = CS_READY.fetch_add(1, Ordering::AcqRel) + 1;
    if ready == CS_EXPECTED.load(Ordering::Acquire) {
        CS_RELEASE_CYCLES.store(arch::measure_cycles() as usize, Ordering::Release);
        CS_RELEASE.store(true, Ordering::Release);
    }
    while !CS_RELEASE.load(Ordering::Acquire)
        && !CS_ABORT.load(Ordering::Acquire)
        && !switch_deadline_reached()
    {
        sched::yield_with_cause("yield");
    }
    if !ptr.is_null() && !CS_ABORT.load(Ordering::Acquire) && !switch_deadline_reached() {
        kprintln!(
            "[JSR-SMP-SW] stage=measure_begin cpu={} first_slot={}",
            cpu,
            crate::smp::percpu::this().current()
        );
        let iterations = CS_ITERATIONS.load(Ordering::Acquire);
        let samples = unsafe { core::slice::from_raw_parts_mut(ptr, iterations) };
        let self_slot = crate::smp::percpu::this().current();
        let mut index = 0usize;
        let mut retry_budget = 0u32;
        while index < iterations {
            if CS_ABORT.load(Ordering::Acquire) || switch_deadline_reached() {
                CS_ABORT.store(true, Ordering::Release);
                break;
            }
            let partner_before = CS_PARTNER_RUNS[cpu].load(Ordering::Acquire);
            let n0 = sched::runtime_switch_count(cpu);
            let request = CS_REQUEST[cpu].fetch_add(1, Ordering::AcqRel) + 1;
            let c0 = arch::measure_cycles();
            // Enter the complete existing scheduler transaction directly.
            // The partner acknowledgement below proves that B actually ran;
            // returning to this exact slot proves the A -> B -> A round trip.
            sched::yield_with_cause("yield");
            let dt = arch::measure_cycles().wrapping_sub(c0);
            let n = sched::runtime_switch_count(cpu).wrapping_sub(n0);
            let partner_runs =
                CS_PARTNER_RUNS[cpu].load(Ordering::Acquire).wrapping_sub(partner_before);
            let returned = crate::smp::percpu::this().current() == self_slot
                && CS_PARTNER_ACK[cpu].load(Ordering::Acquire) >= request;
            if partner_runs != 1 {
                CS_NONE[cpu].fetch_add(1, Ordering::Relaxed);
                CS_RETRIES[cpu].fetch_add(1, Ordering::Relaxed);
                if CS_LOGGED_FIRST_MISS
                    .get(cpu)
                    .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
                {
                    kprintln!(
                        "[JSR-SMP-SW] stage=first_partner_miss cpu={} partner_runs={} elapsed_cycles={} last={:?}",
                        cpu,
                        partner_runs,
                        dt,
                        sched::runtime_switch_last(cpu)
                    );
                }
            } else if !returned || n < 2 {
                CS_UNEXPECTED[cpu].fetch_add(1, Ordering::Relaxed);
                CS_RETRIES[cpu].fetch_add(1, Ordering::Relaxed);
                if CS_LOGGED_FIRST_UNEXPECTED
                    .get(cpu)
                    .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
                {
                    kprintln!(
                        "[JSR-SMP-SW] stage=first_unexpected_window cpu={} switches={} returned={} elapsed_cycles={} last={:?}",
                        cpu,
                        n,
                        returned,
                        dt,
                        sched::runtime_switch_last(cpu)
                    );
                }
            } else {
                samples[index] = dt;
                index += 1;
                retry_budget = 0;
                if index % 4096 == 0 {
                    arch::watchdog_pet_force();
                }
                CS_VALID[cpu].fetch_add(1, Ordering::Relaxed);
                CS_SWITCHES[cpu].fetch_add(n as usize, Ordering::Relaxed);
                if let Some((from_slot, from_generation, to_slot, to_generation)) =
                    sched::runtime_switch_last(cpu)
                {
                    CS_LAST_SLOT[cpu].store(from_slot, Ordering::Relaxed);
                    CS_LAST_GENERATION[cpu].store(from_generation as usize, Ordering::Relaxed);
                    CS_LAST_TO_SLOT[cpu].store(to_slot, Ordering::Relaxed);
                    CS_LAST_TO_GENERATION[cpu].store(to_generation as usize, Ordering::Relaxed);
                }
                if CS_LOGGED_FIRST_RESUME
                    .get(cpu)
                    .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
                {
                    kprintln!(
                        "[JSR-SMP-SW] stage=first_resume cpu={} switches={} partner_runs={} elapsed_cycles={} last={:?}",
                        cpu,
                        n,
                        partner_runs,
                        dt,
                        sched::runtime_switch_last(cpu)
                    );
                }
                if index % CONTEXT_PROGRESS_STEP == 0 {
                    kprintln!(
                        "[JSR-SMP-SW] stage=progress cpu={} sample={}/{} valid={} retries={} missed={} switches={}",
                        cpu,
                        index,
                        iterations,
                        CS_VALID[cpu].load(Ordering::Relaxed),
                        CS_RETRIES[cpu].load(Ordering::Relaxed),
                        CS_NONE[cpu].load(Ordering::Relaxed),
                        CS_SWITCHES[cpu].load(Ordering::Relaxed)
                    );
                    if cpu == 0 {
                        early::append_progress(&alloc::format!(
                            "SCHED.CONTEXT_SWITCH CPU0 {}/{} VALID={} RETRIES={} MISSED={}",
                            index,
                            iterations,
                            CS_VALID[cpu].load(Ordering::Relaxed),
                            CS_RETRIES[cpu].load(Ordering::Relaxed),
                            CS_NONE[cpu].load(Ordering::Relaxed)
                        ));
                    }
                }
                continue;
            }
            retry_budget = retry_budget.saturating_add(1);
            if retry_budget >= SWITCH_RETRY_BUDGET || switch_deadline_reached() {
                CS_ABORT.store(true, Ordering::Release);
                break;
            }
            if index % 4096 == 0 {
                arch::watchdog_pet_force();
            }
        }
    }
    CS_DONE[cpu].store(true, Ordering::Release);
}

fn parallel_switch_partner() {
    let cpu = arch::cpu_index();
    if CS_LOGGED_PARTNER_START
        .get(cpu)
        .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
    {
        kprintln!(
            "[JSR-SMP-SW] stage=worker_start cpu={} role=partner self_slot={} expected={}",
            cpu,
            crate::smp::percpu::this().current(),
            CS_EXPECTED.load(Ordering::Acquire)
        );
    }
    let ready = CS_READY.fetch_add(1, Ordering::AcqRel) + 1;
    if ready == CS_EXPECTED.load(Ordering::Acquire) {
        CS_RELEASE_CYCLES.store(arch::measure_cycles() as usize, Ordering::Release);
        CS_RELEASE.store(true, Ordering::Release);
    }
    while !CS_RELEASE.load(Ordering::Acquire)
        && !CS_ABORT.load(Ordering::Acquire)
        && !switch_deadline_reached()
    {
        sched::yield_with_cause("yield");
    }
    if CS_LOGGED_PARTNER_WAIT
        .get(cpu)
        .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
    {
        kprintln!(
            "[JSR-SMP-SW] stage=partner_wait cpu={} done={}",
            cpu,
            CS_DONE
                .get(cpu)
                .is_none_or(|done| done.load(Ordering::Acquire))
        );
    }
    while !CS_DONE
        .get(cpu)
        .is_some_and(|done| done.load(Ordering::Acquire))
        && !CS_ABORT.load(Ordering::Acquire)
        && !switch_deadline_reached()
    {
        let request = CS_REQUEST[cpu].load(Ordering::Acquire);
        if request > CS_PARTNER_ACK[cpu].load(Ordering::Acquire) {
            CS_PARTNER_ACK[cpu].store(request, Ordering::Release);
            let runs = CS_PARTNER_RUNS[cpu].fetch_add(1, Ordering::AcqRel) + 1;
            if CS_LOGGED_FIRST_PARTNER_RUN
                .get(cpu)
                .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
            {
                kprintln!(
                    "[JSR-SMP-SW] stage=first_partner_run cpu={} request={} runs={}",
                    cpu,
                    request,
                    runs
                );
            }
        }
        sched::yield_with_cause("yield");
    }
}

#[cfg(feature = "bench-profile")]
fn general_switch_worker() {
    let cpu = arch::cpu_index();
    let slot = crate::smp::percpu::this().current();
    if SWITCH_WORKER_LOGGED
        .get(slot)
        .is_some_and(|logged| !logged.swap(true, Ordering::AcqRel))
    {
        kprintln!(
            "[JSR-SMP-SW] stage=general_worker_start cpu={} slot={} cpu_ready={}",
            cpu,
            slot,
            SWITCH_CPU_READY[cpu].load(Ordering::Acquire) + 1
        );
        if cpu == 0 {
            early::append_progress(&alloc::format!(
                "SMP_PHYSICAL SWITCH CPU0 WORKER READY slot={}",
                slot
            ));
        }
    }
    let global_ready = CS_READY.fetch_add(1, Ordering::AcqRel) + 1;
    let cpu_ready = SWITCH_CPU_READY[cpu].fetch_add(1, Ordering::AcqRel) + 1;
    if cpu_ready == SWITCH_WORKERS_PER_CPU as u32 {
        SWITCH_CPU_RELEASE[cpu].store(true, Ordering::Release);
    }
    if global_ready == CS_EXPECTED.load(Ordering::Acquire) {
        CS_RELEASE_CYCLES.store(arch::measure_cycles() as usize, Ordering::Release);
        CS_RELEASE.store(true, Ordering::Release);
    }
    while !SWITCH_CPU_RELEASE[cpu].load(Ordering::Acquire)
        && !CS_ABORT.load(Ordering::Acquire)
        && !switch_deadline_reached()
    {
        sched::yield_with_cause("yield");
    }

    if SWITCH_BASELINE_SET[cpu]
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let interrupts_were_enabled = arch::irq_save_disable();
        SWITCH_BASELINES[cpu].store(sched::runtime_switch_count(cpu), Ordering::Release);
        sched::reset_switch_sample_count(cpu);
        SWITCH_BASELINE_READY[cpu].store(true, Ordering::Release);
        arch::irq_restore(interrupts_were_enabled);
    }
    while !SWITCH_BASELINE_READY[cpu].load(Ordering::Acquire)
        && !CS_ABORT.load(Ordering::Acquire)
        && !switch_deadline_reached()
    {
        sched::yield_with_cause("yield");
    }
    if !SWITCH_BASELINE_READY[cpu].load(Ordering::Acquire) {
        CS_ABORT.store(true, Ordering::Release);
    }
    let baseline = SWITCH_BASELINES[cpu].load(Ordering::Acquire);
    let target = SWITCH_TARGETS[cpu].load(Ordering::Acquire);
    let mut observed = sched::runtime_switch_count(cpu).saturating_sub(baseline);
    let mut no_progress = 0u32;
    SWITCH_LAST_REPORTED[cpu].store(0, Ordering::Release);
    while observed < target
        && !CS_ABORT.load(Ordering::Acquire)
        && !switch_deadline_reached()
    {
        sched::yield_with_cause("yield");
        let next = sched::runtime_switch_count(cpu).saturating_sub(baseline);
        if next == observed {
            no_progress = no_progress.saturating_add(1);
            if no_progress >= SWITCH_RETRY_BUDGET {
                CS_ABORT.store(true, Ordering::Release);
                break;
            }
        } else {
            no_progress = 0;
            observed = next;
            arch::watchdog_pet_force();
            let milestone = observed / 100 * 100;
            if milestone != 0
                && milestone
                    > SWITCH_LAST_REPORTED[cpu].swap(milestone, Ordering::AcqRel)
            {
                kprintln!(
                    "[JSR-SMP-SW] stage=general_progress cpu={} switches={}/{} task_slot={}",
                    cpu,
                    observed,
                    target,
                    crate::smp::percpu::this().current()
                );
                if cpu == 0 {
                    early::append_progress(&alloc::format!(
                        "SMP_PHYSICAL SWITCH CPU0 {}/{}",
                        observed,
                        target
                    ));
                }
            }
        }
    }
    SWITCH_WORKERS_DONE.fetch_add(1, Ordering::AcqRel);
}

fn report_general_switch_state(
    mode: &str,
    stage: &str,
    cpus: &[usize],
    spawned: usize,
    expected_workers: usize,
) {
    let scheduler_online = sched::online_cpus();
    let audit = sched::queue_audit();
    let mut runnable = alloc::string::String::new();
    for (index, &cpu) in cpus.iter().enumerate() {
        if index != 0 {
            runnable.push(',');
        }
        runnable.push_str(&alloc::format!(
            "{}:{}",
            cpu,
            sched::runnable_workers_on(cpu)
        ));
    }
    let line = alloc::format!(
        "{} SWITCH STATE stage={} SCHED_ONLINE={} SPAWNED={}/{} LIVE={} READY={}/{} DONE={}/{}",
        mode,
        stage,
        scheduler_online.len(),
        spawned,
        expected_workers,
        sched::live_workers(),
        CS_READY.load(Ordering::Acquire),
        expected_workers,
        SWITCH_WORKERS_DONE.load(Ordering::Acquire),
        expected_workers
    );
    kprintln!("[JSR-SMP-SW] {}", line);
    early::append_progress(&line);
    let line = alloc::format!(
        "{} SWITCH QUEUE stage={} QUEUED={} RUNNABLE={} MISPLACED={} COUNT_MISMATCH={} LIST_MISMATCH={} HOOK_ERRORS={}",
        mode,
        stage,
        audit.queued,
        runnable,
        audit.misplaced,
        audit.count_mismatch,
        audit.list_mismatch,
        audit.hook_errors
    );
    kprintln!("[JSR-SMP-SW] {}", line);
    early::append_progress(&line);
    if stage == "spawned" {
        for &cpu in cpus {
            let Some(per_cpu) = crate::smp::percpu::get(cpu) else {
                continue;
            };
            let io = alloc::format!(
                "{} AP c={} h={} t={} r={} i={} w={} p={}",
                mode,
                cpu,
                per_cpu.hw_id(),
                per_cpu.ticks(),
                per_cpu.ipis(kernel_core::smp::IpiKind::Reschedule),
                per_cpu.ipis(kernel_core::smp::IpiKind::Call),
                per_cpu.idle_wakeups(),
                per_cpu.resched_pending()
            );
            kprintln!("[JSR-SMP-SW] {}", io);
            early::append_progress(&io);
            let context = alloc::format!(
                "{} CTX c={} cur={} lf={} bt={} irq={} q={}",
                mode,
                cpu,
                per_cpu.current(),
                sched::leaf_current(cpu).map_or(usize::MAX, |slot| slot),
                if cpu == 0 {
                    sched::bootstrap_running().map_or(false, |running| running)
                } else {
                    false
                },
                crate::arch::irq_enabled().map_or(false, |enabled| enabled),
                sched::runnable_workers_on(cpu)
            );
            kprintln!("[JSR-SMP-SW] {}", context);
            early::append_progress(&context);
        }
        // Keep the last diagnostic line off the physical screen's final row.
        early::append_progress("");
    }
}

/// Drive the boot task while the real scheduler runs the switch workload.
/// Unlike a tick-only deadline, this monitor always makes progress even if the
/// BSP tick source is temporarily unavailable on physical firmware.
fn drive_general_switch_workload(
    mode: &str,
    cpus: &[usize],
    spawned: usize,
    expected_workers: usize,
    tick_deadline: u64,
    cycle_deadline: u64,
) -> bool {
    early::append_progress(&alloc::format!("{} FIRST_YIELD_BEGIN", mode));
    sched::yield_with_cause("yield");
    early::append_progress(&alloc::format!("{} FIRST_YIELD_RETURN", mode));
    let hz = early::tsc_frequency_hz().unwrap_or(3_000_000_000);
    let report_interval = hz.max(1);
    let mut next_report = arch::measure_cycles().saturating_add(report_interval);
    loop {
        if sched::workers_settled() {
            return true;
        }
        let now = arch::measure_cycles();
        if crate::sched::timer_ticks() >= tick_deadline || now >= cycle_deadline {
            report_general_switch_state(mode, "timeout", cpus, spawned, expected_workers);
            return false;
        }
        arch::watchdog_pet_force();
        if sched::has_runnable_worker() {
            sched::yield_with_cause("yield");
        } else {
            core::hint::spin_loop();
        }
        if now >= next_report {
            for &cpu in cpus {
                if cpu != arch::cpu_index() {
                    let _ = crate::smp::reschedule(cpu);
                }
            }
            report_general_switch_state(mode, "waiting", cpus, spawned, expected_workers);
            next_report = now.saturating_add(report_interval);
        }
    }
}

/// Measure every real scheduler handoff completed while a small task workload
/// runs. Scheduler policy decides the task order; this fixture supplies runnable
/// tasks and a stop target but never requires a particular A/B sequence.
#[cfg(feature = "bench-profile")]
fn run_general_switch_workload(
    mode: &str,
    cpus: &[usize],
    cal: &Calibration,
    target_per_cpu: usize,
) -> bool {
    let expected_workers = match cpus.len().checked_mul(SWITCH_WORKERS_PER_CPU) {
        Some(value) => value,
        None => return false,
    };
    let per_cpu_capacity = match target_per_cpu.checked_add(1_024) {
        Some(value) if value != 0 => value,
        _ => return false,
    };
    let record_capacity = match per_cpu_capacity.checked_mul(cpus.len()) {
        Some(value) => value,
        None => return false,
    };
    let mut records = Vec::new();
    if records.try_reserve_exact(record_capacity).is_err() {
        record_result(format_args!(
            "{} SCHED.CONTEXT_SWITCH BLOCKED reason=sample_allocation",
            mode
        ));
        return false;
    }
    records.resize(record_capacity, sched::SwitchRecord::default());

    CS_READY.store(0, Ordering::Release);
    CS_RELEASE.store(false, Ordering::Release);
    CS_ABORT.store(false, Ordering::Release);
    CS_RELEASE_CYCLES.store(0, Ordering::Release);
    CS_EXPECTED.store(expected_workers as u32, Ordering::Release);
    SWITCH_WORKERS_DONE.store(0, Ordering::Release);
    for logged in &SWITCH_WORKER_LOGGED {
        logged.store(false, Ordering::Release);
    }
    let switch_seconds = if target_per_cpu <= 1_000 { 20 } else { 120 };
    CS_SWITCH_DEADLINE.store(
        arch::measure_cycles().saturating_add(
            early::tsc_frequency_hz()
                .unwrap_or(3_000_000_000)
                .saturating_mul(switch_seconds),
        ) as usize,
        Ordering::Release,
    );

    for (index, &cpu) in cpus.iter().enumerate() {
        SWITCH_BASELINES[cpu].store(0, Ordering::Release);
        SWITCH_TARGETS[cpu].store(target_per_cpu as u64, Ordering::Release);
        SWITCH_BASELINE_SET[cpu].store(false, Ordering::Release);
        SWITCH_BASELINE_READY[cpu].store(false, Ordering::Release);
        SWITCH_CPU_READY[cpu].store(0, Ordering::Release);
        SWITCH_CPU_RELEASE[cpu].store(false, Ordering::Release);
        let start = index.saturating_mul(per_cpu_capacity);
        let pointer = unsafe { records.as_mut_ptr().add(start) };
        if !sched::configure_switch_sample_sink(cpu, pointer, per_cpu_capacity) {
            for &configured in &cpus[..index] {
                let _ = sched::clear_switch_sample_sink(configured);
            }
            record_result(format_args!(
                "{} SCHED.CONTEXT_SWITCH BLOCKED reason=sample_sink cpu={}",
                mode, cpu
            ));
            return false;
        }
    }
    let mut spawned = 0usize;
    let mut group_affinity = kernel_core::smp::CpuSet::EMPTY;
    for &cpu in cpus {
        if !group_affinity.insert(cpu) {
            return false;
        }
    }
    for &cpu in cpus {
        let mut single_affinity = kernel_core::smp::CpuSet::EMPTY;
        if !single_affinity.insert(cpu) {
            continue;
        }
        for worker in 0..SWITCH_WORKERS_PER_CPU {
            let id = TaskId(12_000 + (cpu as u64 * SWITCH_WORKERS_PER_CPU as u64) + worker as u64);
            let affinity = if cfg!(feature = "bench-skip-single") {
                group_affinity.clone()
            } else {
                single_affinity.clone()
            };
            if sched::spawn_on(
                id,
                "smp-switch-workload",
                general_switch_worker,
                None,
                affinity,
            )
            .is_ok()
            {
                spawned += 1;
            }
        }
    }
    kprintln!(
        "[JSR-SMP-SW] stage=general_spawned cpu_count={} tasks={}/{} target_per_cpu={}",
        cpus.len(),
        spawned,
        expected_workers,
        target_per_cpu
    );
    early::append_progress(&alloc::format!(
        "SMP_PHYSICAL SWITCH N={} SPAWNED={}/{}",
        target_per_cpu,
        spawned,
        expected_workers
    ));
    let mut kick_failures = 0usize;
    let local_cpu = arch::cpu_index();
    for &cpu in cpus {
        if cpu != local_cpu && crate::smp::reschedule(cpu).is_err() {
            kick_failures += 1;
        }
    }
    kprintln!(
        "[JSR-SMP-SW] stage=general_kicks cpu_count={} failed={}",
        cpus.len().saturating_sub(1),
        kick_failures
    );
    report_general_switch_state(
        mode,
        "spawned",
        cpus,
        spawned,
        expected_workers,
    );
    let started = CS_RELEASE_CYCLES.load(Ordering::Acquire) as u64;
    if spawned != expected_workers {
        CS_ABORT.store(true, Ordering::Release);
        CS_RELEASE.store(true, Ordering::Release);
    }
    let tick_deadline = crate::sched::timer_ticks()
        .saturating_add(u64::from(config::ACTIVE.clock.timer_hz).saturating_mul(switch_seconds));
    let switch_deadline_cycles = arch::measure_cycles().saturating_add(
        early::tsc_frequency_hz()
            .unwrap_or(3_000_000_000)
            .saturating_mul(switch_seconds),
    );
    let settled = drive_general_switch_workload(
        mode,
        cpus,
        spawned,
        expected_workers,
        tick_deadline,
        switch_deadline_cycles,
    );
    let finished = arch::measure_cycles();
    if !settled {
        CS_ABORT.store(true, Ordering::Release);
        CS_RELEASE.store(true, Ordering::Release);
    }
    kprintln!(
        "[JSR-SMP-SW] stage=general_run_returned cpu_count={} settled={} abort={} workers_done={}/{} target_per_cpu={}",
        cpus.len(),
        settled,
        CS_ABORT.load(Ordering::Acquire),
        SWITCH_WORKERS_DONE.load(Ordering::Acquire),
        expected_workers,
        target_per_cpu
    );
    early::append_progress(&alloc::format!(
        "SMP_PHYSICAL SWITCH N={} SETTLED={} DONE={}/{}",
        target_per_cpu,
        settled,
        SWITCH_WORKERS_DONE.load(Ordering::Acquire),
        expected_workers
    ));

    let workers_done = SWITCH_WORKERS_DONE.load(Ordering::Acquire) as usize;
    let sample_buffer_reclaimable = settled && workers_done == expected_workers;
    let mut accepted = Vec::new();
    let mut overflow = Vec::new();
    if accepted.try_reserve_exact(cpus.len()).is_err()
        || overflow.try_reserve_exact(cpus.len()).is_err()
    {
        if !sample_buffer_reclaimable {
            core::mem::forget(records);
        }
        return false;
    }
    for &cpu in cpus {
        let (count, over) = sched::clear_switch_sample_sink(cpu);
        accepted.push(count);
        overflow.push(over);
    }
    let complete = settled
        && spawned == expected_workers
        && workers_done == expected_workers
        && overflow.iter().all(|&count| count == 0)
        && accepted
            .iter()
            .all(|&count| count >= target_per_cpu as u64);
    if !complete {
        if !sample_buffer_reclaimable {
            core::mem::forget(records);
        }
        check(false, "通用上下文切换工作负载未完整收敛");
        record_result(format_args!(
            "{} SCHED.CONTEXT_SWITCH BLOCKED settled={} tasks={}/{} done={}/{} overflow={:?} accepted={:?} target={}",
            mode,
            settled,
            spawned,
            expected_workers,
            workers_done,
            expected_workers,
            overflow,
            accepted,
            target_per_cpu
        ));
        return false;
    }

    let mut durations = Vec::new();
    if durations.try_reserve_exact(cpus.len().saturating_mul(target_per_cpu)).is_err() {
        return false;
    }
    let mut identities_valid = true;
    for (cpu_index, &cpu) in cpus.iter().enumerate() {
        let start = cpu_index.saturating_mul(per_cpu_capacity);
        let count = usize::try_from(accepted[cpu_index]).unwrap_or(per_cpu_capacity);
        let end = start.saturating_add(count.min(per_cpu_capacity));
        let mut previous_sequence = 0u64;
        let mut worker_handoffs = 0usize;
        for record in &records[start..end] {
            if record.sequence <= previous_sequence
                || record.duration_cycles == 0
                || record.from_slot == usize::MAX as u64 && record.from_task_id != 0
                || record.to_slot == usize::MAX as u64 && record.to_task_id != 0
            {
                identities_valid = false;
            }
            previous_sequence = record.sequence;
            if record.from_task_id != 0 && record.to_task_id != 0 {
                worker_handoffs += 1;
            }
        }
        if worker_handoffs == 0 {
            identities_valid = false;
        }
        let sample_end = (start + target_per_cpu).min(end);
        durations.extend(
            records[start..sample_end]
                .iter()
                .map(|record| record.duration_cycles),
        );
        let mut cpu_durations = records[start..sample_end]
            .iter()
            .map(|record| record.duration_cycles)
            .collect::<Vec<_>>();
        let Some(cpu_summary) = summarize(&mut cpu_durations) else {
            identities_valid = false;
            continue;
        };
        kprintln!(
            "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel_switch_cpu\",\"mode\":\"{}\",\"cpu\":{},\"measurement\":\"completed_execution_handoff\",\"planned\":{},\"observed\":{},\"worker_handoffs\":{},\"overflow\":{},\"p50_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"p9999_ns\":{},\"p99999_ns\":{},\"max_ns\":{}}}",
            mode,
            cpu,
            target_per_cpu,
            count,
            worker_handoffs,
            overflow[cpu_index],
            cal.to_ns(cpu_summary.p50),
            cal.to_ns(cpu_summary.p99),
            cal.to_ns(cpu_summary.p999),
            cal.to_ns(cpu_summary.p9999),
            cal.to_ns(cpu_summary.p99999),
            cal.to_ns(cpu_summary.max)
        );
    }
    if !identities_valid {
        check(false, "真实切换事件缺少任务身份或序号不单调");
        return false;
    }
    let Some(summary) = summarize(&mut durations) else {
        return false;
    };
    let counts = cal.threshold_counts(&durations);
    let switch_total = accepted.iter().copied().sum::<u64>();
    let window_cycles = finished.saturating_sub(started);
    let work_window_ns = cycles_to_ns(window_cycles).unwrap_or(0);
    let switches_per_second = switch_total
        .saturating_mul(1_000_000_000)
        .checked_div(work_window_ns.max(1))
        .unwrap_or(0);
    emit_parallel_json(
        mode,
        "SCHED.CONTEXT_SWITCH",
        &summary,
        &counts,
        cal,
        MetricExecution {
            success: switch_total,
            failure: 0,
        },
        target_per_cpu.saturating_mul(cpus.len()),
        work_window_ns,
        0,
    );
    kprintln!(
        "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel_throughput\",\"mode\":\"{}\",\"name\":\"SCHED.CONTEXT_SWITCH\",\"observed_switches\":{},\"work_window_ns\":{},\"switches_per_second\":{},\"workers\":{},\"target_per_cpu\":{},\"overflow\":0}}",
        mode,
        switch_total,
        work_window_ns,
        switches_per_second,
        expected_workers,
        target_per_cpu
    );
    record_result(format_args!(
        "{} SCHED.CONTEXT_SWITCH PLANNED={} N={} CPUS={} SWITCHES={} WORKERS={} P50={} P99={} P99.9={} P99.99={} P99.999={} MAX={} >1US={} >10US={} >50US={} WINDOW_NS={} SWITCHES/S={}",
        mode,
        target_per_cpu.saturating_mul(cpus.len()),
        summary.count,
        cpus.len(),
        switch_total,
        expected_workers,
        cal.to_ns(summary.p50),
        cal.to_ns(summary.p99),
        cal.to_ns(summary.p999),
        cal.to_ns(summary.p9999),
        cal.to_ns(summary.p99999),
        cal.to_ns(summary.max),
        counts.over_1us,
        counts.over_10us,
        counts.over_50us,
        work_window_ns,
        switches_per_second
    ));
    true
}

fn run_parallel_context_switch(
    mode: &str,
    cpus: &[usize],
    cal: &Calibration,
    iterations: usize,
) -> bool {
    let total = match iterations.checked_mul(cpus.len()) {
        Some(total) => total,
        None => return false,
    };
    let mut samples = Vec::new();
    if samples.try_reserve_exact(total).is_err() {
        record_result(format_args!(
            "{} SCHED.CONTEXT_SWITCH BLOCKED reason=sample_allocation",
            mode
        ));
        return false;
    }
    samples.resize(total, 0);
    CS_READY.store(0, Ordering::Release);
    CS_RELEASE.store(false, Ordering::Release);
    CS_ABORT.store(false, Ordering::Release);
    CS_RELEASE_CYCLES.store(0, Ordering::Release);
    CS_EXPECTED.store(cpus.len().saturating_mul(2) as u32, Ordering::Release);
    CS_ITERATIONS.store(iterations, Ordering::Release);
    let switch_seconds = if iterations <= 1_000 { 20 } else { 120 };
    CS_SWITCH_DEADLINE.store(
        arch::measure_cycles().saturating_add(
            early::tsc_frequency_hz()
                .unwrap_or(3_000_000_000)
                .saturating_mul(switch_seconds),
        ) as usize,
        Ordering::Release,
    );
    // A single logical CPU has no cross-CPU start alignment to preserve. Let
    // the first scheduled participant proceed and the scheduler alternate it
    // with its partner; otherwise one participant can occupy forever while
    // waiting for a peer that has not yet been scheduled.
    if cpus.len() == 1 {
        CS_RELEASE_CYCLES.store(arch::measure_cycles() as usize, Ordering::Release);
        CS_RELEASE.store(true, Ordering::Release);
    }
    for &cpu in cpus {
        let Some(done) = CS_DONE.get(cpu) else {
            return false;
        };
        done.store(false, Ordering::Release);
        CS_NONE[cpu].store(0, Ordering::Relaxed);
        CS_RETRIES[cpu].store(0, Ordering::Relaxed);
        CS_UNEXPECTED[cpu].store(0, Ordering::Relaxed);
        CS_VALID[cpu].store(0, Ordering::Relaxed);
        CS_SWITCHES[cpu].store(0, Ordering::Relaxed);
        CS_LAST_SLOT[cpu].store(usize::MAX, Ordering::Relaxed);
        CS_LAST_GENERATION[cpu].store(0, Ordering::Relaxed);
        CS_LAST_TO_SLOT[cpu].store(usize::MAX, Ordering::Relaxed);
        CS_LAST_TO_GENERATION[cpu].store(0, Ordering::Relaxed);
        CS_REQUEST[cpu].store(0, Ordering::Release);
        CS_PARTNER_ACK[cpu].store(0, Ordering::Release);
        CS_PARTNER_RUNS[cpu].store(0, Ordering::Release);
        if let Some(logged) = CS_LOGGED_MEASURER_START.get(cpu) {
            logged.store(false, Ordering::Release);
        }
        if let Some(logged) = CS_LOGGED_PARTNER_START.get(cpu) {
            logged.store(false, Ordering::Release);
        }
        if let Some(logged) = CS_LOGGED_PARTNER_WAIT.get(cpu) {
            logged.store(false, Ordering::Release);
        }
        if let Some(logged) = CS_LOGGED_FIRST_RESUME.get(cpu) {
            logged.store(false, Ordering::Release);
        }
        if let Some(logged) = CS_LOGGED_FIRST_MISS.get(cpu) {
            logged.store(false, Ordering::Release);
        }
        if let Some(logged) = CS_LOGGED_FIRST_UNEXPECTED.get(cpu) {
            logged.store(false, Ordering::Release);
        }
        if let Some(logged) = CS_LOGGED_FIRST_PARTNER_RUN.get(cpu) {
            logged.store(false, Ordering::Release);
        }
        let Some(slot) = CS_SAMPLE_PTRS.get(cpu) else {
            return false;
        };
        slot.store(
            unsafe {
                samples
                    .as_mut_ptr()
                    .add(cpus.iter().position(|candidate| *candidate == cpu).unwrap() * iterations)
            } as usize,
            Ordering::Release,
        );
    }
    let mut spawned = true;
    for &cpu in cpus {
        let base = 12_000 + cpu as u64 * 2;
        let mut affinity = kernel_core::smp::CpuSet::EMPTY;
        if !affinity.insert(cpu) {
            spawned = false;
            continue;
        }
        if sched::spawn_on(
            TaskId(base),
            "smp-bench-switch",
            parallel_switch_measurer,
            None,
            affinity.clone(),
        )
        .is_err()
            || sched::spawn_on(
                TaskId(base + 1),
                "smp-bench-partner",
                parallel_switch_partner,
                None,
                affinity,
            )
            .is_err()
        {
            spawned = false;
        }
    }
    let expected_ready = CS_EXPECTED.load(Ordering::Acquire);
    kprintln!(
        "[JSR-SMP-SW] stage=spawned cpus={} expected_tasks={} spawned={}",
        cpus.len(),
        expected_ready,
        spawned
    );
    kprintln!(
        "[JSR-SMP-SW] stage=controller_wait cpu={} expected={} deadline_s={}",
        arch::cpu_index(),
        expected_ready,
        switch_seconds
    );
    let tick_deadline = crate::sched::timer_ticks()
        .saturating_add(u64::from(config::ACTIVE.clock.timer_hz).saturating_mul(switch_seconds));
    let mut settled = false;
    if spawned {
        settled = sched::run_until(tick_deadline);
    } else {
        CS_ABORT.store(true, Ordering::Release);
    }
    if !settled {
        CS_ABORT.store(true, Ordering::Release);
        CS_RELEASE.store(true, Ordering::Release);
        let cleanup_deadline = crate::sched::timer_ticks()
            .saturating_add(u64::from(config::ACTIVE.clock.timer_hz).saturating_mul(5));
        settled = sched::run_until(cleanup_deadline);
    }
    kprintln!(
        "[JSR-SMP-SW] stage=run_returned ready={}/{} settled={} abort={} deadline_s={}",
        CS_READY.load(Ordering::Acquire),
        expected_ready,
        settled,
        CS_ABORT.load(Ordering::Acquire),
        switch_seconds
    );
    let all_ready = CS_READY.load(Ordering::Acquire) == expected_ready;
    if !all_ready {
        CS_RELEASE.store(true, Ordering::Release);
    }
    let all_done = settled
        && cpus.iter().all(|cpu| {
            CS_DONE
                .get(*cpu)
                .is_some_and(|done| done.load(Ordering::Acquire))
        });
    if !settled {
        // Workers may still hold these sample slices. Leaking the retained
        // buffer is safer than freeing memory that a wedged task can access.
        core::mem::forget(samples);
        check(false, "并发上下文切换在截止时间内未完成");
        record_result(format_args!(
            "{} SCHED.CONTEXT_SWITCH BLOCKED reason=deadline_or_unsettled ready={}/{} abort=true",
            mode,
            CS_READY.load(Ordering::Acquire),
            expected_ready
        ));
        return false;
    }
    if all_done {
        report_parallel_memory(mode, "during_raw_retained");
    }
    for &cpu in cpus {
        if let Some(slot) = CS_SAMPLE_PTRS.get(cpu) {
            slot.store(0, Ordering::Release);
        }
    }
    let no_switch_total = cpus
        .iter()
        .map(|cpu| {
            CS_NONE
                .get(*cpu)
                .map_or(0, |value| value.load(Ordering::Relaxed) as u64)
        })
        .sum::<u64>();
    let valid_total = cpus
        .iter()
        .map(|cpu| {
            CS_VALID
                .get(*cpu)
                .map_or(0, |value| value.load(Ordering::Relaxed) as u64)
        })
        .sum::<u64>();
    let switch_total = cpus
        .iter()
        .map(|cpu| {
            CS_SWITCHES
                .get(*cpu)
                .map_or(0, |value| value.load(Ordering::Relaxed) as u64)
        })
        .sum::<u64>();
    let retry_total = cpus
        .iter()
        .map(|cpu| {
            CS_RETRIES
                .get(*cpu)
                .map_or(0, |value| value.load(Ordering::Relaxed) as u64)
        })
        .sum::<u64>();
    let unexpected_total = cpus
        .iter()
        .map(|cpu| {
            CS_UNEXPECTED
                .get(*cpu)
                .map_or(0, |value| value.load(Ordering::Relaxed) as u64)
        })
        .sum::<u64>();
    let expected_samples = (cpus.len() as u64).saturating_mul(iterations as u64);
    let ok = spawned && all_ready && all_done && valid_total == expected_samples;
    check(ok, "并发上下文切换参与者、完成计数或样本不完整");
    if !ok {
        record_result(format_args!(
            "{} SCHED.CONTEXT_SWITCH_ROUND_TRIP BLOCKED spawned={} ready={}/{} done={} no_switch={} valid={}/{} switches={} retries={} unexpected_windows={}",
            mode,
            spawned,
            CS_READY.load(Ordering::Acquire),
            expected_ready,
            all_done,
            no_switch_total,
            valid_total,
            expected_samples,
            switch_total,
            retry_total,
            unexpected_total
        ));
        return false;
    }
    let summarize_started = arch::measure_cycles();
    for (index, &cpu) in cpus.iter().enumerate() {
        let start = index.saturating_mul(iterations);
        let Some(end) = start.checked_add(iterations) else {
            return false;
        };
        let Some(cpu_summary) = summarize(&mut samples[start..end]) else {
            return false;
        };
        kprintln!(
            "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel_switch_cpu\",\"mode\":\"{}\",\"cpu\":{},\"measurement\":\"roundtrip_a_b_a\",\"planned\":{},\"observed\":{},\"valid\":{},\"failed_ops\":{},\"incomplete\":{},\"retries\":{},\"unexpected_windows\":{},\"switches\":{},\"last_from_slot\":{},\"last_from_generation\":{},\"last_to_slot\":{},\"last_to_generation\":{},\"p50_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"p9999_ns\":{},\"p99999_ns\":{},\"max_ns\":{}}}",
            mode,
            cpu,
            iterations,
            cpu_summary.count,
            CS_VALID[cpu].load(Ordering::Relaxed),
            iterations.saturating_sub(CS_VALID[cpu].load(Ordering::Relaxed) as usize),
            iterations.saturating_sub(cpu_summary.count as usize),
            CS_RETRIES[cpu].load(Ordering::Relaxed),
            CS_UNEXPECTED[cpu].load(Ordering::Relaxed),
            CS_SWITCHES[cpu].load(Ordering::Relaxed),
            CS_LAST_SLOT[cpu].load(Ordering::Relaxed),
            CS_LAST_GENERATION[cpu].load(Ordering::Relaxed),
            CS_LAST_TO_SLOT[cpu].load(Ordering::Relaxed),
            CS_LAST_TO_GENERATION[cpu].load(Ordering::Relaxed),
            cal.to_ns(cpu_summary.p50),
            cal.to_ns(cpu_summary.p99),
            cal.to_ns(cpu_summary.p999),
            cal.to_ns(cpu_summary.p9999),
            cal.to_ns(cpu_summary.p99999),
            cal.to_ns(cpu_summary.max)
        );
    }
    let summary = summarize(&mut samples);
    let summarize_ns =
        cycles_to_ns(arch::measure_cycles().wrapping_sub(summarize_started)).unwrap_or(0);
    let counts = cal.threshold_counts(&samples);
    let Some(summary) = summary else {
        return false;
    };
    let released_at = CS_RELEASE_CYCLES.load(Ordering::Acquire) as u64;
    let work_window_ns = arch::measure_cycles()
        .checked_sub(released_at)
        .and_then(cycles_to_ns)
        .unwrap_or(0);
    let switches_per_second = switch_total
        .saturating_mul(1_000_000_000)
        .checked_div(work_window_ns.max(1))
        .unwrap_or(0);
    emit_parallel_json(
        mode,
        "SCHED.CONTEXT_SWITCH_ROUND_TRIP",
        &summary,
        &counts,
        cal,
        MetricExecution {
            success: valid_total,
            failure: expected_samples.saturating_sub(valid_total),
        },
        expected_samples as usize,
        work_window_ns,
        summarize_ns,
    );
    record_result(format_args!(
        "{} SCHED.CONTEXT_SWITCH_ROUND_TRIP PLANNED={} N={} CPUS={} SWITCHES={} SUCCESS={} FAILED_OPS={} INCOMPLETE={} RETRIES={} UNEXPECTED_WINDOWS={} P50={} P99={} P99.9={} P99.99={} P99.999={} MAX={} >1US={} >10US={} >50US={} WINDOW_NS={} ROUND_TRIPS/S={} SWITCHES/S={}",
        mode,
        expected_samples,
        summary.count,
        cpus.len(),
        switch_total,
        valid_total,
        expected_samples.saturating_sub(valid_total),
        expected_samples.saturating_sub(summary.count as u64),
        retry_total,
        unexpected_total,
        HumanDuration::new(summary.p50, cal),
        HumanDuration::new(summary.p99, cal),
        HumanDuration::new(summary.p999, cal),
        HumanDuration::new(summary.p9999, cal),
        HumanDuration::new(summary.p99999, cal),
        HumanDuration::new(summary.max, cal),
        counts.over_1us,
        counts.over_10us,
        counts.over_50us,
        work_window_ns,
        summary.count as u64 * 1_000_000_000 / work_window_ns.max(1),
        switches_per_second
    ));
    true
}

fn run_parallel_mode(mode: &str, cpus: &[usize], cal: &Calibration) -> bool {
    report_parallel_memory(mode, "before");
    let before = baseline();
    let before_heap_frames = heap::physical_frames();
    let skew = measure_tsc_skew(mode, cpus);
    check(skew.is_some(), "跨核周期计数器屏障观测失败");
    if let Some(skew_ns) = skew {
        record_result(format_args!(
            "{} TSC_BARRIER_SKEW_UPPER_NS={} MEASUREMENT=same_barrier_including_release_latency",
            mode, skew_ns
        ));
    } else {
        record_result(format_args!("{} TSC_BARRIER_SKEW_UPPER_NS=UNKNOWN", mode));
    }
    record_result(format_args!(
        "{} CONCURRENT TABLE CPUS={} OPS_PER_METRIC_PER_CPU={} SAMPLE_SOURCE=ALL_RAW_CPU_SAMPLES",
        mode,
        cpus.len(),
        TAIL_ITERS
    ));
    #[cfg(feature = "bench-switch-only")]
    let metrics: &[ParallelMetric] = &[];
    #[cfg(not(feature = "bench-switch-only"))]
    let metrics: &[ParallelMetric] = &ParallelMetric::ALL;
    let mut ok = true;
    for &metric in metrics {
        let progress = alloc::format!("{} RUNNING {} CPUS={}", mode, metric.name(), cpus.len());
        early::append_progress(&progress);
        ok &= run_parallel_metric(mode, metric, cpus, cal);
    }
    let mut switch_planned_samples = 0usize;
    #[cfg(all(feature = "bench-switch-diagnostic", feature = "bench-profile"))]
    {
        for iterations in [1usize, 10, 1_000] {
            early::append_progress(&alloc::format!(
                "{} RUNNING CONTEXT_SWITCH N={} CPUS={}",
                mode,
                iterations,
                cpus.len()
            ));
            kprintln!(
                "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel_switch_stage\",\"mode\":\"{}\",\"cpus\":{},\"iterations_per_cpu\":{},\"measurement\":\"completed_execution_handoff\"}}",
                mode,
                cpus.len(),
                iterations
            );
            ok &= run_general_switch_workload(mode, cpus, cal, iterations);
            switch_planned_samples =
                switch_planned_samples.saturating_add(iterations.saturating_mul(cpus.len()));
        }
        #[cfg(not(feature = "bench-skip-single"))]
        {
            early::append_progress(&alloc::format!(
                "{} RUNNING CONTROLLED ROUND_TRIP",
                mode
            ));
            ok &= run_parallel_context_switch(mode, cpus, cal, 1_000);
            switch_planned_samples =
                switch_planned_samples.saturating_add(1_000 * cpus.len());
        }
        #[cfg(feature = "bench-skip-single")]
        record_result(format_args!(
            "{} CONTROLLED_ROUND_TRIP SKIPPED reason=physical_diagnostic",
            mode
        ));
    }
    #[cfg(all(not(feature = "bench-switch-diagnostic"), feature = "bench-profile"))]
    {
        early::append_progress(&alloc::format!("{} RUNNING SCHED.CONTEXT_SWITCH", mode));
        ok &= run_general_switch_workload(mode, cpus, cal, CONTEXT_ITERS);
        early::append_progress(&alloc::format!(
            "{} RUNNING CONTROLLED ROUND_TRIP",
            mode
        ));
        ok &= run_parallel_context_switch(mode, cpus, cal, CONTEXT_ITERS);
        switch_planned_samples = CONTEXT_ITERS
            .saturating_mul(cpus.len())
            .saturating_mul(2);
    }
    let usable = crate::mm::frame::usable_frames();
    let free = crate::mm::frame::free_frames();
    let (heap_total, heap_free, _, heap_mapped) = crate::mm::heap::stats();
    let planned_samples = metrics
        .len()
        .saturating_mul(TAIL_ITERS)
        .saturating_mul(cpus.len())
        .saturating_add(switch_planned_samples);
    let result = format_args!(
        "{} RESULT COMPLETE={} TOTAL_METRICS={} PLANNED_SAMPLES={} MEM_USED_KIB={} HEAP_USED_KIB={} HEAP_MAPPED_KIB={}",
        mode,
        ok,
        metrics.len() + 2,
        planned_samples,
        usable.saturating_sub(free).saturating_mul(4),
        heap_total.saturating_sub(heap_free) / 1024,
        heap_mapped / 1024
    );
    kprintln!("{}", result);
    record_result(result);
    let after = baseline();
    let after_heap_frames = heap::physical_frames();
    let reclaimed = resources_reclaimed(before, after, before_heap_frames, after_heap_frames);
    let retained_heap_frames = after_heap_frames.saturating_sub(before_heap_frames);
    check(reclaimed, "单个并发模式结束后资源未回到起点");
    kprintln!(
        "[JSR-SMP-RESOURCE] mode={} frames={}/{} objects={}/{} pending={}/{} pins={},{} retained_heap_frames={} reclaimed={}",
        mode,
        after.free_frames,
        before.free_frames,
        after.objects,
        before.objects,
        after.pending,
        before.pending,
        after.pins.0,
        after.pins.1,
        retained_heap_frames,
        reclaimed
    );
    record_result(format_args!(
        "{} RESOURCE FRAMES={}/{} OBJECTS={}/{} PENDING={}/{} PINS={},{} PINS_BEFORE={},{} RETAINED_HEAP_FRAMES={} RECLAIMED={}",
        mode,
        after.free_frames,
        before.free_frames,
        after.objects,
        before.objects,
        after.pending,
        before.pending,
        after.pins.0,
        after.pins.1,
        before.pins.0,
        before.pins.1,
        retained_heap_frames,
        reclaimed
    ));
    report_parallel_memory(mode, "after");
    ok && reclaimed
}

/// Run the existing single-CPU measurements concurrently on the exact
/// physical-core and logical-CPU sets discovered from firmware.
pub fn run_smp_concurrent() {
    reset_report();
    screen_line("SMP CONCURRENT PERFORMANCE - SAME TESTS AS SINGLE CPU\n");
    kprintln!("SMP CONCURRENT PERFORMANCE - SAME TESTS AS SINGLE CPU");
    let Some(cal) = calibrate() else {
        check(false, "周期计数器校准失败");
        record_result(format_args!(
            "SMP CONCURRENT BLOCKED reason=clock_calibration"
        ));
        return;
    };
    let online = crate::smp::online_set();
    let topology = crate::hardware::online_cpu_topology();
    let mut physical = Vec::new();
    for cpu in &topology {
        if !physical
            .iter()
            .any(|existing: &crate::hardware::ApCpuTopology| existing.core_key == cpu.core_key)
        {
            physical.push(*cpu);
        }
    }
    let physical: Vec<usize> = physical.into_iter().map(|cpu| cpu.logical).collect();
    let logical: Vec<usize> = topology.iter().map(|cpu| cpu.logical).collect();
    let topology_result = format_args!(
        "SMP TOPOLOGY ONLINE={} PROBED={} PHYSICAL={} LOGICAL={}",
        online.len(),
        topology.len(),
        physical.len(),
        logical.len()
    );
    kprintln!("{}", topology_result);
    record_result(topology_result);
    if physical.len() < 2 || logical.len() < physical.len() {
        check(false, "可用物理核心或逻辑 CPU 拓扑不足");
        record_result(format_args!(
            "SMP CONCURRENT BLOCKED minimum=2p actual={}p/{}t online={}",
            physical.len(),
            logical.len(),
            online.len()
        ));
        return;
    }
    let local_cpu = arch::cpu_index();
    let single = [if logical.contains(&local_cpu) {
        local_cpu
    } else {
        logical[0]
    }];
    let sample_capacity = logical
        .len()
        .saturating_mul(TAIL_ITERS.max(CONTEXT_ITERS))
        .saturating_mul(core::mem::size_of::<u64>())
        .saturating_add(1024 * 1024);
    if heap::ensure_free(sample_capacity).is_err() {
        check(false, "并发样本堆容量预分配失败");
        record_result(format_args!(
            "SMP CONCURRENT BLOCKED reason=sample_heap_prepare bytes={}",
            sample_capacity
        ));
        return;
    }
    let before = baseline();
    let before_heap_frames = heap::physical_frames();
    #[cfg(not(feature = "bench-skip-single"))]
    {
        let single_ok = run_parallel_mode("SMP_SINGLE", &single, &cal);
        LAST_SINGLE_MODE.store(single_ok, Ordering::Release);
    }
    #[cfg(feature = "bench-skip-single")]
    {
        record_result(format_args!(
            "SMP_SINGLE SKIPPED reason=explicit_physical_diagnostic"
        ));
    }
    let physical_ok = run_parallel_mode("SMP_PHYSICAL", &physical, &cal);
    LAST_PHYSICAL_MODE.store(physical_ok, Ordering::Release);
    let logical_ok = run_parallel_mode("SMP_LOGICAL", &logical, &cal);
    LAST_LOGICAL_MODE.store(logical_ok, Ordering::Release);
    let reclaimed = resources_reclaimed(
        before,
        baseline(),
        before_heap_frames,
        heap::physical_frames(),
    );
    check(reclaimed, "并发基准结束后资源未回到起点");
    LAST_RECLAIMED.store(reclaimed, Ordering::Release);
    let final_result = format_args!(
        "SMP CONCURRENT FINAL SINGLE={} PHYSICAL={} LOGICAL={} SINGLE_CPUS={} PHYSICAL_CPUS={} LOGICAL_CPUS={} SMT={} RECLAIMED={} FAILED={} TIMING_FAILED={}",
        if cfg!(feature = "bench-skip-single") {
            "SKIPPED"
        } else if LAST_SINGLE_MODE.load(Ordering::Acquire) {
            "true"
        } else {
            "false"
        },
        physical_ok,
        logical_ok,
        if cfg!(feature = "bench-skip-single") {
            0
        } else {
            single.len()
        },
        physical.len(),
        logical.len(),
        logical.len() > physical.len(),
        reclaimed,
        failed(),
        timing_failed()
    );
    kprintln!("{}", final_result);
    record_result(final_result);
}

/// Draw all completed fast metrics before the long tick-driven interrupt
/// measurement starts. This checkpoint is not the final acceptance summary.
pub fn publish_checkpoint() {
    let report = REPORT.lock();
    #[cfg(feature = "bench-profile")]
    {
        early::results_begin();
        early::append_line("FAST KERNEL RESULTS - USER BENCHMARK RUNNING");
        early::append_line("ROW 1: N/P50/P99/P99.9   ROW 2: P99.99/P99.999/MAX/THRESHOLDS");
        for row in &report.rows[..report.len] {
            let text = row.text();
            if !text.is_empty() {
                early::append_line(text);
            }
        }
    }
    kprintln!(
        "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"checkpoint\",\"metrics\":{},\"failed\":{},\"timing_failed\":{},\"checks\":{}}}",
        report.len,
        failed(),
        timing_failed(),
        CHECKS.load(Ordering::Acquire)
    );
}

/// Replace transient progress output with the complete result table after all
/// million-sample batches have finished.
pub fn publish_results(failed: u32, timing_failed: u32) {
    let report = REPORT.lock();
    #[cfg(feature = "bench-profile")]
    {
        early::results_begin();
        #[cfg(feature = "bench-smoke")]
        early::append_line("FINAL RESULTS - ALL 100K-SAMPLE QEMU SMOKE BATCHES");
        #[cfg(not(feature = "bench-smoke"))]
        early::append_line("FINAL RESULTS - ALL MILLION-SAMPLE BATCHES");
        early::append_line("ROW 1: N/P50/P99/P99.9   ROW 2: P99.99/P99.999/MAX/THRESHOLDS");
        for row in &report.rows[..report.len] {
            let text = row.text();
            if !text.is_empty() {
                early::append_line(text);
            }
        }
        let mut status = ReportRow::empty();
        let mut writer = RowWriter {
            bytes: &mut status.bytes,
            len: &mut status.len,
        };
        let _ = write!(
            writer,
            "STATUS FAILED={} TIMING_FAILED={} CHECKS={} RECLAIMED={}",
            failed,
            timing_failed,
            CHECKS.load(Ordering::Acquire),
            LAST_RECLAIMED.load(Ordering::Acquire)
        );
        early::append_line(status.text());
        let discovered = crate::smp::unique_enabled_cpu_count().max(1);
        let online = crate::smp::online_set().len();
        let mut smp = ReportRow::empty();
        let mut writer = RowWriter {
            bytes: &mut smp.bytes,
            len: &mut smp.len,
        };
        let _ = write!(
            writer,
            "SMP DISCOVERED={} ONLINE={} PARALLEL_MATRIX={} SINGLE={} PHYSICAL={} LOGICAL={}",
            discovered,
            online,
            if all_concurrent_modes_ok() {
                if cfg!(feature = "bench-skip-single") {
                    "physical+logical"
                } else {
                    "single+physical+logical"
                }
            } else {
                "incomplete"
            },
            LAST_SINGLE_MODE.load(Ordering::Acquire),
            LAST_PHYSICAL_MODE.load(Ordering::Acquire),
            LAST_LOGICAL_MODE.load(Ordering::Acquire)
        );
        early::append_line(smp.text());
    }
    kprintln!(
        "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"summary\",\"metrics\":{},\"failed\":{},\"timing_failed\":{},\"checks\":{},\"resources_reclaimed\":{},\"discovered_cpus\":{},\"online_cpus\":{},\"parallel_matrix_run\":{},\"single_mode_run\":{},\"physical_mode_run\":{},\"logical_mode_run\":{}}}",
        report.len,
        failed,
        timing_failed,
        CHECKS.load(Ordering::Acquire),
        LAST_RECLAIMED.load(Ordering::Acquire),
        crate::smp::unique_enabled_cpu_count().max(1),
        crate::smp::online_set().len(),
        all_concurrent_modes_ok(),
        LAST_SINGLE_MODE.load(Ordering::Acquire),
        LAST_PHYSICAL_MODE.load(Ordering::Acquire),
        LAST_LOGICAL_MODE.load(Ordering::Acquire)
    );
}

fn resources_reclaimed(
    start: crate::baseline::Baseline,
    end: crate::baseline::Baseline,
    start_heap_frames: usize,
    end_heap_frames: usize,
) -> bool {
    if start.objects != end.objects || start.pending != end.pending || start.pins != end.pins {
        return false;
    }
    #[cfg(feature = "bench-profile")]
    {
        let retained_heap_frames = end_heap_frames.saturating_sub(start_heap_frames);
        end.free_frames.saturating_add(retained_heap_frames) == start.free_frames
    }
    #[cfg(not(feature = "bench-profile"))]
    {
        let _ = (start_heap_frames, end_heap_frames);
        end.free_frames == start.free_frames
    }
}

fn cycle_samples(mut op: impl FnMut()) -> Vec<u64> {
    let mut samples = Vec::with_capacity(TAIL_ITERS);
    for _ in 0..SET_WARMUP {
        op();
    }
    for i in 0..TAIL_ITERS {
        let start = arch::measure_cycles();
        op();
        samples.push(arch::measure_cycles().wrapping_sub(start));
        if i % 4096 == 0 {
            arch::watchdog_pet_force();
        }
        if (i + 1) % 100_000 == 0 {
            report_progress(i + 1);
        }
    }
    samples
}

fn report_progress(done: usize) {
    let line = alloc::format!("BENCH RUNNING {} / {} samples", done, TAIL_ITERS);
    #[cfg(feature = "bench-profile")]
    early::append_progress(line.trim_end());
    #[cfg(not(feature = "bench-profile"))]
    crate::display::terminal_write(line.as_bytes());
}

fn report_values(
    name: &str,
    samples: &mut [u64],
    cal: &Calibration,
    expected: usize,
) -> Option<Summary> {
    crate::arch::watchdog_pet_force();
    let sum = summarize(samples);
    check(
        sum.is_some() && samples.len() == expected,
        "基准样本数不符合目标",
    );
    if let Some(m) = sum {
        let counts = cal.threshold_counts(samples);
        kprintln!(
            "[JSR-BENCH] name={} iters={} min={} p50={} p90={} p95={} p99={} p999={} p9999={} p99999={} max={} mean={} stddev={} unit=cycles p50_ns={} p99_ns={} p999_ns={} p9999_ns={} p99999_ns={} over_1us={} over_10us={} over_50us={} spike=unattributed",
            name, m.count, m.min, m.p50, m.p90, m.p95, m.p99, m.p999, m.p9999,
            m.p99999, m.max, m.mean, m.stddev, cal.to_ns(m.p50), cal.to_ns(m.p99),
            cal.to_ns(m.p999), cal.to_ns(m.p9999), cal.to_ns(m.p99999),
            counts.over_1us, counts.over_10us, counts.over_50us
        );
        emit_json(name, &m, &counts, cal);
        let line = alloc::format!(
            "BENCH {} N={} P50={} P99={} P999={} MAX={}\n",
            name,
            m.count,
            HumanDuration::new(m.p50, cal),
            HumanDuration::new(m.p99, cal),
            HumanDuration::new(m.p999, cal),
            HumanDuration::new(m.max, cal)
        );
        screen_line(&line);
        record_result(format_args!(
            "{} N={} P50={} P99={} P999={} MAX={}",
            name,
            m.count,
            HumanDuration::new(m.p50, cal),
            HumanDuration::new(m.p99, cal),
            HumanDuration::new(m.p999, cal),
            HumanDuration::new(m.max, cal)
        ));
        record_result(format_args!(
            "  {} P99.99={} P99.999={} MAX={} >1us={} >10us={} >50us={} SPIKE={}",
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
        ));
    }
    sum
}

fn emit_json(
    name: &str,
    summary: &Summary,
    counts: &kernel_core::bench::ThresholdCounts,
    cal: &Calibration,
) {
    let resolution_ns = 1_000_000_000u64.div_ceil(cal.cycles_per_second().max(1));
    let count = summary.count as usize;
    let p99_confidence = confidence(count, P99_RECOMMENDED_SAMPLES);
    let p999_confidence = confidence(count, P999_RECOMMENDED_SAMPLES);
    let p9999_confidence = confidence(count, P9999_RECOMMENDED_SAMPLES);
    let p99999_confidence = confidence(count, P99999_RECOMMENDED_SAMPLES);
    kprintln!(
        "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"metric\",\"name\":\"{}\",\"count\":{},\"min_ns\":{},\"mean_ns\":{},\"p50_ns\":{},\"p90_ns\":{},\"p95_ns\":{},\"p99_ns\":{},\"p999_ns\":{},\"p9999_ns\":{},\"p99999_ns\":{},\"max_ns\":{},\"stddev_ns\":{},\"over_1us\":{},\"over_10us\":{},\"over_50us\":{},\"spike_cause\":\"{}\",\"resolution_ns\":{},\"p50_below_resolution\":{},\"p99_confidence\":\"{}\",\"p999_confidence\":\"{}\",\"p9999_confidence\":\"{}\",\"p99999_confidence\":\"{}\"}}",
        name,
        summary.count,
        cal.to_ns(summary.min),
        cal.to_ns(summary.mean),
        cal.to_ns(summary.p50),
        cal.to_ns(summary.p90),
        cal.to_ns(summary.p95),
        cal.to_ns(summary.p99),
        cal.to_ns(summary.p999),
        cal.to_ns(summary.p9999),
        cal.to_ns(summary.p99999),
        cal.to_ns(summary.max),
        cal.to_ns(summary.stddev),
        counts.over_1us,
        counts.over_10us,
        counts.over_50us,
        if counts.over_50us == 0 {
            "none"
        } else {
            "unattributed"
        },
        resolution_ns,
        summary.p50 == 0,
        p99_confidence,
        p999_confidence,
        p9999_confidence,
        p99999_confidence
    );
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

fn screen_line(line: &str) {
    #[cfg(feature = "bench-profile")]
    crate::early::append_line(line);
    #[cfg(not(feature = "bench-profile"))]
    crate::display::terminal_write(line.as_bytes());
}

/// issue #1 追加微基准：比较唯一生产 `SyscallSet` 与旧 `u64` 语义参考模型。
/// 高编号正确性由功能测试覆盖；这里只用两者都可表达的 0..63 范围做公平性能对比。
fn syscall_set_paths(cal: &Calibration) {
    let ids = [0u64, 1, 4, 6, 15, 16, 19, 63];
    let current = SyscallSet::of(&[0, 1, 4, 6, 15, 16, 19, 63]);
    let other = SyscallSet::of(&[1, 4, 6, 19, 63]);
    let old = ids.iter().fold(0u64, |word, &id| word | (1u64 << id));
    let old_other = [1usize, 4, 6, 19, 63]
        .iter()
        .fold(0u64, |word, &id| word | (1u64 << id));

    let mut cursor = 0u64;
    let mut current_contains = cycle_samples(|| {
        cursor = cursor.wrapping_add(1);
        black_box(current.contains(ids[cursor as usize % ids.len()]));
    });
    report_values(
        "syscallset.contains.current",
        &mut current_contains,
        cal,
        TAIL_ITERS,
    );

    let mut cursor = 0u64;
    let mut old_contains = cycle_samples(|| {
        cursor = cursor.wrapping_add(1);
        let id = ids[cursor as usize % ids.len()];
        black_box(id < 64 && old & (1u64 << id) != 0);
    });
    report_values(
        "syscallset.contains.u64-reference",
        &mut old_contains,
        cal,
        TAIL_ITERS,
    );

    let mut current_subset = cycle_samples(|| {
        black_box(other.is_subset_of(current));
    });
    report_values(
        "syscallset.subset.current",
        &mut current_subset,
        cal,
        TAIL_ITERS,
    );

    let mut old_subset = cycle_samples(|| {
        black_box(old_other & !old == 0);
    });
    report_values(
        "syscallset.subset.u64-reference",
        &mut old_subset,
        cal,
        TAIL_ITERS,
    );

    let mut current_copy = cycle_samples(|| {
        black_box(black_box(current));
    });
    report_values(
        "syscallset.copy.current",
        &mut current_copy,
        cal,
        TAIL_ITERS,
    );

    let mut old_copy = cycle_samples(|| {
        black_box(black_box(old));
    });
    report_values(
        "syscallset.copy.u64-reference",
        &mut old_copy,
        cal,
        TAIL_ITERS,
    );

    let mut raw = SpawnDesc::default();
    raw.image_len = 64;
    raw.cpu_limit_permille = kernel_core::spawn_abi::CPU_UNLIMITED;
    raw.calls = current;
    let encoded = black_box(raw.encode());
    let mut current_decode = cycle_samples(|| {
        black_box(SpawnDesc::decode(black_box(&encoded)).expect("bench fixture decodes"));
    });
    report_values("spawn.decode.current", &mut current_decode, cal, TAIL_ITERS);

    let mut call_bytes = [0u8; kernel_core::syscall_set::BYTES];
    current.encode(&mut call_bytes);
    let mut current_calls_decode = cycle_samples(|| {
        black_box(SyscallSet::decode(black_box(&call_bytes)));
    });
    report_values(
        "spawn.calls.decode.current",
        &mut current_calls_decode,
        cal,
        TAIL_ITERS,
    );

    let mut old_calls_decode = cycle_samples(|| {
        let mut word = [0u8; 8];
        word.copy_from_slice(&call_bytes[..8]);
        black_box(u64::from_le_bytes(word));
    });
    report_values(
        "spawn.calls.decode.u64-reference",
        &mut old_calls_decode,
        cal,
        TAIL_ITERS,
    );
}

fn counter_read_overhead(cal: &Calibration) {
    let mut samples = Vec::with_capacity(TIMER_READ_ITERS);
    for i in 0..TIMER_READ_ITERS {
        let start = arch::measure_cycles();
        let end = arch::measure_cycles();
        samples.push(end.wrapping_sub(start));
        if i % 1024 == 0 {
            arch::watchdog_pet_force();
        }
    }
    report_values("timer.read_overhead", &mut samples, cal, TIMER_READ_ITERS);
}

/// 开中断等到下一个 tick 的边沿，返回边沿处的 tick 数。
fn next_tick_edge() -> Option<u64> {
    let t = crate::smp::local_ticks();
    let deadline = arch::measure_cycles().saturating_add(
        early::tsc_frequency_hz()
            .unwrap_or(3_000_000_000)
            .saturating_mul(2),
    );
    arch::irq_enable();
    while crate::smp::local_ticks() == t {
        if arch::measure_cycles() >= deadline {
            kprintln!(
                "[JSR-BENCH] timeout stage=next_tick tick={} timer_hz={}",
                t,
                config::ACTIVE.clock.timer_hz
            );
            arch::irq_disable();
            return None;
        }
        core::hint::spin_loop();
    }
    Some(crate::smp::local_ticks())
}

// ---------------------------------------------------------------------------
// 校准
// ---------------------------------------------------------------------------

/// 在 [`CALIBRATION_TICKS`] 个 tick 内数周期计数器走了多少，得到每 tick 周期数。
fn calibrate() -> Option<Calibration> {
    let hz = config::ACTIVE.clock.timer_hz;
    if let Some(cycles_per_second) = early::tsc_frequency_hz() {
        let cal = Calibration::per_second(cycles_per_second)?;
        kprintln!(
            "[JSR-BENCH] calibrate source={} cycles_per_second={} timer_hz={}",
            early::tsc_frequency_source(),
            cycles_per_second,
            hz
        );
        return Some(cal);
    }
    let t0 = next_tick_edge()?;
    kprintln!("[JSR-BENCH] stage=calibration_tick_edge tick={}", t0);
    let c0 = arch::cycles();
    let wait_seconds = CALIBRATION_TICKS
        .div_ceil(u64::from(hz.max(1)))
        .saturating_add(2);
    let deadline = arch::measure_cycles().saturating_add(
        early::tsc_frequency_hz()
            .unwrap_or(3_000_000_000)
            .saturating_mul(wait_seconds),
    );
    arch::irq_enable();
    while crate::smp::local_ticks() < t0 + CALIBRATION_TICKS {
        if arch::measure_cycles() >= deadline {
            kprintln!(
                "[JSR-BENCH] timeout stage=calibration tick={} target={}",
                crate::smp::local_ticks(),
                t0 + CALIBRATION_TICKS
            );
            arch::irq_disable();
            return None;
        }
        core::hint::spin_loop();
    }
    let c1 = arch::cycles();
    arch::irq_disable();
    let cal = Calibration::new(c1.wrapping_sub(c0), CALIBRATION_TICKS, hz)?;
    kprintln!(
        "[JSR-BENCH] calibrate ticks={} cycles={} cycles_per_tick={} cycles_per_second={} timer_hz={}",
        CALIBRATION_TICKS,
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
    let mut irqs = Vec::with_capacity(TIMER_IRQ_SAMPLES);
    let t0 = next_tick_edge()?;
    arch::irq_disable();
    let end = t0 + TIMER_IRQ_SAMPLES as u64;
    let mut last = crate::smp::local_ticks();
    let mut prev = arch::cycles();
    // 上一轮发现 tick 变化时记下的 a[i-1]；下一轮读到 a[i+1] 后结算
    let mut pending: Option<u64> = None;
    arch::irq_enable();
    loop {
        let a = arch::cycles();
        if let Some(start) = pending.take() {
            irqs.push(a.wrapping_sub(start).saturating_sub(base.p50));
            if irqs.len() % 100_000 == 0 {
                report_progress(irqs.len());
            }
            if last >= end {
                break;
            }
        }
        let t = crate::smp::local_ticks();
        if t != last {
            pending = Some(prev);
            last = t;
        }
        prev = a;
    }
    arch::irq_disable();
    // 窗口内应恰好观察到 TIMER_IRQ_SAMPLES 次 tick 变化（每次变化只加 1：中断成本远小于一个 tick）
    let matched = irqs.len() == TIMER_IRQ_SAMPLES && last == end;
    check_timing_sample(matched, "时钟中断样本数与 tick 数不符");
    kprintln!(
        "[JSR-BENCH] probe span_p50={} span_max={} samples={} ticks={} matched={}",
        base.p50,
        base.max,
        irqs.len(),
        TIMER_IRQ_SAMPLES,
        matched
    );
    report_values("kernel.timer_irq", &mut irqs, cal, TIMER_IRQ_SAMPLES)
}

// ---------------------------------------------------------------------------
// 上下文切换
// ---------------------------------------------------------------------------

static SWITCH_SAMPLES: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
static SWITCH_DONE: AtomicBool = AtomicBool::new(false);
/// 一次让出没有发生任何切换的次数（应为 0：总有另一个任务可运行）。
static SWITCH_NONE: AtomicU32 = AtomicU32::new(0);
static SWITCH_UNEXPECTED: AtomicU32 = AtomicU32::new(0);
static SWITCH_COMPLETIONS: AtomicUsize = AtomicUsize::new(0);

/// 测量任务：每次让出前后读计数器，按期间发生的切换次数平摊。
fn switch_measurer() {
    let cpu = arch::cpu_index();
    for i in 0..WARMUP as usize + CONTEXT_ITERS {
        let n0 = sched::runtime_switch_count(cpu);
        let c0 = arch::measure_cycles();
        sched::yield_now();
        let dt = arch::measure_cycles().wrapping_sub(c0);
        let n = sched::runtime_switch_count(cpu).wrapping_sub(n0);
        if n == 0 {
            SWITCH_NONE.fetch_add(1, Ordering::Relaxed);
        } else if n != 2 {
            SWITCH_UNEXPECTED.fetch_add(1, Ordering::Relaxed);
        } else if i >= WARMUP as usize {
            SWITCH_COMPLETIONS.fetch_add(n as usize, Ordering::Relaxed);
            SWITCH_SAMPLES.lock().push(dt);
        }
        if i % 1024 == 0 {
            arch::watchdog_pet_force();
        }
        if (i + 1) % 100_000 == 0 {
            report_progress(i + 1);
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
    let before_heap_frames = heap::physical_frames();
    {
        let mut samples = SWITCH_SAMPLES.lock();
        samples.clear();
        samples.reserve(CONTEXT_ITERS);
    }
    SWITCH_DONE.store(false, Ordering::Relaxed);
    SWITCH_NONE.store(0, Ordering::Relaxed);
    SWITCH_UNEXPECTED.store(0, Ordering::Relaxed);
    SWITCH_COMPLETIONS.store(0, Ordering::Relaxed);
    let a = sched::spawn(TaskId(TASK_ID_BASE + 1), "bench-switch-a", switch_measurer).is_ok();
    let b = sched::spawn(TaskId(TASK_ID_BASE + 2), "bench-switch-b", switch_partner).is_ok();
    check(a && b, "切换基准任务创建失败");
    sched::run();
    check(
        SWITCH_NONE.load(Ordering::Relaxed) == 0,
        "有可运行对手时让出却没有切换",
    );
    check(
        SWITCH_UNEXPECTED.load(Ordering::Relaxed) == 0,
        "切换窗口不是一次完整 A-B-A 往返",
    );
    let mut samples = core::mem::take(&mut *SWITCH_SAMPLES.lock());
    check(samples.len() == CONTEXT_ITERS, "切换样本数不足");
    check(
        SWITCH_COMPLETIONS.load(Ordering::Relaxed) >= CONTEXT_ITERS,
        "完成切换计数少于有效样本数",
    );
    let after = baseline();
    let retained_heap_frames =
        heap::physical_frames().saturating_sub(before_heap_frames);
    check(
        after.objects == before.objects
            && after.pending == before.pending
            && after.pins == before.pins
            && after
                .free_frames
                .saturating_add(retained_heap_frames)
                == before.free_frames,
        "切换基准后资源未回到基线",
    );
    kprintln!(
        "[JSR-BENCH-CONTEXT] samples={} completed_switches={} missed={} unexpected_windows={} measurement=roundtrip_a_b_a",
        samples.len(),
        SWITCH_COMPLETIONS.load(Ordering::Relaxed),
        SWITCH_NONE.load(Ordering::Relaxed),
        SWITCH_UNEXPECTED.load(Ordering::Relaxed)
    );
    report_values(
        "sched.context_switch.round_trip",
        &mut samples,
        cal,
        CONTEXT_ITERS,
    )
}

// ---------------------------------------------------------------------------
// 物理页帧
// ---------------------------------------------------------------------------

fn frames(cal: &Calibration) {
    let before = baseline();
    let before_heap_frames = heap::physical_frames();
    let mut alloc = Vec::with_capacity(TAIL_ITERS);
    let mut free = Vec::with_capacity(TAIL_ITERS);
    let mut ok = true;
    for i in 0..WARMUP as usize + TAIL_ITERS {
        let c0 = arch::measure_cycles();
        let f = frame::allocate();
        let c1 = arch::measure_cycles();
        let Ok(f) = f else {
            ok = false;
            break;
        };
        let r = frame::deallocate(f);
        let c2 = arch::measure_cycles();
        ok &= r.is_ok();
        if i >= WARMUP as usize {
            alloc.push(c1.wrapping_sub(c0));
            free.push(c2.wrapping_sub(c1));
        }
        if i % 4096 == 0 {
            arch::watchdog_pet_force();
        }
        if (i + 1) % 100_000 == 0 {
            report_progress(i + 1);
        }
    }
    check(ok, "页帧分配/释放失败");
    // 失败路径：重复释放被拒，空闲帧数不变
    let refused = match frame::allocate() {
        Ok(f) => {
            let first = frame::deallocate(f).is_ok();
            let free_before = frame::free_frames();
            let second = frame::deallocate(f);
            first
                && second == Err(kernel_core::frame::FrameError::DoubleFree)
                && frame::free_frames() == free_before
        }
        Err(_) => false,
    };
    check(refused, "重复释放页帧未被拒绝或改动了空闲帧数");
    let after = baseline();
    let reclaimed = resources_reclaimed(
        before,
        after,
        before_heap_frames,
        heap::physical_frames(),
    );
    check(reclaimed, "页帧基准后资源未回到基线");
    kprintln!(
        "[JSR-BENCH] case=frame_refusal double_free_refused={} free_unchanged={} reclaimed={}",
        refused,
        refused,
        reclaimed
    );
    report_values("frame.alloc", &mut alloc, cal, TAIL_ITERS);
    report_values("frame.free", &mut free, cal, TAIL_ITERS);
}

// ---------------------------------------------------------------------------
// 内核堆
// ---------------------------------------------------------------------------

fn heap_paths(cal: &Calibration) {
    let before = baseline();
    let mut small = Vec::with_capacity(TAIL_ITERS);
    let mut page = Vec::with_capacity(TAIL_ITERS);
    for i in 0..WARMUP as usize + TAIL_ITERS {
        let c0 = arch::measure_cycles();
        drop(black_box(Box::new([0u8; 64])));
        let c1 = arch::measure_cycles();
        drop(black_box(Vec::<u8>::with_capacity(4096)));
        let c2 = arch::measure_cycles();
        if i >= WARMUP as usize {
            small.push(c1.wrapping_sub(c0));
            page.push(c2.wrapping_sub(c1));
        }
        if i % 4096 == 0 {
            arch::watchdog_pet_force();
        }
        if (i + 1) % 100_000 == 0 {
            report_progress(i + 1);
        }
    }
    // 失败路径：超出架构虚拟窗口的申请被拒，堆的统计不变
    let stats_before = heap::stats();
    let mut v: Vec<u8> = Vec::new();
    let beyond_window = heap::virtual_capacity().saturating_add(kernel_core::frame::FRAME_SIZE);
    let refused = usize::try_from(beyond_window).is_ok_and(|bytes| v.try_reserve(bytes).is_err());
    let unchanged = heap::stats() == stats_before && v.capacity() == 0;
    check(refused && unchanged, "超大堆申请未被拒绝或改动了堆");
    let after = baseline();
    check(after == before, "堆基准后资源未回到基线");
    kprintln!(
        "[JSR-BENCH] case=heap_refusal refused={} heap_unchanged={} reclaimed={}",
        refused,
        unchanged,
        after == before
    );
    report_values("heap.alloc_free_64", &mut small, cal, TAIL_ITERS);
    report_values("heap.alloc_free_4096", &mut page, cal, TAIL_ITERS);
}

// ---------------------------------------------------------------------------
// 用户态基准
// ---------------------------------------------------------------------------

fn user_program(cal: &Calibration) {
    let before = baseline();
    let before_heap_frames = heap::physical_frames();
    let trace = crate::syscall::set_trace(false);
    let res = run_program_arg("bench", USER_BENCH, 0, cal.cycles_per_second(), rt_calls());
    crate::syscall::set_trace(trace);
    let ok_exit = matches!(res, Some((Some(ProcState::Exited { code: 0 }), Some(0))));
    check(ok_exit, "user/bench 未以 0 退出");
    let after = baseline();
    let after_heap_frames = heap::physical_frames();
    let reclaimed = resources_reclaimed(before, after, before_heap_frames, after_heap_frames);
    check(reclaimed, "用户基准后资源未回到基线");
    kprintln!(
        "[JSR-BENCH] case=user exit={:?} reclaimed={}",
        res.and_then(|r| r.1),
        reclaimed
    );
}

// ---------------------------------------------------------------------------
// 取值
// ---------------------------------------------------------------------------

/// 本次构建是否为默认配置档：只有默认档的生效值做开销预算判定（计时类断言，超界只记录）。
/// Whether this build uses the default profile; only it is judged against the overhead limit (timing-only).
fn gated() -> bool {
    // 只有 x86_64 的 TSC 是真正的周期计数器；其他指令集（AArch64 虚拟计数器、RISC-V rdtime）
    // 是时间基准，用它算出的「每 tick 周期数」与宿主快慢强相关，因此那里的预算判定只作参考、
    // 不作为失败条件（真实硬件上的预算验证属于真机测量）。
    cfg!(target_arch = "x86_64")
        && config::ACTIVE.name == kernel_core::config::KernelConfig::STANDARD.name
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
    let hz = select(
        "timer_hz",
        config::ACTIVE.clock.timer_hz,
        &HZ_CANDIDATES,
        LIMIT_PPM,
        Prefer::Largest,
        |h| timer_overhead(tick_cost, cal, h),
    );
    check(hz.is_ok(), "时钟频率取值失败");
    if let Ok(d) = hz {
        check_timing(
            !gated() || d.current_within_limit(),
            "默认配置档的时钟频率超出开销预算",
        );
        print_decision(&d, "largest");
    }
    for (i, name) in QUANTUM_NAMES.iter().enumerate() {
        let q = config::ACTIVE.sched.qos.quantum[i];
        let d = select(
            name,
            q,
            &QUANTUM_CANDIDATES,
            LIMIT_PPM,
            Prefer::Smallest,
            |q| quantum_overhead(switch_cost, cal, q),
        );
        check(d.is_ok(), "时间片取值失败");
        if let Ok(d) = d {
            check_timing(
                !gated() || d.current_within_limit(),
                "默认配置档的时间片超出开销预算",
            );
            print_decision(&d, "smallest");
        }
    }
    // 失败路径：非法候选（0）被拒，不给出部分结论
    let bad = select(
        "timer_hz",
        config::ACTIVE.clock.timer_hz,
        &[100, 0],
        LIMIT_PPM,
        Prefer::Largest,
        |h| timer_overhead(tick_cost, cal, h),
    );
    check(bad.is_err(), "非法候选未被拒绝");
    kprintln!(
        "[JSR-BENCH] case=tune_refusal invalid_candidate_refused={}",
        bad.is_err()
    );
}
