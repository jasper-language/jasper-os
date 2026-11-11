//! PEX-7 real-kernel frame allocation, migration and reclamation matrix.
//! PEX-7 真实内核页帧分配、跨 CPU 释放与回收矩阵。
//!
//! The drill exercises the production bitmap allocator and global frame lock.
//! It does not add a per-CPU cache or change the allocation policy.
//! 本演练验证生产位图分配器与全局页帧锁，不接入每 CPU cache，也不改变分配策略。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use kernel_core::bench::{summarize, Summary};
use kernel_core::frame::PhysFrame;
use kernel_core::smp::CpuSet;

use crate::task::TaskId;
use crate::{arch, hrtime, kprintln, mm, sched};

const MAX_WORKERS: usize = 8;
const FRAMES_PER_WORKER: usize = 128;
const CONTIGUOUS_FRAMES: usize = 16;
const TOTAL_FRAMES: usize = MAX_WORKERS * FRAMES_PER_WORKER;
const TASK_BASE: u64 = 0x5045_5837_0000;

static NEXT_WORKER: AtomicU32 = AtomicU32::new(0);
static READY: AtomicU32 = AtomicU32::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
static ALLOCATED: AtomicU32 = AtomicU32::new(0);
static FREED: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static WORKERS: AtomicU32 = AtomicU32::new(0);
static FRAME_FAILURES: AtomicU32 = AtomicU32::new(0);
static CONTIG_FAILURES: AtomicU32 = AtomicU32::new(0);
static COMPLETE: AtomicBool = AtomicBool::new(false);
static ALLOC_CYCLES: [AtomicU64; TOTAL_FRAMES] =
    [const { AtomicU64::new(0) }; TOTAL_FRAMES];
static FREE_CYCLES: [AtomicU64; TOTAL_FRAMES] =
    [const { AtomicU64::new(0) }; TOTAL_FRAMES];
static FRAME_NUMBERS: [AtomicU64; TOTAL_FRAMES] =
    [const { AtomicU64::new(0) }; TOTAL_FRAMES];
static CONTIG_ALLOC_CYCLES: [AtomicU64; MAX_WORKERS] =
    [const { AtomicU64::new(0) }; MAX_WORKERS];
static CONTIG_FREE_CYCLES: [AtomicU64; MAX_WORKERS] =
    [const { AtomicU64::new(0) }; MAX_WORKERS];
static CONTIG_BASES: [AtomicU64; MAX_WORKERS] =
    [const { AtomicU64::new(0) }; MAX_WORKERS];

fn sample_index(worker: usize, op: usize) -> usize {
    worker * FRAMES_PER_WORKER + op
}

fn wait_for(counter: &AtomicU32, target: u32) {
    while counter.load(Ordering::Acquire) < target {
        sched::pause();
    }
}

fn worker() {
    let worker = NEXT_WORKER.fetch_add(1, Ordering::AcqRel) as usize;
    if worker >= MAX_WORKERS {
        return;
    }
    let workers = WORKERS.load(Ordering::Acquire);
    READY.fetch_add(1, Ordering::Release);
    while GO.load(Ordering::Acquire) == 0 {
        sched::pause();
    }

    if mm::pressure::admit(None, FRAMES_PER_WORKER + CONTIGUOUS_FRAMES).is_err() {
        CONTIG_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    for op in 0..FRAMES_PER_WORKER {
        let start = arch::cycles();
        let result = mm::frame::allocate();
        let end = arch::cycles();
        match result {
            Ok(frame) => {
                let index = sample_index(worker, op);
                FRAME_NUMBERS[index].store(frame.number(), Ordering::Relaxed);
                ALLOC_CYCLES[index].store(end.wrapping_sub(start), Ordering::Relaxed);
            }
            Err(_) => {
                FRAME_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    let contig_start = arch::cycles();
    let contiguous = mm::frame::allocate_contiguous(CONTIGUOUS_FRAMES);
    let contig_end = arch::cycles();
    match contiguous {
        Ok(frame) => {
            CONTIG_BASES[worker].store(frame.number(), Ordering::Relaxed);
            CONTIG_ALLOC_CYCLES[worker]
                .store(contig_end.wrapping_sub(contig_start), Ordering::Relaxed);
        }
        Err(_) => {
            CONTIG_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }

    ALLOCATED.fetch_add(1, Ordering::AcqRel);
    wait_for(&ALLOCATED, workers);

    let source = (worker + 1) % workers as usize;
    for op in 0..FRAMES_PER_WORKER {
        let index = sample_index(source, op);
        let raw = FRAME_NUMBERS[index].load(Ordering::Relaxed);
        if raw == 0 {
            FRAME_FAILURES.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let start = arch::cycles();
        let result = mm::frame::deallocate(PhysFrame::from_number(raw));
        let end = arch::cycles();
        if result.is_ok() {
            FREE_CYCLES[index].store(end.wrapping_sub(start), Ordering::Relaxed);
        } else {
            FRAME_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }

    FREED.fetch_add(1, Ordering::AcqRel);
    wait_for(&FREED, workers);

    let contiguous_source = (worker + 1) % workers as usize;
    let base = CONTIG_BASES[contiguous_source].load(Ordering::Relaxed);
    if base != 0 {
        let start = arch::cycles();
        let result = mm::frame::deallocate_contiguous(
            PhysFrame::from_number(base),
            CONTIGUOUS_FRAMES,
        );
        let end = arch::cycles();
        if result.is_ok() {
            CONTIG_FREE_CYCLES[worker]
                .store(end.wrapping_sub(start), Ordering::Relaxed);
        } else {
            CONTIG_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        CONTIG_FAILURES.fetch_add(1, Ordering::Relaxed);
    }

    DONE.fetch_add(1, Ordering::AcqRel);
}

fn reset(workers: usize) {
    NEXT_WORKER.store(0, Ordering::Relaxed);
    READY.store(0, Ordering::Relaxed);
    GO.store(0, Ordering::Relaxed);
    ALLOCATED.store(0, Ordering::Relaxed);
    FREED.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    WORKERS.store(workers as u32, Ordering::Relaxed);
    FRAME_FAILURES.store(0, Ordering::Relaxed);
    CONTIG_FAILURES.store(0, Ordering::Relaxed);
    COMPLETE.store(false, Ordering::Release);
    for index in 0..TOTAL_FRAMES {
        ALLOC_CYCLES[index].store(0, Ordering::Relaxed);
        FREE_CYCLES[index].store(0, Ordering::Relaxed);
        FRAME_NUMBERS[index].store(0, Ordering::Relaxed);
    }
    for worker in 0..MAX_WORKERS {
        CONTIG_ALLOC_CYCLES[worker].store(0, Ordering::Relaxed);
        CONTIG_FREE_CYCLES[worker].store(0, Ordering::Relaxed);
        CONTIG_BASES[worker].store(0, Ordering::Relaxed);
    }
}

fn summary(samples: &mut [u64]) -> Option<Summary> {
    summarize(samples)
}

/// Whether the last matrix completed with verified reclamation.
/// 上一次矩阵是否完成并通过回收核对。
pub fn complete() -> bool {
    COMPLETE.load(Ordering::Acquire)
}

/// Failure count for the common acceptance summary.
/// 通用验收汇总使用的失败计数。
pub fn failed() -> u32 {
    u32::from(!complete())
}

pub fn run() {
    let online = sched::online_cpus();
    let workers = online.len();
    if workers == 0 || workers > MAX_WORKERS {
        kprintln!("[JSR-PEX7-FAIL] unsupported online CPU count");
        return;
    }
    reset(workers);

    for (index, cpu) in online.iter().enumerate() {
        let mut affinity = CpuSet::EMPTY;
        affinity.insert(cpu);
        if sched::spawn_on(
            TaskId(TASK_BASE + index as u64),
            "pex7-frame-worker",
            worker,
            None,
            affinity,
        )
        .is_err()
        {
            kprintln!("[JSR-PEX7-FAIL] worker spawn failed");
            return;
        }
    }

    while READY.load(Ordering::Acquire) < workers as u32 {
        sched::pause();
    }
    let frames_before = mm::frame::free_frames();
    mm::pressure::reset_stats();
    let pressure_before = mm::pressure::stats();
    GO.store(1, Ordering::Release);
    sched::run();

    let frames_after = mm::frame::free_frames();
    let pressure_after = mm::pressure::stats();
    let done = DONE.load(Ordering::Acquire) == workers as u32;
    let failures = FRAME_FAILURES.load(Ordering::Relaxed)
        + CONTIG_FAILURES.load(Ordering::Relaxed);
    let pressure_ok = pressure_after
        .admitted
        .saturating_sub(pressure_before.admitted)
        == workers as u64
        && pressure_after.refused_kernel == pressure_before.refused_kernel;

    let mut alloc_samples = [0u64; TOTAL_FRAMES];
    let mut free_samples = [0u64; TOTAL_FRAMES];
    let mut alloc_count = 0usize;
    let mut free_count = 0usize;
    for index in 0..workers * FRAMES_PER_WORKER {
        let alloc = ALLOC_CYCLES[index].load(Ordering::Relaxed);
        if alloc != 0 {
            alloc_samples[alloc_count] = alloc;
            alloc_count += 1;
        }
        let free = FREE_CYCLES[index].load(Ordering::Relaxed);
        if free != 0 {
            free_samples[free_count] = free;
            free_count += 1;
        }
    }
    let alloc_summary = summary(&mut alloc_samples[..alloc_count]);
    let free_summary = summary(&mut free_samples[..free_count]);
    let alloc = |value: Option<Summary>| {
        value
            .map(|s| (s.p50, s.p99, s.p999, s.max))
            .unwrap_or((0, 0, 0, 0))
    };
    let (alloc_p50, alloc_p99, alloc_p999, alloc_max) = alloc(alloc_summary);
    let (free_p50, free_p99, free_p999, free_max) = alloc(free_summary);
    let mut contig_alloc = [0u64; MAX_WORKERS];
    let mut contig_free = [0u64; MAX_WORKERS];
    for index in 0..workers {
        contig_alloc[index] = CONTIG_ALLOC_CYCLES[index].load(Ordering::Relaxed);
        contig_free[index] = CONTIG_FREE_CYCLES[index].load(Ordering::Relaxed);
    }
    let contig_alloc_summary = summary(&mut contig_alloc[..workers]);
    let contig_free_summary = summary(&mut contig_free[..workers]);
    let (contig_alloc_p99, contig_free_p99) = (
        contig_alloc_summary.map(|s| s.p99).unwrap_or(0),
        contig_free_summary.map(|s| s.p99).unwrap_or(0),
    );
    let resources = frames_after == frames_before;
    let complete = done
        && failures == 0
        && pressure_ok
        && alloc_count == workers * FRAMES_PER_WORKER
        && free_count == workers * FRAMES_PER_WORKER
        && contig_alloc_summary.is_some()
        && contig_free_summary.is_some();
    if !resources || !complete {
        kprintln!("[JSR-PEX7-FAIL] matrix incomplete resources={} complete={}", resources, complete);
    }
    COMPLETE.store(resources && complete, Ordering::Release);
    kprintln!(
        "[JSR-PEX7] summary vcpus={} workers={} frames_per_worker={} contiguous_frames={} alloc_samples={} free_samples={} frames_before={} frames_after={} alloc_p50_cycles={} alloc_p99_cycles={} alloc_p999_cycles={} alloc_max_cycles={} alloc_p50_ns={} alloc_p99_ns={} alloc_p999_ns={} free_p50_cycles={} free_p99_cycles={} free_p999_cycles={} free_max_cycles={} free_p50_ns={} free_p99_ns={} free_p999_ns={} contig_alloc_p99_ns={} contig_free_p99_ns={} pressure_admitted={} pressure_refused={} pressure_ok={} bitmap_bits_per_frame=1 candidate_cache_bytes={} complete={} resources={} failures={}",
        workers,
        workers,
        FRAMES_PER_WORKER,
        CONTIGUOUS_FRAMES,
        alloc_count,
        free_count,
        frames_before,
        frames_after,
        alloc_p50,
        alloc_p99,
        alloc_p999,
        alloc_max,
        hrtime::counts_to_ns(alloc_p50).unwrap_or(0),
        hrtime::counts_to_ns(alloc_p99).unwrap_or(0),
        hrtime::counts_to_ns(alloc_p999).unwrap_or(0),
        free_p50,
        free_p99,
        free_p999,
        free_max,
        hrtime::counts_to_ns(free_p50).unwrap_or(0),
        hrtime::counts_to_ns(free_p99).unwrap_or(0),
        hrtime::counts_to_ns(free_p999).unwrap_or(0),
        hrtime::counts_to_ns(contig_alloc_p99).unwrap_or(0),
        hrtime::counts_to_ns(contig_free_p99).unwrap_or(0),
        pressure_after.admitted.saturating_sub(pressure_before.admitted),
        pressure_after.refused_kernel.saturating_sub(pressure_before.refused_kernel),
        pressure_ok,
        workers * 64 * core::mem::size_of::<PhysFrame>(),
        complete,
        resources,
        failures,
    );
}
