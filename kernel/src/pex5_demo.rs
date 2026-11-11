//! PEX-5 real-kernel heap growth and mapping-tail matrix.
//! PEX-5 真实内核堆增长与映射尾部矩阵。
//!
//! Every worker grows the production heap through its real frame allocator and
//! kernel mapping path. No allocator policy is changed by this acceptance profile.
//! 每个工作者经真实页帧分配器和内核映射路径扩展生产堆；本验收配置不改变分配策略。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use kernel_core::bench::{summarize, Summary};
use kernel_core::frame::FRAME_SIZE;
use kernel_core::smp::CpuSet;

use crate::task::TaskId;
use crate::{arch, hrtime, kprintln, mm, sched};

const MAX_WORKERS: usize = 8;
const CASES: usize = 5;
const TASK_BASE: u64 = 0x5045_5835_0000;
const REQUESTS: [u64; CASES] = [
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
];

static NEXT_WORKER: AtomicU32 = AtomicU32::new(0);
static READY: AtomicU32 = AtomicU32::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static WORKERS: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static DURATION_CYCLES: [[AtomicU64; CASES]; MAX_WORKERS] =
    [const { [const { AtomicU64::new(0) }; CASES] }; MAX_WORKERS];
static GROWN_BYTES: [[AtomicU64; CASES]; MAX_WORKERS] =
    [const { [const { AtomicU64::new(0) }; CASES] }; MAX_WORKERS];
static VALID: [[AtomicU32; CASES]; MAX_WORKERS] =
    [const { [const { AtomicU32::new(0) }; CASES] }; MAX_WORKERS];

fn check(ok: bool, what: &'static str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-PEX5-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn expected_growth(requested: u64) -> Option<u64> {
    requested
        .max(mm::heap::GROW_STEP)
        .checked_next_multiple_of(FRAME_SIZE)
}

fn worker() {
    let worker = NEXT_WORKER.fetch_add(1, Ordering::AcqRel) as usize;
    if worker >= MAX_WORKERS {
        return;
    }
    READY.fetch_add(1, Ordering::Release);
    while GO.load(Ordering::Acquire) == 0 {
        sched::pause();
    }

    for (case, requested) in REQUESTS.into_iter().enumerate() {
        let start = arch::cycles();
        let result = mm::heap::grow_for_verify(requested);
        let end = arch::cycles();
        let duration = end.wrapping_sub(start);
        let valid = match result {
            Ok(record) => {
                let expected = expected_growth(requested).unwrap_or(u64::MAX);
                let coherent = record.requested == requested
                    && record.grown == expected
                    && record.mapped_after
                        == record.mapped_before.saturating_add(record.grown);
                kprintln!(
                    "[JSR-PEX5] case=growth worker={} request_bytes={} grown_bytes={} mapped_before={} mapped_after={} duration_cycles={} duration_ns={} valid={}",
                    worker,
                    requested,
                    record.grown,
                    record.mapped_before,
                    record.mapped_after,
                    duration,
                    hrtime::counts_to_ns(duration).unwrap_or(0),
                    coherent,
                );
                coherent
            }
            Err(error) => {
                kprintln!(
                    "[JSR-PEX5] case=growth worker={} request_bytes={} error={:?} duration_cycles={} valid=false",
                    worker,
                    requested,
                    error,
                    duration,
                );
                false
            }
        };
        if valid {
            DURATION_CYCLES[worker][case].store(duration, Ordering::Relaxed);
            if let Ok(record) = result {
                GROWN_BYTES[worker][case].store(record.grown, Ordering::Relaxed);
            }
            VALID[worker][case].store(1, Ordering::Relaxed);
        }
    }

    DONE.fetch_add(1, Ordering::AcqRel);
}

fn reset(workers: usize) {
    NEXT_WORKER.store(0, Ordering::Relaxed);
    READY.store(0, Ordering::Relaxed);
    GO.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    WORKERS.store(workers as u32, Ordering::Relaxed);
    for worker in 0..MAX_WORKERS {
        for case in 0..CASES {
            DURATION_CYCLES[worker][case].store(0, Ordering::Relaxed);
            GROWN_BYTES[worker][case].store(0, Ordering::Relaxed);
            VALID[worker][case].store(0, Ordering::Relaxed);
        }
    }
}

pub fn run() {
    let online = sched::online_cpus();
    let workers = online.len();
    if workers == 0 || workers > MAX_WORKERS {
        check(false, "PEX-5 online CPU count is unsupported");
        return;
    }
    reset(workers);

    let mut spawned = true;
    for (index, cpu) in online.iter().enumerate() {
        let mut affinity = CpuSet::EMPTY;
        spawned &= affinity.insert(cpu);
        spawned &= sched::spawn_on(
            TaskId(TASK_BASE + index as u64),
            "pex5-grow-worker",
            worker,
            None,
            affinity,
        )
        .is_ok();
    }
    check(spawned, "PEX-5 worker spawn failed");
    if !spawned {
        return;
    }

    let mut waits = 0usize;
    while READY.load(Ordering::Acquire) < workers as u32 && waits < 2_000 {
        sched::pause();
        waits += 1;
    }
    let all_ready = READY.load(Ordering::Acquire) == workers as u32;
    check(all_ready, "PEX-5 workers did not reach the start barrier");
    if !all_ready {
        return;
    }

    let (total_before, free_before, blocks_before, mapped_before) = mm::heap::stats();
    let frames_before = mm::frame::free_frames();
    GO.store(1, Ordering::Release);
    sched::run();

    let (total_after, free_after, blocks_after, mapped_after) = mm::heap::stats();
    let frames_after = mm::frame::free_frames();
    let done = DONE.load(Ordering::Acquire) == workers as u32;
    check(done, "PEX-5 workers did not finish");

    let mut samples = [0u64; MAX_WORKERS * CASES];
    let mut sample_count = 0usize;
    let mut expected = 0u64;
    let mut all_valid = done;
    for worker in 0..workers {
        for case in 0..CASES {
            let valid = VALID[worker][case].load(Ordering::Relaxed) != 0;
            all_valid &= valid;
            if valid {
                expected = expected.saturating_add(GROWN_BYTES[worker][case].load(Ordering::Relaxed));
                samples[sample_count] =
                    DURATION_CYCLES[worker][case].load(Ordering::Relaxed);
                sample_count += 1;
            }
        }
    }
    check(all_valid, "PEX-5 growth case failed");

    let summary: Option<Summary> = summarize(&mut samples[..sample_count]);
    let mapped_growth = mapped_after.saturating_sub(mapped_before);
    let total_growth = total_after.saturating_sub(total_before) as u64;
    let free_growth = free_after.saturating_sub(free_before) as u64;
    let frame_drop = frames_before.saturating_sub(frames_after) as u64;
    let mapped_pages = mapped_growth / FRAME_SIZE;
    let page_table_frames = frame_drop.saturating_sub(mapped_pages);
    let resources = mapped_growth == expected
        && total_growth == expected
        && free_growth == expected
        && frame_drop >= mapped_pages
        && page_table_frames <= workers as u64 + 8
        && mapped_growth % FRAME_SIZE == 0;
    check(resources, "PEX-5 growth was not fully accounted");

    let (p50, p99, p999, max) = summary
        .map(|value| (value.p50, value.p99, value.p999, value.max))
        .unwrap_or((0, 0, 0, 0));
    kprintln!(
        "[JSR-PEX5] summary vcpus={} workers={} cases={} initial_total={} final_total={} initial_free={} final_free={} initial_blocks={} final_blocks={} initial_mapped={} final_mapped={} mapped_growth={} expected_growth={} frames_before={} frames_after={} mapped_pages={} page_table_frames={} p50_cycles={} p99_cycles={} p999_cycles={} max_cycles={} p50_ns={} p99_ns={} p999_ns={} complete={} resources={} checks={} failed={}",
        workers,
        workers,
        sample_count,
        total_before,
        total_after,
        free_before,
        free_after,
        blocks_before,
        blocks_after,
        mapped_before,
        mapped_after,
        mapped_growth,
        expected,
        frames_before,
        frames_after,
        mapped_pages,
        page_table_frames,
        p50,
        p99,
        p999,
        max,
        hrtime::counts_to_ns(p50).unwrap_or(0),
        hrtime::counts_to_ns(p99).unwrap_or(0),
        hrtime::counts_to_ns(p999).unwrap_or(0),
        all_valid,
        resources,
        CHECKS.load(Ordering::Relaxed),
        failed(),
    );
}
