//! PEX-4 acceptance-only selection-path instrumentation.
//! PEX-4 仅验收使用的选择路径探测。
//!
//! Counters and bounded samples are independent per CPU, so recording a completed
//! selection does not add a new cross-core lock or overwrite another core's work.
//! 每 CPU 独立计数和有界样本，记录已完成选择时不引入新的跨核锁，也不覆盖其他核样本。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use kernel_core::smp::MAX_CPUS;

const SAMPLES_PER_CPU: usize = 1024;

/// Maximum aggregate samples exported for one measurement.
/// 单次测量可导出的最大聚合样本数。
pub const MAX_SAMPLES: usize = MAX_CPUS * SAMPLES_PER_CPU;

static PICKS: AtomicU64 = AtomicU64::new(0);
static VISITED: AtomicU64 = AtomicU64::new(0);
static CANDIDATES: AtomicU64 = AtomicU64::new(0);
static MAX_VISITED: AtomicU32 = AtomicU32::new(0);
static MAX_CANDIDATES: AtomicU32 = AtomicU32::new(0);
static SAMPLE_COUNTS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static DURATION_CYCLES: [[AtomicU64; SAMPLES_PER_CPU]; MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; SAMPLES_PER_CPU] }; MAX_CPUS];

/// Aggregate selection-path counters for one measurement window.
/// 一个测量窗口的选择路径聚合计数。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Completed `prepare_switch` selections.
    pub picks: u64,
    /// Run-list entries reported by the existing scan counter.
    pub visited: u64,
    /// Candidates actually consumed by the scheduling policy.
    pub candidates: u64,
    /// Largest run-list length in one selection.
    pub max_visited: u32,
    /// Largest candidate set in one selection.
    pub max_candidates: u32,
    /// Stored duration samples.
    pub samples: usize,
    /// Samples rejected after the per-CPU bound was reached.
    pub dropped: u64,
}

/// Record one completed local selection.
/// 记录一次已完成的本地选择。
pub fn record(cpu: usize, visited: u32, candidates: u32, duration_cycles: u64) {
    PICKS.fetch_add(1, Ordering::Relaxed);
    VISITED.fetch_add(u64::from(visited), Ordering::Relaxed);
    CANDIDATES.fetch_add(u64::from(candidates), Ordering::Relaxed);
    MAX_VISITED.fetch_max(visited, Ordering::Relaxed);
    MAX_CANDIDATES.fetch_max(candidates, Ordering::Relaxed);
    if cpu >= MAX_CPUS {
        return;
    }
    let index = SAMPLE_COUNTS[cpu].fetch_add(1, Ordering::Relaxed) as usize;
    if index < SAMPLES_PER_CPU {
        DURATION_CYCLES[cpu][index].store(duration_cycles, Ordering::Relaxed);
    }
}

/// Clear all counters and bounded samples.
/// 清零全部计数和有界样本。
pub fn reset() {
    PICKS.store(0, Ordering::Relaxed);
    VISITED.store(0, Ordering::Relaxed);
    CANDIDATES.store(0, Ordering::Relaxed);
    MAX_VISITED.store(0, Ordering::Relaxed);
    MAX_CANDIDATES.store(0, Ordering::Relaxed);
    for cpu in 0..MAX_CPUS {
        SAMPLE_COUNTS[cpu].store(0, Ordering::Relaxed);
        for sample in &DURATION_CYCLES[cpu] {
            sample.store(0, Ordering::Relaxed);
        }
    }
}

/// Copy up to `out.len()` stored duration samples and return `(count, dropped)`.
/// 复制不超过 `out.len()` 个已存持续时间样本，并返回 `(数量, 丢弃数)`。
pub fn copy_samples(out: &mut [u64]) -> (usize, u64) {
    let mut written = 0usize;
    let mut dropped = 0u64;
    for cpu in 0..MAX_CPUS {
        let count = SAMPLE_COUNTS[cpu].load(Ordering::Relaxed) as usize;
        dropped = dropped.saturating_add(count.saturating_sub(SAMPLES_PER_CPU) as u64);
        for index in 0..count.min(SAMPLES_PER_CPU) {
            if written == out.len() {
                return (written, dropped);
            }
            out[written] = DURATION_CYCLES[cpu][index].load(Ordering::Relaxed);
            written += 1;
        }
    }
    (written, dropped)
}

/// Read aggregate counters and sample availability.
/// 读取聚合计数和样本可用量。
pub fn snapshot(out_capacity: usize) -> Snapshot {
    let mut stored = 0usize;
    let mut dropped = 0u64;
    for cpu in 0..MAX_CPUS {
        let count = SAMPLE_COUNTS[cpu].load(Ordering::Relaxed) as usize;
        stored = stored.saturating_add(count.min(SAMPLES_PER_CPU));
        dropped = dropped.saturating_add(count.saturating_sub(SAMPLES_PER_CPU) as u64);
    }
    Snapshot {
        picks: PICKS.load(Ordering::Relaxed),
        visited: VISITED.load(Ordering::Relaxed),
        candidates: CANDIDATES.load(Ordering::Relaxed),
        max_visited: MAX_VISITED.load(Ordering::Relaxed),
        max_candidates: MAX_CANDIDATES.load(Ordering::Relaxed),
        samples: stored.min(out_capacity),
        dropped,
    }
}
