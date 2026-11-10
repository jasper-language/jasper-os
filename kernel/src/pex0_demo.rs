//! PEX-0 parallel multi-process, multi-Ring throughput workload.
//!
//! This drill measures the existing Ring and object-table paths without
//! changing their implementation. Each Ring has one worker, every process owns
//! two Rings, and low/medium/high profiles vary process count while keeping the
//! two-Rings-per-process ratio fixed.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use kernel_core::bench::{summarize, Summary};
use kernel_core::object::HandleId;
use kernel_core::objtable::ObjId;
use kernel_core::ring_abi::Sqe;

use crate::task::TaskId;
use crate::{arch, baseline::baseline, hrtime, kobj, kprintln, proc, ring, sched};

const MAX_WORKERS: usize = 16;
const RINGS_PER_PROCESS: usize = 2;
const OPS_PER_WORKER: usize = 256;

static NEXT_WORKER: AtomicU64 = AtomicU64::new(0);
static WORKERS: AtomicU64 = AtomicU64::new(0);
static START_CYCLES: AtomicU64 = AtomicU64::new(0);
static END_CYCLES: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static COMPLETED: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
static LATENCY_CYCLES: [[AtomicU64; OPS_PER_WORKER]; MAX_WORKERS] =
    [const { [const { AtomicU64::new(0) }; OPS_PER_WORKER] }; MAX_WORKERS];
static PIDS: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
static HANDLES: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
static RINGS: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    processes: usize,
}

const PROFILES: [Profile; 3] = [
    Profile {
        name: "low",
        processes: 2,
    },
    Profile {
        name: "medium",
        processes: 4,
    },
    Profile {
        name: "high",
        processes: 8,
    },
];

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-PEX0-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn reset_measurement(workers: usize) {
    NEXT_WORKER.store(0, Ordering::Relaxed);
    WORKERS.store(workers as u64, Ordering::Relaxed);
    START_CYCLES.store(0, Ordering::Relaxed);
    END_CYCLES.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    for worker in 0..MAX_WORKERS {
        COMPLETED[worker].store(0, Ordering::Relaxed);
        PIDS[worker].store(0, Ordering::Relaxed);
        HANDLES[worker].store(0, Ordering::Relaxed);
        RINGS[worker].store(0, Ordering::Relaxed);
        for op in 0..OPS_PER_WORKER {
            LATENCY_CYCLES[worker][op].store(0, Ordering::Relaxed);
        }
    }
}

fn worker() {
    let index = NEXT_WORKER.fetch_add(1, Ordering::Relaxed) as usize;
    let workers = WORKERS.load(Ordering::Acquire) as usize;
    if index >= workers {
        return;
    }
    let Some(pid) = ObjId::from_raw(PIDS[index].load(Ordering::Acquire)) else {
        return;
    };
    let handle = HandleId::from_raw(HANDLES[index].load(Ordering::Acquire));
    let Some(ring) = ObjId::from_raw(RINGS[index].load(Ordering::Acquire)) else {
        return;
    };

    let mut completed = 0u64;
    for op in 0..OPS_PER_WORKER {
        let tag = ((index as u64) << 32) | op as u64;
        let sqe = Sqe {
            op: crate::syscall::table::SYSTEM_TIME_NOW,
            flags: 0,
            user_tag: tag,
            arg0: 0,
            arg1: 0,
        };
        let begin = arch::cycles();
        let submitted = ring::submit_for(pid, handle, &sqe);
        let reaped = ring::reap_kernel(ring, 1);
        let end = arch::cycles();
        let valid = submitted.is_ok()
            && matches!(
                reaped.as_slice(),
                [(request, value)] if *request == submitted.as_ref().copied().unwrap_or(u64::MAX)
                    && *value > 0
            );
        if valid {
            LATENCY_CYCLES[index][op].store(end.wrapping_sub(begin), Ordering::Relaxed);
            completed = completed.saturating_add(1);
        }
    }
    COMPLETED[index].store(completed, Ordering::Release);
    if DONE.fetch_add(1, Ordering::AcqRel) + 1 == workers as u64 {
        END_CYCLES.store(arch::cycles(), Ordering::Release);
    }
}

fn collect_samples(workers: usize) -> Vec<u64> {
    let mut samples = Vec::with_capacity(workers * OPS_PER_WORKER);
    for worker in 0..workers {
        for op in 0..OPS_PER_WORKER {
            let sample = LATENCY_CYCLES[worker][op].load(Ordering::Relaxed);
            if sample != 0 {
                samples.push(sample);
            }
        }
    }
    samples
}

fn delta(after: u32, before: u32) -> u32 {
    after.saturating_sub(before)
}

fn setup(processes: usize) -> (Vec<ObjId>, usize) {
    let rings = processes * RINGS_PER_PROCESS;
    let mut unique = Vec::with_capacity(processes);
    let mut worker = 0usize;
    for _ in 0..processes {
        let Ok(pid) = proc::create(
            "pex0-parallel",
            crate::syscall::SyscallSet::of(&[crate::syscall::table::SYSTEM_TIME_NOW]),
        ) else {
            check(false, "PEX-0 parallel process creation failed");
            break;
        };
        unique.push(pid);
        for _ in 0..RINGS_PER_PROCESS {
            let Ok(handle) = ring::create_for(pid, 16) else {
                check(false, "PEX-0 parallel Ring creation failed");
                break;
            };
            let Some(ring) = ring::ring_of(pid, handle) else {
                check(false, "PEX-0 parallel Ring resolution failed");
                break;
            };
            PIDS[worker].store(pid.raw(), Ordering::Relaxed);
            HANDLES[worker].store(handle.raw(), Ordering::Relaxed);
            RINGS[worker].store(ring.raw(), Ordering::Relaxed);
            worker += 1;
        }
    }
    check(worker == rings, "PEX-0 parallel workload setup incomplete");
    (unique, worker)
}

fn cleanup(processes: &[ObjId]) {
    for &pid in processes {
        let _ = proc::exit_idle(pid, 0);
    }
    kobj::run_cleanup(usize::MAX);
    for &pid in processes {
        let _ = proc::reap(pid);
    }
    kobj::run_cleanup(usize::MAX);
}

fn print_profile(
    profile: Profile,
    workers: usize,
    before: crate::baseline::Baseline,
    sched_contended: u32,
    sched_spins: u32,
    object_contended: u32,
    object_spins: u32,
) {
    let online = sched::online_cpus().len();
    let total_ops = workers * OPS_PER_WORKER;
    let window_cycles = END_CYCLES
        .load(Ordering::Acquire)
        .saturating_sub(START_CYCLES.load(Ordering::Acquire));
    let window_ns = hrtime::counts_to_ns(window_cycles).unwrap_or(0);
    let mut samples = collect_samples(workers);
    let summary: Option<Summary> = summarize(&mut samples);
    let complete = COMPLETED[..workers]
        .iter()
        .all(|count| count.load(Ordering::Acquire) == OPS_PER_WORKER as u64)
        && summary.is_some_and(|s| s.count as usize == total_ops)
        && END_CYCLES.load(Ordering::Acquire) != 0;
    let throughput = if window_ns == 0 {
        0
    } else {
        (total_ops as u128 * 1_000_000_000 / window_ns as u128) as u64
    };
    let per_cpu = throughput / online.max(1) as u64;
    let (p50, p99, p999, max) = summary
        .map(|s| (s.p50, s.p99, s.p999, s.max))
        .unwrap_or((0, 0, 0, 0));
    let p50_ns = hrtime::counts_to_ns(p50).unwrap_or(0);
    let p99_ns = hrtime::counts_to_ns(p99).unwrap_or(0);
    let p999_ns = hrtime::counts_to_ns(p999).unwrap_or(0);
    let after = baseline();
    let resources = after == before;
    check(
        complete,
        "PEX-0 parallel workers did not complete every operation",
    );
    check(
        resources,
        "PEX-0 parallel workload did not return resources to baseline",
    );
    #[cfg(feature = "pex2-verify")]
    {
        kprintln!(
            "[JSR-PEX2] category=independent-ring density={} processes={} rings={} workers={} ops={} throughput_ops_s={} p50_ns={} p99_ns={} p999_ns={} max={} complete={} resources={}",
            profile.name,
            profile.processes,
            workers,
            workers,
            total_ops,
            throughput,
            p50_ns,
            p99_ns,
            p999_ns,
            max,
            complete,
            resources
        );
        kprintln!(
            "[JSR-PEX2] category=cross-process density={} processes={} rings={} ops={} throughput_ops_s={} p50_ns={} p99_ns={} p999_ns={} max={} sched_contended={} sched_spins={} object_contended={} object_spins={} complete={} resources={}",
            profile.name,
            profile.processes,
            workers,
            total_ops,
            throughput,
            p50_ns,
            p99_ns,
            p999_ns,
            max,
            sched_contended,
            sched_spins,
            object_contended,
            object_spins,
            complete,
            resources
        );
    }
    kprintln!(
        "[JSR-PEX0-PAR] density={} vcpus={} processes={} rings={} workers={} ops={} window_cycles={} window_ns={} throughput_ops_s={} per_cpu_ops_s={} p50={} p99={} p999={} max={} p50_ns={} p99_ns={} p999_ns={} sched_contended={} sched_spins={} object_contended={} object_spins={} complete={} resources={}",
        profile.name,
        online,
        profile.processes,
        workers,
        workers,
        total_ops,
        window_cycles,
        window_ns,
        throughput,
        per_cpu,
        p50,
        p99,
        p999,
        max,
        p50_ns,
        p99_ns,
        p999_ns,
        sched_contended,
        sched_spins,
        object_contended,
        object_spins,
        complete,
        resources
    );
}

fn run_profile(profile: Profile, sequence: u64) {
    reset_measurement(profile.processes * RINGS_PER_PROCESS);
    let before = baseline();
    let (processes, workers) = setup(profile.processes);
    if processes.len() != profile.processes || workers != profile.processes * RINGS_PER_PROCESS {
        cleanup(&processes);
        check(false, "PEX-0 parallel workload setup incomplete");
        return;
    }

    let affinity = sched::online_cpus();
    // `spawn_on` can publish a worker to another CPU immediately. Start the
    // common window before the first task is published; task creation cost is
    // therefore included conservatively in the measured window.
    START_CYCLES.store(arch::cycles(), Ordering::Release);
    let mut spawned = true;
    for index in 0..workers {
        let id = TaskId(0x5045_5830_0000 + sequence * 0x100 + index as u64);
        spawned &= sched::spawn_on(id, "pex0-ring-worker", worker, None, affinity).is_ok();
    }
    check(spawned, "PEX-0 parallel worker spawn failed");
    if spawned {
        let sched_before = sched::lock_stats();
        let object_before = kobj::lock_stats();
        sched::run();
        let sched_after = sched::lock_stats();
        let object_after = kobj::lock_stats();
        cleanup(&processes);
        print_profile(
            profile,
            workers,
            before,
            delta(sched_after.contended, sched_before.contended),
            delta(sched_after.spins, sched_before.spins),
            delta(object_after.contended, object_before.contended),
            delta(object_after.spins, object_before.spins),
        );
    } else {
        cleanup(&processes);
    }
}

pub fn run() {
    for (index, profile) in PROFILES.into_iter().enumerate() {
        run_profile(profile, index as u64 + 1);
    }
    kprintln!(
        "[JSR-PEX0] checks={} failed={}",
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
