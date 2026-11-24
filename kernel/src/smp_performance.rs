//! Parallel execution matrix over the CPUs that firmware enabled and the
//! scheduler admitted.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::hint::black_box;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{arch, early, hardware, kprintln, mm, smp};

static REPORT: kernel_core::sync::SpinLock<Vec<String>> =
    kernel_core::sync::SpinLock::new(Vec::new());

/// Each worker performs this many individually executed, compiler-visible
/// workload operations.
const OPERATIONS_PER_WORKER: u64 = 1_000_000;

static SHARED_ATOMIC: AtomicU64 = AtomicU64::new(0);
static CONTENDED_LOCK: kernel_core::sync::SpinLock<u64> =
    kernel_core::sync::SpinLock::new(0);

#[derive(Clone, Copy)]
enum ContentionKind {
    Atomic = 1,
    SpinLock = 2,
    Frame = 3,
    Heap = 4,
    Tlb = 5,
}

impl ContentionKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Atomic => "atomic_rmw",
            Self::SpinLock => "spin_lock",
            Self::Frame => "frame_alloc_free",
            Self::Heap => "heap_alloc_free_64",
            Self::Tlb => "tlb_invalidate_local",
        }
    }

    fn from_arg(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Atomic),
            2 => Some(Self::SpinLock),
            3 => Some(Self::Frame),
            4 => Some(Self::Heap),
            5 => Some(Self::Tlb),
            _ => None,
        }
    }
}

fn scalar_work(seed: u64) -> u64 {
    let start = arch::measure_cycles();
    let mut value = seed | 1;
    for index in 0..OPERATIONS_PER_WORKER {
        value = value
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(index ^ 0x9e37_79b9_7f4a_7c15);
        // SAFETY: the pointer names a live local for the complete iteration.
        unsafe {
            core::ptr::write_volatile(&mut value, value);
        }
    }
    black_box(value);
    arch::measure_cycles().wrapping_sub(start)
}

fn contention_work(arg: u64) -> u64 {
    let Some(kind) = ContentionKind::from_arg(arg) else {
        return 0;
    };
    let start = arch::measure_cycles();
    for index in 0..OPERATIONS_PER_WORKER {
        match kind {
            ContentionKind::Atomic => {
                black_box(SHARED_ATOMIC.fetch_add(1, Ordering::Relaxed));
            }
            ContentionKind::SpinLock => {
                let mut value = CONTENDED_LOCK.lock();
                *value = value.wrapping_add(1);
            }
            ContentionKind::Frame => {
                if let Ok(frame) = mm::frame::allocate() {
                    let _ = mm::frame::deallocate(frame);
                }
            }
            ContentionKind::Heap => {
                black_box(Box::new([index as u8; 64]));
            }
            ContentionKind::Tlb => {
                arch::tlb_flush_local(arch::KERNEL_PROBE_VA + 0x60_0000, 1);
            }
        }
    }
    arch::measure_cycles().wrapping_sub(start)
}

fn cycles_to_ns(cycles: u64) -> Option<u64> {
    early::tsc_frequency_hz()
        .map(|hz| {
            (u128::from(cycles) * 1_000_000_000u128 / u128::from(hz.max(1)))
                .min(u128::from(u64::MAX)) as u64
        })
}

fn physical_cpus() -> Vec<usize> {
    let topology = hardware::online_cpu_topology();
    let mut out = Vec::new();
    for cpu in topology {
        if !out
            .iter()
            .any(|existing: &hardware::ApCpuTopology| existing.core_key == cpu.core_key)
        {
            let _ = out.try_reserve(1);
            out.push(cpu);
        }
    }
    out.into_iter().map(|cpu| cpu.logical).collect()
}

fn logical_cpus() -> Vec<usize> {
    hardware::online_cpu_topology()
        .into_iter()
        .map(|cpu| cpu.logical)
        .collect()
}

fn run_mode(
    mode: &'static str,
    cpus: &[usize],
    single_throughput: Option<u64>,
) -> Option<u64> {
    if cpus.is_empty() || cpus[0] != 0 {
        kprintln!("[JSR-PERF-SMP] mode={} status=invalid reason=bsp_missing", mode);
        return None;
    }
    let mut posted = Vec::new();
    if posted.try_reserve_exact(cpus.len().saturating_sub(1)).is_err() {
        kprintln!("[JSR-SMP] mode={} status=invalid reason=call_slot_allocation", mode);
        return None;
    }
    let mut worker_ns = Vec::new();
    if worker_ns.try_reserve_exact(cpus.len()).is_err() {
        kprintln!("[JSR-SMP] mode={} status=invalid reason=result_allocation", mode);
        return None;
    }
    let (usable, free, heap_total, heap_free, _, heap_mapped) = memory();
    let start = arch::measure_cycles();
    for &cpu in cpus.iter().filter(|&&cpu| cpu != 0) {
        if smp::post_call(cpu, scalar_work, cpu as u64).is_ok() {
            posted.push(cpu);
        }
    }
    let bsp_cycles = scalar_work(0);
    let Some(bsp_ns) = cycles_to_ns(bsp_cycles) else {
        kprintln!("[JSR-PERF-SMP] mode={} status=invalid reason=bsp_clock_unavailable", mode);
        return None;
    };
    worker_ns.push(bsp_ns);
    let mut completed = 1usize;
    let mut failed = 0usize;
    for cpu in posted {
        match smp::collect_call(cpu) {
            Ok(cycles) if cycles != 0 => {
                let Some(ns) = cycles_to_ns(cycles) else {
                    kprintln!(
                        "[JSR-PERF-SMP] mode={} status=invalid reason=worker_clock_unavailable cpu={}",
                        mode,
                        cpu
                    );
                    return None;
                };
                worker_ns.push(ns);
                completed += 1;
            }
            _ => failed += 1,
        }
    }
    let Some(elapsed_ns) = cycles_to_ns(arch::measure_cycles().wrapping_sub(start)) else {
        kprintln!("[JSR-PERF-SMP] mode={} status=invalid reason=elapsed_clock_unavailable", mode);
        return None;
    };
    let Some(throughput) = total_throughput(completed, elapsed_ns) else {
        kprintln!("[JSR-PERF-SMP] mode={} status=invalid reason=zero_elapsed", mode);
        return None;
    };
    let total_operations = OPERATIONS_PER_WORKER.saturating_mul(completed as u64);
    let (Some(min_ns), Some(max_ns)) =
        (worker_ns.iter().copied().min(), worker_ns.iter().copied().max())
    else {
        kprintln!("[JSR-PERF-SMP] mode={} status=invalid reason=worker_result_missing", mode);
        return None;
    };
    let Some(mean_ns) = worker_ns
        .iter()
        .copied()
        .fold(0u64, u64::saturating_add)
        .checked_div(completed.max(1) as u64)
    else {
        kprintln!("[JSR-PERF-SMP] mode={} status=invalid reason=worker_mean_unavailable", mode);
        return None;
    };
    let scaling = match single_throughput {
        None => 1000,
        Some(base) if base != 0 => throughput.saturating_mul(1000) / base,
        Some(_) => {
            kprintln!("[JSR-PERF-SMP] mode={} status=invalid reason=single_throughput_zero", mode);
            return None;
        }
    };
    let (usable_after, free_after, heap_total_after, heap_free_after, _, mapped_after) = memory();
    let reclaimed = usable == usable_after
        && free == free_after
        && heap_total == heap_total_after
        && heap_free == heap_free_after
        && heap_mapped == mapped_after;
    let expected = cpus.len();
    let line = alloc::format!(
        "SMP MATRIX mode={} workers={}/{} operations_per_worker={} total_operations={} elapsed_ns={} throughput_ops_s={} scaling_permille={} worker_mean_ns={} worker_min_ns={} worker_max_ns={} failed={} reclaimed={}\n",
        mode,
        completed,
        expected,
        OPERATIONS_PER_WORKER,
        total_operations,
        elapsed_ns,
        throughput,
        scaling,
        mean_ns,
        min_ns,
        max_ns,
        failed,
        reclaimed
    );
    early::append_line(line.trim_end());
    kprintln!("{}", line.trim_end());
    REPORT.lock().push(alloc::format!(
        "{} workers={}/{} total_ops={} elapsed_ns={} throughput_ops_s={} scaling_ppm={} worker_min_ns={} worker_max_ns={} failed={} reclaimed={}",
        mode,
        completed,
        expected,
        total_operations,
        elapsed_ns,
        throughput,
        scaling,
        min_ns,
        max_ns,
        failed,
        reclaimed
    ));
    kprintln!(
        "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel-mode\",\"mode\":\"{}\",\"workers_expected\":{},\"workers_completed\":{},\"operations_per_worker\":{},\"total_operations\":{},\"elapsed_ns\":{},\"throughput_ops_s\":{},\"scaling_permille\":{},\"worker_mean_ns\":{},\"worker_min_ns\":{},\"worker_max_ns\":{},\"failed_workers\":{},\"resources_reclaimed\":{},\"usable_kib_before\":{},\"free_kib_before\":{},\"heap_used_kib_before\":{},\"heap_mapped_kib_before\":{}}}",
        mode,
        expected,
        completed,
        OPERATIONS_PER_WORKER,
        total_operations,
        elapsed_ns,
        throughput,
        scaling,
        mean_ns,
        min_ns,
        max_ns,
        failed,
        reclaimed,
        usable.saturating_mul(4),
        free.saturating_mul(4),
        heap_total.saturating_sub(heap_free) / 1024,
        heap_mapped / 1024
    );
    Some(throughput)
}

fn run_contention(kind: ContentionKind, cpus: &[usize]) -> Option<u64> {
    if cpus.len() < 2 || cpus[0] != 0 {
        kprintln!(
            "[JSR-PERF-SMP] kind={} status=unavailable workers={}",
            kind.name(),
            cpus.len()
        );
        return None;
    }
    let start = arch::measure_cycles();
    let mut posted = Vec::new();
    if posted.try_reserve_exact(cpus.len().saturating_sub(1)).is_err() {
        return None;
    }
    for &cpu in cpus.iter().filter(|&&cpu| cpu != 0) {
        if smp::post_call(cpu, contention_work, kind as u64).is_ok() {
            posted.push(cpu);
        }
    }
    let bsp_cycles = contention_work(kind as u64);
    let mut worker_cycles = Vec::new();
    if worker_cycles.try_reserve_exact(cpus.len()).is_err() {
        return None;
    }
    worker_cycles.push(bsp_cycles);
    for cpu in posted {
        if let Ok(cycles) = smp::collect_call(cpu) {
            if cycles != 0 {
                worker_cycles.push(cycles);
            }
        }
    }
    let elapsed_ns = cycles_to_ns(arch::measure_cycles().wrapping_sub(start))?;
    let operations = OPERATIONS_PER_WORKER.saturating_mul(worker_cycles.len() as u64);
    let throughput = operations
        .saturating_mul(1_000_000_000)
        .checked_div(elapsed_ns)
        .filter(|value| *value != 0)?;
    let min_ns = cycles_to_ns(*worker_cycles.iter().min()?)?;
    let max_ns = cycles_to_ns(*worker_cycles.iter().max()?)?;
    let line = alloc::format!(
        "SMP KIND matrix kind={} workers={}/{} operations_per_worker={} total_operations={} elapsed_ns={} throughput_ops_s={} worker_min_ns={} worker_max_ns={}",
        kind.name(),
        worker_cycles.len(),
        cpus.len(),
        OPERATIONS_PER_WORKER,
        operations,
        elapsed_ns,
        throughput,
        min_ns,
        max_ns
    );
    early::append_line(&line);
    kprintln!("{}", line);
    REPORT.lock().push(alloc::format!(
        "{} workers={}/{} total_ops={} elapsed_ns={} throughput_ops_s={} worker_min_ns={} worker_max_ns={}",
        kind.name(),
        worker_cycles.len(),
        cpus.len(),
        operations,
        elapsed_ns,
        throughput,
        min_ns,
        max_ns
    ));
    kprintln!(
        "{{\"schema\":\"jasper.perf.v1\",\"kind\":\"parallel-operation\",\"operation\":\"{}\",\"workers_expected\":{},\"workers_completed\":{},\"operations_per_worker\":{},\"total_operations\":{},\"elapsed_ns\":{},\"throughput_ops_s\":{},\"worker_min_ns\":{},\"worker_max_ns\":{}}}",
        kind.name(),
        cpus.len(),
        worker_cycles.len(),
        OPERATIONS_PER_WORKER,
        operations,
        elapsed_ns,
        throughput,
        min_ns,
        max_ns
    );
    Some(throughput)
}

fn total_throughput(completed: usize, elapsed_ns: u64) -> Option<u64> {
    OPERATIONS_PER_WORKER
        .saturating_mul(completed as u64)
        .saturating_mul(1_000_000_000)
        .checked_div(elapsed_ns)
        .filter(|value| *value != 0)
}

fn memory() -> (usize, usize, usize, usize, usize, u64) {
    let (heap_total, heap_free, blocks, heap_mapped) = mm::heap::stats();
    (
        mm::frame::usable_frames(),
        mm::frame::free_frames(),
        heap_total,
        heap_free,
        blocks,
        heap_mapped,
    )
}

/// Run single-core, one-thread-per-physical-core, and all-logical-CPU modes.
pub fn run() {
    REPORT.lock().clear();
    let physical = physical_cpus();
    let logical = logical_cpus();
    let online = smp::online_set().len();
    if logical.len() != online {
        kprintln!(
            "[JSR-PERF-SMP] reject=topology_probe_complete online={} probed={}",
            online,
            logical.len()
        );
    }
    kprintln!(
        "[JSR-PERF-SMP] discovery online={} probed={} physical={} logical={}",
        online,
        logical.len(),
        physical.len(),
        logical.len()
    );
    let Some(single) = run_mode("single", &[0], None) else {
        kprintln!("[JSR-PERF-SMP] matrix=unavailable reason=single_mode_failed");
        return;
    };
    if physical.len() > 1 {
        run_mode("all_physical_cores", &physical, Some(single));
    } else {
        kprintln!("[JSR-PERF-SMP] mode=all_physical_cores status=unavailable physical={}", physical.len());
    }
    if logical.len() > 1 {
        run_mode("all_logical_threads", &logical, Some(single));
    } else {
        kprintln!("[JSR-PERF-SMP] mode=all_logical_threads status=unavailable logical={}", logical.len());
    }
    if logical.len() > 1 {
        for kind in [
            ContentionKind::Atomic,
            ContentionKind::SpinLock,
            ContentionKind::Frame,
            ContentionKind::Heap,
            ContentionKind::Tlb,
        ] {
            run_contention(kind, &logical);
        }
    }
}

/// Render the SMP result records after discovery and all matrices have
/// completed, so boot-stage output cannot scroll them off the screen.
pub fn publish_results() {
    let report = REPORT.lock();
    early::results_begin();
    early::append_line("SMP PERFORMANCE MATRIX");
    early::append_line("Scalar: single/all-physical/all-logical; then contention/memory paths");
    for line in report.iter() {
        early::append_line(line);
    }
}
