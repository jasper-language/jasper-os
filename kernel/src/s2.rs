//! S-2: bounded concurrent syscall campaign across the online processors.
//! Each worker uses a fixed input stream; scheduling order is not deterministic.
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kernel_core::argcase::{s2_probes, s2_seed, s2_workers};
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;
use kernel_core::smp::CpuSet;

use crate::{arch, baseline::baseline, kprintln, proc, robust_demo, sched, syscall};

/// One-shot failure point used to exercise the MMIO rollback branch.
pub static MMIO_MAP: kernel_core::fault::FaultPoint = kernel_core::fault::FaultPoint::new();

const MAX_WORKERS: usize = 8;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static CPUS: AtomicU32 = AtomicU32::new(0);
static CALLS: [AtomicU32; MAX_WORKERS] = [const { AtomicU32::new(0) }; MAX_WORKERS];

/// Called from the real syscall dispatch entry; records actual per-CPU progress.
pub fn observe() {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    let cpu = arch::cpu_index();
    if cpu < MAX_WORKERS {
        CPUS.fetch_or(1 << cpu, Ordering::Relaxed);
        CALLS[cpu].fetch_add(1, Ordering::Relaxed);
    }
}

fn start(worker: u64, cpu: usize, probes: u64) -> Option<(ObjId, bool)> {
    let pid = proc::create("s2-worker", robust_demo::all_calls()).ok()?;
    let started = (|| {
        let entry = proc::load_elf(pid, robust_demo::USER_ROBUST).ok()?;
        let stack = arch::USER_WINDOW.0 + 0xc0_0000;
        for i in 1..=4 {
            proc::map_new(pid, stack - i * 4096, MapFlags::USER | MapFlags::WRITE).ok()?;
        }
        let arg = worker | (probes << 32);
        // Author: chatgpt. Affinity must be installed before publication: a
        // short-lived worker may otherwise finish before set_affinity runs.
        let mut set = CpuSet::EMPTY;
        set.insert(cpu);
        proc::spawn_thread_affinity(pid, "s2-worker", entry, stack, arg, 0, Some(set)).ok()?;
        Some(())
    })()
    .is_some();
    Some((pid, started))
}

/// Run the multi-process campaign, then the fault-path and teardown audits.
pub fn run() -> bool {
    let online = crate::smp::online_set();
    let workers = s2_workers(online.len());
    if online.len() < 2 {
        kprintln!("[JSR-S2] failure reason=single_cpu online={}", online.len());
        return false;
    }
    let probes = match s2_probes(workers) {
        Some(p) => p,
        None => {
            kprintln!("[JSR-S2] failure reason=bad_worker_count workers={}", workers);
            return false;
        }
    };
    let before = baseline();
    let previous = sched::set_preemption(true);
    let trace = syscall::set_trace(false);
    CPUS.store(0, Ordering::Relaxed);
    for c in &CALLS {
        c.store(0, Ordering::Relaxed);
    }
    ACTIVE.store(true, Ordering::Release);

    let mut results: [Option<(ObjId, bool)>; MAX_WORKERS] = [None; MAX_WORKERS];
    for i in 0..workers as usize {
        let worker = i as u64 + 1;
        let cpu = online.iter().nth(i).unwrap_or(i);
        kprintln!(
            "[JSR-S2] worker={} cpu={} seed={:#x} probes={}",
            worker,
            cpu,
            s2_seed(worker).unwrap(),
            probes
        );
        results[i] = start(worker, cpu, probes);
    }
    sched::run();
    ACTIVE.store(false, Ordering::Release);

    let mut passed = 0u64;
    for i in 0..workers as usize {
        if let Some((pid, started)) = results[i] {
            if crate::rt_demo::finish_program(pid, started)
                == Some((Some(proc::ProcState::Exited { code: 0 }), Some(0)))
            {
                passed += 1;
            }
        }
    }
    syscall::set_trace(trace);
    sched::set_preemption(previous);

    let after = baseline();
    let mask = CPUS.load(Ordering::Relaxed);
    let calls: [u32; MAX_WORKERS] = core::array::from_fn(|i| CALLS[i].load(Ordering::Relaxed));
    let total: u64 = calls[..workers as usize].iter().map(|&c| c as u64).sum();
    let expected_mask = online
        .iter()
        .take(workers as usize)
        .fold(0u32, |m, c| m | (1 << c));
    let ok = passed == workers
        && total >= probes * workers
        && mask == expected_mask
        && calls[..workers as usize]
            .iter()
            .all(|&c| c as u64 >= probes)
        && after == before;
    kprintln!(
        "[JSR-S2] summary workers={}/{} probes={} calls={} cpu_mask={:#x} per_cpu={:?} free_frames={}/{} objects={}/{} pending={} reclaimed={} passed={}",
        passed,
        workers,
        probes * workers,
        total,
        mask,
        calls,
        after.free_frames,
        before.free_frames,
        after.objects,
        before.objects,
        after.pending,
        after == before,
        ok
    );

    #[cfg(feature = "fault-inject")]
    let rollback_ok = process_error_tests() && mmio_rollback_test() && dma_missing_readback_test();
    #[cfg(not(feature = "fault-inject"))]
    let rollback_ok = false; // The fault-path audit requires the actual timeout hook.
    ok && rollback_ok
}

#[cfg(feature = "fault-inject")]
fn mmio_rollback_test() -> bool {
    use kernel_core::pci::Bar;

    use crate::fault_inject::IPI_TIMEOUT;
    use crate::mm;
    use crate::mmio::{Mapping, MmioError};

    // A real enumerated BAR, mapped but never read or written: no RAM is reclaimed.
    let bar = crate::pci::table()
        .devices()
        .flat_map(|d| d.bars.iter())
        .find(|bar| matches!(bar, Bar::Memory { base, size, .. } if *base != 0 && *size >= 8192));
    let Some(bar) = bar else {
        kprintln!("[JSR-S2-MMIO] failure no_two_page_bar");
        return false;
    };
    // Warm the page-table path, then measure. This also tests normal Drop.
    let Ok(warm) = Mapping::map(bar, 0, 8192) else {
        return false;
    };
    drop(warm);
    let slots = crate::mmio::slots_used();
    let frames = mm::frame::free_frames();
    MMIO_MAP.arm(0, 1).unwrap();
    let zero = matches!(Mapping::map(bar, 0, 8192), Err(MmioError::MapFailed))
        && crate::mmio::slots_used() == slots;
    let nth = MMIO_MAP.arm(0, 2).unwrap();
    let rollback = nth == 2
        && matches!(Mapping::map(bar, 0, 8192), Err(MmioError::MapFailed))
        && crate::mmio::slots_used() == slots;
    MMIO_MAP.arm(0, 2).unwrap();
    IPI_TIMEOUT.arm(0, 1).unwrap();
    let timeout = matches!(Mapping::map(bar, 0, 8192), Err(MmioError::MapFailed));
    MMIO_MAP.disarm();
    IPI_TIMEOUT.disarm();
    let quarantined = crate::mmio::slots_used() == slots + 1;
    let normal = match Mapping::map(bar, 0, 4096) {
        Ok(m) => {
            let allocated = crate::mmio::slots_used() == slots + 2;
            drop(m);
            allocated && crate::mmio::slots_used() == slots + 1
        }
        Err(_) => false,
    };
    let frame_conserved = mm::frame::free_frames() == frames;
    let ok = zero && rollback && timeout && quarantined && normal && frame_conserved;
    kprintln!(
        "[JSR-S2-MMIO] zero={} rollback={} timeout={} quarantined={} recovery={} frames_conserved={} intentional_slot_quarantine=1 passed={}",
        zero,
        rollback,
        timeout,
        quarantined,
        normal,
        frame_conserved,
        ok
    );
    ok
}

#[cfg(feature = "fault-inject")]
fn process_error_tests() -> bool {
    use crate::fault_inject::{FRAME, HEAP, IPI_TIMEOUT};
    use crate::syscall::SyscallSet;

    let mut ok = true;
    for case in 0..4 {
        let quarantine_before = proc::quarantined_frames();
        let before = baseline();
        let Some(pid) = proc::create("s2-error", SyscallSet::of(&[])).ok() else {
            return false;
        };
        let va = arch::USER_WINDOW.0 + 0x3400_0000;
        let expected = match case {
            0 => {
                HEAP.arm(0, 1).unwrap();
                proc::map_anon(pid, va, 2, true) == Err(proc::MemError::OutOfMemory)
            }
            1 => {
                FRAME.arm(0, 2).unwrap();
                proc::map_anon(pid, va, 2, true) == Err(proc::MemError::OutOfMemory)
            }
            _ => {
                let mapped = proc::map_anon(pid, va, 2, true).is_ok();
                IPI_TIMEOUT.arm(0, 1).unwrap();
                let result = if case == 2 {
                    proc::unmap_range(pid, va, 2)
                } else {
                    proc::protect_range(pid, va, 2, false, false)
                };
                // The page-table change is already visible locally, but the unconfirmed
                // shootdown must fail-stop the process and quarantine both frames.
                mapped && result == Err(proc::MemError::Busy)
            }
        };
        FRAME.disarm();
        HEAP.disarm();
        IPI_TIMEOUT.disarm();
        let exited = proc::exit_idle(pid, 0);
        let reaped = proc::reap(pid).is_some();
        let after = baseline();
        let quarantined = proc::quarantined_frames().wrapping_sub(quarantine_before) as usize;
        let expected_quarantine = if case >= 2 { 2 } else { 0 };
        let reclaimed = after.free_frames + quarantined == before.free_frames
            && after.objects == before.objects
            && after.pending == before.pending
            && after.pins == before.pins;
        let passed = expected && exited && reaped && quarantined == expected_quarantine && reclaimed;
        kprintln!(
            "[JSR-S2-ERROR] case={} expected_error={} exited={} reaped={} quarantine={} reclaimed={} passed={}",
            case,
            expected,
            exited,
            reaped,
            quarantined,
            reclaimed,
            passed
        );
        ok &= passed;
    }
    kprintln!(
        "[JSR-S2-QUARANTINE] total={} intentional=true",
        proc::quarantined_frames()
    );
    ok
}

#[cfg(feature = "fault-inject")]
fn dma_missing_readback_test() -> bool {
    use kernel_core::dma_quiesce::{QuiesceVerdict, ResetOutcome};

    use crate::{mm, pci, virtio};

    let device = pci::table()
        .devices()
        .find(|d| d.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_rng_device(d.header.device));
    let Some(device) = device else {
        return false;
    };
    let Ok(handle) = virtio::VirtioPci::new(device) else {
        return false;
    };
    let frames = mm::frame::free_frames();
    let held = virtio::quarantined_frames();
    let Some(queue) = crate::krn0_demo::dma_setup(&handle) else {
        return false;
    };
    let verdict = virtio::quiesce_with(&handle, queue, true, || ResetOutcome::TimedOut, || None);
    let missing = frames.saturating_sub(mm::frame::free_frames());
    let quarantine = virtio::quarantined_frames() - held;
    let off = pci::bus_master_enabled(handle.bdf()) == Ok(false);
    let ok = verdict == QuiesceVerdict::Quarantine
        && off
        && missing == virtio::QUEUE_PAGES
        && quarantine == virtio::QUEUE_PAGES;
    kprintln!(
        "[JSR-S2-DMA] readback=unavailable bus_master_off={} missing={} quarantine={} intentional=true passed={}",
        off,
        missing,
        quarantine,
        ok
    );
    ok
}
