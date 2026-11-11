//! PEX-3 central versus stable-slot-sharded object-table A/B drill.
//! PEX-3 中央对象表与稳定槽位分片对象表的 A/B 验证。
//!
//! The drill keeps production tables unchanged. Both candidates use the real
//! object-table lifecycle implementation and execute create, lookup, owner and
//! internal references, closing, death, generation reuse and cleanup.
//! 本演练不改变生产对象表。两个候选都使用真实对象表生命周期实现，并执行创建、
//! 查找、外部/内部引用、closing、死亡、世代复用与清理。

use alloc::boxed::Box;
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use kernel_core::bench::{summarize, Summary};
use kernel_core::objtable::{Lifecycle, ObjId, ObjectTable, Released, Slot};
use kernel_core::smp::CpuSet;

use crate::sync::IrqSpinLock;
use crate::task::TaskId;
use crate::{arch, hrtime, kprintln, sched};

const SHARDS: usize = 8;
const OPS_PER_WORKER: usize = 1024;
const MAX_WORKERS: usize = 8;
const CENTRAL_CAPACITY: usize = 64;
const SHARD_CAPACITY: usize = 16;
const TASK_BASE: u64 = 0x5045_5833_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value {
    Leaf(u64),
    Holder(ObjId),
}

type Table = ObjectTable<Value>;

static CENTRAL: IrqSpinLock<Table> =
    IrqSpinLock::ranked(crate::lockorder::OBJECT_TABLE, ObjectTable::empty());
static SHARDED: [IrqSpinLock<Table>; SHARDS] =
    [const { IrqSpinLock::ranked(crate::lockorder::OBJECT_TABLE, ObjectTable::empty()) }; SHARDS];

static MODE: AtomicU32 = AtomicU32::new(0);
static NEXT_WORKER: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static WORKERS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
static END_CYCLES: AtomicU64 = AtomicU64::new(0);
static COMPLETED: [AtomicU32; MAX_WORKERS] = [const { AtomicU32::new(0) }; MAX_WORKERS];
static WORKER_CYCLES: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
static LATENCY_CYCLES: [[AtomicU64; OPS_PER_WORKER]; MAX_WORKERS] =
    [const { [const { AtomicU64::new(0) }; OPS_PER_WORKER] }; MAX_WORKERS];

fn check(ok: bool, what: &'static str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-PEX3-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn install_table(lock: &IrqSpinLock<Table>, capacity: usize) -> Result<(), &'static str> {
    let slots = crate::bootcap::try_boxed(capacity, || Slot::VACANT).ok_or("allocation")?;
    let pending = match crate::bootcap::try_boxed(capacity, || 0u32) {
        Some(pending) => pending,
        None => return Err("allocation"),
    };
    let slots = Box::into_raw(slots);
    let pending = Box::into_raw(pending);
    let installed = lock.lock().install(unsafe { &mut *slots }, unsafe { &mut *pending });
    if installed.is_err() {
        // SAFETY: the table rejected both allocations and therefore did not
        // retain either slice. 表拒绝安装时未保留任一存储切片。
        unsafe {
            drop(Box::from_raw(slots));
            drop(Box::from_raw(pending));
        }
    }
    installed.map(|_| ()).map_err(|error| error.as_str())
}

fn rollback_table(lock: &IrqSpinLock<Table>) {
    let storage = lock.lock().take_storage_if_vacant();
    if let Some((slots, pending)) = storage {
        // SAFETY: the table relinquished allocations created by install_table.
        // 表已交还 install_table 创建的分配。
        unsafe {
            drop(Box::from_raw(slots));
            drop(Box::from_raw(pending));
        }
    }
}

fn install_candidates() -> Result<(), &'static str> {
    if let Err(error) = install_table(&CENTRAL, CENTRAL_CAPACITY) {
        return Err(error);
    }
    for (index, shard) in SHARDED.iter().enumerate() {
        if let Err(error) = install_table(shard, SHARD_CAPACITY) {
            for installed in &SHARDED[..index] {
                rollback_table(installed);
            }
            rollback_table(&CENTRAL);
            return Err(error);
        }
    }
    Ok(())
}

fn hot_operation(table: &mut Table, seed: u64) -> bool {
    let Ok(id) = table.insert(Value::Leaf(seed), 1, 1) else {
        return false;
    };
    if table.counts(id) != Ok((1, 1, Lifecycle::Live)) {
        return false;
    }
    if table.get(id) != Ok(&Value::Leaf(seed)) {
        return false;
    }
    if table.acquire_internal(id).is_err() || table.release_internal(id).is_err() {
        return false;
    }

    let mut closing_observed = false;
    let Ok(released) = table.release_owner_with_closing(id, |table, current| {
        if let Ok(Value::Leaf(value)) = table.get_mut(current) {
            *value = value.wrapping_add(1);
            closing_observed = true;
        }
    }) else {
        return false;
    };
    if released
        != (Released {
            became_unowned: true,
            dead: false,
        })
        || !closing_observed
        || table.counts(id) != Ok((0, 1, Lifecycle::Closing))
    {
        return false;
    }
    if !table.release_internal(id).is_ok_and(|released| released.dead) {
        return false;
    }
    matches!(table.take_dead(), Some((gone, Value::Leaf(_))) if gone == id)
}

fn shard_index(worker: usize) -> usize {
    worker % SHARDS
}

fn worker() {
    let worker = NEXT_WORKER.fetch_add(1, Ordering::AcqRel) as usize;
    if worker >= MAX_WORKERS {
        return;
    }

    let mode = MODE.load(Ordering::Acquire);
    let begin = arch::cycles();
    let mut completed = 0u32;
    for op in 0..OPS_PER_WORKER {
        let seed = ((worker as u64) << 32) | op as u64;
        let start = arch::cycles();
        let valid = if mode == 0 {
            let mut table = CENTRAL.lock();
            hot_operation(&mut table, seed)
        } else {
            let mut table = SHARDED[shard_index(worker)].lock();
            hot_operation(&mut table, seed)
        };
        let end = arch::cycles();
        if valid {
            LATENCY_CYCLES[worker][op].store(end.wrapping_sub(start), Ordering::Relaxed);
            completed = completed.saturating_add(1);
        }
    }
    let end = arch::cycles();
    WORKER_CYCLES[worker].store(end.wrapping_sub(begin), Ordering::Relaxed);
    COMPLETED[worker].store(completed, Ordering::Release);
    if DONE.fetch_add(1, Ordering::AcqRel) + 1 == WORKERS.load(Ordering::Acquire) {
        END_CYCLES.store(arch::cycles(), Ordering::Release);
    }
}

fn reset_measurement(mode: u32, workers: usize) {
    MODE.store(mode, Ordering::Relaxed);
    NEXT_WORKER.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    WORKERS.store(workers as u32, Ordering::Relaxed);
    END_CYCLES.store(0, Ordering::Relaxed);
    for worker in 0..MAX_WORKERS {
        COMPLETED[worker].store(0, Ordering::Relaxed);
        WORKER_CYCLES[worker].store(0, Ordering::Relaxed);
        for op in 0..OPS_PER_WORKER {
            LATENCY_CYCLES[worker][op].store(0, Ordering::Relaxed);
        }
    }
}

fn collect_samples(workers: usize) -> alloc::vec::Vec<u64> {
    let mut samples = alloc::vec::Vec::with_capacity(workers * OPS_PER_WORKER);
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

fn lock_stats(mode: u32) -> crate::sync::LockStats {
    if mode == 0 {
        CENTRAL.stats()
    } else {
        let mut total = crate::sync::LockStats::default();
        for shard in &SHARDED {
            let stats = shard.stats();
            total.acquired = total.acquired.wrapping_add(stats.acquired);
            total.contended = total.contended.wrapping_add(stats.contended);
            total.spins = total.spins.wrapping_add(stats.spins);
            total.max_spins = total.max_spins.max(stats.max_spins);
        }
        total
    }
}

fn reset_lock_stats() {
    CENTRAL.reset_stats();
    for shard in &SHARDED {
        shard.reset_stats();
    }
}

fn table_state() -> (usize, usize, usize) {
    let mut live = CENTRAL.lock().live();
    let mut pending = CENTRAL.lock().pending();
    for shard in &SHARDED {
        let table = shard.lock();
        live += table.live();
        pending += table.pending();
    }
    (live, pending, SHARDS)
}

fn clear_table(lock: &IrqSpinLock<Table>) {
    while lock.lock().take_dead().is_some() {}
    let ids: alloc::vec::Vec<ObjId> = {
        let table = lock.lock();
        let mut ids = alloc::vec::Vec::new();
        table.for_each_live(|id, _| {
            ids.push(id);
            true
        });
        ids
    };
    for id in ids {
        for _ in 0..8 {
            let mut table = lock.lock();
            let Ok((owners, internal, _)) = table.counts(id) else {
                break;
            };
            if owners != 0 {
                let _ = table.release_owner(id);
            }
            if internal != 0 {
                let _ = table.release_internal(id);
            }
            let _ = table.take_dead();
        }
    }
    while lock.lock().take_dead().is_some() {}
}

fn clear_candidates() {
    clear_table(&CENTRAL);
    for shard in &SHARDED {
        clear_table(shard);
    }
}

fn run_mode(mode: u32, sequence: u64) -> bool {
    let cpus: alloc::vec::Vec<usize> = sched::online_cpus().iter().collect();
    if cpus.is_empty() || cpus.len() > MAX_WORKERS {
        check(false, "PEX-3 online CPU count is unsupported");
        return false;
    }
    reset_measurement(mode, cpus.len());
    reset_lock_stats();

    let mut spawned = true;
    for (index, cpu) in cpus.iter().copied().enumerate() {
        let mut affinity = CpuSet::EMPTY;
        spawned &= affinity.insert(cpu);
        spawned &= sched::spawn_on(
            TaskId(TASK_BASE + sequence * 0x100 + index as u64),
            "pex3-object-worker",
            worker,
            None,
            affinity,
        )
        .is_ok();
    }
    check(spawned, "PEX-3 worker spawn failed");
    if !spawned {
        return false;
    }

    sched::run();

    let workers = WORKERS.load(Ordering::Acquire) as usize;
    let complete = COMPLETED[..workers]
        .iter()
        .all(|count| count.load(Ordering::Acquire) == OPS_PER_WORKER as u32)
        && END_CYCLES.load(Ordering::Acquire) != 0;
    check(complete, "PEX-3 workers did not complete every operation");

    let samples = collect_samples(workers);
    let summary: Option<Summary> = summarize(&mut samples.clone());
    let (live, pending, shard_count) = table_state();
    let resources = live == 0 && pending == 0;
    check(resources, "PEX-3 candidate tables did not return to an empty state");
    if !complete || !resources {
        clear_candidates();
    }

    let active_cycles: u64 = WORKER_CYCLES[..workers]
        .iter()
        .map(|cycles| cycles.load(Ordering::Acquire))
        .sum();
    let total_ops = workers * OPS_PER_WORKER;
    let active_ns = hrtime::counts_to_ns(active_cycles).unwrap_or(0);
    let throughput = if active_ns == 0 {
        0
    } else {
        (total_ops as u128 * 1_000_000_000 / active_ns as u128) as u64
    };
    let stats = lock_stats(mode);
    let (p50, p99, p999, max) = summary
        .map(|value| (value.p50, value.p99, value.p999, value.max))
        .unwrap_or((0, 0, 0, 0));
    kprintln!(
        "[JSR-PEX3] mode={} vcpus={} workers={} shards={} ops={} samples={} throughput_ops_s={} p50_cycles={} p99_cycles={} p999_cycles={} max_cycles={} p50_ns={} p99_ns={} p999_ns={} lock_acquired={} lock_contended={} lock_spins={} lock_max_spins={} live={} pending={} resources={} complete={}",
        if mode == 0 { "central" } else { "sharded" },
        cpus.len(),
        workers,
        shard_count,
        total_ops,
        samples.len(),
        throughput,
        p50,
        p99,
        p999,
        max,
        hrtime::counts_to_ns(p50).unwrap_or(0),
        hrtime::counts_to_ns(p99).unwrap_or(0),
        hrtime::counts_to_ns(p999).unwrap_or(0),
        stats.acquired,
        stats.contended,
        stats.spins,
        stats.max_spins,
        live,
        pending,
        resources,
        complete,
    );
    complete && resources
}

fn cross_shard_lifecycle_inner() -> bool {
    let child = match SHARDED[1].lock().insert(Value::Leaf(41), 1, 1) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let parent = match SHARDED[0].lock().insert(Value::Holder(child), 1, 1) {
        Ok(id) => id,
        Err(_) => return false,
    };

    let child_release = SHARDED[1]
        .lock()
        .release_owner_with_closing(child, |table, current| {
            let _ = table.get_mut(current);
        });
    if child_release
        != Ok(Released {
            became_unowned: true,
            dead: false,
        })
        || SHARDED[1].lock().counts(child) != Ok((0, 1, Lifecycle::Closing))
        || SHARDED[1].lock().acquire_owner(child).is_ok()
    {
        return false;
    }

    let parent_release = SHARDED[0]
        .lock()
        .release_owner_with_closing(parent, |table, current| {
            let _ = table.get(current);
        });
    if parent_release
        != Ok(Released {
            became_unowned: true,
            dead: false,
        })
        || !SHARDED[0]
            .lock()
            .release_internal(parent)
            .is_ok_and(|released| released.dead)
    {
        return false;
    }
    let Some((gone_parent, Value::Holder(held_child))) = SHARDED[0].lock().take_dead() else {
        return false;
    };
    if gone_parent != parent || held_child != child {
        return false;
    }
    if !SHARDED[1]
        .lock()
        .release_internal(child)
        .is_ok_and(|released| released.dead)
    {
        return false;
    }
    let Some((gone_child, Value::Leaf(value))) = SHARDED[1].lock().take_dead() else {
        return false;
    };
    if gone_child != child || value != 41 {
        return false;
    }

    let Ok(replacement) = SHARDED[1].lock().insert(Value::Leaf(42), 1, 0) else {
        return false;
    };
    if replacement.index() != child.index()
        || replacement.generation() <= child.generation()
        || SHARDED[1].lock().get(child).is_ok()
    {
        return false;
    }
    let replacement_released = SHARDED[1]
        .lock()
        .release_owner(replacement)
        .is_ok_and(|released| released.dead);
    replacement_released && SHARDED[1].lock().take_dead().is_some()
}

fn cross_shard_lifecycle() -> bool {
    let ok = cross_shard_lifecycle_inner();
    if !ok {
        clear_candidates();
    }
    ok
}

pub fn run() {
    if let Err(_) = install_candidates() {
        check(false, "PEX-3 candidate table allocation failed");
        return;
    }
    reset_lock_stats();
    check(cross_shard_lifecycle(), "PEX-3 cross-shard lifecycle failed");
    check(
        run_mode(0, 1),
        "PEX-3 central candidate did not finish a valid round",
    );
    check(
        run_mode(1, 2),
        "PEX-3 sharded candidate did not finish a valid round",
    );
    let table_bytes = CENTRAL_CAPACITY
        .saturating_mul(size_of::<Slot<Value>>() + size_of::<u32>())
        + SHARDS
            .saturating_mul(SHARD_CAPACITY)
            .saturating_mul(size_of::<Slot<Value>>() + size_of::<u32>());
    kprintln!(
        "[JSR-PEX3] summary shards={} central_capacity={} shard_capacity={} table_bytes={} checks={} failed={}",
        SHARDS,
        CENTRAL_CAPACITY,
        SHARD_CAPACITY,
        table_bytes,
        CHECKS.load(Ordering::Relaxed),
        failed(),
    );
}
