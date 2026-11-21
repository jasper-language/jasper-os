//! Native address-condition synchronization over a real shared MemoryObject.
//!
//! This is a kernel-level integration drill, not a new user ABI. Two real
//! Process objects map the same MemoryObject, two scheduler tasks park through
//! their existing Task event-wait keys, and one task publishes the condition
//! while holding the same address-condition critical section that protects the
//! mapped word.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use kernel_core::address_sync::{AddressGrant, AddressState, AddressSync, AddressWait};
use kernel_core::memory_capability::MemoryRights;
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::sched::Qos;
use kernel_core::smp::CpuSet;

use crate::kobj;
use crate::mm::pin::PinnedRange;
use crate::proc;
use crate::sched;
use crate::sync::IrqSpinLock;
use crate::task::TaskId;
use crate::{arch, kprintln};

const WORD_BYTES: u64 = 8;
const PUBLISHED: u64 = 0x4a53_5241_4452_5359;

static FAILED: AtomicU32 = AtomicU32::new(0);
static PARKED: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static STAGE: AtomicU32 = AtomicU32::new(0);
static PASS_CPUS: AtomicU32 = AtomicU32::new(0);
static DISTRIBUTED: AtomicBool = AtomicBool::new(false);
static PUBLISHER_DISTRIBUTED: AtomicBool = AtomicBool::new(false);
static REVOKE_MODE: AtomicBool = AtomicBool::new(false);
static EXIT_MODE: AtomicBool = AtomicBool::new(false);
static REMAP_MODE: AtomicBool = AtomicBool::new(false);
static REVOKED: AtomicBool = AtomicBool::new(false);
static PROCESS_EXITED: AtomicBool = AtomicBool::new(false);
static REMAPPED: AtomicBool = AtomicBool::new(false);
static SYNC: IrqSpinLock<Option<AddressSync<4>>> = IrqSpinLock::new(None);
static GRANTS: IrqSpinLock<[Option<AddressGrant>; 2]> = IrqSpinLock::new([None; 2]);
static TARGETS: IrqSpinLock<[Option<(ObjId, u64)>; 2]> = IrqSpinLock::new([None; 2]);
static REMAP: IrqSpinLock<Option<(HandleId, u64)>> = IrqSpinLock::new(None);

fn fail() {
    FAILED.fetch_add(1, Ordering::Relaxed);
    kprintln!(
        "[JSR-ADDRESS-SYNC-FAIL] stage={}",
        STAGE.load(Ordering::Relaxed)
    );
}

fn finish(index: usize, ok: bool) {
    if !ok {
        fail();
    }
    DONE.fetch_add(1, Ordering::Release);
    let _ = index;
}

fn wait_until_parked(expected: u32) -> bool {
    loop {
        if PARKED.load(Ordering::Acquire) == expected {
            return true;
        }
        if DONE.load(Ordering::Acquire) != 0 {
            return false;
        }
        sched::yield_with_cause("yield");
    }
}

fn only(cpu: usize) -> CpuSet {
    let mut set = CpuSet::EMPTY;
    set.insert(cpu);
    set
}

fn read_word(pin: &PinnedRange) -> Option<u64> {
    let mut bytes = [0u8; WORD_BYTES as usize];
    pin.read_at(0, &mut bytes)
        .then_some(u64::from_le_bytes(bytes))
}

fn word_pin(index: usize, write: bool) -> Option<PinnedRange> {
    let (pid, va) = *TARGETS.lock()[index].as_ref()?;
    kobj::with(|t| proc::pin_user_in(t, pid, va, WORD_BYTES as usize, write)).ok()
}

fn waiter(index: usize) {
    let grant = { GRANTS.lock()[index] };
    let Some(grant) = grant else {
        finish(index, false);
        return;
    };
    let Some(pin) = word_pin(index, false) else {
        finish(index, false);
        return;
    };

    let expected = {
        let sync = SYNC.lock();
        let Some(sync) = sync.as_ref() else {
            finish(index, false);
            return;
        };
        let Some(value) = read_word(&pin) else {
            finish(index, false);
            return;
        };
        AddressState {
            version: sync.state().version,
            value,
        }
    };

    loop {
        {
            let sync = SYNC.lock();
            let Some(sync) = sync.as_ref() else {
                finish(index, false);
                return;
            };
            match sync.observe(grant, expected) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    let value = read_word(&pin);
                    finish(index, value == Some(PUBLISHED));
                    return;
                }
                Err(_) => {
                    finish(index, false);
                    return;
                }
            }
        }

        let key = match sched::enroll_event_wait(None, None) {
            Ok(Some(key)) => key,
            _ => {
                finish(index, false);
                return;
            }
        };

        let armed = {
            let mut guard = SYNC.lock();
            match guard.as_mut() {
                Some(sync) => {
                    read_word(&pin).is_some_and(|value| value == expected.value)
                        && sync.observe(grant, expected) == Ok(None)
                        && sync.arm_key(grant, key).is_ok()
                }
                _ => false,
            }
        };
        if !armed {
            let _ = sched::wake_event_wait(key);
            sched::yield_with_cause("address-sync-retry");
            continue;
        }

        PARKED.fetch_add(1, Ordering::Release);
        sched::yield_with_cause("block");

        let ready = {
            let mut sync = SYNC.lock();
            sync.as_mut().map(|sync| sync.take_key(key))
        };
        if REVOKE_MODE.load(Ordering::Acquire) {
            let Some((pid, va)) = TARGETS.lock()[index] else {
                finish(index, false);
                return;
            };
            let revoked =
                proc::memory_capability_use(pid, va, WORD_BYTES, MemoryRights::READ).is_none();
            finish(index, revoked && ready.is_some());
            return;
        }
        let ok = matches!(ready, Some(Ok(AddressWait::Ready(state)))
            if state.value == PUBLISHED && state.version == 1);
        finish(index, ok && read_word(&pin) == Some(PUBLISHED));
        return;
    }
}

fn waiter0() {
    waiter(0);
}

fn waiter1() {
    waiter(1);
}

fn publisher() {
    fn abort() {
        let mut wake = [None; 4];
        {
            let mut sync = SYNC.lock();
            if let Some(sync) = sync.as_mut() {
                sync.drain_keys(&mut wake);
            }
        }
        for key in wake.into_iter().flatten() {
            let _ = sched::wake_event_wait(key);
        }
        finish(2, false);
    }

    if sched::set_current_qos(Qos::Background).is_err() {
        abort();
        return;
    }
    if !wait_until_parked(2) {
        abort();
        return;
    }
    let Some(pin) = word_pin(0, true) else {
        abort();
        return;
    };
    let Some(range) = GRANTS.lock()[0].map(|grant| grant.range()) else {
        abort();
        return;
    };
    let mut wake = [None; 4];
    let published = {
        let mut guard = SYNC.lock();
        match guard.as_mut() {
            Some(sync) if pin.write_at(0, &PUBLISHED.to_le_bytes()) => {
                sync.publish_keys(range, PUBLISHED, wake.len(), &mut wake)
            }
            _ => Err(kernel_core::address_sync::AddressSyncError::InternalSet),
        }
    };
    if published != Ok(2) {
        abort();
        return;
    }
    for key in wake.into_iter().flatten() {
        let _ = sched::wake_event_wait(key);
    }
    finish(2, true);
}

fn revoker() {
    if sched::set_current_qos(Qos::Background).is_err() {
        finish(2, false);
        return;
    }
    if !wait_until_parked(1) {
        finish(2, false);
        return;
    }
    let Some((pid, va)) = TARGETS.lock()[1] else {
        finish(2, false);
        return;
    };
    let released = if EXIT_MODE.load(Ordering::Acquire) {
        let exited = proc::exit_idle(pid, 0);
        let reaped = exited && proc::reap(pid).is_some();
        PROCESS_EXITED.store(exited && reaped, Ordering::Release);
        exited && reaped
    } else if REMAP_MODE.load(Ordering::Acquire) {
        let unmapped = proc::unmap_memory(pid, va, 1).is_ok();
        let remap = {
            let Some((handle, new_va)) = *REMAP.lock() else {
                finish(2, false);
                return;
            };
            proc::map_memory(pid, handle, new_va, 0, 1, true).is_ok()
                && proc::memory_capability_use(
                    pid,
                    new_va,
                    WORD_BYTES,
                    MemoryRights::READ.union(MemoryRights::WRITE),
                )
                .is_some()
        };
        REMAPPED.store(unmapped && remap, Ordering::Release);
        unmapped && remap
    } else {
        proc::unmap_memory(pid, va, 1).is_ok()
    };
    let revoked = proc::memory_capability_use(pid, va, WORD_BYTES, MemoryRights::READ).is_none();
    REVOKED.store(released && revoked, Ordering::Release);
    let mut wake = [None; 4];
    {
        let mut sync = SYNC.lock();
        if let Some(sync) = sync.as_mut() {
            sync.drain_keys(&mut wake);
        }
    }
    for key in wake.into_iter().flatten() {
        let _ = sched::wake_event_wait(key);
    }
    finish(2, released && revoked);
}

fn reset_globals() {
    PARKED.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    STAGE.store(0, Ordering::Relaxed);
    PASS_CPUS.store(0, Ordering::Relaxed);
    DISTRIBUTED.store(false, Ordering::Relaxed);
    PUBLISHER_DISTRIBUTED.store(false, Ordering::Relaxed);
    REVOKE_MODE.store(false, Ordering::Relaxed);
    EXIT_MODE.store(false, Ordering::Relaxed);
    REMAP_MODE.store(false, Ordering::Relaxed);
    REVOKED.store(false, Ordering::Relaxed);
    PROCESS_EXITED.store(false, Ordering::Relaxed);
    REMAPPED.store(false, Ordering::Relaxed);
    *SYNC.lock() = None;
    *GRANTS.lock() = [None; 2];
    *TARGETS.lock() = [None; 2];
    *REMAP.lock() = None;
}

fn run_pass(pass: u64, revoke_mode: bool, exit_mode: bool, remap_mode: bool) -> bool {
    let before = crate::baseline::baseline();
    reset_globals();
    REVOKE_MODE.store(revoke_mode, Ordering::Release);
    EXIT_MODE.store(exit_mode, Ordering::Release);
    REMAP_MODE.store(remap_mode, Ordering::Release);
    STAGE.store(1, Ordering::Relaxed);
    let calls = crate::syscall::SyscallSet::of(&[]);
    let Ok(a) = proc::create("address-sync-a", calls) else {
        fail();
        return false;
    };
    let Ok(b) = proc::create("address-sync-b", calls) else {
        let _ = proc::exit_idle(a, 0);
        if proc::reap(a).is_none() {
            fail();
        }
        return false;
    };
    STAGE.store(2, Ordering::Relaxed);
    let Ok(memory) = proc::create_memory(a, 1) else {
        fail();
        return false;
    };
    STAGE.store(3, Ordering::Relaxed);
    let Some(memory_id) =
        proc::handle_info(a, memory).and_then(|info| ObjId::from_raw(info.0.id.0))
    else {
        fail();
        return false;
    };
    let rights = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::MAP)
        .union(Rights::DUPLICATE);
    let Ok(second) = proc::grant(b, memory_id, ObjectType::Memory, rights) else {
        fail();
        return false;
    };
    STAGE.store(4, Ordering::Relaxed);
    let a_va = arch::USER_WINDOW.0 + 0x40_0000;
    let b_va = arch::USER_WINDOW.0 + 0x50_0000;
    if proc::map_memory(a, memory, a_va, 0, 1, true).is_err()
        || proc::map_memory(b, second, b_va, 0, 1, true).is_err()
    {
        fail();
        return false;
    }
    STAGE.store(5, Ordering::Relaxed);
    let Some(a_use) = proc::memory_capability_use(
        a,
        a_va,
        WORD_BYTES,
        MemoryRights::READ.union(MemoryRights::WRITE),
    ) else {
        fail();
        return false;
    };
    STAGE.store(6, Ordering::Relaxed);
    let Some(b_use) = proc::memory_capability_use(
        b,
        b_va,
        WORD_BYTES,
        MemoryRights::READ.union(MemoryRights::WRITE),
    ) else {
        fail();
        return false;
    };
    STAGE.store(7, Ordering::Relaxed);
    let Ok(a_grant) = AddressGrant::from_use(a_use, 0, WORD_BYTES as u32, MemoryRights::READ)
    else {
        fail();
        return false;
    };
    let Ok(b_grant) = AddressGrant::from_use(b_use, 0, WORD_BYTES as u32, MemoryRights::READ)
    else {
        fail();
        return false;
    };
    STAGE.store(8, Ordering::Relaxed);
    if a_grant.range() != b_grant.range() {
        fail();
        return false;
    }
    STAGE.store(9, Ordering::Relaxed);
    *SYNC.lock() = Some(AddressSync::new(a_grant.range(), AddressState::default()));
    *GRANTS.lock() = [Some(a_grant), Some(b_grant)];
    *TARGETS.lock() = [Some((a, a_va)), Some((b, b_va))];
    if remap_mode {
        *REMAP.lock() = Some((second, arch::USER_WINDOW.0 + 0x60_0000));
    }

    STAGE.store(10, Ordering::Relaxed);
    let base = 0xa44_2000 + pass * 0x10;
    let online: alloc::vec::Vec<_> = sched::online_cpus().iter().collect();
    if online.is_empty() {
        fail();
        return false;
    }
    let cpu_a = online[0];
    let cpu_b = online.get(1).copied().unwrap_or(cpu_a);
    let cpu_p = online.get(2).copied().unwrap_or(cpu_a);
    PASS_CPUS.store(online.len() as u32, Ordering::Relaxed);
    DISTRIBUTED.store(cpu_a != cpu_b, Ordering::Relaxed);
    PUBLISHER_DISTRIBUTED.store(cpu_p != cpu_a && cpu_p != cpu_b, Ordering::Relaxed);
    let spawned = if revoke_mode {
        sched::spawn_on(
            TaskId(base + 1),
            "address-sync-revoke-waiter",
            waiter1,
            None,
            only(cpu_a),
        )
        .is_ok()
            && sched::spawn_on(
                TaskId(base + 2),
                "address-sync-revoker",
                revoker,
                None,
                only(cpu_b),
            )
            .is_ok()
    } else {
        sched::spawn_on(TaskId(base), "address-sync-a", waiter0, None, only(cpu_a)).is_ok()
            && sched::spawn_on(
                TaskId(base + 1),
                "address-sync-b",
                waiter1,
                None,
                only(cpu_b),
            )
            .is_ok()
            && sched::spawn_on(
                TaskId(base + 2),
                "address-sync-publisher",
                publisher,
                None,
                only(cpu_p),
            )
            .is_ok()
    };
    if !spawned {
        fail();
        return false;
    }
    STAGE.store(11, Ordering::Relaxed);
    sched::run();
    STAGE.store(12, Ordering::Relaxed);
    let affinity_ok = if revoke_mode {
        sched::ran_on(TaskId(base + 1)).is_some_and(|set| set.contains(cpu_a))
            && sched::ran_on(TaskId(base + 2)).is_some_and(|set| set.contains(cpu_b))
    } else {
        sched::ran_on(TaskId(base)).is_some_and(|set| set.contains(cpu_a))
            && sched::ran_on(TaskId(base + 1)).is_some_and(|set| set.contains(cpu_b))
            && sched::ran_on(TaskId(base + 2)).is_some_and(|set| set.contains(cpu_p))
    };
    if !affinity_ok {
        fail();
    }
    let expected_done = if revoke_mode { 2 } else { 3 };
    if DONE.load(Ordering::Acquire) != expected_done || FAILED.load(Ordering::Relaxed) != 0 {
        fail();
    }
    let exited =
        proc::exit_idle(a, 0) && (proc::exit_idle(b, 0) || PROCESS_EXITED.load(Ordering::Acquire));
    let a_reaped = proc::reap(a).is_some();
    let b_reaped = proc::reap(b).is_some()
        || (EXIT_MODE.load(Ordering::Acquire) && PROCESS_EXITED.load(Ordering::Acquire));
    if !a_reaped || !b_reaped {
        fail();
    }
    kobj::run_cleanup(usize::MAX);
    STAGE.store(13, Ordering::Relaxed);
    let after = crate::baseline::baseline();
    exited && before == after
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    FAILED.store(0, Ordering::Relaxed);
    for pass in 0..2 {
        let ok = run_pass(pass, false, false, false);
        let parked = PARKED.load(Ordering::Acquire) == 2;
        let terminal = DONE.load(Ordering::Acquire) == 3 && FAILED.load(Ordering::Relaxed) == 0;
        kprintln!(
            "[JSR-ADDRESS-SYNC] pass={} phase={} mode=sync cpus={} distributed={} publisher_distributed={} parked={} terminal={} same_object={} resources={} failed={}",
            pass + 1,
            if pass == 0 { "warmup" } else { "measured" },
            PASS_CPUS.load(Ordering::Relaxed),
            DISTRIBUTED.load(Ordering::Relaxed),
            PUBLISHER_DISTRIBUTED.load(Ordering::Relaxed),
            if parked { 2 } else { PARKED.load(Ordering::Acquire) },
            terminal,
            ok && FAILED.load(Ordering::Relaxed) == 0,
            ok,
            failed()
        );
    }
    let ok = run_pass(2, true, false, false);
    let parked = PARKED.load(Ordering::Acquire) == 1;
    let terminal = DONE.load(Ordering::Acquire) == 2 && FAILED.load(Ordering::Relaxed) == 0;
    kprintln!(
        "[JSR-ADDRESS-SYNC] pass=3 phase=revoke mode=revoke cpus={} distributed={} parked={} terminal={} revoked={} resources={} failed={}",
        PASS_CPUS.load(Ordering::Relaxed),
        DISTRIBUTED.load(Ordering::Relaxed),
        if parked { 1 } else { PARKED.load(Ordering::Acquire) },
        terminal,
        REVOKED.load(Ordering::Acquire),
        ok,
        failed()
    );
    let ok = run_pass(3, true, true, false);
    let parked = PARKED.load(Ordering::Acquire) == 1;
    let terminal = DONE.load(Ordering::Acquire) == 2 && FAILED.load(Ordering::Relaxed) == 0;
    kprintln!(
        "[JSR-ADDRESS-SYNC] pass=4 phase=exit mode=exit cpus={} distributed={} parked={} terminal={} exited={} revoked={} resources={} failed={}",
        PASS_CPUS.load(Ordering::Relaxed),
        DISTRIBUTED.load(Ordering::Relaxed),
        if parked { 1 } else { PARKED.load(Ordering::Acquire) },
        terminal,
        PROCESS_EXITED.load(Ordering::Acquire),
        REVOKED.load(Ordering::Acquire),
        ok,
        failed()
    );
    let ok = run_pass(4, true, false, true);
    let parked = PARKED.load(Ordering::Acquire) == 1;
    let terminal = DONE.load(Ordering::Acquire) == 2 && FAILED.load(Ordering::Relaxed) == 0;
    kprintln!(
        "[JSR-ADDRESS-SYNC] pass=5 phase=remap mode=remap cpus={} distributed={} parked={} terminal={} remapped={} revoked={} resources={} failed={}",
        PASS_CPUS.load(Ordering::Relaxed),
        DISTRIBUTED.load(Ordering::Relaxed),
        if parked { 1 } else { PARKED.load(Ordering::Acquire) },
        terminal,
        REMAPPED.load(Ordering::Acquire),
        REVOKED.load(Ordering::Acquire),
        ok,
        failed()
    );
}
