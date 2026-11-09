//! ARCH-2 acceptance: a real user-space driver, service withdrawal and restart.
//!
//! The driver opens and maps virtio-net, creates a Ring and publishes opaque
//! process-local handles through a private control page. A USI client queries
//! service availability while the driver is alive. Killing the driver must
//! make the service unavailable, invalidate the old handles and mapping, and
//! return every resource to the pre-test baseline. A second driver proves that
//! restart restores availability.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::arch2::{
    BAR_MAP_WORD, CONTROL_MAGIC, DEVICE_HANDLE_WORD, READY_VALUE, READY_WORD, RING_HANDLE_WORD,
};
use kernel_core::assembly::Health;
use kernel_core::frame::FRAME_SIZE;
use kernel_core::object::{HandleId, ObjectType};
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;

use crate::baseline::baseline;
use crate::proc::{self, ProcState};
use crate::syscall::table as abi;
use crate::syscall::SyscallSet;
use crate::{arch, assembly, kobj, kprintln, rt_demo, sched, usi1_demo};

static USER_DEVPROBE: &[u8] = include_bytes!(env!("JSR_USER_DEVPROBE"));
static USER_USI: &[u8] = include_bytes!(env!("JSR_USER_USI"));
static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

const CONTROL_OFF: u64 = 256 << 20;
const STACK_OFF: u64 = 0xC0_0000;
const DRIVER_BAR_OFF: u64 = 960 << 20;
const DRIVER_EXIT_CODE: i64 = 137;

fn check(ok: bool, what: &'static str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-ARCH2-FAIL] {}", what);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn driver_calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_DEVICE_LIST,
        abi::SYSTEM_DEVICE_OPEN,
        abi::SYSTEM_DEVICE_GET,
        abi::SYSTEM_DEVICE_CAPABILITY_LIST,
        abi::SYSTEM_DEVICE_MAP,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_TASK_EXIT,
    ])
}

struct Driver {
    pid: ObjId,
    device: HandleId,
    ring: HandleId,
    device_object: ObjId,
    ring_object: ObjId,
}

fn cleanup_failed_start(pid: ObjId) {
    let _ = proc::begin_exit(pid, -1);
    sched::run();
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

fn launch_driver(name: &'static str) -> Option<Driver> {
    let base = arch::USER_WINDOW.0;
    let control_va = base + CONTROL_OFF;
    let stack_top = base + STACK_OFF;
    let pid = proc::create(name, driver_calls()).ok()?;
    let entry = proc::load_elf(pid, USER_DEVPROBE).ok()?;
    if proc::map_anon(pid, control_va, 1, true).is_err() {
        cleanup_failed_start(pid);
        return None;
    }
    for i in 1..=4 {
        if proc::map_new(
            pid,
            stack_top - i * FRAME_SIZE,
            MapFlags::USER | MapFlags::WRITE,
        )
        .is_err()
        {
            cleanup_failed_start(pid);
            return None;
        }
    }
    if proc::spawn_thread(pid, name, entry, stack_top, 5, control_va).is_err() {
        cleanup_failed_start(pid);
        return None;
    }

    let mut ready = false;
    for _ in 0..512 {
        sched::yield_now();
        if proc::read_u64(pid, control_va) == Some(CONTROL_MAGIC) {
            ready = true;
            break;
        }
        if matches!(proc::state(pid), Some(ProcState::Exited { .. }) | None) {
            break;
        }
    }
    if !ready {
        cleanup_failed_start(pid);
        return None;
    }

    let word = |index: usize| {
        proc::read_u64(
            pid,
            control_va + (index * core::mem::size_of::<u64>()) as u64,
        )
    };
    let device = HandleId::from_raw(word(DEVICE_HANDLE_WORD)?);
    let ring = HandleId::from_raw(word(RING_HANDLE_WORD)?);
    let mapped = word(BAR_MAP_WORD)?;
    if word(READY_WORD) != Some(READY_VALUE)
        || mapped != base + DRIVER_BAR_OFF
        || proc::handle_info(pid, device).is_none_or(|(object, _)| object.ty != ObjectType::Device)
        || proc::handle_info(pid, ring).is_none_or(|(object, _)| object.ty != ObjectType::Ring)
        || proc::device_map_count(pid) != Some(1)
        || proc::ring_quota(pid).is_none_or(|quota| quota.rings != 1)
    {
        cleanup_failed_start(pid);
        return None;
    }
    let device_object = ObjId::from_raw(proc::handle_info(pid, device)?.0.id.0)?;
    let ring_object = ObjId::from_raw(proc::handle_info(pid, ring)?.0.id.0)?;
    kprintln!(
        "[JSR-ARCH2] driver={} state=running device=0x{:x} ring=0x{:x} maps=1 ring_quota=1",
        name,
        device.raw(),
        ring.raw()
    );
    Some(Driver {
        pid,
        device,
        ring,
        device_object,
        ring_object,
    })
}

fn usi_query(mode: u64) -> bool {
    let Some((pid, started)) = rt_demo::start_program(
        "arch2-usi-client",
        USER_USI,
        mode,
        usi1_demo::usi_calls(),
        |_| Ok(()),
    ) else {
        return false;
    };
    if !started {
        cleanup_failed_start(pid);
        return false;
    }
    for _ in 0..512 {
        if matches!(proc::state(pid), Some(ProcState::Exited { .. }) | None) {
            break;
        }
        sched::yield_now();
    }
    let state = proc::state(pid);
    let reaped = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    matches!(
        (state, reaped),
        (
            Some(ProcState::Exited { code: 0 }),
            Some(proc::ExitInfo { code: 0, .. })
        )
    )
}

fn stop_driver(driver: &Driver) -> bool {
    if !proc::begin_exit(driver.pid, DRIVER_EXIT_CODE) {
        return false;
    }
    sched::run();
    let state = proc::state(driver.pid);
    let old_handles_invalid = proc::handle_info(driver.pid, driver.device).is_none()
        && proc::handle_info(driver.pid, driver.ring).is_none();
    let old_mapping_invalid = proc::device_map_count(driver.pid) == Some(0);
    let reaped = proc::reap(driver.pid);
    kobj::run_cleanup(usize::MAX);
    let objects_reclaimed = kobj::with(|table| {
        table.get(driver.device_object).is_err() && table.get(driver.ring_object).is_err()
    });
    kprintln!(
        "[JSR-ARCH2] driver_exit pid={:#x} state={:?} old_handles=false old_mapping=false objects_reclaimed={}",
        driver.pid.raw(),
        state,
        objects_reclaimed
    );
    matches!(
        (state, reaped),
        (
            Some(ProcState::Exited {
                code: DRIVER_EXIT_CODE
            }),
            Some(proc::ExitInfo {
                code: DRIVER_EXIT_CODE,
                ..
            })
        )
    ) && old_handles_invalid
        && old_mapping_invalid
        && objects_reclaimed
}

pub fn run() {
    let before = baseline();
    let previous_preemption = sched::set_preemption(true);

    check(
        assembly::acquire("device.pci").is_some(),
        "device service not initially available",
    );
    let Some(first) = launch_driver("arch2-driver-a") else {
        check(false, "first user-space driver did not become ready");
        sched::set_preemption(previous_preemption);
        kprintln!(
            "[JSR-ARCH2] summary drivers=0 restarts=0 failed={}",
            failed()
        );
        return;
    };
    check(
        usi_query(4),
        "USI did not report the live driver service available",
    );

    check(
        stop_driver(&first),
        "driver death did not invalidate handles/mapping or preserve exit",
    );
    check(
        assembly::report_health("devices", Health::Unhealthy).is_ok(),
        "device service withdrawal failed",
    );
    let old_publication_lease_reacquired = assembly::acquire("device.pci").is_some();
    check(
        !old_publication_lease_reacquired,
        "withdrawn service accepted an old-generation lease",
    );
    check(
        usi_query(3),
        "USI did not report unavailable after driver death",
    );

    check(
        assembly::report_health("devices", Health::Healthy).is_ok(),
        "device service recovery failed",
    );
    let Some(second) = launch_driver("arch2-driver-b") else {
        check(false, "restarted user-space driver did not become ready");
        let _ = assembly::report_health("devices", Health::Healthy);
        sched::set_preemption(previous_preemption);
        kprintln!(
            "[JSR-ARCH2] summary drivers=1 restarts=0 failed={}",
            failed()
        );
        return;
    };
    check(
        assembly::acquire("device.pci").is_some(),
        "restarted service is not available",
    );
    check(
        usi_query(4),
        "USI did not report the restarted driver available",
    );
    check(
        stop_driver(&second),
        "restarted driver teardown was incomplete",
    );
    check(
        assembly::report_health("devices", Health::Unhealthy).is_ok(),
        "second device service withdrawal failed",
    );
    check(
        usi_query(3),
        "USI did not report unavailable after second death",
    );
    check(
        assembly::report_health("devices", Health::Healthy).is_ok(),
        "final device service restoration failed",
    );

    sched::set_preemption(previous_preemption);
    let after = baseline();
    check(
        after == before,
        "ARCH-2 resources did not return to baseline",
    );
    let abi = kernel_core::abi_version::NATIVE;
    kprintln!(
        "[JSR-ARCH2] summary drivers=2 restarts=1 available=true unavailable=true old_handles=false old_mapping=false old_lease=false abi={}.{}.{} unchanged=true resources={} failed={}",
        abi.major,
        abi.minor,
        abi.patch,
        after == before,
        failed()
    );
}
