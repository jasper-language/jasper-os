//! HWV-5-VMM: user-space VMM service, stable ABI, crash and restart proof.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::async_ring::Exec;
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::hwvirt::Backend;
use kernel_core::hwvirt_vcpu::{GuestPermissions, VcpuState};
use kernel_core::hwvirt_vmm::{
    ServiceLifecycle, ServiceState, VmExitEvent, VmExitRecord, VMM_ABI_VERSION, VMM_CONTROL_MAGIC,
    VM_EXIT_RECORD_BYTES,
};
use kernel_core::object::{HandleId, ObjectType};
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;

use crate::baseline;
use crate::proc::{self, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::{arch, kobj, kprintln, mm, ring, sched, vcpu};

static USER_VMM: &[u8] = include_bytes!(env!("JSR_USER_VMM"));
static FAILED: AtomicU32 = AtomicU32::new(0);

const CONTROL_OFF: u64 = 256 << 20;
const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;
const GENERATION_WORD: u64 = 5;
const STATUS_WORD: u64 = 6;
const EXIT_COUNT_WORD: u64 = 7;
const RECORDS_OFFSET: u64 = 64;
const START_OFFSET: u64 = 320;
const START_MAGIC: u64 = 0x5354_4152_5400_0000;
const STATUS_OK: u64 = 0x4857_5635_4f4b;
const EXIT_COUNT: usize = 6;

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-HWV5-VMM-FAIL] {}", what);
    }
}

fn calls() -> SyscallSet {
    SyscallSet::of(&[
        abi::SYSTEM_CONSOLE_WRITE,
        abi::SYSTEM_ASYNC_RING_CREATE,
        abi::SYSTEM_ASYNC_RING_ENTER,
        abi::SYSTEM_TASK_YIELD,
        abi::SYSTEM_TIME_WAIT,
        abi::SYSTEM_TASK_EXIT,
    ])
}

struct ServiceProcess {
    pid: ObjId,
    ring: HandleId,
    ring_object: ObjId,
    control: u64,
}

fn control_word(service: &ServiceProcess, index: u64) -> Option<u64> {
    proc::read_u64(service.pid, service.control + index * 8)
}

fn launch(name: &'static str, role: u64, generation: u32) -> Option<ServiceProcess> {
    let base = arch::USER_WINDOW.0;
    let control = base + CONTROL_OFF;
    let stack = base + STACK_TOP_OFF;
    let pid = proc::create(name, calls()).ok()?;
    let entry = match proc::load_elf(pid, USER_VMM) {
        Ok(entry) => entry,
        Err(_) => {
            cleanup_pid(pid);
            return None;
        }
    };
    if proc::map_anon(pid, control, 1, true).is_err() {
        cleanup_pid(pid);
        return None;
    }
    for page in 1..=STACK_PAGES {
        if proc::map_new(
            pid,
            stack - page * FRAME_SIZE,
            MapFlags::USER | MapFlags::WRITE,
        )
        .is_err()
        {
            cleanup_pid(pid);
            return None;
        }
    }
    if proc::spawn_thread(pid, name, entry, stack, role, u64::from(generation)).is_err() {
        cleanup_pid(pid);
        return None;
    }

    let mut ready = false;
    for _ in 0..2048 {
        sched::yield_now();
        if proc::read_u64(pid, control) == Some(VMM_CONTROL_MAGIC) {
            ready = true;
            break;
        }
        if matches!(proc::state(pid), Some(ProcState::Exited { .. }) | None) {
            break;
        }
    }
    if !ready {
        cleanup_pid(pid);
        return None;
    }

    let ring_handle = HandleId::from_raw(proc::read_u64(pid, control + 4 * 8)?);
    let object = proc::handle_info(pid, ring_handle)?;
    if object.0.ty != ObjectType::Ring
        || proc::ring_quota(pid).is_none_or(|quota| quota.rings != 1)
        || proc::read_u64(pid, control + 8) != Some(u64::from(VMM_ABI_VERSION))
        || proc::read_u64(pid, control + GENERATION_WORD * 8) != Some(u64::from(generation))
    {
        cleanup_pid(pid);
        return None;
    }
    let ring_object = ObjId::from_raw(object.0.id.0)?;
    kprintln!(
        "[JSR-HWV5-VMM] service={} state=ready generation={} ring=0x{:x}",
        name,
        generation,
        ring_handle.raw()
    );
    Some(ServiceProcess {
        pid,
        ring: ring_handle,
        ring_object,
        control,
    })
}

fn create_owned_resources(service: &ServiceProcess) -> Option<(HandleId, ObjId, HandleId, ObjId)> {
    let memory = proc::create_guest_memory(service.pid, 512).ok()?;
    let memory_object = ObjId::from_raw(proc::handle_info(service.pid, memory)?.0.id.0)?;
    let cpu = vcpu::create_for(service.pid, Backend::Vmx).ok()?;
    let cpu_object = ObjId::from_raw(proc::handle_info(service.pid, cpu)?.0.id.0)?;
    if vcpu::map_for(
        service.pid,
        cpu,
        memory,
        vcpu::MapRequest {
            guest_start: 0,
            pages: 512,
            memory_offset: 0,
            permissions: GuestPermissions::ALL,
        },
    )
    .is_err()
    {
        let _ = proc::close_handle_for(service.pid, cpu);
        let _ = proc::close_handle_for(service.pid, memory);
        kobj::run_cleanup(usize::MAX);
        return None;
    }
    Some((memory, memory_object, cpu, cpu_object))
}

fn crash_service(
    service: &ServiceProcess,
    cpu: HandleId,
    memory: HandleId,
    cpu_object: ObjId,
    memory_object: ObjId,
) -> bool {
    if !proc::begin_exit(service.pid, 137) {
        return false;
    }
    sched::run();
    let state = proc::state(service.pid);
    let old_handles = proc::handle_info(service.pid, service.ring).is_none()
        && proc::handle_info(service.pid, cpu).is_none()
        && proc::handle_info(service.pid, memory).is_none();
    let old_mapping =
        proc::vm_guest_memory_quota(service.pid).is_some_and(|usage| usage.mapped == 0);
    let reaped = proc::reap(service.pid).is_some();
    kobj::run_cleanup(usize::MAX);
    let objects = kobj::with(|table| {
        table.get(service.ring_object).is_err()
            && table.get(cpu_object).is_err()
            && table.get(memory_object).is_err()
    });
    kprintln!(
        "[JSR-HWV5-VMM] crash generation=1 state={:?} old_handles={} old_mapping={} objects={} reaped={}",
        state,
        old_handles,
        old_mapping,
        objects,
        reaped
    );
    old_handles && old_mapping && objects && reaped && state.is_some()
}

fn wait_exited(pid: ObjId) -> Option<ProcState> {
    for _ in 0..4096 {
        sched::yield_now();
        if matches!(proc::state(pid), Some(ProcState::Exited { .. }) | None) {
            break;
        }
    }
    proc::state(pid)
}

fn run_dispatch(service: &ServiceProcess, generation: u32) -> bool {
    let Some((memory, _memory_object, cpu, _cpu_object)) = create_owned_resources(service) else {
        kprintln!("[JSR-HWV5-VMM-FAIL] stage=resources");
        return false;
    };
    prepare_guest(service.pid, cpu);

    let Some(ring_id) = ring::ring_of(service.pid, service.ring) else {
        kprintln!("[JSR-HWV5-VMM-FAIL] stage=ring-resolve");
        return false;
    };
    let mut requests = [0u64; EXIT_COUNT];
    for (index, request) in requests.iter_mut().enumerate() {
        *request = match ring::submit_manual(
            service.pid,
            service.ring,
            index as u64,
            Some(Exec::Abortable),
            None,
        ) {
            Ok(id) => id,
            Err(error) => {
                kprintln!(
                    "[JSR-HWV5-VMM-FAIL] stage=ring-submit index={} error={}",
                    index,
                    error
                );
                return false;
            }
        };
    }
    if proc::write(
        service.pid,
        service.control + START_OFFSET,
        &(START_MAGIC | u64::from(generation)).to_le_bytes(),
    )
    .is_err()
    {
        kprintln!("[JSR-HWV5-VMM-FAIL] stage=start-publish");
        return false;
    }

    let mut state = VcpuState::initial();
    state.cr0 = 0x8001_0011;
    state.cr3 = 0x1000;
    state.cr4 = 0x20;
    state.xcr0 = 3;
    state.rip = 0x4000;
    state.rflags = 2;
    state.registers[4] = 0x1f_f000;
    if vcpu::save_state_for(service.pid, cpu, state).is_err()
        || vcpu::make_ready_for(service.pid, cpu).is_err()
    {
        kprintln!("[JSR-HWV5-VMM-FAIL] stage=vcpu-state");
        return false;
    }
    let ept_root = match vcpu::view(service.pid, cpu) {
        Ok(view) => view.table_root,
        Err(error) => {
            kprintln!("[JSR-HWV5-VMM-FAIL] stage=vcpu-view error={:?}", error);
            return false;
        }
    };
    let execution = crate::arch::x86_64::vmx::GuestExecutionState {
        state,
        rsp: 0x1f_f000,
        cr3_gpa: 0x1000,
        efer: 0x500,
        tsc_offset: -1000,
    };
    let mut vm = match crate::arch::x86_64::vmx::VmxVm::new(ept_root, execution) {
        Ok(vm) => vm,
        Err(error) => {
            kprintln!(
                "[JSR-HWV5-VMM-FAIL] stage=vmx-setup error={:?} name={}",
                error,
                error.name()
            );
            return false;
        }
    };
    if vm.set_guest_idt(0x6000, 0xfff).is_err()
        || vm.set_guest_gdt(0x5000, 0x17).is_err()
        || vcpu::begin_run_for(service.pid, cpu).is_err()
    {
        kprintln!("[JSR-HWV5-VMM-FAIL] stage=vmx-preentry");
        return false;
    }

    let mut exit_count = 0usize;
    let mut delivered = 0usize;
    let mut observer = |event: VmExitEvent| {
        let index = exit_count;
        if !crate::hwv5_policy::vmm_exit(generation) {
            kprintln!(
                "[JSR-HWV5-VMM-FAIL] stage=policy index={} generation={}",
                index,
                generation
            );
            return Err(crate::arch::x86_64::vmx::VmxError::EventDelivery);
        }
        kprintln!(
            "[JSR-HWV5-VMM] exit index={} reason={} vector={} gpa=0x{:x} rip_len={}",
            index,
            event.reason,
            event.vector,
            event.guest_physical,
            event.instruction_length
        );
        if index >= EXIT_COUNT {
            kprintln!(
                "[JSR-HWV5-VMM-FAIL] stage=observer-overflow index={} reason={}",
                index,
                event.reason
            );
            return Err(crate::arch::x86_64::vmx::VmxError::EventDelivery);
        }
        let Some(record) = VmExitRecord::new(generation, event) else {
            kprintln!("[JSR-HWV5-VMM-FAIL] stage=observer-record index={}", index);
            return Err(crate::arch::x86_64::vmx::VmxError::EventDelivery);
        };
        if proc::write(
            service.pid,
            service.control + RECORDS_OFFSET + (index * VM_EXIT_RECORD_BYTES) as u64,
            &record.encode(),
        )
        .is_err()
        {
            kprintln!("[JSR-HWV5-VMM-FAIL] stage=observer-write index={}", index);
            return Err(crate::arch::x86_64::vmx::VmxError::EventDelivery);
        }
        if proc::write(
            service.pid,
            service.control + EXIT_COUNT_WORD * 8,
            &((index + 1) as u64).to_le_bytes(),
        )
        .is_err()
        {
            kprintln!("[JSR-HWV5-VMM-FAIL] stage=observer-count index={}", index);
            return Err(crate::arch::x86_64::vmx::VmxError::EventDelivery);
        }
        exit_count += 1;
        if ring::manual_finish(ring_id, requests[index], i64::from(event.reason)) {
            delivered += 1;
        } else {
            kprintln!(
                "[JSR-HWV5-VMM-FAIL] stage=observer-ring index={} request={} reason={}",
                index,
                requests[index],
                event.reason
            );
            return Err(crate::arch::x86_64::vmx::VmxError::EventDelivery);
        }
        if index == 4 {
            Ok(crate::arch::x86_64::vmx::VmxObserverAction::Inject(0x20))
        } else {
            Ok(crate::arch::x86_64::vmx::VmxObserverAction::Continue)
        }
    };
    let report = match vm.run_with_observer(&mut observer) {
        Ok(report) => report,
        Err(error) => {
            vcpu::fail_run_for(service.pid, cpu);
            kprintln!(
                "[JSR-HWV5-VMM-FAIL] stage=vmx-run error={:?} name={}",
                error,
                error.name()
            );
            return false;
        }
    };
    let final_state = vm.guest_state();
    let lifecycle = vcpu::finish_run_for(service.pid, cpu, final_state).is_ok();
    let shutdown = vm.shutdown().is_ok();
    drop(vm);
    let guest_marker = read_gpa(service.pid, cpu, 0x7000);
    let _ = proc::close_handle_for(service.pid, cpu);
    let _ = proc::close_handle_for(service.pid, memory);
    kobj::run_cleanup(usize::MAX);

    let state = wait_exited(service.pid);
    let status = control_word(service, STATUS_WORD);
    let count = control_word(service, EXIT_COUNT_WORD);
    let service_generation = control_word(service, GENERATION_WORD);
    let exit = proc::reap(service.pid);
    kobj::run_cleanup(usize::MAX);
    let ok = report.exits == EXIT_COUNT as u32
        && exit_count == EXIT_COUNT
        && delivered == EXIT_COUNT
        && lifecycle
        && shutdown
        && guest_marker == 0x4857_5634_494e_4a45
        && status == Some(STATUS_OK)
        && count == Some(EXIT_COUNT as u64)
        && service_generation == Some(u64::from(generation))
        && matches!(
            (state, exit),
            (
                Some(ProcState::Exited { code: 0 }),
                Some(proc::ExitInfo { code: 0, .. })
            )
        );
    kprintln!(
        "[JSR-HWV5-VMM] dispatch generation={} exits={} delivered={} records={} status={:?} lifecycle={} shutdown={} guest={} service_exit={:?}",
        generation,
        report.exits,
        delivered,
        exit_count,
        status,
        lifecycle,
        shutdown,
        guest_marker == 0x4857_5634_494e_4a45,
        exit.map(|info| info.code)
    );
    ok
}

pub fn run() -> bool {
    let before = baseline::baseline();
    let previous_preemption = sched::set_preemption(true);
    let mut service = ServiceLifecycle::new();
    check(service.attach(1), "first VMM generation did not attach");

    let Some(first) = launch("hwv5-vmm-a", 0, 1) else {
        check(false, "first user-space VMM did not become ready");
        sched::set_preemption(previous_preemption);
        return false;
    };
    let Some((memory, memory_object, cpu, cpu_object)) = create_owned_resources(&first) else {
        check(false, "first VMM did not own VM resources");
        sched::set_preemption(previous_preemption);
        return false;
    };
    check(
        crash_service(&first, cpu, memory, cpu_object, memory_object),
        "VMM crash did not revoke or reclaim its resources",
    );
    check(service.crash(), "service lifecycle did not enter Failed");
    let next_generation = service.recover().unwrap_or(0);
    check(
        next_generation == 2,
        "service restart did not advance generation",
    );
    check(
        before == baseline::baseline(),
        "crashed VMM resources did not return to baseline",
    );

    check(service.begin(), "restarted service did not enter Running");
    let Some(second) = launch("hwv5-vmm-b", 1, next_generation) else {
        check(false, "restarted user-space VMM did not become ready");
        sched::set_preemption(previous_preemption);
        return false;
    };
    let dispatch = run_dispatch(&second, next_generation);
    check(
        dispatch,
        "restarted VMM did not complete the exit delivery path",
    );
    if dispatch {
        check(service.finish(), "service could not return to Ready");
    }
    check(
        matches!(service.state(), ServiceState::Ready),
        "service did not remain ready after successful dispatch",
    );

    sched::set_preemption(previous_preemption);
    let after = baseline::baseline();
    let resources = after == before;
    check(
        resources,
        "VMM restart resources did not return to baseline",
    );
    kprintln!(
        "[JSR-HWV5-VMM] abi={} generation=2 crashed=true old_handles=false old_mapping=false exits={} records={} ring=true restart=true revoked=true resources={} failed={}",
        VMM_ABI_VERSION,
        if dispatch { EXIT_COUNT } else { 0 },
        if dispatch { EXIT_COUNT } else { 0 },
        resources,
        failed()
    );
    failed() == 0
}

fn cleanup_pid(pid: ObjId) {
    let _ = proc::begin_exit(pid, -1);
    sched::run();
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

fn prepare_guest(pid: ObjId, handle: HandleId) {
    write_u64(pid, handle, 0x1000, 0x2003);
    write_u64(pid, handle, 0x2000, 0x3003);
    write_u64(pid, handle, 0x3000, 0x83);
    write_u64(pid, handle, 0x3008, 0x20_0083);
    let code = [
        0x0f, 0xa2, 0x0f, 0x31, 0xb9, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x32, 0x66, 0xba, 0x80, 0x00,
        0xec, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x20, 0x00, 0x48, 0x89, 0x00, 0x0f, 0x0b,
    ];
    write_gpa(pid, handle, 0x4000, &code);
    let handler = [
        0x48, 0xb8, 0x45, 0x4a, 0x4e, 0x49, 0x34, 0x56, 0x57, 0x48, 0x48, 0xa3, 0x00, 0x70, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x0b,
    ];
    write_gpa(pid, handle, 0x4100, &handler);
    let gdt: [u64; 3] = [0, 0x00af_9a00_0000_ffff, 0x00cf_9200_0000_ffff];
    for (index, entry) in gdt.into_iter().enumerate() {
        write_u64(pid, handle, 0x5000 + index as u64 * 8, entry);
    }
    let mut gate = [0u8; 16];
    gate[0..2].copy_from_slice(&0x4100u16.to_le_bytes());
    gate[2..4].copy_from_slice(&0x8u16.to_le_bytes());
    gate[5] = 0x8e;
    gate[6..8].copy_from_slice(&(0x4100u64 >> 16).to_le_bytes()[..2]);
    gate[8..12].copy_from_slice(&(0x4100u64 >> 32).to_le_bytes()[..4]);
    write_gpa(pid, handle, 0x6000 + 0x20 * 16, &gate);
    write_u64(pid, handle, 0x7000, 0);
}

fn write_u64(pid: ObjId, handle: HandleId, gpa: u64, value: u64) {
    write_gpa(pid, handle, gpa, &value.to_le_bytes());
}

fn write_gpa(pid: ObjId, handle: HandleId, gpa: u64, bytes: &[u8]) {
    let frame: PhysFrame = vcpu::translate(pid, handle, gpa)
        .ok()
        .flatten()
        .expect("guest GPA translation");
    let mapped = mm::phys_to_virt(frame.start() + gpa % FRAME_SIZE).expect("guest physical map");
    assert!((gpa % FRAME_SIZE) as usize + bytes.len() <= FRAME_SIZE as usize);
    // SAFETY: the GPA is pinned by the vCPU mapping and this write stays in
    // one physical page.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped, bytes.len()) };
}

fn read_gpa(pid: ObjId, handle: HandleId, gpa: u64) -> u64 {
    let frame: PhysFrame = vcpu::translate(pid, handle, gpa)
        .ok()
        .flatten()
        .expect("guest GPA translation");
    let mapped = mm::phys_to_virt(frame.start() + gpa % FRAME_SIZE).expect("guest physical map");
    // SAFETY: the GPA is pinned and this reads one aligned u64 within a page.
    unsafe { (mapped as *const u64).read_volatile() }
}
