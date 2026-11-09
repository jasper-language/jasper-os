//! HWV-4 first checkpoint: VM exits through the existing Ring state machine,
//! cancellation/single-terminal checks, and the virtual interrupt core.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use kernel_core::async_ring::Exec;
use kernel_core::frame::PhysFrame;
use kernel_core::hwvirt::Backend;
use kernel_core::hwvirt_vcpu::{GuestPermissions, VcpuState};

use crate::arch::x86_64::virtual_interrupt::{RaiseResult, VirtualInterruptController};
use crate::{kobj, kprintln, mm, proc, ring, vcpu};

static FAILED: AtomicU32 = AtomicU32::new(0);
static WAIT_RING: AtomicU64 = AtomicU64::new(0);
static WAIT_REQUEST: AtomicU64 = AtomicU64::new(0);
static WAIT_PID: AtomicU64 = AtomicU64::new(0);
static WAIT_RING_HANDLE: AtomicU64 = AtomicU64::new(0);
static WAIT_DELIVERED: AtomicBool = AtomicBool::new(false);
static WAIT_WOKE: AtomicBool = AtomicBool::new(false);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-HWV4-FAIL] {}", what);
    }
}

pub fn run() {
    let interrupts_ok = check_virtual_interrupts();
    let backend = crate::hwvirt_demo::selected_backend();
    if backend != Some(Backend::Vmx) {
        kprintln!(
            "[JSR-HWV4] backend={:?} exit_ring=false vic={} reason=vendor_mismatch failed={}",
            backend,
            interrupts_ok,
            failed()
        );
        return;
    }

    let before = crate::baseline::baseline();
    let pid = match proc::create("hwv4-vmx", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let memory = match proc::create_guest_memory(pid, 512) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "guest backing allocation failed");
            abort_process(pid, None, None, None, before);
            return;
        }
    };
    check(
        proc::memory_quota(pid).is_some_and(|usage| usage.mapped == 0),
        "guest RAM leaked into the ordinary process account",
    );
    check(
        proc::vm_guest_memory_quota(pid).is_some_and(|usage| usage.mapped == 512),
        "guest RAM was not charged to the VM account",
    );
    let large = match proc::create_guest_memory(pid, 9000) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "guest RAM is still capped near 32 MiB");
            abort_process(pid, None, Some(memory), None, before);
            return;
        }
    };
    check(
        proc::vm_guest_memory_quota(pid).is_some_and(|usage| usage.mapped == 9512),
        "large guest reservation was not charged",
    );
    check(
        proc::close_handle_for(pid, large).is_ok(),
        "large guest reservation close failed",
    );
    kobj::run_cleanup(usize::MAX);
    check(
        proc::vm_guest_memory_quota(pid).is_some_and(|usage| usage.mapped == 512),
        "large guest reservation did not return",
    );
    let vcpu_handle = match vcpu::create_for(pid, Backend::Vmx) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "vCPU creation failed");
            abort_process(pid, None, Some(memory), None, before);
            return;
        }
    };
    if vcpu::map_for(
        pid,
        vcpu_handle,
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
        check(false, "EPT mapping failed");
        abort_process(pid, Some(vcpu_handle), Some(memory), None, before);
        return;
    }
    prepare_guest(pid, vcpu_handle);

    let ring_handle = match ring::create_for(pid, 8) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "exit Ring creation failed");
            abort_process(pid, Some(vcpu_handle), Some(memory), None, before);
            return;
        }
    };
    let ring_id = match ring::ring_of(pid, ring_handle) {
        Some(id) => id,
        None => {
            check(false, "exit Ring resolution failed");
            abort_process(
                pid,
                Some(vcpu_handle),
                Some(memory),
                Some(ring_handle),
                before,
            );
            return;
        }
    };
    let mut requests = [0u64; 6];
    for (index, request) in requests.iter_mut().enumerate() {
        *request = match ring::submit_manual(
            pid,
            ring_handle,
            index as u64,
            Some(Exec::Abortable),
            None,
        ) {
            Ok(id) => id,
            Err(_) => {
                check(false, "VM-exit Ring wait submission failed");
                abort_process(
                    pid,
                    Some(vcpu_handle),
                    Some(memory),
                    Some(ring_handle),
                    before,
                );
                return;
            }
        };
    }
    let cancelled_request = requests[4];
    check(
        ring::cancel_for(pid, ring_handle, cancelled_request) == 0,
        "pre-exit cancellation failed",
    );

    let mut state = VcpuState::initial();
    state.cr0 = 0x8001_0011;
    state.cr3 = 0x1000;
    state.cr4 = 0x20;
    state.xcr0 = 3;
    state.rip = 0x4000;
    state.rflags = 2;
    state.registers[4] = 0x1f_f000;
    if vcpu::save_state_for(pid, vcpu_handle, state).is_err()
        || vcpu::make_ready_for(pid, vcpu_handle).is_err()
    {
        check(false, "vCPU state setup failed");
        abort_process(
            pid,
            Some(vcpu_handle),
            Some(memory),
            Some(ring_handle),
            before,
        );
        return;
    }
    let ept_root = match vcpu::view(pid, vcpu_handle) {
        Ok(view) => view.table_root,
        Err(_) => {
            check(false, "vCPU view failed");
            abort_process(
                pid,
                Some(vcpu_handle),
                Some(memory),
                Some(ring_handle),
                before,
            );
            return;
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
                "[JSR-HWV4-FAIL] vmx_setup={:?} name={}",
                error,
                error.name()
            );
            FAILED.fetch_add(1, Ordering::Relaxed);
            abort_process(
                pid,
                Some(vcpu_handle),
                Some(memory),
                Some(ring_handle),
                before,
            );
            return;
        }
    };
    check(
        vm.set_guest_idt(0x6000, 0xfff).is_ok(),
        "guest IDT setup failed",
    );
    check(
        vm.set_guest_gdt(0x5000, 0x17).is_ok(),
        "guest GDT setup failed",
    );
    check(
        vcpu::begin_run_for(pid, vcpu_handle).is_ok(),
        "Ready -> Running failed",
    );

    let mut observed = [(0u32, 0u8, 0u8); 6];
    let mut observed_count = 0usize;
    let mut observer = |event: kernel_core::hwvirt_vmm::VmExitEvent| {
        let index = observed_count;
        if index >= requests.len() {
            return Err(crate::arch::x86_64::vmx::VmxError::EventDelivery);
        }
        observed[index] = (event.reason, event.vector, event.instruction_length);
        observed_count += 1;
        if !ring::manual_finish(ring_id, requests[index], i64::from(event.reason)) {
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
            vcpu::fail_run_for(pid, vcpu_handle);
            kprintln!("[JSR-HWV4-FAIL] vmx_run={:?} name={}", error, error.name());
            FAILED.fetch_add(1, Ordering::Relaxed);
            let _ = vm.shutdown();
            drop(vm);
            abort_process(
                pid,
                Some(vcpu_handle),
                Some(memory),
                Some(ring_handle),
                before,
            );
            return;
        }
    };
    let final_state = vm.guest_state();
    check(
        vcpu::finish_run_for(pid, vcpu_handle, final_state).is_ok(),
        "Running -> Halted commit failed",
    );
    check(vm.shutdown().is_ok(), "VMX shutdown failed");
    drop(vm);

    check(
        observed_count == 6,
        "not every VM exit reached the Ring observer",
    );
    check(
        observed[0].0 == 10 && observed[1].0 == 16 && observed[2].0 == 31,
        "CPUID/RDTSC/MSR exit sequence changed",
    );
    check(
        observed[3].0 == 30 && observed[4].0 == 48 && observed[5].0 == 0,
        "I/O/EPT/exception exit sequence changed",
    );
    check(observed[5].1 == 6, "exception exit lost its #UD vector");
    check(report.exits == 6, "VMX report exit count changed");
    check(
        read_gpa(pid, vcpu_handle, 0x7000) == 0x4857_5634_494e_4a45,
        "VMCS external-interrupt injection did not execute the guest IDT handler",
    );
    check(
        !ring::manual_finish(ring_id, cancelled_request, 48),
        "a cancelled exit wait accepted a second terminal",
    );
    check(
        ring::wait_ready_for(pid, ring_handle, 6).is_ok(),
        "vCPU exit wait did not observe all terminal records",
    );
    let completions = ring::reap_kernel(ring_id, 8);
    check(completions.len() == 6, "exit Ring lost completion records");
    let cancelled = completions.iter().filter(|(_, value)| *value < 0).count();
    check(cancelled == 1, "cancel terminal was not unique");
    for reason in [10i64, 16, 31, 30, 0] {
        check(
            completions.iter().any(|(_, value)| *value == reason),
            "exit Ring lost a VM-exit reason",
        );
    }
    check(
        !completions.iter().any(|(_, value)| *value == 48),
        "cancelled exit was delivered as completed",
    );
    check(
        ring::cancel_for(pid, ring_handle, requests[0]) < 0,
        "completed request remained cancellable",
    );
    if let Some(view) = ring::view(ring_id) {
        check(
            view.in_flight == 0,
            "exit Ring retained an in-flight control block",
        );
        check(view.ready == 0, "exit Ring retained a published completion");
        check(view.running_backends == 0, "exit Ring retained a backend");
    } else {
        check(false, "exit Ring view unavailable");
    }

    check(
        proc::close_handle_for(pid, ring_handle).is_ok(),
        "exit Ring handle close failed",
    );
    check(
        proc::close_handle_for(pid, vcpu_handle).is_ok(),
        "vCPU close failed",
    );
    check(
        proc::close_handle_for(pid, memory).is_ok(),
        "Memory close failed",
    );
    kobj::run_cleanup(usize::MAX);
    check(
        proc::vm_guest_memory_quota(pid).is_some_and(|usage| usage.mapped == 0),
        "VM guest account did not return to zero",
    );
    check(proc::exit_idle(pid, 0), "process exit failed");
    check(proc::reap(pid).is_some(), "process reap failed");
    kobj::run_cleanup(usize::MAX);
    let reclaimed = before == crate::baseline::baseline();
    check(reclaimed, "HWV-4 resources did not return to baseline");
    let cross_task_wait = cross_task_wait();
    check(cross_task_wait, "cross-task vCPU exit wait/wake failed");
    #[cfg(feature = "hwv4-linux")]
    let linux_guest = crate::arch::x86_64::linux_guest::run();
    #[cfg(not(feature = "hwv4-linux"))]
    let linux_guest = false;
    #[cfg(feature = "hwv4-linux")]
    check(linux_guest, "minimal native Linux guest did not boot");
    kprintln!(
        "[JSR-HWV4] backend=Vmx exit_ring=true exits={} cancelled=1 single_terminal=true wait_ready=true cross_task_wait={} inject=true vic={} pic=true ioapic=true pit=true linux={} reclaim={} failed={}",
        report.exits,
        cross_task_wait,
        interrupts_ok,
        linux_guest,
        reclaimed,
        failed()
    );
}

fn cross_task_wait() -> bool {
    let before = crate::baseline::baseline();
    let pid = match proc::create("hwv4-wait", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => return false,
    };
    let ring_handle = match ring::create_for(pid, 2) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = proc::exit_idle(pid, 0);
            let _ = proc::reap(pid);
            return false;
        }
    };
    let Some(ring_id) = ring::ring_of(pid, ring_handle) else {
        let _ = proc::close_handle_for(pid, ring_handle);
        let _ = proc::exit_idle(pid, 0);
        let _ = proc::reap(pid);
        return false;
    };
    let request =
        match ring::submit_manual(pid, ring_handle, 0x4857_5634, Some(Exec::Abortable), None) {
            Ok(request) => request,
            Err(_) => {
                let _ = proc::close_handle_for(pid, ring_handle);
                let _ = proc::exit_idle(pid, 0);
                let _ = proc::reap(pid);
                return false;
            }
        };
    WAIT_RING.store(ring_id.raw(), Ordering::Release);
    WAIT_REQUEST.store(request, Ordering::Release);
    WAIT_PID.store(pid.raw(), Ordering::Release);
    WAIT_RING_HANDLE.store(ring_handle.raw(), Ordering::Release);
    WAIT_DELIVERED.store(false, Ordering::Release);
    WAIT_WOKE.store(false, Ordering::Release);
    if crate::sched::spawn_on(
        crate::task::TaskId(0x4857_5634),
        "hwv4-exit-waiter",
        cross_wait_waiter,
        None,
        kernel_core::smp::CpuSet::first(1),
    )
    .is_err()
        || crate::sched::spawn_on(
            crate::task::TaskId(0x4857_5635),
            "hwv4-exit-deliverer",
            cross_wait_deliverer,
            None,
            kernel_core::smp::CpuSet::first(1),
        )
        .is_err()
    {
        let _ = proc::close_handle_for(pid, ring_handle);
        let _ = proc::exit_idle(pid, 0);
        let _ = proc::reap(pid);
        return false;
    }
    crate::sched::sleep_ticks(4);
    let woke = WAIT_WOKE.load(Ordering::Acquire);
    let completions = ring::reap_kernel(ring_id, 1);
    let delivered = WAIT_DELIVERED.load(Ordering::Acquire);
    let terminal = completions
        .first()
        .is_some_and(|(id, value)| *id == request && *value == 10);
    let _ = proc::close_handle_for(pid, ring_handle);
    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    let reclaimed = before == crate::baseline::baseline();
    kprintln!(
        "[JSR-HWV4-WAIT] woke={} delivered={} terminal={} reclaimed={} completions={:?}",
        woke,
        delivered,
        terminal,
        reclaimed,
        completions
    );
    woke && delivered && terminal && reclaimed
}

fn cross_wait_waiter() {
    let Some(pid) = kernel_core::objtable::ObjId::from_raw(WAIT_PID.load(Ordering::Acquire)) else {
        return;
    };
    let handle = kernel_core::object::HandleId::from_raw(WAIT_RING_HANDLE.load(Ordering::Acquire));
    if ring::wait_ready_for(pid, handle, 1).is_ok() {
        WAIT_WOKE.store(true, Ordering::Release);
    }
}

fn cross_wait_deliverer() {
    crate::sched::sleep_ticks(1);
    let Some(ring_id) = kernel_core::objtable::ObjId::from_raw(WAIT_RING.load(Ordering::Acquire))
    else {
        return;
    };
    let request = WAIT_REQUEST.load(Ordering::Acquire);
    if ring::manual_finish(ring_id, request, 10) {
        WAIT_DELIVERED.store(true, Ordering::Release);
    }
}

fn check_virtual_interrupts() -> bool {
    let mut vic = VirtualInterruptController::new();
    let mut ok = true;
    ok &= vic.raise_pic(0) == Ok(RaiseResult::Masked);
    ok &= vic.set_pic_mask(0, false).is_ok();
    ok &= vic.raise_pic(0) == Ok(RaiseResult::Queued(32));
    ok &= vic.take_pending() == Some(32);
    ok &= vic.in_service(32);
    ok &= vic.eoi(32).is_ok();
    ok &= vic.route_ioapic(4, 0x30, 1).is_ok();
    ok &= vic.ioapic_destination(4) == Ok(1);
    ok &= vic.raise_ioapic(4) == Ok(RaiseResult::Queued(0x30));
    ok &= vic.arm_pit(0x21, 2).is_ok();
    ok &= vic.tick() == Ok(None);
    ok &= vic.tick() == Ok(Some(RaiseResult::Queued(0x21)));
    ok &= vic.pending_count() == 2;
    check(ok, "virtual PIC/IOAPIC/PIT contract failed");
    ok
}

fn abort_process(
    pid: kernel_core::objtable::ObjId,
    vcpu_handle: Option<kernel_core::object::HandleId>,
    memory: Option<kernel_core::object::HandleId>,
    ring_handle: Option<kernel_core::object::HandleId>,
    before: crate::baseline::Baseline,
) {
    if let Some(handle) = ring_handle {
        let _ = proc::close_handle_for(pid, handle);
    }
    if let Some(handle) = vcpu_handle {
        let _ = proc::close_handle_for(pid, handle);
    }
    if let Some(handle) = memory {
        let _ = proc::close_handle_for(pid, handle);
    }
    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    check(
        before == crate::baseline::baseline(),
        "HWV-4 setup failure leaked resources",
    );
}

fn prepare_guest(pid: kernel_core::objtable::ObjId, handle: kernel_core::object::HandleId) {
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

fn write_u64(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    gpa: u64,
    value: u64,
) {
    write_gpa(pid, handle, gpa, &value.to_le_bytes());
}

fn write_gpa(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    gpa: u64,
    bytes: &[u8],
) {
    let frame: PhysFrame = vcpu::translate(pid, handle, gpa)
        .ok()
        .flatten()
        .expect("guest GPA translation");
    let Some(mapped) = mm::phys_to_virt(frame.start() + gpa % 4096) else {
        check(false, "guest physical map unavailable");
        return;
    };
    assert!((gpa % 4096) as usize + bytes.len() <= 4096);
    // SAFETY: the GPA is pinned by the HWV-1 mapping and the write stays in
    // one physical page.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped, bytes.len()) };
}

fn read_gpa(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    gpa: u64,
) -> u64 {
    let frame: PhysFrame = vcpu::translate(pid, handle, gpa)
        .ok()
        .flatten()
        .expect("guest GPA translation");
    let Some(mapped) = mm::phys_to_virt(frame.start() + gpa % 4096) else {
        check(false, "guest physical map unavailable");
        return 0;
    };
    // SAFETY: the GPA is pinned and this reads one aligned u64 within a page.
    unsafe { (mapped as *const u64).read_volatile() }
}
