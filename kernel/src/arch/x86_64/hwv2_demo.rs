//! HWV-2 Intel VMX execution drill.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::PhysFrame;
use kernel_core::hwvirt::Backend;
use kernel_core::hwvirt_vcpu::{GuestPermissions, VcpuState};

use crate::{kobj, kprintln, mm, proc, vcpu};

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, what: &'static str) {
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-HWV2-FAIL] {}", what);
    }
}

pub fn run() {
    let backend = crate::hwvirt_demo::selected_backend();
    check(
        backend == Some(Backend::Vmx),
        "Intel VMX backend not selected",
    );
    if backend != Some(Backend::Vmx) {
        return;
    }

    let before = crate::baseline::baseline();
    let pid = match proc::create("hwv2-vmx", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let memory = match proc::create_guest_memory(pid, 512) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "2 MiB guest backing allocation failed");
            return;
        }
    };
    let handle = match vcpu::create_for(pid, Backend::Vmx) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "vCPU creation failed");
            return;
        }
    };
    if vcpu::map_for(
        pid,
        handle,
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
        check(false, "2 MiB EPT identity mapping failed");
        return;
    }
    prepare_guest(pid, handle);
    let mut state = VcpuState::initial();
    state.cr0 = 0x8001_0011;
    state.cr3 = 0x1000;
    state.cr4 = 0x20;
    state.xcr0 = 3;
    state.rip = 0x4000;
    state.rflags = 2;
    state.registers[4] = 0x1f_f000;
    check(
        vcpu::save_state_for(pid, handle, state).is_ok(),
        "initial guest state save failed",
    );
    check(
        vcpu::make_ready_for(pid, handle).is_ok(),
        "Offline -> Ready failed",
    );

    let ept_root = match vcpu::view(pid, handle) {
        Ok(view) => view.table_root,
        Err(_) => {
            check(false, "vCPU view failed");
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
    let host_before = crate::arch::x86_64::vmx::host_snapshot();
    let mut vm = match crate::arch::x86_64::vmx::VmxVm::new(ept_root, execution) {
        Ok(vm) => vm,
        Err(error) => {
            vcpu::fail_run_for(pid, handle);
            kprintln!("[JSR-HWV2-FAIL] setup={:?} name={}", error, error.name());
            FAILED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    if vcpu::begin_run_for(pid, handle).is_err() {
        check(false, "Ready -> Running failed");
        return;
    }
    let report = match vm.run() {
        Ok(report) => {
            let final_state = vm.guest_state();
            check(
                vcpu::finish_run_for(pid, handle, final_state).is_ok(),
                "Running -> Halted commit failed",
            );
            report
        }
        Err(error) => {
            vcpu::fail_run_for(pid, handle);
            kprintln!(
                "[JSR-HWV2-FAIL] execution={:?} name={}",
                error,
                error.name()
            );
            FAILED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let vmxoff_ok = vm.shutdown().is_ok();
    check(vmxoff_ok, "VMCLEAR/VMXOFF shutdown failed");
    check(
        crate::arch::x86_64::vmx::stack_pointer_restored(),
        "VMX entry did not restore the host stack pointer",
    );
    drop(vm);
    let host_after = crate::arch::x86_64::vmx::host_snapshot();
    if host_before != host_after {
        kprintln!(
            "[JSR-HWV2-FAIL] host_before={:?} host_after={:?}",
            host_before,
            host_after
        );
        FAILED.fetch_add(1, Ordering::Relaxed);
    }

    check(report.cpuid == 1, "CPUID did not cause exactly one VM exit");
    check(report.rdtsc == 1, "RDTSC did not cause exactly one VM exit");
    check(
        report.msr_reads == 1,
        "MSR read did not cause exactly one VM exit",
    );
    check(
        report.io == 1,
        "I/O instruction did not cause exactly one VM exit",
    );
    check(
        report.ept_violations == 1,
        "MMIO/E2PT violation was not observed",
    );
    check(
        report.exceptions == 1,
        "guest #UD exception was not observed",
    );
    check(report.exits == 6, "unexpected total VM-exit count");
    let final_state = vcpu::view(pid, handle)
        .map(|view| view.state)
        .unwrap_or_else(|_| VcpuState::initial());
    check(
        final_state.rip == 0x4038,
        "guest architectural state did not advance through exits",
    );

    let mut invalid = execution;
    invalid.efer = 0;
    check(
        crate::arch::x86_64::vmx::VmxVm::new(ept_root, invalid).is_err(),
        "invalid VMCS guest state was not rejected",
    );
    check(
        crate::arch::x86_64::vmx::VmxVm::new(ept_root + 1, execution).is_err(),
        "misaligned EPT pointer was not rejected",
    );

    if proc::exit_idle(pid, 0) {
        check(proc::reap(pid).is_some(), "HWV-2 process reap failed");
    } else {
        check(false, "HWV-2 process exit failed");
    }
    kobj::run_cleanup(usize::MAX);
    check(
        before == crate::baseline::baseline(),
        "HWV-2 frames/objects did not return to baseline",
    );
    kprintln!(
        "[JSR-HWV2] backend=Vmx entered=true vmxoff={} vmcs=true ept=true cpuid={} rdtsc={} msr={} io={} ept_exit={} exception={} exits={} tsc=true xsave={} state_saved=true failed={}",
        vmxoff_ok,
        report.cpuid,
        report.rdtsc,
        report.msr_reads,
        report.io,
        report.ept_violations,
        report.exceptions,
        report.exits,
        report.xsave_enabled,
        failed()
    );
}

fn prepare_guest(pid: kernel_core::objtable::ObjId, handle: kernel_core::object::HandleId) {
    write_u64(pid, handle, 0x1000, 0x2003);
    write_u64(pid, handle, 0x2000, 0x3003);
    write_u64(pid, handle, 0x3000, 0x83);
    write_u64(pid, handle, 0x3008, 0x20_0083);
    // CPUID; RDTSC; ECX=TSC MSR; RDMSR; DX=0x80; IN AL,DX;
    // FNINIT+FLD1; XMM0=0x12345678; EAX=3/EDX=0 XSAVE mask;
    // XSAVE at 0x5000; RAX=2 MiB unmapped GPA; write through EPT; UD2.
    let code = [
        0x0f, 0xa2, 0x0f, 0x31, 0xb9, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x32, 0x66, 0xba, 0x80, 0x00,
        0xec, 0xdb, 0xe3, 0xd9, 0xe8, 0xb9, 0x78, 0x56, 0x34, 0x12, 0x66, 0x0f, 0x6e, 0xc1, 0xb8,
        0x03, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x48, 0xc7, 0xc0, 0x00, 0x50, 0x00, 0x00, 0x0f, 0xae,
        0x20, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x20, 0x00, 0x48, 0x89, 0x00, 0x0f, 0x0b,
    ];
    write_gpa(pid, handle, 0x4000, &code);
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
    let Some(ptr) = mm::phys_to_virt(frame.start() + gpa % 4096) else {
        check(false, "guest physical map unavailable");
        return;
    };
    assert!((gpa % 4096) as usize + bytes.len() <= 4096);
    // SAFETY: the GPA is pinned by the HWV-1 mapping and the write stays in
    // one physical page.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
}
