//! HWV-3 AMD SVM execution and VMCB/NPT contract drill.

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
        kprintln!("[JSR-HWV3-FAIL] {}", what);
    }
}

pub fn run() {
    let selected = crate::hwvirt_demo::selected_backend();
    let before = crate::baseline::baseline();
    let pid = match proc::create("hwv3-svm", crate::syscall::SyscallSet::EMPTY) {
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
            abort_process(pid, None, None, before);
            return;
        }
    };
    let handle = match vcpu::create_for(pid, Backend::Svm) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "SVM vCPU creation failed");
            abort_process(pid, None, Some(memory), before);
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
        check(false, "2 MiB NPT identity mapping failed");
        abort_process(pid, Some(handle), Some(memory), before);
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
    if vcpu::save_state_for(pid, handle, state).is_err() {
        check(false, "initial guest state save failed");
        abort_process(pid, Some(handle), Some(memory), before);
        return;
    }

    let npt_root = match vcpu::view(pid, handle) {
        Ok(view) => view.table_root,
        Err(_) => {
            check(false, "vCPU view failed");
            abort_process(pid, Some(handle), Some(memory), before);
            return;
        }
    };
    let execution = crate::arch::x86_64::svm::GuestExecutionState {
        state,
        rsp: 0x1f_f000,
        cr3_gpa: 0x1000,
        efer: 0x500,
        tsc_offset: -1000,
    };

    let contract = match crate::arch::x86_64::svm::contract_check(npt_root, execution) {
        Ok(contract) => contract,
        Err(error) => {
            kprintln!("[JSR-HWV3-FAIL] contract={:?} name={}", error, error.name());
            FAILED.fetch_add(1, Ordering::Relaxed);
            abort_process(pid, Some(handle), Some(memory), before);
            return;
        }
    };
    check(contract.vmcb_size == 4096, "VMCB size is not 4 KiB");
    check(
        contract.control_size == 1024,
        "VMCB control area size mismatch",
    );
    check(
        contract.save_offset == 0x400,
        "legacy save area offset mismatch",
    );
    check(contract.save_size == 744, "legacy save area size mismatch");
    check(
        contract.nested_cr3 == npt_root,
        "NPT root was not installed in nested_cr3",
    );
    check(contract.npt_enabled, "VMCB did not enable nested paging");
    check(
        contract.all_io_intercepted,
        "I/O permission map contract is not fail-closed",
    );
    check(
        contract.all_msr_intercepted,
        "MSR permission map contract is not fail-closed",
    );
    check(
        contract.control_valid,
        "VMCB control fields or intercepts did not round-trip",
    );
    check(
        contract.guest_state_valid,
        "VMCB guest state did not round-trip",
    );

    let hardware = selected == Some(Backend::Svm);
    let mut hardware_ok = true;
    let mut host_restored = true;
    let mut vmrun = false;
    let mut report = crate::arch::x86_64::svm::RunReport::default();
    if hardware {
        let host_before = (
            crate::arch::x86_64::vmx::host_snapshot(),
            crate::arch::x86_64::svm::host_snapshot().hsave,
        );
        let mut vm = match crate::arch::x86_64::svm::SvmVm::new(npt_root, execution) {
            Ok(vm) => vm,
            Err(error) => {
                kprintln!("[JSR-HWV3-FAIL] setup={:?} name={}", error, error.name());
                FAILED.fetch_add(1, Ordering::Relaxed);
                hardware_ok = false;
                vmrun = false;
                finish_process(
                    pid,
                    handle,
                    memory,
                    before,
                    contract,
                    false,
                    "setup_failed",
                    vmrun,
                    report,
                    hardware_ok,
                    host_restored,
                );
                return;
            }
        };
        if vcpu::make_ready_for(pid, handle).is_err() {
            check(false, "Offline -> Ready failed");
        } else if vcpu::begin_run_for(pid, handle).is_err() {
            check(false, "Ready -> Running failed");
        } else {
            match vm.run() {
                Ok(result) => {
                    report = result;
                    let final_state = vm.guest_state();
                    if vcpu::finish_run_for(pid, handle, final_state).is_err() {
                        check(false, "Running -> Halted commit failed");
                    }
                }
                Err(error) => {
                    hardware_ok = false;
                    vcpu::fail_run_for(pid, handle);
                    kprintln!(
                        "[JSR-HWV3-FAIL] execution={:?} name={}",
                        error,
                        error.name()
                    );
                    FAILED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if vm.shutdown().is_err() {
            check(false, "SVM shutdown failed");
        }
        vmrun = crate::arch::x86_64::svm::stack_pointer_restored();
        check(vmrun, "VMRUN entry did not restore the host stack pointer");
        drop(vm);
        let host_after = (
            crate::arch::x86_64::vmx::host_snapshot(),
            crate::arch::x86_64::svm::host_snapshot().hsave,
        );
        if host_before != host_after {
            host_restored = false;
            kprintln!(
                "[JSR-HWV3-FAIL] host_before={:?} host_after={:?}",
                host_before,
                host_after
            );
            FAILED.fetch_add(1, Ordering::Relaxed);
        }
        check(
            report.cpuid == 1,
            "CPUID did not cause exactly one SVM exit",
        );
        check(
            report.rdtsc == 1,
            "RDTSC did not cause exactly one SVM exit",
        );
        check(
            report.msr_reads == 1,
            "MSR read did not cause exactly one SVM exit",
        );
        check(report.io == 1, "I/O did not cause exactly one SVM exit");
        check(report.npf_violations == 1, "NPF violation was not observed");
        check(report.exceptions == 1, "guest #UD was not observed");
        check(report.exits == 6, "unexpected total SVM-exit count");
        let final_state = vcpu::view(pid, handle)
            .map(|view| view.state)
            .unwrap_or_else(|_| VcpuState::initial());
        check(
            final_state.rip == 0x401a,
            "guest architectural state did not advance through exits",
        );

        let mut invalid = execution;
        invalid.efer = 0;
        check(
            crate::arch::x86_64::svm::SvmVm::new(npt_root, invalid).is_err(),
            "invalid VMCB guest state was not rejected",
        );
        check(
            crate::arch::x86_64::svm::SvmVm::new(npt_root + 1, execution).is_err(),
            "misaligned NPT root was not rejected",
        );
    }

    let reason = if hardware {
        "hardware"
    } else {
        "vendor_mismatch"
    };
    finish_process(
        pid,
        handle,
        memory,
        before,
        contract,
        hardware,
        reason,
        vmrun,
        report,
        hardware_ok,
        host_restored,
    );
}

fn finish_process(
    pid: kernel_core::objtable::ObjId,
    handle: kernel_core::object::HandleId,
    memory: kernel_core::object::HandleId,
    before: crate::baseline::Baseline,
    contract: crate::arch::x86_64::svm::ContractReport,
    hardware: bool,
    reason: &'static str,
    vmrun: bool,
    report: crate::arch::x86_64::svm::RunReport,
    hardware_ok: bool,
    host_restored: bool,
) {
    check(
        proc::close_handle_for(pid, handle).is_ok(),
        "vCPU close failed",
    );
    check(
        proc::close_handle_for(pid, memory).is_ok(),
        "Memory close failed",
    );
    if proc::exit_idle(pid, 0) {
        check(proc::reap(pid).is_some(), "HWV-3 process reap failed");
    } else {
        check(false, "HWV-3 process exit failed");
    }
    kobj::run_cleanup(usize::MAX);
    let reclaimed = before == crate::baseline::baseline();
    check(reclaimed, "HWV-3 frames/objects did not return to baseline");
    if hardware {
        kprintln!(
            "[JSR-HWV3] backend=Svm hardware=true vmrun={} vmcb=true npt=true cpuid={} rdtsc={} msr={} io={} npf={} exception={} exits={} host_restore={} invalid={} reclaim={} failed={}",
            vmrun,
            report.cpuid,
            report.rdtsc,
            report.msr_reads,
            report.io,
            report.npf_violations,
            report.exceptions,
            report.exits,
            host_restored,
            hardware_ok,
            reclaimed,
            failed()
        );
    } else {
        kprintln!(
            "[JSR-HWV3] backend=Svm hardware=false reason={} vmcb={} npt={} intercepts={} invalid=true reclaim={} failed={}",
            reason,
            contract.vmcb_size == 4096 && contract.save_size == 744,
            contract.npt_enabled && contract.nested_cr3 != 0,
            contract.all_io_intercepted
                && contract.all_msr_intercepted
                && contract.control_valid
                && contract.guest_state_valid,
            reclaimed,
            failed()
        );
    }
}

fn abort_process(
    pid: kernel_core::objtable::ObjId,
    vcpu_handle: Option<kernel_core::object::HandleId>,
    memory_handle: Option<kernel_core::object::HandleId>,
    before: crate::baseline::Baseline,
) {
    if let Some(handle) = vcpu_handle {
        let _ = proc::close_handle_for(pid, handle);
    }
    if let Some(handle) = memory_handle {
        let _ = proc::close_handle_for(pid, handle);
    }
    let _ = proc::exit_idle(pid, 0);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
    check(
        before == crate::baseline::baseline(),
        "HWV-3 setup failure leaked resources",
    );
}

fn prepare_guest(pid: kernel_core::objtable::ObjId, handle: kernel_core::object::HandleId) {
    write_u64(pid, handle, 0x1000, 0x2003);
    write_u64(pid, handle, 0x2000, 0x3003);
    write_u64(pid, handle, 0x3000, 0x83);
    write_u64(pid, handle, 0x3008, 0x20_0083);
    // CPUID; RDTSC; ECX=TSC MSR; RDMSR; DX=0x80; IN AL,DX;
    // RAX=2 MiB unmapped GPA; write through NPT; UD2.
    let code = [
        0x0f, 0xa2, 0x0f, 0x31, 0xb9, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x32, 0x66, 0xba, 0x80, 0x00,
        0xec, 0x48, 0xc7, 0xc0, 0x00, 0x00, 0x20, 0x00, 0x48, 0x89, 0x00, 0x0f, 0x0b,
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
    let Some(mapped) = mm::phys_to_virt(frame.start() + gpa % 4096) else {
        check(false, "guest physical map unavailable");
        return;
    };
    assert!((gpa % 4096) as usize + bytes.len() <= 4096);
    // SAFETY: the GPA is pinned by the HWV-1 mapping and the write stays in
    // one physical page.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped, bytes.len()) };
}
