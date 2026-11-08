//! HWV-1 kernel contract drill: vCPU lifecycle, GPA translation, Memory pins,
//! state save/restore and table reclamation. It never performs VM Entry.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::hwvirt_vcpu::{GuestPermissions, Lifecycle, MapError, VcpuState, MAX_GPA};

use crate::{kobj, kprintln, mm, proc, vcpu};

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-HWV1-FAIL] {}", what);
    }
}

fn write_physical(frame: kernel_core::frame::PhysFrame, bytes: &[u8]) {
    let ptr = mm::phys_to_virt(frame.start()).expect("physical map");
    // SAFETY: the frame is owned by a pinned Memory object and is at least
    // four KiB; every caller writes fewer than 4096 bytes.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
}

fn read_u64(frame: kernel_core::frame::PhysFrame) -> u64 {
    let ptr = mm::phys_to_virt(frame.start()).expect("physical map") as *const u64;
    // SAFETY: the frame is pinned and four KiB, so an aligned u64 read is valid.
    unsafe { ptr.read_volatile() }
}

pub fn run() {
    let Some(backend) = crate::hwvirt_demo::selected_backend() else {
        check(false, "HWV-0 produced no supported backend for HWV-1");
        kprintln!("[JSR-HWV1] backend=none entered=false failed=1");
        return;
    };

    let before = crate::baseline::baseline();
    let pid = match proc::create("hwv1-vcpu", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let memory_a = match proc::create_memory(pid, 2) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "first Memory object creation failed");
            return;
        }
    };
    let memory_b = match proc::create_memory(pid, 1) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "second Memory object creation failed");
            return;
        }
    };
    let vcpu_a = match vcpu::create_for(pid, backend) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "first vCPU creation failed");
            return;
        }
    };
    let vcpu_b = match vcpu::create_for(pid, backend) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "second vCPU creation failed");
            return;
        }
    };

    let a_initial = vcpu::view(pid, vcpu_a).expect("vCPU a view");
    let b_initial = vcpu::view(pid, vcpu_b).expect("vCPU b view");
    check(a_initial.status == Lifecycle::Offline, "new vCPU must be Offline");
    check(a_initial.mappings == 0 && a_initial.pinned_memory == 0, "new vCPU must be empty");
    check(a_initial.table_root % 4096 == 0 && a_initial.table_root != 0, "EPT/NPT root must be an aligned frame");
    check(a_initial.table_root != b_initial.table_root, "vCPUs must own isolated second-level roots");

    let read_write = GuestPermissions::READ_WRITE;
    check(
        vcpu::map_for(
            pid,
            vcpu_a,
            memory_a,
            vcpu::MapRequest { guest_start: 0x1000, pages: 2, memory_offset: 0, permissions: read_write },
        )
        .is_ok(),
        "first GPA mapping failed",
    );
    check(
        vcpu::map_for(
            pid,
            vcpu_a,
            memory_a,
            vcpu::MapRequest { guest_start: 0x8000, pages: 2, memory_offset: 0, permissions: read_write },
        )
        .is_ok(),
        "same-Memory alias mapping failed",
    );
    check(
        vcpu::map_for(
            pid,
            vcpu_b,
            memory_b,
            vcpu::MapRequest { guest_start: 0x1000, pages: 1, memory_offset: 0, permissions: read_write },
        )
        .is_ok(),
        "second vCPU mapping failed",
    );

    let mapped_a = vcpu::view(pid, vcpu_a).expect("mapped vCPU a");
    check(mapped_a.mappings == 2 && mapped_a.pinned_memory == 2, "one Memory pin is required per GPA mapping");

    let frame_a0 = vcpu::translate(pid, vcpu_a, 0x1000).expect("translation a0").expect("mapped a0");
    let frame_a1 = vcpu::translate(pid, vcpu_a, 0x2000).expect("translation a1").expect("mapped a1");
    let alias_a = vcpu::translate(pid, vcpu_a, 0x8000).expect("translation alias").expect("mapped alias");
    let frame_b = vcpu::translate(pid, vcpu_b, 0x1000).expect("translation b").expect("mapped b");
    check(alias_a == frame_a0, "same Memory aliases must resolve to the same host frame");
    check(frame_a0 != frame_a1, "distinct Memory pages must not collapse into one frame");
    check(frame_a0 != frame_b, "equal GPAs in different vCPUs must remain isolated");

    write_physical(frame_a0, &0x4857_5631_414c_4941u64.to_le_bytes());
    write_physical(frame_a1, &0x4857_5631_5041_4745u64.to_le_bytes());
    write_physical(frame_b, &0x4857_5631_49534f4cu64.to_le_bytes());
    check(read_u64(frame_a0) == 0x4857_5631_414c_4941, "first backing page lost its contents");
    check(read_u64(alias_a) == 0x4857_5631_414c_4941, "alias did not observe its backing page");
    check(read_u64(frame_b) == 0x4857_5631_49534f4c, "vCPU B backing was overwritten by vCPU A");

    check(
        vcpu::map_for(
            pid,
            vcpu_a,
            memory_b,
            vcpu::MapRequest { guest_start: 0x2000, pages: 1, memory_offset: 0, permissions: read_write },
        ) == Err(vcpu::VcpuError::Map(MapError::Overlap)),
        "overlapping GPA was accepted",
    );
    check(
        vcpu::map_for(
            pid,
            vcpu_a,
            memory_b,
            vcpu::MapRequest { guest_start: 0x3001, pages: 1, memory_offset: 0, permissions: read_write },
        ) == Err(vcpu::VcpuError::Map(MapError::Misaligned)),
        "misaligned GPA was accepted",
    );
    check(
        vcpu::map_for(
            pid,
            vcpu_a,
            memory_a,
            vcpu::MapRequest { guest_start: 0x20000, pages: 3, memory_offset: 0, permissions: read_write },
        ) == Err(vcpu::VcpuError::Map(MapError::OutsideMemory)),
        "mapping escaped its Memory object",
    );
    check(
        vcpu::map_for(
            pid,
            vcpu_a,
            memory_b,
            vcpu::MapRequest {
                guest_start: 0x30000,
                pages: 1,
                memory_offset: 0,
                permissions: GuestPermissions::default(),
            },
        ) == Err(vcpu::VcpuError::Map(MapError::Permissions)),
        "unreadable GPA was accepted",
    );
    check(
        vcpu::map_for(
            pid,
            vcpu_a,
            memory_b,
            vcpu::MapRequest { guest_start: MAX_GPA - 4096, pages: 2, memory_offset: 0, permissions: read_write },
        ) == Err(vcpu::VcpuError::Map(MapError::OutsideGuestWindow)),
        "GPA range beyond the 48-bit window was accepted",
    );
    check(vcpu::translate(pid, vcpu_a, 0x30000).expect("post-failure translation").is_none(), "failed mapping leaked a table entry");
    check(vcpu::view(pid, vcpu_a).expect("post-failure view").pinned_memory == 2, "failed mapping leaked a Memory pin");

    let mut state = VcpuState::initial();
    state.rip = 0xfeed_0000;
    state.registers[0] = 0x1122_3344_5566_7788;
    check(vcpu::save_state_for(pid, vcpu_a, state).is_ok(), "stable vCPU state save failed");
    let saved = vcpu::view(pid, vcpu_a).expect("saved-state view");
    check(saved.state == state, "saved vCPU state did not round-trip");
    check(vcpu::make_ready_for(pid, vcpu_a).is_ok(), "Offline -> Ready transition failed");
    check(vcpu::view(pid, vcpu_a).expect("ready view").status == Lifecycle::Ready, "vCPU did not become Ready");

    let removed = vcpu::unmap_exact_for(pid, vcpu_a, 0x8000, 2);
    check(removed.is_ok(), "exact GPA unmap failed");
    check(vcpu::translate(pid, vcpu_a, 0x8000).expect("unmapped translation").is_none(), "hardware alias survived unmap");
    check(vcpu::lookup(pid, vcpu_a, 0x8000).expect("unmapped lookup").is_none(), "metadata alias survived unmap");
    check(vcpu::translate(pid, vcpu_a, 0x1000).expect("survivor translation").is_some(), "unrelated alias was removed");
    check(vcpu::view(pid, vcpu_a).expect("post-unmap view").pinned_memory == 1, "unmap did not release exactly one Memory pin");

    check(proc::close_handle_for(pid, memory_a).is_ok(), "Memory owner handle close failed");
    check(
        vcpu::translate(pid, vcpu_a, 0x1000).expect("pinned Memory translation").is_some(),
        "vCPU pin did not keep its Memory backing valid after owner close",
    );
    check(proc::close_handle_for(pid, vcpu_a).is_ok(), "vCPU handle close failed");
    check(vcpu::view(pid, vcpu_a).is_err(), "closed vCPU handle remained usable");
    check(proc::close_handle_for(pid, memory_b).is_ok(), "second Memory close failed");
    check(proc::close_handle_for(pid, vcpu_b).is_ok(), "second vCPU close failed");
    kobj::run_cleanup(usize::MAX);

    let live = kobj::stats().0;
    check(live >= 1, "process disappeared before reap");
    check(proc::exit_idle(pid, 0), "HWV-1 process exit failed");
    check(proc::reap(pid).is_some(), "HWV-1 process reap failed");
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    check(before == after, "HWV-1 objects, frames or pins did not return to baseline");

    let failed = failed();
    kprintln!(
        "[JSR-HWV1] backend={:?} entered=false roots=true aliases=true isolation=true pins=true state=true invalid=true reclaim=true failed={}",
        backend,
        failed
    );
}
