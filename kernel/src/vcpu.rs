//! HWV-1 vendor-neutral vCPU objects.
//!
//! This layer owns Handle/Rights, saved state, the fixed guest-physical map and
//! Memory object pins. Hardware VM Entry is intentionally unavailable until
//! HWV-2 (Intel) and HWV-3 (AMD) provide their backends.

use alloc::boxed::Box;

use kernel_core::hwvirt::Backend;
use kernel_core::hwvirt_vcpu::{
    GuestMap, GuestMapping, GuestPermissions, Lifecycle, MapError, StateError, VcpuLifecycle,
    VcpuState, MAX_GUEST_MAPPINGS,
};
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapError as TableError;

use crate::kobj::{self, KObject, Table};
use crate::proc::{self, ProcError};
use crate::arch::second_level::SecondLevel;
use crate::syscall::err;
use crate::syscall::table::{
    SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_RIGHTS_DENIED, SYSTEM_HANDLE_ERROR_INVALID,
};

const VCPU_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::WAIT)
    .union(Rights::CONTROL)
    .union(Rights::DUPLICATE);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapRequest {
    pub guest_start: u64,
    pub pages: u64,
    pub memory_offset: u64,
    pub permissions: GuestPermissions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuError {
    Process(ProcError),
    State(StateError),
    Map(MapError),
    Table(TableError),
    Closed,
    InvalidMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VcpuView {
    pub backend: Backend,
    pub status: Lifecycle,
    pub mappings: usize,
    pub pinned_memory: usize,
    pub table_root: u64,
    pub state: VcpuState,
    pub closing: bool,
}

pub struct VcpuObj {
    owner: ObjId,
    lifecycle: VcpuLifecycle,
    guest: GuestMap<MAX_GUEST_MAPPINGS>,
    second_level: SecondLevel,
    /// One internal Memory reference for each occupied guest-map slot.
    pins: [Option<ObjId>; MAX_GUEST_MAPPINGS],
    closing: bool,
}

impl Drop for VcpuObj {
    fn drop(&mut self) {
        assert!(self.closing, "Vcpu dropped without its closing transition");
        assert!(self.pins.iter().all(Option::is_none), "Vcpu dropped with pinned Memory");
        assert!(self.guest.is_empty(), "Vcpu dropped with live GPA mappings");
    }
}

fn vcpu_mut(t: &mut Table, id: ObjId) -> Option<&mut VcpuObj> {
    match t.get_mut(id) {
        Ok(KObject::Vcpu(vcpu)) => Some(vcpu),
        _ => None,
    }
}

fn resolve(t: &mut Table, pid: ObjId, h: HandleId, rights: Rights) -> Result<ObjId, VcpuError> {
    let id = proc::resolve_in(t, pid, h, ObjectType::Vcpu, rights)
        .map_err(VcpuError::Process)?;
    let owner = match t.get(id) {
        Ok(KObject::Vcpu(vcpu)) => vcpu.owner,
        _ => return Err(VcpuError::InvalidMemory),
    };
    if owner != pid {
        return Err(VcpuError::InvalidMemory);
    }
    Ok(id)
}

pub fn create_for(pid: ObjId, backend: Backend) -> Result<HandleId, VcpuError> {
    let second_level = SecondLevel::new(backend).map_err(VcpuError::Table)?;
    kobj::with(|t| {
        if !proc::running_in(t, pid) {
            return Err(VcpuError::Process(ProcError::NoSuchProcess));
        }
        let object = VcpuObj {
            owner: pid,
            lifecycle: VcpuLifecycle::new(backend),
            guest: GuestMap::new(),
            second_level,
            pins: [None; MAX_GUEST_MAPPINGS],
            closing: false,
        };
        proc::grant_new_in(t, pid, KObject::Vcpu(Box::new(object)), ObjectType::Vcpu, VCPU_RIGHTS)
            .map(|(handle, _)| handle)
            .map_err(VcpuError::Process)
    })
}

/// Pin a Memory range and install one non-overlapping GPA mapping.
pub fn map_for(
    pid: ObjId,
    vcpu_handle: HandleId,
    memory_handle: HandleId,
    request: MapRequest,
) -> Result<usize, VcpuError> {
    kobj::with(|t| {
        let vcpu_id = resolve(t, pid, vcpu_handle, Rights::CONTROL)?;
        let mut rights = Rights::READ.union(Rights::MAP);
        if request.permissions.write {
            rights = rights.union(Rights::WRITE);
        }
        let memory_id = proc::resolve_in(t, pid, memory_handle, ObjectType::Memory, rights)
            .map_err(VcpuError::Process)?;
        let memory_pages = match t.get(memory_id) {
            Ok(KObject::Memory(memory)) => memory.page_count(),
            _ => return Err(VcpuError::InvalidMemory),
        };
        if vcpu_mut(t, vcpu_id).is_none_or(|vcpu| vcpu.closing) {
            return Err(VcpuError::Closed);
        }
        if vcpu_mut(t, vcpu_id).is_some_and(|vcpu| vcpu.lifecycle.status() == Lifecycle::Running) {
            return Err(VcpuError::State(StateError::Running));
        }
        vcpu_mut(t, vcpu_id)
            .expect("resolved Vcpu")
            .guest
            .validate(
                request.guest_start,
                request.pages,
                request.memory_offset,
                memory_pages,
                request.permissions,
            )
            .map_err(VcpuError::Map)?;
        let frames = match t.get(memory_id) {
            Ok(KObject::Memory(memory)) => memory
                .physical_range(request.memory_offset / 4096, request.pages)
                .ok_or(VcpuError::Map(MapError::OutsideMemory))?,
            _ => return Err(VcpuError::InvalidMemory),
        };
        t.acquire_internal(memory_id).map_err(|_| VcpuError::InvalidMemory)?;
        if let Err(error) = vcpu_mut(t, vcpu_id)
            .expect("resolved Vcpu")
            .second_level
            .map(request.guest_start, &frames, request.permissions)
        {
            let _ = t.release_internal(memory_id);
            return Err(VcpuError::Table(error));
        }
        let result = vcpu_mut(t, vcpu_id)
            .expect("resolved Vcpu")
            .guest
            .map(
                request.guest_start,
                request.pages,
                memory_id.raw(),
                request.memory_offset,
                memory_pages,
                request.permissions,
            );
        let slot = match result {
            Ok(slot) => slot,
            Err(error) => {
                let _ = vcpu_mut(t, vcpu_id)
                    .expect("resolved Vcpu")
                    .second_level
                    .unmap(request.guest_start, request.pages);
                let _ = t.release_internal(memory_id);
                return Err(VcpuError::Map(error));
            }
        };
        let vcpu = vcpu_mut(t, vcpu_id).expect("resolved Vcpu");
        assert!(vcpu.pins[slot].is_none());
        vcpu.pins[slot] = Some(memory_id);
        Ok(slot)
    })
}

pub fn unmap_exact_for(
    pid: ObjId,
    vcpu_handle: HandleId,
    guest_start: u64,
    pages: u64,
) -> Result<GuestMapping, VcpuError> {
    kobj::with(|t| {
        let vcpu_id = resolve(t, pid, vcpu_handle, Rights::CONTROL)?;
        let vcpu = vcpu_mut(t, vcpu_id).ok_or(VcpuError::Closed)?;
        if vcpu.closing {
            return Err(VcpuError::Closed);
        }
        if vcpu.lifecycle.status() == Lifecycle::Running {
            return Err(VcpuError::State(StateError::Running));
        }
        let slot = vcpu
            .guest
            .iter()
            .find_map(|(slot, mapping)| {
                (mapping.guest_start == guest_start && mapping.pages == pages).then_some(slot)
            })
            .ok_or(VcpuError::Map(MapError::NotFound))?;
        vcpu.second_level
            .unmap(guest_start, pages)
            .map_err(VcpuError::Table)?;
        let mapping = vcpu.guest.unmap_exact(guest_start, pages).map_err(VcpuError::Map)?;
        let memory = vcpu.pins[slot].take().ok_or(VcpuError::InvalidMemory)?;
        let _ = t.release_internal(memory);
        Ok(mapping)
    })
}

pub fn lookup(pid: ObjId, vcpu_handle: HandleId, guest: u64) -> Result<Option<GuestMapping>, VcpuError> {
    kobj::with(|t| {
        let vcpu_id = resolve(t, pid, vcpu_handle, Rights::READ)?;
        Ok(vcpu_mut(t, vcpu_id)
            .filter(|vcpu| !vcpu.closing)
            .and_then(|vcpu| vcpu.guest.lookup(guest).map(|(_, mapping)| mapping)))
    })
}

/// Read the second-level translation without entering the guest. Diagnostic
/// and HWV-2/HWV-3 pre-entry validation use this path.
pub fn translate(
    pid: ObjId,
    vcpu_handle: HandleId,
    guest: u64,
) -> Result<Option<kernel_core::frame::PhysFrame>, VcpuError> {
    kobj::with(|t| {
        let id = resolve(t, pid, vcpu_handle, Rights::READ)?;
        Ok(vcpu_mut(t, id)
            .filter(|vcpu| !vcpu.closing)
            .and_then(|vcpu| vcpu.second_level.translate(guest)))
    })
}

pub fn save_state_for(
    pid: ObjId,
    vcpu_handle: HandleId,
    state: VcpuState,
) -> Result<(), VcpuError> {
    kobj::with(|t| {
        let id = resolve(t, pid, vcpu_handle, Rights::WRITE)?;
        let vcpu = vcpu_mut(t, id).ok_or(VcpuError::Closed)?;
        if vcpu.closing {
            return Err(VcpuError::Closed);
        }
        vcpu.lifecycle.save(state).map_err(VcpuError::State)
    })
}

pub fn make_ready_for(pid: ObjId, vcpu_handle: HandleId) -> Result<(), VcpuError> {
    kobj::with(|t| {
        let id = resolve(t, pid, vcpu_handle, Rights::CONTROL)?;
        let vcpu = vcpu_mut(t, id).ok_or(VcpuError::Closed)?;
        if vcpu.closing {
            return Err(VcpuError::Closed);
        }
        vcpu.lifecycle.make_ready().map_err(VcpuError::State)
    })
}

/// Mark the vCPU Running immediately before the HWV-2 hardware backend enters
/// the guest. The caller must pair this with `finish_run_for` or `fail_run_for`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn begin_run_for(pid: ObjId, vcpu_handle: HandleId) -> Result<(), VcpuError> {
    kobj::with(|t| {
        let id = resolve(t, pid, vcpu_handle, Rights::CONTROL)?;
        let vcpu = vcpu_mut(t, id).ok_or(VcpuError::Closed)?;
        if vcpu.closing {
            return Err(VcpuError::Closed);
        }
        vcpu.lifecycle.begin_run().map_err(VcpuError::State)
    })
}

/// Commit the architectural state captured after a hardware VM exit and move
/// the vCPU to Halted.
#[cfg(target_arch = "x86_64")]
pub(crate) fn finish_run_for(
    pid: ObjId,
    vcpu_handle: HandleId,
    state: VcpuState,
) -> Result<(), VcpuError> {
    kobj::with(|t| {
        let id = resolve(t, pid, vcpu_handle, Rights::CONTROL)?;
        let vcpu = vcpu_mut(t, id).ok_or(VcpuError::Closed)?;
        if vcpu.closing {
            return Err(VcpuError::Closed);
        }
        vcpu.lifecycle.halt().map_err(VcpuError::State)?;
        vcpu.lifecycle.save(state).map_err(VcpuError::State)
    })
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn fail_run_for(pid: ObjId, vcpu_handle: HandleId) {
    let _ = kobj::with(|t| {
        let id = resolve(t, pid, vcpu_handle, Rights::READ)?;
        if let Some(vcpu) = vcpu_mut(t, id) {
            vcpu.lifecycle.fail();
        }
        Ok::<(), VcpuError>(())
    });
}

pub fn view(pid: ObjId, vcpu_handle: HandleId) -> Result<VcpuView, VcpuError> {
    kobj::with(|t| {
        let id = resolve(t, pid, vcpu_handle, Rights::READ)?;
        let vcpu = vcpu_mut(t, id).ok_or(VcpuError::Closed)?;
        Ok(VcpuView {
            backend: vcpu.lifecycle.backend(),
            status: vcpu.lifecycle.status(),
            mappings: vcpu.guest.len(),
            pinned_memory: vcpu.pins.iter().flatten().count(),
            table_root: vcpu.second_level.root_physical(),
            state: vcpu.lifecycle.state(),
            closing: vcpu.closing,
        })
    })
}

/// Closing releases every pinned Memory reference exactly once.
pub fn close_in(t: &mut Table, id: ObjId) {
    let memory_ids = {
        let Some(vcpu) = vcpu_mut(t, id) else { return };
        if vcpu.closing {
            return;
        }
        vcpu.closing = true;
        vcpu.lifecycle.close();
        vcpu.guest.clear();
        vcpu.pins
    };
    for memory in memory_ids.into_iter().flatten() {
        let _ = t.release_internal(memory);
    }
    if let Some(vcpu) = vcpu_mut(t, id) {
        vcpu.pins.fill(None);
    }
}

pub fn error_code(error: VcpuError) -> i64 {
    match error {
        VcpuError::Process(ProcError::Handle(_)) => err(SYSTEM_HANDLE_ERROR_INVALID),
        VcpuError::Process(_) => err(SYSTEM_ERROR_RIGHTS_DENIED),
        VcpuError::State(StateError::Closed) | VcpuError::Closed => err(SYSTEM_HANDLE_ERROR_INVALID),
        VcpuError::State(_) => err(SYSTEM_ERROR_INVALID_ARGUMENT),
        VcpuError::Map(MapError::Permissions) => err(SYSTEM_ERROR_RIGHTS_DENIED),
        VcpuError::Map(_) | VcpuError::Table(_) | VcpuError::InvalidMemory => {
            err(SYSTEM_ERROR_INVALID_ARGUMENT)
        }
    }
}
