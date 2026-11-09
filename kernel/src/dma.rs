//! Device-visible mappings of pinned Memory objects (DRV-3).
//!
//! A DMA handle owns one mapping. It strongly references both the Memory object
//! and the Device object, and reserves the mapping's page count in the creator's
//! pin quota. User space receives only the opaque IOVA, never a host frame.

use alloc::boxed::Box;
use alloc::vec::Vec;

use kernel_core::dma_abi::{self, MapArgs};
use kernel_core::frame::PhysFrame;
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::pci::Bdf;

use crate::kobj::{self, KObject, Table};
use crate::proc::{self, ProcError};
use crate::sync::IrqSpinLock;
use crate::syscall::err;
use crate::syscall::table::{
    SYSTEM_ERROR_INVALID_ARGUMENT, SYSTEM_ERROR_RIGHTS_DENIED,
    SYSTEM_HANDLE_ERROR_INVALID,
};

const DMA_RIGHTS: Rights = Rights::READ
    .union(Rights::CONTROL)
    .union(Rights::DUPLICATE);
const IOVA_BASE: u64 = 0x0000_0100_0000;
const IOVA_LIMIT: u64 = 1 << 48;
const IOVA_PAGE: u64 = kernel_core::memory_object::PAGE_BYTES;

static NEXT_IOVA: IrqSpinLock<u64> = IrqSpinLock::new(IOVA_BASE);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaError {
    Process(ProcError),
    InvalidHandle,
    Rights,
    Range,
    Quota,
    Exhausted,
    Closed,
}

pub struct DmaMapping {
    owner: ObjId,
    device: ObjId,
    bdf: Bdf,
    memory: ObjId,
    offset_pages: u64,
    pages: u64,
    iova: u64,
    writable: bool,
    closing: bool,
    _pin_charge: crate::mm::memory_quota::Charge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaView {
    pub owner: ObjId,
    pub device: ObjId,
    pub memory: ObjId,
    pub offset_pages: u64,
    pub pages: u64,
    pub iova: u64,
    pub writable: bool,
    pub closing: bool,
}

fn mapping_mut(t: &mut Table, id: ObjId) -> Option<&mut DmaMapping> {
    match t.get_mut(id) {
        Ok(KObject::DmaMapping(mapping)) => Some(mapping),
        _ => None,
    }
}

fn resolve(t: &mut Table, pid: ObjId, handle: HandleId) -> Result<ObjId, DmaError> {
    let id = proc::resolve_in(t, pid, handle, ObjectType::DmaMapping, Rights::READ)
        .map_err(DmaError::Process)?;
    match t.get(id) {
        Ok(KObject::DmaMapping(mapping)) if mapping.owner == pid && !mapping.closing => Ok(id),
        Ok(KObject::DmaMapping(_)) => Err(DmaError::Closed),
        _ => Err(DmaError::InvalidHandle),
    }
}

fn allocate_iova(pages: u64) -> Option<u64> {
    let bytes = pages.checked_mul(IOVA_PAGE)?;
    let mut next = NEXT_IOVA.lock();
    let start = *next;
    if start == u64::MAX {
        return None;
    }
    let end = start.checked_add(bytes)?;
    if end > IOVA_LIMIT {
        *next = u64::MAX;
        return None;
    }
    *next = end;
    Some(start)
}

pub fn create_for(
    pid: ObjId,
    memory_handle: HandleId,
    args: MapArgs,
) -> Result<(HandleId, u64), DmaError> {
    kobj::with(|t| {
        if !proc::running_in(t, pid) {
            return Err(DmaError::Process(ProcError::NoSuchProcess));
        }
        let (_, memory_rights) =
            proc::handle_in(t, pid, memory_handle).map_err(DmaError::Process)?;
        let memory_id = proc::resolve_in(
            t,
            pid,
            memory_handle,
            ObjectType::Memory,
            Rights::READ,
        )
        .map_err(DmaError::Process)?;
        let memory_pages = match t.get(memory_id) {
            Ok(KObject::Memory(memory)) => memory.page_count(),
            _ => return Err(DmaError::InvalidHandle),
        };
        let range = args.validate(memory_rights).map_err(|error| match error {
            dma_abi::Error::Rights => DmaError::Rights,
            dma_abi::Error::Invalid | dma_abi::Error::Range => DmaError::Range,
        })?;
        if !range.within(memory_pages) {
            return Err(DmaError::Range);
        }

        let device = HandleId::from_raw(args.device);
        let device_id = proc::resolve_in(t, pid, device, ObjectType::Device, Rights::CONTROL)
            .map_err(DmaError::Process)?;
        let bdf = match t.get(device_id) {
            Ok(KObject::Device(device)) => device.bdf,
            _ => return Err(DmaError::InvalidHandle),
        };

        let charge =
            proc::reserve_memory_pins_in(t, pid, range.pages).ok_or(DmaError::Quota)?;
        let iova = allocate_iova(range.pages).ok_or(DmaError::Exhausted)?;
        t.acquire_internal(memory_id)
            .map_err(|_| DmaError::InvalidHandle)?;
        if t.acquire_internal(device_id).is_err() {
            let _ = t.release_internal(memory_id);
            return Err(DmaError::InvalidHandle);
        }
        let object = DmaMapping {
            owner: pid,
            device: device_id,
            bdf,
            memory: memory_id,
            offset_pages: range.offset_pages,
            pages: range.pages,
            iova,
            writable: range.writable,
            closing: false,
            _pin_charge: charge,
        };
        match proc::grant_new_in(
            t,
            pid,
            KObject::DmaMapping(Box::new(object)),
            ObjectType::DmaMapping,
            DMA_RIGHTS,
        ) {
            Ok((handle, _)) => Ok((handle, iova)),
            Err(error) => {
                let _ = t.release_internal(memory_id);
                let _ = t.release_internal(device_id);
                Err(DmaError::Process(error))
            }
        }
    })
}

pub fn view(pid: ObjId, handle: HandleId) -> Result<DmaView, DmaError> {
    kobj::with(|t| {
        let id = resolve(t, pid, handle)?;
        let mapping = mapping_mut(t, id).ok_or(DmaError::InvalidHandle)?;
        Ok(DmaView {
            owner: mapping.owner,
            device: mapping.device,
            memory: mapping.memory,
            offset_pages: mapping.offset_pages,
            pages: mapping.pages,
            iova: mapping.iova,
            writable: mapping.writable,
            closing: mapping.closing,
        })
    })
}

/// Kernel-only translation for the eventual device backend. The returned frame
/// list remains valid because the DMA object keeps its Memory reference until close.
pub fn physical_range(
    pid: ObjId,
    handle: HandleId,
    offset_pages: u64,
    pages: u64,
) -> Result<Vec<PhysFrame>, DmaError> {
    let (memory, start) = kobj::with(|t| {
        let id = resolve(t, pid, handle)?;
        let mapping = mapping_mut(t, id).ok_or(DmaError::InvalidHandle)?;
        let end = offset_pages.checked_add(pages).ok_or(DmaError::Range)?;
        if pages == 0 || end > mapping.pages {
            return Err(DmaError::Range);
        }
        Ok((mapping.memory, mapping.offset_pages + offset_pages))
    })?;
    kobj::with(|t| match t.get(memory) {
        Ok(KObject::Memory(memory)) => memory
            .physical_range(start, pages)
            .ok_or(DmaError::Range),
        _ => Err(DmaError::InvalidHandle),
    })
}

pub fn close_in(t: &mut Table, id: ObjId) {
    let (memory, device, bdf, offset_pages, pages) = {
        let Some(mapping) = mapping_mut(t, id) else {
            return;
        };
        if mapping.closing {
            return;
        }
        mapping.closing = true;
        (
            mapping.memory,
            mapping.device,
            mapping.bdf,
            mapping.offset_pages,
            mapping.pages,
        )
    };
    let quiesced = crate::pci::set_bus_master(bdf, false).is_ok()
        && matches!(crate::pci::bus_master_enabled(bdf), Ok(false));
    if !quiesced {
        if let Ok(KObject::Memory(memory)) = t.get(memory) {
            let _ = memory.quarantine_range(offset_pages, pages);
        }
    }
    let _ = t.release_internal(memory);
    let _ = t.release_internal(device);
}

pub fn error_code(error: DmaError) -> i64 {
    match error {
        DmaError::Process(ProcError::Handle(_)) | DmaError::InvalidHandle | DmaError::Closed => {
            err(SYSTEM_HANDLE_ERROR_INVALID)
        }
        DmaError::Process(_) | DmaError::Rights => err(SYSTEM_ERROR_RIGHTS_DENIED),
        DmaError::Quota => err(SYSTEM_ERROR_RIGHTS_DENIED),
        DmaError::Exhausted | DmaError::Range => err(SYSTEM_ERROR_INVALID_ARGUMENT),
    }
}
