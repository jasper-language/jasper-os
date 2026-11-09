//! Kernel-owned virtio-blk driver used by the BLK-1 acceptance.
//!
//! Requests use one bounded descriptor chain and complete through the device
//! used ring. The data buffer is a DRV-3 DMA mapping over a pinned Memory
//! object; this module is the only path that translates the mapping to physical
//! addresses for the device.

use alloc::vec::Vec;
use core::mem::ManuallyDrop;

use kernel_core::block::{self, Features, Request, RequestKind, Terminal};
use kernel_core::dma_abi::MapArgs;
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;

use crate::kobj::{self, DeviceObj, KObject};
use crate::syscall::SyscallSet;
use crate::virtio::{self, Queue, VirtioPci};
use crate::{dma, mm, pci, proc, sched};

const FEATURE_FLUSH: u32 = 1 << 9;
const FEATURE_BLOCK_SIZE: u32 = 1 << 6;
const FEATURE_DISCARD: u32 = 1 << 13;
const WAIT_TICKS: u64 = 1_000;
const HEADER_OFFSET: u64 = 0;
const STATUS_OFFSET: u64 = 16;
const DISCARD_OFFSET: u64 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlkError {
    NoDevice,
    Virtio(&'static str),
    Process,
    Dma,
    Admission(block::Error),
    Queue,
    Timeout,
    StaleCompletion,
    DeviceStatus(u8),
    Cancelled,
}

impl BlkError {
    pub const fn name(self) -> &'static str {
        match self {
            BlkError::NoDevice => "system.block.error.no_device",
            BlkError::Virtio(name) => name,
            BlkError::Process => "system.block.error.process",
            BlkError::Dma => "system.block.error.dma",
            BlkError::Admission(_) => "system.block.error.admission",
            BlkError::Queue => "system.block.error.queue",
            BlkError::Timeout => "system.block.error.timeout",
            BlkError::StaleCompletion => "system.block.error.stale_completion",
            BlkError::DeviceStatus(_) => "system.block.error.device",
            BlkError::Cancelled => "system.block.error.cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub capacity_sectors: u64,
    pub logical_block_size: u32,
    pub physical_block_size: u32,
    pub atomic_write_bytes: u32,
    pub discard: bool,
    pub fua: bool,
}

pub struct BlockDevice {
    virtio: VirtioPci,
    queue: ManuallyDrop<Queue>,
    notify_off: u16,
    bus_master_was_on: bool,
    pid: ObjId,
    memory_handle: HandleId,
    device_handle: HandleId,
    mapping_handle: HandleId,
    data_pages: u64,
    features: Features,
    geometry: Geometry,
}

fn discard_process(pid: ObjId) {
    let _ = proc::exit_idle(pid, -1);
    let _ = proc::reap(pid);
    kobj::run_cleanup(usize::MAX);
}

impl BlockDevice {
    pub fn new(device: &pci::Device, data_pages: u64) -> Result<Self, BlkError> {
        if data_pages == 0 || data_pages > block::MAX_DATA_PAGES as u64 {
            return Err(BlkError::Admission(block::Error::ChainTooLong));
        }
        let virtio = VirtioPci::new(device).map_err(|e| BlkError::Virtio(e.name()))?;
        virtio.reset().map_err(|e| BlkError::Virtio(e.name()))?;
        let offered = virtio.device_features(0);
        if offered & FEATURE_FLUSH == 0 {
            return Err(BlkError::Virtio("system.block.error.flush_unsupported"));
        }
        let selected = FEATURE_FLUSH
            | if offered & FEATURE_BLOCK_SIZE != 0 {
                FEATURE_BLOCK_SIZE
            } else {
                0
            }
            | if offered & FEATURE_DISCARD != 0 {
                FEATURE_DISCARD
            } else {
                0
            };
        virtio
            .negotiate_features(selected)
            .map_err(|e| BlkError::Virtio(e.name()))?;

        let capacity_sectors =
            virtio.read_device_config64(0).ok_or(BlkError::Virtio("system.block.error.config"))?;
        let logical_block_size = if selected & FEATURE_BLOCK_SIZE != 0 {
            virtio.read_device_config32(20)
        } else {
            block::SECTOR_BYTES as u32
        };
        if logical_block_size == 0 || logical_block_size > block::IO_ALIGNMENT as u32 {
            return Err(BlkError::Virtio("system.block.error.block_size"));
        }
        let physical_exp = virtio.read_device_config8(24).unwrap_or(0);
        let physical_block_size = logical_block_size
            .checked_shl(u32::from(physical_exp))
            .ok_or(BlkError::Virtio("system.block.error.block_size"))?;
        let features = Features {
            flush: true,
            discard: selected & FEATURE_DISCARD != 0,
            block_size: selected & FEATURE_BLOCK_SIZE != 0,
        };
        let geometry = Geometry {
            capacity_sectors,
            logical_block_size,
            physical_block_size,
            atomic_write_bytes: logical_block_size,
            discard: features.discard,
            fua: true,
        };

        let mut queue = Queue::new().map_err(|e| BlkError::Virtio(e.name()))?;
        let notify_off =
            virtio.setup_queue(&mut queue, 0).map_err(|e| BlkError::Virtio(e.name()))?;

        let pid = proc::create("blk1", SyscallSet::EMPTY).map_err(|_| BlkError::Process)?;
        let memory_handle = match proc::create_memory(pid, data_pages) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = proc::exit_idle(pid, -1);
                let _ = proc::reap(pid);
                return Err(BlkError::Process);
            }
        };
        let device_handle = match proc::grant_new(
            pid,
            KObject::Device(DeviceObj { bdf: device.bdf }),
            ObjectType::Device,
            Rights::READ.union(Rights::CONTROL),
        ) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = proc::exit_idle(pid, -1);
                let _ = proc::reap(pid);
                kobj::run_cleanup(usize::MAX);
                return Err(BlkError::Process);
            }
        };
        let (mapping_handle, _) = match dma::create_for(
            pid,
            memory_handle,
            MapArgs::new(device_handle.raw(), 0, data_pages, true),
        ) {
            Ok(mapped) => mapped,
            Err(_) => {
                discard_process(pid);
                return Err(BlkError::Dma);
            }
        };
        let bus_master_was_on = match pci::set_bus_master(device.bdf, true) {
            Ok(was_on) => was_on,
            Err(_) => {
                discard_process(pid);
                return Err(BlkError::Virtio("system.block.error.bus_master"));
            }
        };
        virtio.add_status(virtio::STATUS_DRIVER_OK);
        Ok(Self {
            virtio,
            queue: ManuallyDrop::new(queue),
            notify_off,
            bus_master_was_on,
            pid,
            memory_handle,
            device_handle,
            mapping_handle,
            data_pages,
            features,
            geometry,
        })
    }

    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    fn frames(&self) -> Result<Vec<PhysFrame>, BlkError> {
        dma::physical_range(self.pid, self.mapping_handle, 0, self.data_pages)
            .map_err(|_| BlkError::Dma)
    }

    pub fn fill_pattern(&self, seed: u8, prefix: &[u8]) -> Result<(), BlkError> {
        for (page_index, frame) in self.frames()?.into_iter().enumerate() {
            let Some(ptr) = mm::phys_to_virt(frame.start()) else {
                return Err(BlkError::Dma);
            };
            // SAFETY: this is the exclusively mapped DMA backing frame.
            unsafe {
                for offset in 0..FRAME_SIZE as usize {
                    let absolute = page_index * FRAME_SIZE as usize + offset;
                    ptr.add(offset)
                        .write_volatile(seed.wrapping_add(absolute as u8));
                }
            }
        }
        if prefix.len() > self.data_pages as usize * FRAME_SIZE as usize {
            return Err(BlkError::Dma);
        }
        let frames = self.frames()?;
        let mut copied = 0usize;
        for frame in frames {
            if copied == prefix.len() {
                break;
            }
            let Some(ptr) = mm::phys_to_virt(frame.start()) else {
                return Err(BlkError::Dma);
            };
            let count = (prefix.len() - copied).min(FRAME_SIZE as usize);
            // SAFETY: the destination is the exclusive DMA backing frame.
            unsafe {
                core::ptr::copy_nonoverlapping(prefix[copied..].as_ptr(), ptr, count);
            }
            copied += count;
        }
        Ok(())
    }

    pub fn data_equals(&self, seed: u8, prefix: &[u8]) -> Result<bool, BlkError> {
        for (page_index, frame) in self.frames()?.into_iter().enumerate() {
            let Some(ptr) = mm::phys_to_virt(frame.start()) else {
                return Err(BlkError::Dma);
            };
            for offset in 0..FRAME_SIZE as usize {
                let absolute = page_index * FRAME_SIZE as usize + offset;
                let expected = prefix.get(absolute).copied().unwrap_or_else(|| {
                    seed.wrapping_add(absolute as u8)
                });
                // SAFETY: this is the exclusively mapped DMA backing frame.
                let actual = unsafe { ptr.add(offset).read_volatile() };
                if actual != expected {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    pub fn copy_prefix(&self, out: &mut [u8]) -> Result<(), BlkError> {
        let frames = self.frames()?;
        let mut copied = 0usize;
        for frame in frames {
            if copied == out.len() {
                break;
            }
            let Some(ptr) = mm::phys_to_virt(frame.start()) else {
                return Err(BlkError::Dma);
            };
            let count = (out.len() - copied).min(FRAME_SIZE as usize);
            // SAFETY: source and destination ranges are checked and disjoint
            // from other active callers of this exclusive DMA mapping.
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, out[copied..].as_mut_ptr(), count);
            }
            copied += count;
        }
        Ok(())
    }

    pub fn execute(
        &mut self,
        request: Request,
        cancel_after_submit: bool,
    ) -> Result<Terminal, BlkError> {
        if request.kind == RequestKind::Write && request.fua {
            let write = Request::write(request.sector, request.pages, false);
            match self.execute_one(write, cancel_after_submit)? {
                Terminal::Completed => {}
                terminal => return Ok(terminal),
            }
            return self.execute_one(Request::flush(), false);
        }
        self.execute_one(request, cancel_after_submit)
    }

    fn execute_one(
        &mut self,
        request: Request,
        cancel_after_submit: bool,
    ) -> Result<Terminal, BlkError> {
        request
            .validate(self.features, self.geometry.capacity_sectors)
            .map_err(BlkError::Admission)?;
        if self.queue.take_used().is_some() {
            return Err(BlkError::StaleCompletion);
        }
        if !self.queue.write_buffer(HEADER_OFFSET, &request.header())
            || !self.queue.write_buffer(STATUS_OFFSET, &[0xff])
        {
            return Err(BlkError::Queue);
        }

        let mut descriptor = 1u16;
        match request.kind {
            RequestKind::Read | RequestKind::Write => {
                let flags = if request.kind == RequestKind::Read {
                    virtio::VIRTQ_DESC_F_WRITE
                } else {
                    0
                };
                for frame in self.frames()? {
                    self.queue
                        .set_descriptor(
                            descriptor,
                            frame.start(),
                            FRAME_SIZE as u32,
                            flags | virtio::VIRTQ_DESC_F_NEXT,
                            descriptor + 1,
                        )
                        .map_err(|_| BlkError::Queue)?;
                    descriptor += 1;
                }
            }
            RequestKind::Discard => {
                if !self.queue.write_buffer(DISCARD_OFFSET, &request.discard_range()) {
                    return Err(BlkError::Queue);
                }
                let buffer_phys = self.queue.buffer_phys();
                self.queue
                    .set_descriptor(
                        descriptor,
                        buffer_phys + DISCARD_OFFSET,
                        block::DISCARD_RANGE_BYTES as u32,
                        virtio::VIRTQ_DESC_F_NEXT,
                        descriptor + 1,
                    )
                    .map_err(|_| BlkError::Queue)?;
                descriptor += 1;
            }
            RequestKind::Flush => {}
        }
        let next = descriptor;
        let buffer_phys = self.queue.buffer_phys();
        self.queue
            .set_descriptor(
                0,
                buffer_phys + HEADER_OFFSET,
                block::HEADER_BYTES as u32,
                virtio::VIRTQ_DESC_F_NEXT,
                1,
            )
            .map_err(|_| BlkError::Queue)?;
        self.queue
            .set_descriptor(
                next,
                buffer_phys + STATUS_OFFSET,
                block::STATUS_BYTES as u32,
                virtio::VIRTQ_DESC_F_WRITE,
                0,
            )
            .map_err(|_| BlkError::Queue)?;

        let mut lifecycle = block::Lifecycle::new();
        lifecycle.submit().map_err(|_| BlkError::Queue)?;
        self.queue.submit(0).map_err(|_| BlkError::Queue)?;
        self.virtio.notify(self.notify_off).map_err(|e| BlkError::Virtio(e.name()))?;
        if cancel_after_submit {
            lifecycle.cancel().map_err(|_| BlkError::Queue)?;
        }

        let start = sched::timer_ticks();
        let (completion, _) = loop {
            if let Some(used) = self.queue.take_used() {
                break used;
            }
            if sched::timer_ticks().wrapping_sub(start) >= WAIT_TICKS {
                return Err(BlkError::Timeout);
            }
            sched::pause();
        };
        if completion != 0 {
            return Err(BlkError::Queue);
        }
        let mut status = [0xffu8; 1];
        if !self.queue.read_buffer(STATUS_OFFSET, &mut status) {
            return Err(BlkError::Queue);
        }
        lifecycle
            .complete(status[0])
            .map_err(|_| BlkError::Queue)
    }
}

impl Drop for BlockDevice {
    fn drop(&mut self) {
        // SAFETY: the queue is taken exactly once and this structure never uses
        // the field after Drop starts.
        let queue = unsafe { ManuallyDrop::take(&mut self.queue) };
        let _ = virtio::quiesce(&self.virtio, queue, !self.bus_master_was_on);
        let _ = proc::close_handle_for(self.pid, self.mapping_handle);
        kobj::run_cleanup(usize::MAX);
        let _ = proc::close_handle_for(self.pid, self.memory_handle);
        let _ = proc::close_handle_for(self.pid, self.device_handle);
        let _ = proc::exit_idle(self.pid, 0);
        let _ = proc::reap(self.pid);
        kobj::run_cleanup(usize::MAX);
    }
}
