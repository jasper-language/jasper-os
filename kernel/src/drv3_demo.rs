//! DRV-3 DMA mapping lifecycle drill.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::dma_abi::MapArgs;
use kernel_core::object::{ObjectType, Rights};

use crate::kobj::{self, KObject};
use crate::{dma, kobj::DeviceObj, kprintln, proc};

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(condition: bool, what: &'static str) {
    if !condition {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-DRV3-FAIL] {}", what);
    }
}

pub fn run() {
    let before = crate::baseline::baseline();
    let Some(device) = crate::pci::table()
        .devices()
        .find(|device| device.header.vendor == 0x1af4)
    else {
        check(false, "no virtio PCI device for DMA mapping drill");
        return;
    };
    let pid = match proc::create("drv3-dma", crate::syscall::SyscallSet::EMPTY) {
        Ok(pid) => pid,
        Err(_) => {
            check(false, "process creation failed");
            return;
        }
    };
    let memory = match proc::create_memory(pid, 2) {
        Ok(handle) => handle,
        Err(_) => {
            check(false, "Memory creation failed");
            return;
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
            check(false, "Device handle creation failed");
            return;
        }
    };

    let outside = MapArgs::new(device_handle.raw(), 2, 1, false);
    check(
        dma::create_for(pid, memory, outside).is_err(),
        "out-of-range DMA map was accepted",
    );
    let zero = MapArgs::new(device_handle.raw(), 0, 0, false);
    check(
        dma::create_for(pid, memory, zero).is_err(),
        "zero-length DMA map was accepted",
    );
    check(
        proc::memory_quota(pid).is_some_and(|usage| usage.pinned == 0),
        "failed DMA map changed pin quota",
    );

    let writable = MapArgs::new(device_handle.raw(), 0, 1, true);
    let (mapping, iova) = match dma::create_for(pid, memory, writable) {
        Ok(mapped) => mapped,
        Err(_) => {
            check(false, "DMA map creation failed");
            return;
        }
    };
    check(
        iova % kernel_core::memory_object::PAGE_BYTES == 0,
        "DMA IOVA is not page aligned",
    );
    let view = dma::view(pid, mapping).expect("DMA view");
    check(
        view.iova == iova && view.pages == 1 && view.writable,
        "DMA mapping view disagrees with creation",
    );
    check(
        dma::physical_range(pid, mapping, 0, 1)
            .is_ok_and(|frames| frames.len() == 1),
        "kernel DMA translation failed",
    );
    check(
        proc::memory_quota(pid).is_some_and(|usage| usage.pinned == 1),
        "DMA map did not reserve one pinned page",
    );

    check(
        proc::close_handle_for(pid, memory).is_ok(),
        "Memory owner close failed",
    );
    check(
        proc::close_handle_for(pid, device_handle).is_ok(),
        "Device owner close failed",
    );
    check(
        dma::physical_range(pid, mapping, 0, 1)
            .is_ok_and(|frames| frames.len() == 1),
        "DMA map did not keep Memory and Device alive",
    );

    check(
        proc::close_handle_for(pid, mapping).is_ok(),
        "DMA mapping close failed",
    );
    check(
        dma::view(pid, mapping).is_err(),
        "closed DMA handle remained usable",
    );
    kobj::run_cleanup(usize::MAX);
    check(
        proc::memory_quota(pid).is_some_and(|usage| usage.pinned == 0),
        "DMA close did not release pinned quota",
    );

    check(proc::exit_idle(pid, 0), "process exit failed");
    check(proc::reap(pid).is_some(), "process reap failed");
    kobj::run_cleanup(usize::MAX);
    let after = crate::baseline::baseline();
    check(before == after, "DRV-3 resources did not return to baseline");

    kprintln!(
        "[JSR-DRV3] device=0x{:x} iova=0x{:x} pages=1 writable=true iova_opaque=true pinned=true owner_close=true reclaim=true failed={}",
        kernel_core::device::pack_bdf(device.bdf),
        iova,
        failed()
    );
}
