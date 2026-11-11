//! Bounded synchronous virtio-rng backend for Linux compatibility getrandom.
//! Linux 兼容 getrandom 使用的有界同步 virtio-rng 后端。
//!
//! The device queue is initialized once and protected by a kernel mutex. Requests wait
//! for used-ring completion without depending on MSI-X; every request has bounded tick
//! and spin limits. 设备队列只初始化一次，并由内核互斥锁串行化；请求不依赖 MSI-X，
//! 只等待 used ring，tick 与自旋都有确定上界。

use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;

use crate::virtio::{self, Queue, VirtioPci, BUFFER_BYTES};
use crate::{kprintln, mmio, pci, sched};

const QUEUE_ENTRY: u16 = 0;
const WAIT_TICKS: u64 = 1_000;
const MAX_SPINS: u64 = 50_000_000;

struct Device {
    virtio: VirtioPci,
    queue: Queue,
    notify_off: u16,
    previous_bus_master: bool,
}

// SAFETY: all register and DMA queue access is serialized by DEVICE. The raw queue
// pointers identify kernel-owned contiguous pages, not thread-local state.
// 所有寄存器与 DMA 队列访问均由 DEVICE 串行化；裸指针只指向内核独占连续页。
unsafe impl Send for Device {}

static DEVICE: Mutex<Option<Device>> = Mutex::new(None);
static INIT_FAILED: AtomicBool = AtomicBool::new(false);

fn initialize_failed(stage: &'static str) -> Option<Device> {
    kprintln!("[JSR-COMPAT-RNG-FAIL] stage={}", stage);
    None
}

fn initialize() -> Option<Device> {
    if INIT_FAILED.load(Ordering::Acquire) {
        return None;
    }
    // The boot path may already have prepared this window. Re-probing is a best-effort
    // page-table warmup; the actual capability mapping below remains authoritative.
    let _ = mmio::prepare_window();
    let pci_device = pci::table().devices().find(|device| {
        device.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_rng_device(device.header.device)
    });
    let Some(pci_device) = pci_device else {
        return initialize_failed("device");
    };
    let virtio = match VirtioPci::new(pci_device) {
        Ok(virtio) => virtio,
        Err(error) => {
            kprintln!("[JSR-COMPAT-RNG-FAIL] stage=transport error={}", error.name());
            return None;
        }
    };
    if virtio.reset().is_err() {
        return initialize_failed("reset");
    }
    if virtio.negotiate_version_1().is_err() {
        return initialize_failed("features");
    }
    let mut queue = match Queue::new() {
        Ok(queue) => queue,
        Err(error) => {
            kprintln!("[JSR-COMPAT-RNG-FAIL] stage=queue error={}", error.name());
            return None;
        }
    };
    let notify_off = match virtio.setup_queue_polling(&mut queue) {
        Ok(value) => value,
        Err(error) => {
            kprintln!("[JSR-COMPAT-RNG-FAIL] stage=setup error={}", error.name());
            return None;
        }
    };
    let previous_bus_master = match pci::set_bus_master(virtio.bdf(), true) {
        Ok(value) => value,
        Err(_) => return initialize_failed("bus-master"),
    };
    virtio.add_status(virtio::STATUS_DRIVER_OK);
    kprintln!(
        "[JSR-COMPAT-RNG] source=virtio-rng queue_size={} bdf={:02x}:{:02x}.{}",
        queue.size(),
        virtio.bdf().bus(),
        virtio.bdf().device(),
        virtio.bdf().function()
    );
    Some(Device {
        virtio,
        queue,
        notify_off,
        previous_bus_master,
    })
}

fn wait_for_used(device: &mut Device) -> Option<u32> {
    let start = sched::timer_ticks();
    for spin in 0..MAX_SPINS {
        if let Some((_, length)) = device.queue.take_used() {
            return Some(length);
        }
        if spin % 4096 == 0
            && sched::timer_ticks().wrapping_sub(start) >= WAIT_TICKS
        {
            return None;
        }
        core::hint::spin_loop();
    }
    None
}

fn request(device: &mut Device, output: &mut [u8]) -> bool {
    if output.len() > BUFFER_BYTES {
        return false;
    }
    if device.queue.submit(QUEUE_ENTRY).is_err()
        || device.virtio.notify(device.notify_off).is_err()
    {
        return false;
    }
    let Some(length) = wait_for_used(device) else {
        return false;
    };
    length as usize >= output.len() && device.queue.read_buffer(0, output)
}

/// Fills the output from one bounded virtio-rng device.
/// 使用一个有界 virtio-rng 设备填充输出。
pub fn fill(output: &mut [u8]) -> bool {
    let mut guard = DEVICE.lock();
    if guard.is_none() {
        *guard = initialize();
        if guard.is_none() {
            INIT_FAILED.store(true, Ordering::Release);
        }
    }
    let Some(device) = guard.as_mut() else {
        return false;
    };
    let mut offset = 0;
    while offset < output.len() {
        let end = (offset + BUFFER_BYTES).min(output.len());
        if !request(device, &mut output[offset..end]) {
            let _ = pci::set_bus_master(device.virtio.bdf(), false);
            let _ = device.virtio.reset();
            if device.previous_bus_master {
                let _ = pci::set_bus_master(device.virtio.bdf(), true);
            }
            *guard = None;
            INIT_FAILED.store(true, Ordering::Release);
            return false;
        }
        offset = end;
    }
    true
}
