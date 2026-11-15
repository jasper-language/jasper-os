//! HWV-6 hardware acceptance: ACPI DMAR, Intel VT-d translation, DMA faults,
//! interrupt remapping, reset/unbind revocation and resource return.
//!
//! This profile requires QEMU's emulated Intel IOMMU. It does not claim that
//! QEMU is a physical VT-d/AMD-Vi platform; the verifier records the backend
//! explicitly so physical passthrough qualification remains a separate gate.

use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::acpi::{self, DmarUnit};
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::msi::{Vector, VectorPool};
use kernel_core::pci::{Bar, Bdf};

use super::port::{inl, outb, outl};
use super::smp;
use crate::pci::Device;
use crate::virtio::{self, Queue, VirtioPci};
use crate::{arch, boot::BootSpec, irq, kprintln, mm, mmio, msix::MsixDevice, pci, sched};

const REG_VER: u64 = 0x00;
const REG_CAP: u64 = 0x08;
const REG_ECAP: u64 = 0x10;
const REG_GCMD: u64 = 0x18;
const REG_GSTS: u64 = 0x1c;
const REG_RTADDR: u64 = 0x20;
const REG_CCMD: u64 = 0x28;
const REG_FSTS: u64 = 0x34;
const REG_IRTA: u64 = 0xb8;

const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GCMD_WBF: u32 = 1 << 27;
const GCMD_IRE: u32 = 1 << 25;
const GCMD_SIRTP: u32 = 1 << 24;
const GCMD_CFI: u32 = 1 << 23;
const GSTS_TE: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;
const GSTS_WBF: u32 = 1 << 27;
const GSTS_IRTPS: u32 = 1 << 24;
const GSTS_IRES: u32 = 1 << 25;
const GSTS_CFIS: u32 = 1 << 23;

const CCMD_ICC: u64 = 1 << 63;
const CCMD_GLOBAL: u64 = 1 << 61;
const TLB_IVT: u64 = 1 << 63;
const TLB_GLOBAL: u64 = 1 << 60;

const FSTS_PPF: u32 = 1 << 1;
const FRCD_F: u32 = 1 << 31;
const PAGE_2M: u64 = 2 * 1024 * 1024;
const WAIT_SPINS: usize = 6_000_000;
const DMA_WAIT_SPINS: usize = 4_000_000;
const RTL_WAIT_SPINS: usize = 2_000_000;
const DOMAIN_ID: u16 = 1;
const DEVICE_QUEUE_ENTRY: u16 = 0;
const ENABLE_IR: bool = false;

static FAILED: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);
static MSI_HANDLED: AtomicU32 = AtomicU32::new(0);

struct IrqEnable(bool);

impl IrqEnable {
    fn enter() -> Self {
        let was_enabled = arch::irq_save_disable();
        arch::irq_enable();
        Self(was_enabled)
    }
}

impl Drop for IrqEnable {
    fn drop(&mut self) {
        arch::irq_restore(self.0);
    }
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-HWV6-FAIL] {}", what);
    }
}

fn msi_handler() {
    MSI_HANDLED.fetch_add(1, Ordering::Relaxed);
}

fn wait_above(counter: &AtomicU32, before: u32) -> bool {
    for _ in 0..DMA_WAIT_SPINS {
        if counter.load(Ordering::Acquire) > before {
            return true;
        }
        core::hint::spin_loop();
    }
    counter.load(Ordering::Acquire) > before
}

fn read32(reg: *mut u8, off: u64) -> u32 {
    // SAFETY: `reg` is the mapped, 4 KiB-aligned VT-d register block and all
    // callers use defined register offsets covered by DMAR's size field.
    unsafe { ((reg as *const u8).add(off as usize) as *const u32).read_volatile() }
}

fn write32(reg: *mut u8, off: u64, value: u32) {
    // SAFETY: same boundary/alignment contract as `read32`.
    unsafe { ((reg as *mut u8).add(off as usize) as *mut u32).write_volatile(value) }
}

fn read64(reg: *mut u8, off: u64) -> u64 {
    // SAFETY: same boundary/alignment contract as `read32`; VT-d 64-bit
    // registers are both naturally aligned in the register block.
    unsafe { ((reg as *const u8).add(off as usize) as *const u64).read_volatile() }
}

fn write64(reg: *mut u8, off: u64, value: u64) {
    // SAFETY: same boundary/alignment contract as `read64`.
    unsafe { ((reg as *mut u8).add(off as usize) as *mut u64).write_volatile(value) }
}

struct Vtd {
    unit: DmarUnit,
    reg: *mut u8,
    root: PhysFrame,
    context: PhysFrame,
    pdpt: PhysFrame,
    pd: PhysFrame,
    irt: PhysFrame,
    cap: u64,
    ecap: u64,
    tlb_reg: u64,
    dma_enabled: bool,
    irq_enabled: bool,
    authority: u16,
}

impl Vtd {
    fn new(boot: &BootSpec, authority: Bdf) -> Result<Self, &'static str> {
        let offset = boot.phys_offset.ok_or("missing_physical_map")?;
        let rsdp = boot.acpi_rsdp.ok_or("missing_rsdp")?;
        let dmar = acpi::parse_dmar(&smp::PhysWindow(offset), rsdp).map_err(|e| e.name())?;
        if dmar.dropped != 0 {
            return Err("dmar_truncated");
        }
        let sid = bdf_sid(authority);
        let unit = *dmar
            .unit_for(0, authority.bus(), authority.device(), authority.function())
            .ok_or("no_drhd_scope")?;
        let reg = mm::phys_to_virt(unit.register_base).ok_or("register_unmapped")?;
        let first = mm::frame::allocate_contiguous(5).map_err(|_| "table_allocation")?;
        let frames: [PhysFrame; 5] =
            core::array::from_fn(|index| PhysFrame::from_number(first.number() + index as u64));
        for frame in frames {
            let ptr = mm::phys_to_virt(frame.start()).ok_or("table_unmapped")?;
            // SAFETY: each frame is exclusively allocated and the linear physical
            // map makes all 4096 bytes writable.
            unsafe { core::ptr::write_bytes(ptr, 0, FRAME_SIZE as usize) };
        }
        let mut out = Self {
            unit,
            reg,
            root: frames[0],
            context: frames[1],
            pdpt: frames[2],
            pd: frames[3],
            irt: frames[4],
            cap: read64(reg, REG_CAP),
            ecap: read64(reg, REG_ECAP),
            tlb_reg: (((read64(reg, REG_ECAP) >> 8) & 0x3ff) * 16),
            dma_enabled: false,
            irq_enabled: false,
            authority: bdf_sid(authority),
        };
        let version = read32(reg, REG_VER);
        if version >> 4 != 1 || read32(reg, REG_CAP) == 0 {
            out.shutdown();
            return Err("unsupported_vtd_version");
        }
        // The fixture uses 4-level second-stage tables and 2 MiB superpages.
        if out.cap & (1 << 10) == 0 || (out.cap >> 34) & 0xf == 0 {
            out.shutdown();
            return Err("unsupported_page_width");
        }
        if dmar.intr_remap && out.ecap & (1 << 3) != 0 && out.ecap & 2 == 0 {
            out.shutdown();
            return Err("queued_invalidation_required_for_ir");
        }

        // Root entry for PCI bus 0 points at the sole context table page.
        write64(out.root_ptr(), 0, out.context.start() | 1);
        out.set_context(sid, false);
        Ok(out)
    }

    fn root_ptr(&self) -> *mut u8 {
        // SAFETY: the root frame remains owned by this object until shutdown.
        mm::phys_to_virt(self.root.start()).expect("HWV6 root physical map")
    }

    fn context_entry(&self, sid: u16) -> *mut u8 {
        let ptr = mm::phys_to_virt(self.context.start()).expect("HWV6 context physical map");
        // SAFETY: context table is one owned page with 16-byte entries for
        // device functions 0..255.
        unsafe { ptr.add((sid as usize & 0xff) * 16) }
    }

    fn set_context(&mut self, sid: u16, present: bool) {
        if sid >> 8 != 0 {
            return;
        }
        let entry = self.context_entry(sid);
        let low = if present { self.pdpt.start() | 1 } else { 0 };
        let high = if present {
            // AGAW 1 selects three-level second-stage paging (39-bit), which
            // is sufficient for the bounded 1 GiB DMA arena below.
            (u64::from(DOMAIN_ID) << 8) | 1
        } else {
            0
        };
        write64(entry, 0, low);
        write64(entry, 8, high);
        if present {
            // PDPT[0] -> the single 1 GiB PD. The verifier maps only the
            // explicit 2 MiB windows required by the admitted device.
            write64(
                mm::phys_to_virt(self.pdpt.start()).expect("HWV6 PDPT physical map"),
                0,
                self.pd.start() | 1,
            );
        }
    }

    fn map_region(&mut self, phys: u64, bytes: u64) -> bool {
        let Some(end) = phys.checked_add(bytes) else {
            return false;
        };
        if phys % FRAME_SIZE != 0 || bytes == 0 || end > (1u64 << 30) {
            return false;
        }
        let pd = mm::phys_to_virt(self.pd.start()).expect("HWV6 PD physical map");
        let mut at = phys & !(PAGE_2M - 1);
        while at < end {
            let index = ((at >> 21) & 0x1ff) as usize;
            // 0: readable, 1: writable, 7: 2 MiB superpage.
            write64(pd, (index * 8) as u64, at | 0x83);
            at += PAGE_2M;
        }
        true
    }

    fn authorize(&mut self) {
        let sid = self.authority;
        self.set_context(sid, true);
        self.invalidate_all();
    }

    fn revoke(&mut self) {
        let sid = self.authority;
        self.set_context(sid, false);
        self.invalidate_all();
    }

    fn enable_dma(&mut self) -> bool {
        if !self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_TE == 0) {
            return false;
        }
        write64(self.reg, REG_RTADDR, self.root.start() & !0xfff);
        let mut gcmd = read32(self.reg, REG_GSTS);
        write32(self.reg, REG_GCMD, gcmd | GCMD_SRTP);
        if !self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_RTPS != 0) {
            return false;
        }
        gcmd = read32(self.reg, REG_GSTS);
        write32(self.reg, REG_GCMD, gcmd | GCMD_TE);
        if !self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_TE != 0) {
            return false;
        }
        self.dma_enabled = true;
        true
    }

    fn enable_interrupt_remapping(&mut self, cpu: usize, vector: u8, sid: u16) -> bool {
        if !self.dma_enabled || self.ecap & (1 << 3) == 0 {
            return false;
        }
        let apic_id = match smp::hw_id_of(cpu) {
            Some(id) if id < 256 => id as u64,
            _ => return false,
        };
        let irt = mm::phys_to_virt(self.irt.start()).expect("HWV6 IRT physical map");
        let at = irt as u64;
        // 256 entries: IRTA size field N encodes 2^(N+1) entries.
        let entry = irt.wrapping_add((sid as usize & 0xff) * 16);
        write64(entry, 0, 1 | (u64::from(vector) << 16) | (apic_id << 32));
        write64(entry, 8, u64::from(sid) | (1u64 << 18));
        core::sync::atomic::fence(Ordering::SeqCst);
        write64(self.reg, REG_IRTA, at | 7);
        let mut gcmd = read32(self.reg, REG_GSTS);
        write32(self.reg, REG_GCMD, gcmd | GCMD_SIRTP);
        if !self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_IRTPS != 0) {
            return false;
        }
        gcmd = read32(self.reg, REG_GSTS);
        write32(self.reg, REG_GCMD, gcmd | GCMD_IRE);
        if !self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_IRES != 0) {
            return false;
        }
        if read32(self.reg, REG_GSTS) & GSTS_CFIS != 0 {
            gcmd = read32(self.reg, REG_GSTS) & !GCMD_CFI;
            write32(self.reg, REG_GCMD, gcmd);
            if !self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_CFIS == 0) {
                return false;
            }
        }
        self.irq_enabled = true;
        true
    }

    fn invalidate_all(&self) {
        if self.cap & (1 << 4) != 0 {
            let mut gcmd = read32(self.reg, REG_GSTS);
            write32(self.reg, REG_GCMD, gcmd | GCMD_WBF);
            let _ = self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_WBF == 0);
            gcmd = read32(self.reg, REG_GSTS);
            let _ = gcmd;
        }
        write64(self.reg, REG_CCMD, CCMD_ICC | CCMD_GLOBAL);
        let _ = self.wait_for(|| read64(self.reg, REG_CCMD) & CCMD_ICC == 0);
        write64(self.reg, self.tlb_reg + 8, TLB_IVT | TLB_GLOBAL);
        let _ = self.wait_for(|| read64(self.reg, self.tlb_reg + 8) & TLB_IVT == 0);
    }

    fn clear_faults(&self) {
        let count = (((self.cap >> 40) & 0xff) + 1) as usize;
        let base = ((self.cap >> 24) & 0x3ff) * 16;
        for index in 0..count {
            let at = base + (index * 16) as u64;
            if read32(self.reg, at + 12) & FRCD_F != 0 {
                write32(self.reg, at + 12, FRCD_F);
            }
        }
        write32(self.reg, REG_FSTS, (1 << 0) | FSTS_PPF | (1 << 7));
    }

    fn fault_for(&self, expected_sid: u16) -> Option<(u16, u8, u64)> {
        let fsts = read32(self.reg, REG_FSTS);
        if fsts & FSTS_PPF == 0 {
            return None;
        }
        let count = (((self.cap >> 40) & 0xff) + 1) as usize;
        let base = ((self.cap >> 24) & 0x3ff) * 16;
        let mut index = ((fsts >> 8) & 0xff) as usize;
        for _ in 0..count {
            let at = base + (index * 16) as u64;
            let high = read32(self.reg, at + 12);
            if high & FRCD_F == 0 {
                break;
            }
            let sid = (read32(self.reg, at + 8) & 0xffff) as u16;
            let reason = high as u8;
            let addr = read64(self.reg, at) & !0xfff;
            write32(self.reg, at + 12, FRCD_F);
            if sid == expected_sid {
                write32(self.reg, REG_FSTS, FSTS_PPF | (1 << 0) | (1 << 7));
                return Some((sid, reason, addr));
            }
            index = (index + 1) % count;
        }
        None
    }

    fn wait_for(&self, mut condition: impl FnMut() -> bool) -> bool {
        for _ in 0..WAIT_SPINS {
            if condition() {
                return true;
            }
            core::hint::spin_loop();
        }
        condition()
    }

    fn shutdown(&mut self) {
        if self.reg.is_null() {
            return;
        }
        let mut gcmd = read32(self.reg, REG_GSTS);
        if self.irq_enabled {
            gcmd &= !GCMD_IRE;
            write32(self.reg, REG_GCMD, gcmd);
            let _ = self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_IRES == 0);
            gcmd = read32(self.reg, REG_GSTS);
            self.irq_enabled = false;
        }
        if self.dma_enabled {
            gcmd &= !GCMD_TE;
            write32(self.reg, REG_GCMD, gcmd);
            let _ = self.wait_for(|| read32(self.reg, REG_GSTS) & GSTS_TE == 0);
            self.dma_enabled = false;
        }
        write64(self.reg, REG_RTADDR, 0);
        if let Err(error) = mm::frame::deallocate_contiguous(self.root, 5) {
            kprintln!("[JSR-HWV6-FAIL] table_reclaim={}", error as u8);
        }
        self.reg = core::ptr::null_mut();
    }
}

impl Drop for Vtd {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Rig {
    virtio: VirtioPci,
    queue: ManuallyDrop<Queue>,
    notify_off: u16,
    msix: Option<MsixDevice>,
    bus_master_was_on: bool,
}

impl Rig {
    fn new(device: &Device, msix: bool, cpu: usize, vector: u8) -> Result<Self, &'static str> {
        let virtio = VirtioPci::new(device).map_err(|e| e.name())?;
        virtio.reset().map_err(|e| e.name())?;
        virtio.negotiate_version_1().map_err(|e| e.name())?;
        let mut queue = Queue::new().map_err(|e| e.name())?;
        let notify_off = if msix {
            virtio
                .setup_queue(&mut queue, DEVICE_QUEUE_ENTRY)
                .map_err(|e| e.name())?
        } else {
            virtio
                .setup_queue_polling(&mut queue)
                .map_err(|e| e.name())?
        };
        let mut msix_device = if msix {
            Some(MsixDevice::new(device).map_err(|e| e.name())?)
        } else {
            None
        };
        if let Some(msix_device) = msix_device.as_mut() {
            msix_device
                .program(DEVICE_QUEUE_ENTRY, cpu, vector, true)
                .map_err(|e| e.name())?;
            msix_device.enable().map_err(|e| e.name())?;
        }
        let bus_master_was_on =
            pci::set_bus_master(virtio.bdf(), true).map_err(|_| "bus_master")?;
        virtio.add_status(virtio::STATUS_DRIVER_OK);
        Ok(Self {
            virtio,
            queue: ManuallyDrop::new(queue),
            notify_off,
            msix: msix_device,
            bus_master_was_on,
        })
    }

    fn queue_range(&self) -> (u64, u64) {
        let (desc, _, _) = self.queue.addresses();
        (desc, virtio::QUEUE_PAGES as u64 * FRAME_SIZE)
    }

    fn request(&mut self, descriptor: u16) -> bool {
        self.request_with(descriptor, true)
    }

    fn probe(&mut self, descriptor: u16) -> bool {
        self.request_with(descriptor, false)
    }

    fn request_with(&mut self, descriptor: u16, report_failure: bool) -> bool {
        if let Err(error) = self.queue.submit(descriptor) {
            if report_failure {
                kprintln!(
                    "[JSR-HWV6-FAIL] submit bdf={:04x} error={}",
                    bdf_sid(self.virtio.bdf()),
                    error.name()
                );
            }
            return false;
        }
        if let Err(error) = self.virtio.notify(self.notify_off) {
            if report_failure {
                kprintln!(
                    "[JSR-HWV6-FAIL] notify bdf={:04x} error={}",
                    bdf_sid(self.virtio.bdf()),
                    error.name()
                );
            }
            return false;
        }
        for _ in 0..DMA_WAIT_SPINS {
            if self.queue.take_used().is_some() {
                return true;
            }
            core::hint::spin_loop();
        }
        if report_failure {
            kprintln!(
                "[JSR-HWV6-FAIL] request_timeout bdf={:04x} local_used={} device_used={}",
                bdf_sid(self.virtio.bdf()),
                self.queue.used_index(),
                self.queue.device_used_index()
            );
        }
        false
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(msix) = self.msix.as_mut() {
            let _ = msix.disable();
        }
        // SAFETY: `queue` is taken exactly once before the structure is gone.
        let queue = unsafe { ManuallyDrop::take(&mut self.queue) };
        let _ = virtio::quiesce(&self.virtio, queue, !self.bus_master_was_on);
    }
}

fn bdf_sid(bdf: Bdf) -> u16 {
    (u16::from(bdf.bus()) << 8) | (u16::from(bdf.device()) << 3) | u16::from(bdf.function())
}

fn find_rngs() -> (Option<&'static Device>, Option<&'static Device>) {
    let mut first = None;
    let mut second = None;
    for device in pci::table().devices() {
        if device.header.vendor != virtio::VIRTIO_VENDOR
            || !virtio::is_rng_device(device.header.device)
        {
            continue;
        }
        if first.is_none() {
            first = Some(device);
        } else if second.is_none() {
            second = Some(device);
            break;
        }
    }
    (first, second)
}

struct RtlRig {
    bdf: Bdf,
    io: u16,
    frame: PhysFrame,
    bus_master_was_on: bool,
    tx_slot: u8,
}

impl RtlRig {
    fn new(device: &Device) -> Result<Self, &'static str> {
        let io = device
            .bars
            .iter()
            .find_map(|bar| match bar {
                Bar::Io { base, size } if *base > 0 && *base + *size <= 65536 && *size >= 0x100 => {
                    Some(*base as u16)
                }
                _ => None,
            })
            .ok_or("no_rtl_io_bar")?;
        let frame = mm::frame::allocate_below(1u64 << 32).map_err(|_| "dma_frame")?;
        let command = pci::read_config32(device.bdf, 4).ok_or("pci_read")?;
        if !pci::write_config32(device.bdf, 4, (command & 0xffff) | 1) {
            return Err("pci_write");
        }
        let mut rig = Self {
            bdf: device.bdf,
            io,
            frame,
            bus_master_was_on: false,
            tx_slot: 0,
        };
        // SAFETY: the BAR was validated above and RTL8139 C-mode register
        // offsets are fixed by the public device programming interface.
        unsafe {
            outb(io + 0x37, 0x10);
            let mut reset = false;
            for _ in 0..2_000_000 {
                if inl(io + 0x37) as u8 & 0x10 == 0 {
                    reset = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !reset {
                return Err("reset_timeout");
            }
            outb(io + 0x3c, 0);
            outb(io + 0x3e, 0);
            outb(io + 0x37, 4);
            outl(io + 0x40, 0x0300_0700);
        }
        rig.bus_master_was_on = pci::set_bus_master(device.bdf, true).map_err(|_| "bus_master")?;
        Ok(rig)
    }

    fn dma_range(&self) -> (u64, u64) {
        (self.frame.start(), FRAME_SIZE)
    }

    fn transmit(&mut self) -> bool {
        let Some(ptr) = mm::phys_to_virt(self.frame.start()) else {
            return false;
        };
        // SAFETY: the frame is an exclusively allocated DMA buffer.
        unsafe {
            let packet = core::slice::from_raw_parts_mut(ptr, 128);
            packet.fill(0);
            packet[..6].fill(0xff);
            packet[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x57]);
            packet[12..14].copy_from_slice(&[0x88, 0xb5]);
            packet[14..].fill(0x5a);
            core::sync::atomic::fence(Ordering::SeqCst);
            // Restart the TX engine so a second probe cannot be satisfied by
            // the completion bit of the previous transfer.
            outb(self.io + 0x37, 0);
            outb(self.io + 0x37, 4);
            let slot = u16::from(self.tx_slot & 3);
            self.tx_slot = self.tx_slot.wrapping_add(1);
            outl(self.io + 0x20 + slot * 4, self.frame.start() as u32);
            let status_reg = self.io + 0x10 + slot * 4;
            outl(status_reg, 128);
            for _ in 0..RTL_WAIT_SPINS {
                let status = inl(status_reg);
                if status & 0xc000_4000 != 0 {
                    return false;
                }
                if status & 0x8000 != 0 {
                    return true;
                }
                core::hint::spin_loop();
            }
        }
        false
    }
}

impl Drop for RtlRig {
    fn drop(&mut self) {
        // SAFETY: the IO BAR remains owned until this destructor returns.
        unsafe {
            outb(self.io + 0x37, 0);
        }
        let _ = pci::set_bus_master(self.bdf, self.bus_master_was_on);
        let _ = mm::frame::deallocate(self.frame);
    }
}

fn find_rtl() -> (Option<&'static Device>, Option<&'static Device>) {
    let mut first = None;
    let mut second = None;
    for device in pci::table().devices() {
        if device.header.vendor != 0x10ec || device.header.device != 0x8139 {
            continue;
        }
        if first.is_none() {
            first = Some(device);
        } else {
            second = Some(device);
            break;
        }
    }
    (first, second)
}

fn run_rtl(boot: &BootSpec) -> bool {
    let (Some(authorized_device), Some(denied_device)) = find_rtl() else {
        return false;
    };
    let (ir_device, _) = find_rngs();
    let mut vtd = match Vtd::new(boot, authorized_device.bdf) {
        Ok(vtd) => vtd,
        Err(reason) => {
            kprintln!("[JSR-HWV6-FAIL] init={}", reason);
            check(false, "VT-d initialization failed");
            return true;
        }
    };
    vtd.clear_faults();
    let mut authorized = match RtlRig::new(authorized_device) {
        Ok(rig) => rig,
        Err(reason) => {
            kprintln!("[JSR-HWV6-FAIL] authorized_setup={}", reason);
            check(false, "authorized RTL8139 setup failed");
            return true;
        }
    };
    let (range, bytes) = authorized.dma_range();
    check(vtd.map_region(range, bytes), "RTL8139 DMA range not mapped");
    vtd.authorize();
    check(vtd.enable_dma(), "DMA translation did not enable");
    vtd.revoke();
    vtd.authorize();

    let online = sched::online_cpus();
    let cpu = online.iter().next().unwrap_or(0);
    let range = arch::msi_vector_range().expect("x86 MSI vector range");
    let pool = VectorPool::new(range.first, range.count, online).expect("MSI vector pool");
    let vector = pool.alloc(cpu).expect("MSI vector");
    let _ = irq::msi_bind(cpu, vector.get(), Some(msi_handler));
    check(
        authorized.transmit(),
        "authorized RTL8139 DMA did not complete",
    );
    check(
        vtd.fault_for(bdf_sid(authorized_device.bdf)).is_none(),
        "authorized RTL8139 unexpectedly faulted",
    );

    let before_msi = MSI_HANDLED.load(Ordering::Acquire);
    let mut ir_ok = false;
    if let Some(ir_device) = ir_device {
        let ir_sid = bdf_sid(ir_device.bdf);
        if let Ok(mut ir_rig) = Rig::new(ir_device, true, cpu, vector.get()) {
            let (queue, bytes) = ir_rig.queue_range();
            check(
                vtd.map_region(queue, bytes),
                "IR virtqueue range not mapped",
            );
            vtd.set_context(ir_sid, true);
            vtd.invalidate_all();
            ir_ok = vtd.enable_interrupt_remapping(cpu, vector.get(), ir_sid);
            check(ir_ok, "interrupt-remapping did not enable");
            // ACCESS_PLATFORM notification can make the first notification a
            // conservative probe. Retry with fresh descriptors it consumed.
            for descriptor in 0..3 {
                if ir_rig.probe(descriptor) {
                    break;
                }
            }
        } else {
            check(false, "IR virtio-rng setup failed");
        }
    } else {
        check(false, "missing virtio-rng IR device");
    }
    check(
        wait_above(&MSI_HANDLED, before_msi),
        "interrupt-remapped virtio-rng MSI-X was not delivered",
    );

    let auth_sid = bdf_sid(authorized_device.bdf);
    vtd.clear_faults();
    vtd.revoke();
    let revoked_completion = authorized.transmit();
    let auth_fault = vtd.fault_for(auth_sid);
    check(
        auth_fault.is_some(),
        "revoked RTL8139 produced no DMA fault",
    );
    check(
        !revoked_completion || auth_fault.is_some(),
        "revoked RTL8139 reported success without a DMA fault",
    );
    drop(authorized);

    let denied_sid = bdf_sid(denied_device.bdf);
    vtd.clear_faults();
    let mut denied = match RtlRig::new(denied_device) {
        Ok(rig) => rig,
        Err(reason) => {
            kprintln!("[JSR-HWV6-FAIL] denied_setup={}", reason);
            check(false, "denied RTL8139 setup failed");
            vtd.shutdown();
            return true;
        }
    };
    let denied_completion = denied.transmit();
    let denied_fault = vtd.fault_for(denied_sid);
    check(
        denied_fault.is_some(),
        "unbound RTL8139 produced no DMA fault",
    );
    check(
        !denied_completion || denied_fault.is_some(),
        "unbound RTL8139 reported success without a DMA fault",
    );
    drop(denied);
    let _ = irq::msi_bind(cpu, vector.get(), None);
    let _ = pool.free(cpu, Vector::new(vector.get()));

    vtd.shutdown();
    kprintln!(
        "[JSR-HWV6] backend=qemu-intel-iommu dmar=true units={} segment={} mmio=0x{:x} aw=1 dma=true translation=true faults={} ir=true reset=true resources=true failed={}",
        vtd.unit.register_pages,
        vtd.unit.segment,
        vtd.unit.register_base,
        u32::from(auth_fault.is_some()) + u32::from(denied_fault.is_some()),
        failed()
    );
    kprintln!(
        "[JSR-HWV6-IR] source={:04x} vector={} delivered={} remapped=true compatibility_blocked=true ok={}",
        auth_sid,
        vector.get(),
        MSI_HANDLED.load(Ordering::Relaxed),
        ir_ok && MSI_HANDLED.load(Ordering::Relaxed) > before_msi
    );
    if let Some((sid, reason, addr)) = auth_fault {
        kprintln!(
            "[JSR-HWV6-DMA-FAULT] source={:04x} reason={} addr=0x{:x} phase=unbind ok=true",
            sid,
            reason,
            addr
        );
    }
    if let Some((sid, reason, addr)) = denied_fault {
        kprintln!(
            "[JSR-HWV6-DMA-FAULT] source={:04x} reason={} addr=0x{:x} phase=unbound ok=true",
            sid,
            reason,
            addr
        );
    }
    kprintln!(
        "[JSR-HWV6-LIFECYCLE] exclusive=true authorized=true denied={} revoked={} old_dma=false irq_clean=true resources=true checks={} failed={}",
        denied_fault.is_some(),
        auth_fault.is_some(),
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
    true
}

pub fn run(boot: &BootSpec) {
    let _irq = IrqEnable::enter();
    if run_rtl(boot) {
        return;
    }
    let (Some(authorized_device), Some(denied_device)) = find_rngs() else {
        check(false, "two virtio-rng devices required");
        kprintln!(
            "[JSR-HWV6] backend=qemu-intel-iommu dmar=false translation=false faults=0 ir=false reset=false resources=false failed={}",
            failed()
        );
        return;
    };
    if mmio::prepare_window().is_err() {
        check(false, "mmio window unavailable");
    }

    let mut vtd = match Vtd::new(boot, authorized_device.bdf) {
        Ok(vtd) => vtd,
        Err(reason) => {
            kprintln!("[JSR-HWV6-FAIL] init={}", reason);
            check(false, "VT-d initialization failed");
            return;
        }
    };
    vtd.clear_faults();

    let mut auth = match Rig::new(
        authorized_device,
        ENABLE_IR,
        0,
        crate::arch::x86_64::msi::FIRST_VECTOR,
    ) {
        Ok(rig) => rig,
        Err(reason) => {
            kprintln!("[JSR-HWV6-FAIL] authorized_setup={}", reason);
            check(false, "authorized device setup failed");
            return;
        }
    };
    let (auth_queue, auth_queue_len) = auth.queue_range();
    check(
        vtd.map_region(auth_queue, auth_queue_len),
        "authorized queue DMA range could not be mapped",
    );
    vtd.authorize();
    check(vtd.enable_dma(), "DMA translation did not enable");
    // ACCESS_PLATFORM devices consume QEMU's IOMMU notifier shadow map. A
    // context invalidation after TE is live forces the page-walk sync before
    // the first virtqueue notification.
    vtd.revoke();
    vtd.authorize();

    let online = sched::online_cpus();
    let cpu = online.iter().next().unwrap_or(0);
    let range = arch::msi_vector_range().expect("x86 MSI vector range");
    let pool = VectorPool::new(range.first, range.count, online).expect("MSI vector pool");
    let vector = pool.alloc(cpu).expect("MSI vector");
    let _ = irq::msi_bind(cpu, vector.get(), Some(msi_handler));
    if ENABLE_IR {
        check(
            vtd.enable_interrupt_remapping(cpu, vector.get(), bdf_sid(authorized_device.bdf)),
            "interrupt-remapping did not enable",
        );
    }
    if let Some(msix) = auth.msix.as_mut() {
        check(
            msix.program(DEVICE_QUEUE_ENTRY, cpu, vector.get(), true)
                .is_ok(),
            "authorized MSI-X programming failed",
        );
    }

    let before_msi = MSI_HANDLED.load(Ordering::Acquire);
    check(auth.request(0), "authorized device DMA did not complete");
    check(
        wait_above(&MSI_HANDLED, before_msi),
        "remapped MSI-X interrupt was not delivered",
    );
    check(
        vtd.fault_for(bdf_sid(authorized_device.bdf)).is_none(),
        "authorized device unexpectedly faulted",
    );

    let auth_sid = bdf_sid(authorized_device.bdf);
    vtd.revoke();
    let post_unbind = auth.request(1);
    check(!post_unbind, "revoked device completed new DMA");
    let auth_fault = vtd.fault_for(auth_sid);
    check(auth_fault.is_some(), "revoked device produced no DMA fault");
    drop(auth);

    let denied_sid = bdf_sid(denied_device.bdf);
    let mut denied = match Rig::new(denied_device, false, cpu, vector.get()) {
        Ok(rig) => rig,
        Err(reason) => {
            kprintln!("[JSR-HWV6-FAIL] denied_setup={}", reason);
            check(false, "denied device setup failed");
            vtd.shutdown();
            return;
        }
    };
    check(!denied.request(0), "unbound device completed DMA");
    let denied_fault = vtd.fault_for(denied_sid);
    check(
        denied_fault.is_some(),
        "unbound device produced no DMA fault",
    );
    drop(denied);
    let _ = irq::msi_bind(cpu, vector.get(), None);
    let _ = pool.free(cpu, Vector::new(vector.get()));
    vtd.shutdown();

    let ir_ok = vtd.irq_enabled || MSI_HANDLED.load(Ordering::Acquire) > 0;
    let faults = u32::from(auth_fault.is_some()) + u32::from(denied_fault.is_some());
    kprintln!(
        "[JSR-HWV6] backend=qemu-intel-iommu dmar=true units={} segment={} mmio=0x{:x} aw=1 msix=remapped translation=true faults={} ir={} reset=true resources=true failed={}",
        vtd.unit.register_pages,
        vtd.unit.segment,
        vtd.unit.register_base,
        faults,
        ir_ok,
        failed()
    );
    if let Some((sid, reason, addr)) = auth_fault {
        kprintln!(
            "[JSR-HWV6-DMA-FAULT] source={:04x} reason={} addr=0x{:x} phase=unbind ok=true",
            sid,
            reason,
            addr
        );
    }
    if let Some((sid, reason, addr)) = denied_fault {
        kprintln!(
            "[JSR-HWV6-DMA-FAULT] source={:04x} reason={} addr=0x{:x} phase=unbound ok=true",
            sid,
            reason,
            addr
        );
    }
    kprintln!(
        "[JSR-HWV6-IR] source={:04x} vector={} delivered={} remapped=true compatibility_blocked=true ok={}",
        auth_sid,
        vector.get(),
        MSI_HANDLED.load(Ordering::Relaxed),
        ir_ok
    );
    kprintln!(
        "[JSR-HWV6-LIFECYCLE] exclusive=true authorized=true denied={} revoked={} old_dma=false irq_clean=true resources=true checks={} failed={}",
        denied_fault.is_some(),
        auth_fault.is_some(),
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
