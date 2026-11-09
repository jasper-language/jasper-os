//! GICv2/GICv3 interrupt-controller backend.
//!
//! GICv2 uses distributor + banked CPU interface MMIO. GICv3 uses the
//! distributor for SPIs, a per-CPU redistributor (GICR) for PPIs/SGIs, and the
//! ICC system-register interface for acknowledge/EOI/group enable.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use kernel_core::smp::{IpiKind, MAX_CPUS};

use super::cpu::{read_sysreg, write_sysreg};

const VERSION_UNKNOWN: u8 = 0;
const VERSION_2: u8 = 2;
const VERSION_3: u8 = 3;

const GICD_CTLR: u64 = 0x000;
const GICD_TYPER: u64 = 0x004;
const GICD_IGROUPR: u64 = 0x080;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_ISPENDR: u64 = 0x200;
const GICD_ICPENDR: u64 = 0x280;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ITARGETSR: u64 = 0x800;
const GICD_ICFGR: u64 = 0xc00;
const GICD_IROUTER: u64 = 0x6000;
const GICD_SGIR: u64 = 0xf00;

const GICC_CTLR: u64 = 0x000;
const GICC_PMR: u64 = 0x004;
const GICC_BPR: u64 = 0x008;
const GICC_IAR: u64 = 0x00c;
const GICC_EOIR: u64 = 0x010;

const GICR_WAKER: u64 = 0x014;
const GICR_TYPER: u64 = 0x008;
const GICR_SGI_BASE: u64 = 0x1_0000;
const GICR_IGROUPR0: u64 = 0x080;
const GICR_ISENABLER0: u64 = 0x100;
const GICR_ICENABLER0: u64 = 0x180;
const GICR_IPRIORITYR0: u64 = 0x400;

pub const SPI_BASE: u32 = 32;
const SGI_RESCHEDULE: u32 = 0;
const SGI_SHOOTDOWN: u32 = 1;
const SGI_CALL: u32 = 2;
const SGI_MASK: u32 = (1 << SGI_RESCHEDULE) | (1 << SGI_SHOOTDOWN) | (1 << SGI_CALL);
const IAR_ID_MASK: u32 = 0x3ff;
pub const SPURIOUS: u32 = 1023;
const PRIORITY: u8 = 0xa0;

static VERSION: AtomicU8 = AtomicU8::new(VERSION_UNKNOWN);
static DIST: AtomicU64 = AtomicU64::new(0);
static CPU: AtomicU64 = AtomicU64::new(0);
static REDIST: AtomicU64 = AtomicU64::new(0);
static REDIST_SIZE: AtomicU64 = AtomicU64::new(0);
static REDIST_STRIDE: AtomicU64 = AtomicU64::new(0x20_000);
static INTERFACE: [AtomicU8; MAX_CPUS] = [const { AtomicU8::new(0) }; MAX_CPUS];
static AFFINITY: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static REGISTERED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

pub fn set_bases(dist: u64, cpu: u64, redist: u64, redist_size: u64, stride: u64) {
    DIST.store(dist, Ordering::Relaxed);
    CPU.store(cpu, Ordering::Relaxed);
    REDIST.store(redist, Ordering::Relaxed);
    REDIST_SIZE.store(redist_size, Ordering::Relaxed);
    REDIST_STRIDE.store(if stride == 0 { 0x20_000 } else { stride }, Ordering::Relaxed);
    VERSION.store(if redist != 0 { VERSION_3 } else { VERSION_2 }, Ordering::Relaxed);
}
unsafe fn w32(base: u64, off: u64, value: u32) {
    ((base + off) as *mut u32).write_volatile(value)
}

unsafe fn r32(base: u64, off: u64) -> u32 {
    ((base + off) as *const u32).read_volatile()
}

unsafe fn w64(base: u64, off: u64, value: u64) {
    ((base + off) as *mut u64).write_volatile(value)
}

unsafe fn r64(base: u64, off: u64) -> u64 {
    ((base + off) as *const u64).read_volatile()
}

fn is_v3() -> bool {
    VERSION.load(Ordering::Relaxed) == VERSION_3
}

fn affinity() -> u32 {
    super::cpu::boot_affinity()
}

/// GICR_TYPER.Affinity_Value uses the MPIDR affinity fields directly.
fn gicr_affinity() -> u32 {
    affinity() & 0x00ff_ffff
}

fn find_current_redist() -> Option<u64> {
    let base = REDIST.load(Ordering::Relaxed);
    let size = REDIST_SIZE.load(Ordering::Relaxed);
    let stride = REDIST_STRIDE.load(Ordering::Relaxed);
    if base == 0 || stride < 0x2_0000 {
        return None;
    }
    let frames = (size / stride).min(MAX_CPUS as u64);
    for index in 0..frames {
        let frame = base + index * stride;
        // SAFETY: frame is within the GICR range from the validated DTB.
        let typer = unsafe { r64(frame, GICR_TYPER) };
        if (typer >> 32) as u32 == gicr_affinity() {
            return Some(frame);
        }
        if typer & (1 << 4) != 0 {
            break;
        }
    }
    None
}

unsafe fn init_v2_banked(dist: u64, cpu: u64, ppi: u32) {
    w32(dist, GICD_ICENABLER, u32::MAX);
    for id in [ppi, SGI_RESCHEDULE, SGI_SHOOTDOWN, SGI_CALL] {
        ((dist + GICD_IPRIORITYR + u64::from(id)) as *mut u8).write_volatile(PRIORITY);
    }
    w32(dist, GICD_ISENABLER, (1 << ppi) | SGI_MASK);
    w32(cpu, GICC_PMR, 0xff);
    w32(cpu, GICC_BPR, 0);
    w32(cpu, GICC_CTLR, 1);
}

unsafe fn init_v3_redist(frame: u64, ppi: u32) -> bool {
    let waker = (frame + GICR_WAKER) as *mut u32;
    let mut value = waker.read_volatile();
    value &= !(1 << 1);
    waker.write_volatile(value);
    core::arch::asm!("dsb ish", options(nostack, preserves_flags));
    let mut spins = 0u32;
    while waker.read_volatile() & (1 << 2) != 0 {
        spins += 1;
        if spins > 1_000_000 {
            return false;
        }
        core::hint::spin_loop();
    }

    let sgi = frame + GICR_SGI_BASE;
    w32(sgi, GICR_ICENABLER0, u32::MAX);
    w32(sgi, GICR_IGROUPR0, u32::MAX);
    for id in [ppi, SGI_RESCHEDULE, SGI_SHOOTDOWN, SGI_CALL] {
        ((sgi + GICR_IPRIORITYR0 + u64::from(id)) as *mut u8).write_volatile(PRIORITY);
    }
    w32(sgi, GICR_ISENABLER0, (1 << ppi) | SGI_MASK);

    let mut sre = read_sysreg!("icc_sre_el1");
    sre |= 1;
    write_sysreg!("icc_sre_el1", sre);
    super::cpu::isb();
    write_sysreg!("icc_pmr_el1", 0xffu64);
    write_sysreg!("icc_bpr1_el1", 0u64);
    write_sysreg!("icc_ctlr_el1", 0u64);
    write_sysreg!("icc_igrpen1_el1", 1u64);
    super::cpu::isb();
    core::arch::asm!("dsb ish", options(nostack, preserves_flags));
    true
}

fn init_v3_cpu(ppi: u32) -> bool {
    if ppi >= 32 {
        return false;
    }
    let Some(frame) = find_current_redist() else {
        return false;
    };
    // SAFETY: redistributor frame and its SGI page are within the DTB range.
    unsafe { init_v3_redist(frame, ppi) }
}

pub fn init(ppi: u32) -> bool {
    let dist = DIST.load(Ordering::Relaxed);
    if dist == 0 || ppi >= 32 {
        return false;
    }
    if is_v3() {
        // SAFETY: GICD/GICR ranges come from the validated device tree.
        unsafe {
            w32(dist, GICD_CTLR, 0);
            write_sysreg!("icc_sre_el1", 1u64);
            super::cpu::isb();
        }
        let ready = init_v3_cpu(ppi);
        if ready {
            AFFINITY[0].store(affinity(), Ordering::Release);
            REGISTERED[0].store(true, Ordering::Release);
        }
        unsafe {
            w32(dist, GICD_CTLR, (1 << 1) | (1 << 4));
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }
        ready
    } else {
        let cpu = CPU.load(Ordering::Relaxed);
        if cpu == 0 {
            return false;
        }
        // SAFETY: GICv2 GICD/GICC addresses come from the validated DTB.
        unsafe {
            w32(dist, GICD_CTLR, 0);
            init_v2_banked(dist, cpu, ppi);
            w32(dist, GICD_CTLR, 1);
            INTERFACE[0].store(r32(dist, GICD_ITARGETSR) as u8, Ordering::Release);
            REGISTERED[0].store(true, Ordering::Release);
        }
        true
    }
}

pub fn init_cpu(ppi: u32) -> bool {
    if is_v3() {
        init_v3_cpu(ppi)
    } else {
        let (dist, cpu) = (DIST.load(Ordering::Relaxed), CPU.load(Ordering::Relaxed));
        if dist == 0 || cpu == 0 || ppi >= 32 {
            return false;
        }
        // SAFETY: GICv2 banked registers only affect the executing processor.
        unsafe { init_v2_banked(dist, cpu, ppi) };
        true
    }
}

pub fn record_interface(index: usize) -> u8 {
    if index >= MAX_CPUS {
        return 0;
    }
    if is_v3() {
        if find_current_redist().is_none() {
            return 0;
        }
        AFFINITY[index].store(affinity(), Ordering::Release);
        REGISTERED[index].store(true, Ordering::Release);
        return 1;
    }
    let dist = DIST.load(Ordering::Relaxed);
    if dist == 0 {
        return 0;
    }
    // SAFETY: GICv2 target register group0 is banked and readable.
    let bit = unsafe { r32(dist, GICD_ITARGETSR) } as u8;
    INTERFACE[index].store(bit, Ordering::Release);
    REGISTERED[index].store(bit != 0, Ordering::Release);
    bit
}

pub fn send_sgi(index: usize, kind: IpiKind) -> bool {
    if index >= MAX_CPUS {
        return false;
    }
    let id = match kind {
        IpiKind::Reschedule => SGI_RESCHEDULE,
        IpiKind::TlbShootdown => SGI_SHOOTDOWN,
        IpiKind::Call => SGI_CALL,
    };
    if is_v3() {
        let hw = AFFINITY[index].load(Ordering::Acquire);
        let aff0 = hw & 0xff;
        if aff0 >= 16 {
            return false;
        }
        let value = u64::from(id) << 24
            | u64::from((hw >> 8) & 0xff) << 16
            | u64::from((hw >> 16) & 0xff) << 32
            | 1u64 << aff0;
        // SAFETY: ICC_SGI1R writes only generate the selected SGI.
        unsafe {
            core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
            write_sysreg!("icc_sgi1r_el1", value);
            super::cpu::isb();
        }
        true
    } else {
        let d = DIST.load(Ordering::Relaxed);
        let bit = INTERFACE[index].load(Ordering::Acquire);
        if d == 0 || bit == 0 {
            return false;
        }
        // SAFETY: GICD_SGIR generates one SGI for the selected interface bit.
        unsafe {
            core::arch::asm!("dsb ishst", options(nostack, preserves_flags));
            w32(d, GICD_SGIR, (u32::from(bit) << 16) | id);
        }
        true
    }
}

pub fn ipi_kind(id: u32) -> Option<IpiKind> {
    match id {
        SGI_RESCHEDULE => Some(IpiKind::Reschedule),
        SGI_SHOOTDOWN => Some(IpiKind::TlbShootdown),
        SGI_CALL => Some(IpiKind::Call),
        _ => None,
    }
}

pub fn acknowledge() -> u32 {
    if is_v3() {
        read_sysreg!("icc_iar1_el1") as u32
    } else {
        // SAFETY: called only from IRQ entry.
        unsafe { r32(CPU.load(Ordering::Relaxed), GICC_IAR) }
    }
}

pub fn interrupt_id(iar: u32) -> u32 {
    iar & IAR_ID_MASK
}

pub fn end(iar: u32) {
    if is_v3() {
        // SAFETY: IAR came from ICC_IAR1_EL1 in acknowledge().
        unsafe { write_sysreg!("icc_eoir1_el1", u64::from(iar)) };
        super::cpu::isb();
    } else {
        // SAFETY: IAR came from acknowledge().
        unsafe { w32(CPU.load(Ordering::Relaxed), GICC_EOIR, iar) };
    }
}

pub fn spi_supported(id: u32) -> bool {
    let d = DIST.load(Ordering::Relaxed);
    if d == 0 || !(SPI_BASE..1020).contains(&id) {
        return false;
    }
    // SAFETY: distributor type register is read-only.
    let lines = ((unsafe { r32(d, GICD_TYPER) } & 0x1f) + 1) * 32;
    id < lines
}

fn bit_of(id: u32) -> (u64, u32) {
    (u64::from(id / 32) * 4, 1 << (id % 32))
}

pub fn spi_configure(id: u32) -> bool {
    if !spi_supported(id) {
        return false;
    }
    let dist = DIST.load(Ordering::Relaxed);
    let (word, bit) = bit_of(id);
    let target = INTERFACE[0].load(Ordering::Acquire);
    // SAFETY: id was range-checked against GICD_TYPER.
    unsafe {
        w32(dist, GICD_ICENABLER + word, bit);
        w32(dist, GICD_ICPENDR + word, bit);
        if is_v3() {
            let group = r32(dist, GICD_IGROUPR + word);
            w32(dist, GICD_IGROUPR + word, group | bit);
        }
        let config = dist + GICD_ICFGR + u64::from(id / 16) * 4;
        let shift = (id % 16) * 2;
        let mut value = r32(config, 0);
        value &= !(1 << shift);
        value |= 1 << (shift + 1);
        w32(config, 0, value);
        ((dist + GICD_IPRIORITYR + u64::from(id)) as *mut u8).write_volatile(PRIORITY);
        if is_v3() {
            w64(dist, GICD_IROUTER + u64::from(id) * 8, u64::from(AFFINITY[0].load(Ordering::Acquire)));
        } else {
            if target == 0 {
                return false;
            }
            ((dist + GICD_ITARGETSR + u64::from(id)) as *mut u8).write_volatile(target);
        }
    }
    true
}

pub fn spi_set_target(id: u32, index: usize) -> bool {
    if !spi_supported(id) || index >= MAX_CPUS {
        return false;
    }
    let dist = DIST.load(Ordering::Relaxed);
    if is_v3() {
        let hw = AFFINITY[index].load(Ordering::Acquire);
        if !REGISTERED[index].load(Ordering::Acquire) {
            return false;
        }
        // SAFETY: route register affects exactly one SPI.
        unsafe { w64(dist, GICD_IROUTER + u64::from(id) * 8, u64::from(hw)) };
    } else {
        let bit = INTERFACE[index].load(Ordering::Acquire);
        if !REGISTERED[index].load(Ordering::Acquire) {
            return false;
        }
        // SAFETY: byte access changes only this interrupt's target.
        unsafe { ((dist + GICD_ITARGETSR + u64::from(id)) as *mut u8).write_volatile(bit) };
    }
    true
}

pub fn spi_set_enabled(id: u32, on: bool) {
    if !spi_supported(id) {
        return;
    }
    let (word, bit) = bit_of(id);
    let register = (if on { GICD_ISENABLER } else { GICD_ICENABLER }) + word;
    // SAFETY: one enabled bit is changed.
    unsafe { w32(DIST.load(Ordering::Relaxed), register, bit) };
}
pub fn spi_set_pending(id: u32, pending: bool) {
    if !spi_supported(id) {
        return;
    }
    let (word, bit) = bit_of(id);
    let register = (if pending { GICD_ISPENDR } else { GICD_ICPENDR }) + word;
    // SAFETY: one pending bit is changed.
    unsafe { w32(DIST.load(Ordering::Relaxed), register, bit) };
}
