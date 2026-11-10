//! LoongArch SMP start-up and IPI routing for the QEMU `virt` board.
//!
//! QEMU starts secondary CPUs in its flash mailbox loop. The boot CPU writes
//! a physical entry point to mailbox zero, then sends the boot action through
//! the LoongArch IOCSR IPI device.

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::fdt::Fdt;
use kernel_core::smp::{CpuSet, IpiKind, SmpError, Topology, MAX_CPUS};

const FDT_PA: u64 = 0x0010_0000;
const IOCSR_IPI_STATUS: u64 = 0x1000;
const IOCSR_IPI_EN: u64 = 0x1004;
const IOCSR_IPI_SEND: u64 = 0x1040;
const IOCSR_IPI_CLEAR: u64 = 0x100c;
const IOCSR_MBUF_SEND: u64 = 0x1048;

// IPI_SEND carries a vector number in bits 0..4; the receiving STATUS register
// records the corresponding bit.
const IPI_RESCHEDULE: u32 = 1 << 1;
const IPI_TLB: u32 = 1 << 2;
const IPI_CALL: u32 = 1 << 4;
const ECFG_IPI: u64 = 1 << 12;
const ESTAT_IPI: u64 = 1 << 12;

static CPU_COUNT: AtomicU32 = AtomicU32::new(1);
static TIMER_HZ: AtomicU32 = AtomicU32::new(100);
static HW_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

const AP_STACK_BYTES: usize = 16 * 1024;
#[repr(C, align(16))]
struct ApStack([u8; AP_STACK_BYTES]);

#[no_mangle]
static mut JSR_LOONGARCH64_AP_STACKS: [ApStack; MAX_CPUS] =
    [const { ApStack([0; AP_STACK_BYTES]) }; MAX_CPUS];

extern "C" {
    fn jsr_loongarch64_secondary_entry() -> !;
}

global_asm!(
    r#"
    .section .text.jsr_loongarch64_secondary_entry, "ax"
    .balign 4
    .global jsr_loongarch64_secondary_entry
jsr_loongarch64_secondary_entry:
    csrrd  $a0, 0x20
    la.local $t0, JSR_LOONGARCH64_AP_STACKS
    slli.d $t1, $a0, 14
    add.d  $t0, $t0, $t1
    li.d   $t1, 16384
    add.d  $t0, $t0, $t1
    move   $sp, $t0
    bl     jsr_loongarch64_secondary_rust
1:
    idle   0
    b      1b
    .previous
    "#,
);

#[inline(always)]
unsafe fn iocsr_write64(value: u64, address: u64) {
    core::arch::asm!(
        "iocsrwr.d {value}, {address}",
        value = in(reg) value,
        address = in(reg) address,
        options(nostack)
    );
}

#[inline(always)]
unsafe fn iocsr_read32(address: u64) -> u32 {
    let value: u64;
    core::arch::asm!(
        "iocsrrd.w {value}, {address}",
        value = out(reg) value,
        address = in(reg) address,
        options(nostack)
    );
    value as u32
}

#[inline(always)]
unsafe fn iocsr_write32(value: u32, address: u64) {
    core::arch::asm!(
        "iocsrwr.w {value}, {address}",
        value = in(reg) value,
        address = in(reg) address,
        options(nostack)
    );
}

/// Parse the firmware DTB before paging is enabled and retain its CPU topology.
pub fn discover_fdt() -> &'static str {
    // SAFETY: QEMU places the DTB at FDT_BASE in RAM. The first eight bytes
    // declare the total length, which is validated by the shared parser.
    let first8 = unsafe { core::ptr::read_volatile(FDT_PA as *const [u8; 8]) };
    let Some(total) = kernel_core::fdt::total_size(&first8) else {
        return "qemu-fdt-missing";
    };
    if total > 1024 * 1024 {
        return "qemu-fdt-too-large";
    }
    // SAFETY: QEMU reserves one MiB for direct-boot metadata and the DTB.
    let bytes = unsafe { core::slice::from_raw_parts(FDT_PA as *const u8, total) };
    let Ok(fdt) = Fdt::parse(bytes) else {
        return "qemu-fdt-invalid";
    };
    let Ok(cpus) = fdt.cpu_topology(0, |hw| (hw <= u32::MAX as u64).then_some(hw as u32)) else {
        return "qemu-fdt-cpu-invalid";
    };
    if !cpus.boot_listed {
        return "qemu-fdt-boot-cpu-missing";
    }
    let topology = cpus.topology;
    CPU_COUNT.store(topology.count().min(MAX_CPUS) as u32, Ordering::Release);
    for index in 0..topology.count().min(MAX_CPUS) {
        HW_IDS[index].store(topology.hw_id(index).unwrap_or(0), Ordering::Release);
    }
    "qemu-fdt-cpu-map"
}

pub fn init_boot() -> super::CpuDiscovery {
    super::CpuDiscovery { topology: topology(), source: "qemu-fdt-cpu-map" }
}

fn topology() -> Topology {
    let mut topology = Topology::boot_only(HW_IDS[0].load(Ordering::Acquire));
    for index in 1..CPU_COUNT.load(Ordering::Acquire) as usize {
        topology.push(HW_IDS[index].load(Ordering::Acquire));
    }
    topology
}

fn cpu_hw_id() -> u32 {
    super::cpu::cpuid() as u32
}

pub fn cpu_index() -> usize {
    let hw = cpu_hw_id();
    for index in 0..CPU_COUNT.load(Ordering::Acquire).min(MAX_CPUS as u32) as usize {
        if HW_IDS[index].load(Ordering::Acquire) == hw {
            return index;
        }
    }
    0
}

pub fn send_ipi(cpu: usize, kind: IpiKind) -> Result<(), SmpError> {
    if cpu == 0 || cpu >= CPU_COUNT.load(Ordering::Acquire) as usize {
        return Err(SmpError::NoSuchCpu);
    }
    let vector = match kind {
        IpiKind::Reschedule => 1,
        IpiKind::TlbShootdown => 2,
        IpiKind::Call => 4,
    };
    let hw = HW_IDS[cpu].load(Ordering::Acquire);
    let value = (1u32 << 31) | (hw << 16) | vector;
    // SAFETY: IPI_SEND is a 32-bit IOCSR doorbell register.
    unsafe { iocsr_write32(value, IOCSR_IPI_SEND) };
    Ok(())
}

fn mail_send(value: u64, hw: u32) {
    let common = (1u64 << 31) | ((hw as u64) << 16);
    // SAFETY: mailbox zero is the protocol consumed by QEMU's secondary boot
    // loop. High and low halves are written as two blocking IOCSR messages.
    unsafe {
        iocsr_write64(
            common | (1 << 2) | (value & 0xffff_ffff_0000_0000),
            IOCSR_MBUF_SEND,
        );
        iocsr_write64(common | (value << 32), IOCSR_MBUF_SEND);
    }
}

pub unsafe fn start_cpu(
    start: &crate::arch::CpuStart<super::space::SpaceRoot>,
) -> Result<(), SmpError> {
    if start.index == 0 || start.index >= CPU_COUNT.load(Ordering::Acquire) as usize {
        return Err(SmpError::NoSuchCpu);
    }
    TIMER_HZ.store(start.timer_hz, Ordering::Release);
    let entry = jsr_loongarch64_secondary_entry as *const () as u64;
    mail_send(entry, start.hw_id);
    let value = (1u32 << 31) | (start.hw_id << 16) | 1;
    iocsr_write32(value, IOCSR_IPI_SEND);
    Ok(())
}

pub fn tlb_flush_local(va: u64, pages: u64) {
    for page in 0..pages {
        super::cpu::tlb_flush_page(va.wrapping_add(page * 4096));
    }
}

pub fn online_set() -> CpuSet {
    let mut set = CpuSet::EMPTY;
    set.insert(0);
    set
}

pub fn handle_ipi() {
    // SAFETY: these are this CPU's IOCSR IPI status/clear registers.
    let actions = unsafe { iocsr_read32(IOCSR_IPI_STATUS) };
    unsafe { iocsr_write32(actions, IOCSR_IPI_CLEAR) };
    if actions & IPI_TLB != 0 {
        crate::smp::on_ipi(IpiKind::TlbShootdown);
    }
    if actions & IPI_CALL != 0 {
        crate::smp::on_ipi(IpiKind::Call);
    }
    if actions & IPI_RESCHEDULE != 0 {
        crate::smp::on_ipi(IpiKind::Reschedule);
    }
}

pub fn ipi_pending() -> bool {
    super::cpu::read_csr!("0x5") & ESTAT_IPI != 0
}

pub fn enable_ipi() {
    unsafe { super::cpu::set_csr_bits(super::cpu::CSR_ECFG, ECFG_IPI) };
    // SAFETY: unmask every source bit delivered by the LoongArch IPI device.
    unsafe {
        iocsr_write32(u32::MAX, IOCSR_IPI_EN);
        iocsr_write32(u32::MAX, IOCSR_IPI_CLEAR);
    }
}

#[no_mangle]
extern "C" fn jsr_loongarch64_secondary_rust(hw_id: u64) -> ! {
    // SAFETY: the AP has a private static boot stack inside the identity map.
    unsafe {
        super::mmu::enable();
        super::trap::init();
        super::uart::init_mapped();
        enable_ipi();
        super::timer::init(TIMER_HZ.load(Ordering::Acquire));
        super::cpu::irq_unmask();
    }
    let index = cpu_index();
    let _ = hw_id;
    crate::smp::secondary_main(index)
}
