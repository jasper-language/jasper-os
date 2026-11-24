//! LoongArch SMP start-up and IPI routing for the QEMU `virt` board.
//!
//! QEMU starts secondary CPUs in its flash mailbox loop. The boot CPU writes
//! a physical entry point to mailbox zero, then sends the boot action through
//! the LoongArch IOCSR IPI device.

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, Ordering};

use alloc::vec::Vec;
use kernel_core::fdt::Fdt;
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::smp::{CpuSet, IpiKind, SmpError, Topology};
use spin::Once;

use super::qemu_virt::{
    EFI_CONFIG_TABLE_BUDGET, EFI_CONFIG_TABLE_ENTRY_BYTES, EFI_DEVICE_TREE_GUID,
    EFI_SYSTEM_TABLE_CONFIG_TABLES, EFI_SYSTEM_TABLE_NR_TABLES, EFI_SYSTEM_TABLE_SIGNATURE,
    FDT_LIMIT, IOCSR_IPI_CLEAR, IOCSR_IPI_EN, IOCSR_IPI_SEND, IOCSR_IPI_STATUS, IOCSR_MBUF_SEND,
    MACHINE_COMPATIBLE,
};

// IPI_SEND carries a vector number in bits 0..4; the receiving STATUS register
// records the corresponding bit.
const IPI_RESCHEDULE: u32 = 1 << 1;
const IPI_TLB: u32 = 1 << 2;
const IPI_CALL: u32 = 1 << 4;
const ECFG_IPI: u64 = 1 << 12;
const ESTAT_IPI: u64 = 1 << 12;

static TIMER_HZ: AtomicU32 = AtomicU32::new(100);
static FIRMWARE_FDT: Once<(Fdt<'static>, u32)> = Once::new();
static FIRMWARE_TOPOLOGY: Once<Topology> = Once::new();

const AP_STACK_BYTES: usize = 16 * 1024;
const AP_STACK_FRAMES: usize = AP_STACK_BYTES / FRAME_SIZE as usize;

struct ApStack {
    first: PhysFrame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeStorageError {
    Allocation,
    Mapping,
    AlreadyPreparedTooSmall,
}

impl RuntimeStorageError {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Allocation => "system.cpu.error.loongarch64_smp_storage_allocation",
            Self::Mapping => "system.cpu.error.loongarch64_smp_storage_mapping",
            Self::AlreadyPreparedTooSmall => "system.cpu.error.loongarch64_smp_storage_capacity",
        }
    }
}

static AP_STACKS: Once<Result<Vec<ApStack>, RuntimeStorageError>> = Once::new();

#[no_mangle]
static mut JSR_LOONGARCH64_AP_START_STACK: u64 = 0;

pub(super) fn prepare(cpus: usize) -> Result<(), RuntimeStorageError> {
    let stacks = AP_STACKS.call_once(|| {
        let mut stacks = Vec::new();
        stacks
            .try_reserve_exact(cpus)
            .map_err(|_| RuntimeStorageError::Allocation)?;
        for _ in 0..cpus {
            let first = crate::mm::frame::allocate_contiguous(AP_STACK_FRAMES)
                .map_err(|_| RuntimeStorageError::Allocation)?;
            for page in 0..AP_STACK_FRAMES {
                let physical = first
                    .start()
                    .checked_add(page as u64 * FRAME_SIZE as u64)
                    .ok_or(RuntimeStorageError::Mapping)?;
                let frame = PhysFrame::from_start(physical).ok_or(RuntimeStorageError::Mapping)?;
                let virtual_page =
                    VirtPage::from_start(physical).ok_or(RuntimeStorageError::Mapping)?;
                crate::mm::map::map(
                    virtual_page,
                    frame,
                    MapFlags::WRITE.union(MapFlags::GLOBAL),
                )
                .map_err(|_| RuntimeStorageError::Mapping)?;
            }
            stacks.push(ApStack { first });
        }
        Ok(stacks)
    });
    match stacks {
        Ok(stacks) if stacks.len() >= cpus => Ok(()),
        Ok(_) => Err(RuntimeStorageError::AlreadyPreparedTooSmall),
        Err(error) => Err(*error),
    }
}

fn stack_top(index: usize) -> Option<u64> {
    let stack = AP_STACKS.get()?.as_ref().ok()?.get(index)?;
    Some(stack.first.start() + AP_STACK_BYTES as u64)
}

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
    csrwr  $zero, 0x2
    la.local $t0, JSR_LOONGARCH64_AP_START_STACK
    ld.d   $sp, $t0, 0
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

#[derive(Clone, Copy)]
pub struct FirmwareFdt {
    pub physical: u64,
    pub length: usize,
}

/// Parse the firmware DTB before paging is enabled and retain its CPU topology.
pub fn discover_fdt(efi_boot: bool, system_table: u64) -> Result<FirmwareFdt, &'static str> {
    if !efi_boot {
        return Err("boot-efi-table-not-provided");
    }
    let fdt_physical = firmware_fdt_physical(system_table)?;
    // SAFETY: the physical direct-boot mode makes the trusted firmware pointer
    // readable. Header length is capped before constructing the parser view.
    let first8 = unsafe { core::ptr::read_volatile(fdt_physical as *const [u8; 8]) };
    let Some(total) = kernel_core::fdt::total_size(&first8) else {
        return Err("qemu-fdt-missing"); // JASPER-HARDCODE-REVIEW: issue=35 source=loongarch-qemu-verification-platform reason=qemu-virt-fdt-failure-marker
    };
    if total > FDT_LIMIT {
        return Err("qemu-fdt-too-large"); // JASPER-HARDCODE-REVIEW: issue=35 source=loongarch-qemu-verification-platform reason=qemu-virt-fdt-failure-marker
    }
    // SAFETY: the first eight bytes declared an in-budget blob at the firmware
    // supplied physical address. Strict validation happens before use.
    let bytes = unsafe { core::slice::from_raw_parts(fdt_physical as *const u8, total) };
    let Ok(fdt) = Fdt::parse(bytes) else {
        return Err("qemu-fdt-invalid"); // JASPER-HARDCODE-REVIEW: issue=35 source=loongarch-qemu-verification-platform reason=qemu-virt-fdt-failure-marker
    };
    let root_matches = fdt
        .find_named("")
        .ok()
        .flatten()
        .is_some_and(|root| root.is_compatible(MACHINE_COMPATIBLE));
    if !root_matches {
        return Err("qemu-platform-unverified"); // JASPER-HARDCODE-REVIEW: issue=35 source=loongarch-qemu-verification-platform reason=qemu-virt-platform-failure-marker
    }
    Ok(FirmwareFdt {
        physical: fdt_physical,
        length: total,
    })
}

fn firmware_fdt_physical(system_table: u64) -> Result<u64, &'static str> {
    unsafe fn read_u64(physical: u64) -> Option<u64> {
        if physical == 0 || physical % core::mem::align_of::<u64>() as u64 != 0 {
            return None;
        }
        // SAFETY: callers pass addresses from the trusted direct-boot ABI while
        // physical addressing is active. Every computed pointer is nonzero.
        Some(core::ptr::read_volatile(physical as *const u64))
    }

    // SAFETY: this is the direct-boot ABI pointer captured from `$a2`.
    if unsafe { read_u64(system_table) } != Some(EFI_SYSTEM_TABLE_SIGNATURE) {
        return Err("boot-system-table-invalid");
    }
    let count_address = system_table
        .checked_add(EFI_SYSTEM_TABLE_NR_TABLES)
        .ok_or("boot-system-table-overflow")?;
    let count = unsafe { read_u64(count_address) }.ok_or("boot-system-table-invalid")?;
    if count == 0 {
        return Err("boot-config-table-empty");
    }
    if count > EFI_CONFIG_TABLE_BUDGET {
        return Err("boot-config-table-budget");
    }
    let tables_address = system_table
        .checked_add(EFI_SYSTEM_TABLE_CONFIG_TABLES)
        .ok_or("boot-system-table-overflow")?;
    let tables = unsafe { read_u64(tables_address) }
        .filter(|address| *address != 0)
        .ok_or("boot-config-table-missing")?;

    for index in 0..count {
        let entry = tables
            .checked_add(
                index
                    .checked_mul(EFI_CONFIG_TABLE_ENTRY_BYTES)
                    .ok_or("boot-config-table-overflow")?,
            )
            .ok_or("boot-config-table-overflow")?;
        let mut guid = [0u8; 16];
        for (offset, byte) in guid.iter_mut().enumerate() {
            let byte_address = entry
                .checked_add(offset as u64)
                .ok_or("boot-config-table-overflow")?;
            // SAFETY: the ABI supplies one bounded configuration-table array.
            *byte = unsafe { core::ptr::read_volatile(byte_address as *const u8) };
        }
        if guid == EFI_DEVICE_TREE_GUID {
            let pointer_address = entry.checked_add(16).ok_or("boot-config-table-overflow")?;
            return unsafe { read_u64(pointer_address) }
                .filter(|address| *address != 0)
                .ok_or("boot-fdt-address-invalid");
        }
    }
    Err("boot-fdt-not-provided")
}

/// Save the post-MMU device tree for heap-backed CPU topology publication.
pub fn configure(fdt: Fdt<'static>, boot_hart: u32) {
    FIRMWARE_FDT.call_once(|| (fdt, boot_hart));
}

pub fn init_boot() -> super::CpuDiscovery {
    let Some((fdt, boot_hart)) = FIRMWARE_FDT.get() else {
        return super::CpuDiscovery {
            topology: Topology::boot_only(super::cpu::cpuid() as u32),
            source: "boot_only",
            inventory: kernel_core::acpi::CpuInventory::default(),
            inventory_complete: false,
        };
    };
    let (topology, source, inventory_complete) =
        match fdt.cpu_topology(*boot_hart, |hw| (hw <= u32::MAX as u64).then_some(hw as u32)) {
            Err(error) => (Topology::boot_only(*boot_hart), error.name(), false),
            Ok(cpus) if !cpus.boot_listed => (
                Topology::boot_only(*boot_hart),
                "system.firmware.error.boot_cpu_unlisted",
                false,
            ),
            Ok(cpus) if cpus.topology.count() > 1 => (cpus.topology, "fdt.cpus", true),
            Ok(cpus) => (cpus.topology, "boot_only", true),
        };
    let topology = FIRMWARE_TOPOLOGY.call_once(|| topology).clone();
    super::CpuDiscovery {
        topology,
        source,
        inventory: kernel_core::acpi::CpuInventory::default(),
        inventory_complete,
    }
}

fn topology() -> Option<&'static Topology> {
    FIRMWARE_TOPOLOGY.get()
}

fn cpu_hw_id() -> u32 {
    super::cpu::cpuid() as u32
}

pub fn cpu_index() -> usize {
    let hw = cpu_hw_id();
    let Some(topology) = topology() else {
        // Only the boot hart executes before the heap-backed topology is
        // published. Secondary CPUs start strictly after that transaction.
        return 0;
    };
    let mut registered = None;
    for index in 0..topology.count() {
        if topology.hw_id(index) == Some(hw) {
            registered = Some(index);
            break;
        }
    }
    match kernel_core::cpu_identity::resolve_index(hw, registered, true, None, topology.count()) {
        Ok(index) => index,
        Err(error) => {
            crate::kprintln!(
                "[JSR-SMP] reject=cpu_id_unregistered domain={} hw={} online={}",
                error.name(),
                hw,
                topology.count()
            );
            crate::arch::halt_forever()
        }
    }
}

pub fn send_ipi(cpu: usize, kind: IpiKind) -> Result<(), SmpError> {
    let Some(topology) = topology() else {
        return Err(SmpError::NotOnline);
    };
    if cpu >= topology.count() {
        return Err(SmpError::NoSuchCpu);
    }
    if cpu == cpu_index() {
        return Err(SmpError::SelfTarget);
    }
    let vector = match kind {
        IpiKind::Reschedule => 1,
        IpiKind::TlbShootdown => 2,
        IpiKind::Call => 4,
    };
    let hw = topology.hw_id(cpu).ok_or(SmpError::NoSuchCpu)?;
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
    let Some(topology) = topology() else {
        return Err(SmpError::NotOnline);
    };
    if start.index == 0 || start.index >= topology.count() {
        return Err(SmpError::NoSuchCpu);
    }
    TIMER_HZ.store(start.timer_hz, Ordering::Release);
    let Some(stack_top) = stack_top(start.index) else {
        return Err(SmpError::StartFailed);
    };
    // The BSP starts and waits for each AP serially, so the target consumes
    // this start block before another AP can replace it.
    unsafe { JSR_LOONGARCH64_AP_START_STACK = stack_top };
    core::sync::atomic::fence(Ordering::SeqCst);
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
    if super::cpu::disable_extended_units() != 0 {
        crate::console::write_str("[JSR-SMP] secondary reject=euen-not-disabled\n");
        loop {
            // SAFETY: halting this secondary forever is the failure-closed behavior.
            unsafe { core::arch::asm!("idle 0", options(nomem, nostack)) };
        }
    }
    // SAFETY: the AP has a private static boot stack inside the identity map.
    unsafe {
        super::mmu::enable();
        super::trap::init();
        super::uart::init_mapped();
        enable_ipi();
        if !super::timer::init(TIMER_HZ.load(Ordering::Acquire)) {
            crate::console::write_str("[JSR-SMP] secondary timer unavailable\n");
        }
        super::cpu::irq_unmask();
    }
    let index = cpu_index();
    let _ = hw_id;
    crate::smp::secondary_main(index)
}
