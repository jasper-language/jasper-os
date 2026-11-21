//! LoongArch64 引导适配层：`_start`、BSS、启动栈、早期串口、直接映射窗口与分页。
//!
//! QEMU `virt` 以物理地址 0x0020_0000 从 ELF 入口直接启动。平台固定字段由
//! [`super::qemu_virt`] 显式隔离；实际 RAM、保留区和 CPU 拓扑均来自校验后的 DTB。

use core::arch::global_asm;

use kernel_core::fdt::Fdt;
use kernel_core::frame::{PhysRegion, RegionKind};

use super::{cpu, mmu, uart};
use crate::boot::{self, BootSpec};

const BOOT_STACK_BYTES: usize = 64 * 1024;
#[repr(C, align(16))]
struct BootStack([u8; BOOT_STACK_BYTES]);

#[no_mangle]
static mut JSR_BOOT_STACK: BootStack = BootStack([0; BOOT_STACK_BYTES]);
#[no_mangle]
static mut JSR_LOONGARCH_BOOT_EFI_BOOT: u64 = 0;
#[no_mangle]
static mut JSR_LOONGARCH_BOOT_SYSTEM_TABLE: u64 = 0;

global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
_start:
    csrrd $t0, 0x20
    bnez  $t0, 9f
    csrwr $zero, 0x2
    move  $tp, $zero
    csrrd $t0, 0x0
    li.d  $t1, (1 << 2)
    csrxchg $zero, $t1, 0x0
    la.local $t0, __bss_start
    la.local $t1, __bss_end
1:
    bgeu  $t0, $t1, 2f
    st.d  $zero, $t0, 0
    addi.d $t0, $t0, 8
    b     1b
2:
    la.local $t0, JSR_LOONGARCH_BOOT_EFI_BOOT
    st.d  $a0, $t0, 0
    la.local $t0, JSR_LOONGARCH_BOOT_SYSTEM_TABLE
    st.d  $a2, $t0, 0
    la.local $sp, JSR_BOOT_STACK
    li.d  $t0, {stack_bytes}
    add.d $sp, $sp, $t0
    bl    jsr_loongarch64_boot
9:
    idle 0
    b     9b
    .previous
    "#,
    stack_bytes = const BOOT_STACK_BYTES,
);

/// First Rust entry, still using physical addressing.
#[no_mangle]
extern "C" fn jsr_loongarch64_boot() -> ! {
    uart::init_physical();
    crate::console::write_str(
        "[JSR-ARCH] loongarch64 entry=physical console=uart16550 qemu=virt\n", // JASPER-HARDCODE-REVIEW: issue=35 source=loongarch-qemu-verification-platform reason=qemu-virt-verification-marker
    );
    let euen = cpu::disable_extended_units();
    if euen != 0 {
        crate::console::write_str("[JSR-EXTSTATE] failure reason=euen-not-disabled\n");
        super::testdev::stop(35);
    }
    crate::console::write_str(
        "[JSR-EXTSTATE] arch=loongarch64 fpen=0 lsxen=0 lasxen=0 euen=0 source=fail-closed\n",
    );
    // SAFETY: written once by `_start` before Rust runs and before MMU enable.
    let efi_boot = unsafe { core::ptr::read_volatile(&raw const JSR_LOONGARCH_BOOT_EFI_BOOT) };
    // SAFETY: written once by `_start` before Rust runs and before MMU enable.
    let system_table =
        unsafe { core::ptr::read_volatile(&raw const JSR_LOONGARCH_BOOT_SYSTEM_TABLE) };
    let fdt_discovery = super::smp::discover_fdt(efi_boot != 0, system_table);
    crate::console::_print(format_args!(
        "[JSR-SMP-FDT] source={}\n",
        match fdt_discovery {
            Ok(_) => "qemu-fdt-cpu-map", // JASPER-HARDCODE-REVIEW: issue=35 source=loongarch-qemu-verification-platform reason=qemu-virt-fdt-diagnostic
            Err(reason) => reason,
        }
    ));
    crate::console::_print(format_args!(
        "[JSR-CPUCFG] id={} timer_hz={}\n",
        cpu::cpuid(),
        cpu::timer_frequency()
    ));

    // SAFETY: single boot thread, physical addressing, and the boot stack is inside the image.
    unsafe {
        if !mmu::build_boot_tables() {
            crate::console::write_str("[JSR-PGTABLE] failure reason=image-layout\n");
            super::testdev::stop(35);
        }
        mmu::enable();
    }
    uart::init_mapped();
    crate::console::_print(format_args!(
        "[JSR-PGTABLE] enabled root={:#x} levels=4 va_bits=48 phys_offset={:#x}\n",
        mmu::root_phys(),
        mmu::PHYS_OFFSET
    ));

    let firmware_fdt = match fdt_discovery {
        Ok(fdt) => fdt,
        Err(_) => super::testdev::stop(35),
    };
    let Some(fdt_pointer) = mmu::PHYS_OFFSET
        .checked_add(firmware_fdt.physical)
        .filter(|pointer| *pointer != 0)
    else {
        crate::console::write_str("[JSR-DTB] reject=direct-map-overflow\n");
        super::testdev::stop(35);
    };
    // SAFETY: the DTB was validated before MMU enable and the coherent direct
    // map exposes the same firmware bytes after enable.
    let fdt_bytes =
        unsafe { core::slice::from_raw_parts(fdt_pointer as *const u8, firmware_fdt.length) };
    let Ok(fdt) = Fdt::parse(fdt_bytes) else {
        crate::console::write_str("[JSR-DTB] reject=system.boot.error.fdt_bad_structure\n");
        super::testdev::stop(35);
    };
    if let Err(error) = fdt.validate_strict() {
        crate::console::_print(format_args!("[JSR-DTB] reject={}\n", error.name()));
        super::testdev::stop(35);
    }
    super::smp::configure(fdt, cpu::cpuid() as u32);

    let (image_start, image_end) = mmu::image_range();
    let mut spec = BootSpec::new();
    // QEMU's direct-boot ABI data, command line and EFI System Table precede
    // the ELF. Reserve the complete prefix through the discovered image start;
    // the DTB below supplies actual RAM and any additional firmware exclusions.
    spec.push_region(PhysRegion {
        start: 0,
        end: image_start,
        kind: RegionKind::Reserved,
    });
    spec.push_region(PhysRegion {
        start: image_start,
        end: image_end,
        kind: RegionKind::Reserved,
    });
    let mut range_overflow = false;
    fdt.for_each_reserved(|start, size| {
        let Some(end) = start.checked_add(size) else {
            range_overflow = true;
            return;
        };
        spec.push_region(PhysRegion {
            start,
            end,
            kind: RegionKind::Reserved,
        });
    });
    let mut memory_found = false;
    let memory_walked = fdt.for_each_memory(|start, size| {
        if size != 0 {
            let Some(end) = start.checked_add(size) else {
                range_overflow = true;
                return;
            };
            memory_found = true;
            spec.push_region(PhysRegion {
                start,
                end,
                kind: RegionKind::Usable,
            });
        }
    });
    if memory_walked.is_err() {
        crate::console::write_str("[JSR-DTB] reject=memory-map-malformed\n");
        super::testdev::stop(35);
    }
    if range_overflow {
        crate::console::write_str("[JSR-DTB] reject=memory-map-overflow\n");
        super::testdev::stop(35);
    }
    if !memory_found {
        crate::console::write_str("[JSR-DTB] reject=memory-map-empty\n");
        super::testdev::stop(35);
    }
    if !spec.has_complete_regions() {
        crate::console::write_str("[JSR-DTB] reject=memory-map-truncated\n");
        super::testdev::stop(35);
    }
    spec.phys_offset = Some(mmu::PHYS_OFFSET);
    crate::kmain::start(boot::install(spec))
}
