//! LoongArch64 引导适配层：`_start`、BSS、启动栈、早期串口、直接映射窗口与分页。
//!
//! QEMU `virt` 以物理地址 0x0020_0000 从 ELF 入口直接启动。内存大小在 OEM
//! 固件路径成熟前使用 QEMU 显式约定的 128 MiB；真实板卡需提供固件启动协议和
//! 内存/FDT 位置后才能替换这一段。

use core::arch::global_asm;

use kernel_core::frame::{PhysRegion, RegionKind};

use super::{cpu, mmu, uart};
use crate::boot::{self, BootSpec};

const BOOT_STACK_BYTES: usize = 64 * 1024;
const QEMU_RAM_BYTES: u64 = 128 * 1024 * 1024;

#[repr(C, align(16))]
struct BootStack([u8; BOOT_STACK_BYTES]);

#[no_mangle]
static mut JSR_BOOT_STACK: BootStack = BootStack([0; BOOT_STACK_BYTES]);

global_asm!(
    r#"
    .section .text.boot, "ax"
    .global _start
_start:
    csrrd $t0, 0x20
    bnez  $t0, 9f
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
        "[JSR-ARCH] loongarch64 entry=physical console=uart16550 qemu=virt\n",
    );
    crate::console::_print(format_args!(
        "[JSR-SMP-FDT] source={}\n",
        super::smp::discover_fdt()
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

    let (image_start, image_end) = mmu::image_range();
    let mut spec = BootSpec::new();
    // QEMU's direct boot metadata, command line and DTB occupy the first 2 MiB.
    spec.push_region(PhysRegion {
        start: 0,
        end: image_start,
        kind: RegionKind::Reserved,
    });
    spec.push_region(PhysRegion {
        start: 0,
        end: QEMU_RAM_BYTES,
        kind: RegionKind::Usable,
    });
    spec.push_region(PhysRegion {
        start: image_start,
        end: image_end,
        kind: RegionKind::Reserved,
    });
    spec.phys_offset = Some(mmu::PHYS_OFFSET);
    crate::kmain::start(boot::install(spec))
}
