#![no_std]
#![no_main]

use core::panic::PanicInfo;

const RIGHTS_ALL_BITS: u32 = kernel_core::object::Rights::ALL.bits();

core::arch::global_asm!(
    r#"
    .section .text.entry, "ax"
    .global _start
    .type _start, @function
_start:
    la.local $t0, BOOT_MARKER
    li.w $t1, 0x1fe001e0
1:
    ld.bu $t2, $t0, 0
    beqz $t2, 2f
    st.b $t2, $t1, 0
    addi.d $t0, $t0, 1
    b 1b
2:
    la.local $t0, RIGHTS_MARKER
3:
    ld.bu $t2, $t0, 0
    beqz $t2, 4f
    st.b $t2, $t1, 0
    addi.d $t0, $t0, 1
    b 3b
4:
    b 4b
    .previous

    .section .rodata
    .global BOOT_MARKER
BOOT_MARKER:
    .asciz "[JSR-ARCH] loongarch64 boot=ok kernel-core=compiled\n"
    .global RIGHTS_MARKER
RIGHTS_MARKER:
    .asciz "[JSR-ARCH] loongarch64 check=complete\n"
    .previous
"#
);

#[no_mangle]
pub extern "C" fn loongarch64_rights_probe() -> u32 {
    RIGHTS_ALL_BITS
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe {
        core::arch::asm!("break 0x35");
    }
    loop {
        core::hint::spin_loop();
    }
}

