#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use core::panic::PanicInfo;

const RIGHTS_ALL_BITS: u32 = kernel_core::object::Rights::ALL.bits();

core::arch::global_asm!(
    r#"
    .set noreorder
    .section .text.entry, "ax"
    .global _start
    .type _start, @function
_start:
    dla $s0, BOOT_MARKER
    dla $s1, BOOT_MARKER_END
1:
    beq $s0, $s1, 3f
    nop
    lbu $t0, 0($s0)
    addiu $sp, $sp, -16
    sb $t0, 0($sp)
    li $4, 1
    move $5, $sp
    li $6, 1
    li $2, 5001
    syscall
    addiu $sp, $sp, 16
    b 1b
    addiu $s0, $s0, 1
3:
    li $4, 0
    li $2, 5058
    syscall
4:
    b 4b
    nop
    .previous

    .section .rodata
BOOT_MARKER:
    .ascii "[JSR-ARCH] mips64 userspace=ok kernel-core=compiled\n"
BOOT_MARKER_END:
    .previous
"#
);

#[no_mangle]
pub extern "C" fn mips64_rights_probe() -> u32 {
    RIGHTS_ALL_BITS
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    unsafe { core::arch::asm!("move $4, $zero", "li $2, 5058", "syscall", options(noreturn)) }
}

