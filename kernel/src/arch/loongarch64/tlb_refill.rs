//! Fast TLB refill for LoongArch CPUs without the hardware page-table walker.
//!
//! `la464` (Loongson 3A5000-class) has a TLB but no PTW. Paging therefore
//! requires a dedicated refill vector at CSR 0x88. The hardware supplies the
//! faulting address through TLBRBADV; `lddir`/`ldpte` apply the four level
//! directory geometry programmed in PWCL/PWCH and fill both parity entries.

use core::arch::global_asm;

use super::cpu::{self, write_csr};

extern "C" {
    static jsr_loongarch64_tlb_refill: u8;
}

global_asm!(
    r#"
    .section .text.jsr_loongarch64_tlb_refill, "ax"
    .balign 4
    .global jsr_loongarch64_tlb_refill
jsr_loongarch64_tlb_refill:
    csrwr  $t0, 0x8b
    csrrd  $t0, 0x1b
    lddir  $t0, $t0, 3
    lddir  $t0, $t0, 2
    lddir  $t0, $t0, 1
    ldpte  $t0, 0
    ldpte  $t0, 1
    tlbfill
    csrrd  $t0, 0x8b
    ertn
    .previous
    "#,
);

/// Install the refill vector before CRMD.PG is enabled.
pub fn init() {
    // SAFETY: the symbol is a naturally aligned instruction sequence and the
    // refill vector remains mapped by the boot page tables.
    unsafe {
        write_csr!(
            "0x88",
            core::ptr::addr_of!(jsr_loongarch64_tlb_refill) as u64
        );
    }
    cpu::sync_icache();
}
