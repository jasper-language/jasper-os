//! Minimal resident EL2 stage-2 identity mapping for verification builds.

use core::sync::atomic::{AtomicU64, Ordering};

const STAGE2_ENTRIES: usize = 512;
const STAGE2_L2_ENTRIES: usize = 512;
const STAGE2_IPA_T0SZ: u64 = 25; // 39-bit IPA, 512 GiB covered by one level-1 table.
const STAGE2_VTCR: u64 = (1 << 31)
    | (2 << 16)
    | (3 << 12)
    | (1 << 10)
    | (1 << 8)
    | (1 << 6)
    | STAGE2_IPA_T0SZ;
const STAGE2_BLOCK_VALID: u64 = 1;
const STAGE2_NORMAL: u64 = STAGE2_BLOCK_VALID
    | (0xf << 2)
    | (1 << 6)
    | (1 << 7)
    | (3 << 8)
    | (1 << 10);
const STAGE2_DEVICE: u64 =
    STAGE2_BLOCK_VALID | (0x1 << 2) | (1 << 6) | (1 << 7) | (3 << 8) | (1 << 10) | (3 << 53);

#[repr(C, align(4096))]
struct Stage2Root([u64; STAGE2_ENTRIES]);

#[repr(C, align(4096))]
struct Stage2L2([u64; STAGE2_L2_ENTRIES]);

static mut STAGE2_ROOT: Stage2Root = Stage2Root([0; STAGE2_ENTRIES]);
static mut STAGE2_L2: Stage2L2 = Stage2L2([0; STAGE2_L2_ENTRIES]);
static STAGE2_RAM_BASE: AtomicU64 = AtomicU64::new(0);

fn root_physical_address() -> Option<u64> {
    // SAFETY: Only the address is observed; ASLR is disabled and the static
    // cannot move. This image is identity-mapped, so its linked address is also
    // the physical address used by the EL2 page-table walker.
    Some(unsafe { (&raw const STAGE2_ROOT.0) as u64 })
}

fn l2_physical_address() -> Option<u64> {
    // SAFETY: As for the root table, this identity-mapped static has a fixed
    // address and is filled once before any secondary CPU runs.
    Some(unsafe { (&raw const STAGE2_L2.0) as u64 })
}

/// Build the verification map before the first CPU enables stage 2.
///
/// While the test guest runs, only the blocks intersecting the kernel image and
/// its guest stack are mapped. All other RAM and device blocks are invalid. The
/// host full map is restored only after the guest exits.
pub fn initialize_identity_table(ram_base: u64) -> bool {
    let Some(root_pa) = root_physical_address() else {
        return false;
    };
    let Some(l2_pa) = l2_physical_address() else {
        return false;
    };
    let ram_block = (ram_base >> 30) as usize;
    if root_pa & 0xfff != 0
        || l2_pa & 0xfff != 0
        || ram_base & ((1 << 30) - 1) != 0
        || ram_block >= STAGE2_ENTRIES
        || ram_base.checked_add(1 << 30).is_none()
    {
        return false;
    }
    STAGE2_RAM_BASE.store(ram_base, Ordering::Release);
    // The test guest sees a fail-closed map; opening the host map is a separate
    // explicit EL2 operation after the guest has exited.
    for index in 0..STAGE2_ENTRIES {
        let entry = if index == ram_block {
            l2_pa | 3
        } else {
            0
        };
        // SAFETY: The static table has exactly STAGE2_ENTRIES aligned entries.
        unsafe {
            ((&raw mut STAGE2_ROOT.0) as *mut u64).add(index).write(entry);
        }
    }
    let (image_start, image_end) = super::mmu::image_range();
    let (stack_start, stack_end) = super::boot::guest_stack_range();
    for index in 0..STAGE2_L2_ENTRIES {
        let block_start = ram_base + ((index as u64) << 21);
        let block_end = block_start + (1 << 21);
        let entry = if intersects(block_start, block_end, image_start, image_end)
            || intersects(block_start, block_end, stack_start, stack_end)
        {
            block_start | STAGE2_NORMAL
        } else {
            0
        };
        // SAFETY: The L2 static has exactly STAGE2_L2_ENTRIES aligned entries.
        unsafe {
            ((&raw mut STAGE2_L2.0) as *mut u64).add(index).write(entry);
        }
    }
    // SAFETY: Publish the complete table before the EL2 page-table walker sees it.
    unsafe {
        core::arch::asm!("dsb ish", "isb", options(nostack));
    }
    true
}

fn intersects(block_start: u64, block_end: u64, start: u64, end: u64) -> bool {
    block_start < end && start < block_end
}

/// Restore the host RAM/device map and invalidate stage-2 TLB entries after the
/// restricted test guest has exited.
pub fn open_verification_block() -> bool {
    let ram_base = STAGE2_RAM_BASE.load(Ordering::Acquire);
    let Some(l2_pa) = l2_physical_address() else {
        return false;
    };
    if ram_base == 0 || l2_pa & 0xfff != 0 {
        return false;
    }
    let ram_block = (ram_base >> 30) as usize;
    for index in 0..STAGE2_ENTRIES {
        let entry = if index == ram_block {
            l2_pa | 3
        } else {
            ((index as u64) << 30) | STAGE2_DEVICE
        };
        // SAFETY: The root table has exactly STAGE2_ENTRIES aligned entries.
        unsafe {
            ((&raw mut STAGE2_ROOT.0) as *mut u64).add(index).write(entry);
        }
    }
    for index in 0..STAGE2_L2_ENTRIES {
        let entry = ram_base + ((index as u64) << 21) | STAGE2_NORMAL;
        // SAFETY: The L2 table has exactly STAGE2_L2_ENTRIES aligned entries.
        unsafe {
            ((&raw mut STAGE2_L2.0) as *mut u64).add(index).write(entry);
        }
    }
    // SAFETY: The L2 table is identity mapped and the fixed index is in range.
    unsafe {
        core::arch::asm!("dsb ish", "isb", options(nostack));
    }
    let status: u64;
    let reply: u64;
    // SAFETY: The resident EL2 handler owns stage-2 TLB invalidation.
    unsafe {
        core::arch::asm!(
            "mov x0, #0",
            "mov x1, #0",
            "hvc #0x4a5a", // JASPER-HARDCODE-REVIEW: issue=22 source=aarch64-stage2-negative reason=private-hypercall-contract
            "mov {status}, x0",
            "mov {reply}, x1",
            status = out(reg) status,
            reply = out(reg) reply,
            out("x0") _,
            out("x1") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            options(nostack),
        );
    }
    status == 1 && reply == 0x4f50
}

/// Enable the shared identity stage on the current PE through its resident EL2.
pub fn enable_current_cpu() -> bool {
    let Some(root_pa) = root_physical_address() else {
        return false;
    };
    let status: u64;
    let reply: u64;
    // SAFETY: The caller first installed the EL2 vector table; x0/x1 carry the
    // request and result, while the handler explicitly clobbers x9-x13.
    unsafe {
        core::arch::asm!(
            "mov x0, #2",
            "mov x1, {vtcr}",
            "mov x2, {root}",
            "hvc #0x4a54",
            "mov {status}, x0",
            "mov {reply}, x1",
            vtcr = in(reg) STAGE2_VTCR,
            root = in(reg) root_pa,
            status = out(reg) status,
            reply = out(reg) reply,
            out("x0") _,
            out("x1") _,
            out("x2") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            options(nostack),
        );
    }
    status == 1 && reply == 0x5354
}
