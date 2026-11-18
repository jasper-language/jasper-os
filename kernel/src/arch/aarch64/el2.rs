//! Minimal resident EL2 stage-2 identity mapping for verification builds.

const STAGE2_ENTRIES: usize = 512;
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

static mut STAGE2_ROOT: Stage2Root = Stage2Root([0; STAGE2_ENTRIES]);

fn root_physical_address() -> Option<u64> {
    // SAFETY: Only the address is observed; ASLR is disabled and the static
    // cannot move. This image is identity-mapped, so its linked address is also
    // the physical address used by the EL2 page-table walker.
    Some(unsafe { (&raw const STAGE2_ROOT.0) as u64 })
}

/// Build a bounded identity map before the first CPU enables stage 2.
pub fn initialize_identity_table() -> bool {
    let Some(root_pa) = root_physical_address() else {
        return false;
    };
    if root_pa & 0xfff != 0 {
        return false;
    }
    // Only the 1 GiB block containing RAM is mapped as Normal memory. Other
    // identity blocks remain Device so the verification build can reach the
    // platform's high MMIO apertures without claiming a final memory policy.
    for index in 0..STAGE2_ENTRIES {
        let attributes = if index == 1 {
            STAGE2_NORMAL
        } else {
            STAGE2_DEVICE
        };
        // SAFETY: The static table has exactly STAGE2_ENTRIES aligned entries.
        unsafe {
            ((&raw mut STAGE2_ROOT.0) as *mut u64)
                .add(index)
                .write(((index as u64) << 30) | attributes);
        }
    }
    // SAFETY: Publish the complete table before the EL2 page-table walker sees it.
    unsafe {
        core::arch::asm!("dsb ish", "isb", options(nostack));
    }
    true
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
