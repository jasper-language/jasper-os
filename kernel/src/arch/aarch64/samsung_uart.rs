//! Minimal Samsung/Exynos UART transmitter used by the Pixel 6a smoke probe.
//!
//! The stock GS101 boot config selects `earlycon=exynos4210,mmio32,0x10a00000`.
//! ABL has already configured the controller, so this driver only emits bytes and
//! deliberately does not reprogram clocks or baud divisors.

use core::sync::atomic::{AtomicU64, Ordering};

const UFSTAT: u64 = 0x18;
const UTXH: u64 = 0x20;
const TX_FIFO_FULL: u32 = 1 << 24;

static BASE: AtomicU64 = AtomicU64::new(0);

pub fn set_base(va: u64) {
    BASE.store(va, Ordering::Relaxed);
}

pub fn init() {}

pub fn write_byte(byte: u8) {
    let base = BASE.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    // SAFETY: the base comes from the stock Pixel boot command line, and the
    // surrounding early MMU maps it as Device memory.
    unsafe {
        let status = (base + UFSTAT) as *const u32;
        while status.read_volatile() & TX_FIFO_FULL != 0 {
            core::hint::spin_loop();
        }
        ((base + UTXH) as *mut u32).write_volatile(u32::from(byte));
    }
}
