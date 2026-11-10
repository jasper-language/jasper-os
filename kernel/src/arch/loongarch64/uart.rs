//! QEMU `loongarch64/virt` 的 16550-compatible UART。
//!
//! 设备基址为 `0x1fe0_01e0`。分页启用后经 DMW0 的强序非缓存窗口访问，
//! 避免把轮询设备寄存器当作普通可缓存内存。

use core::sync::atomic::{AtomicU64, Ordering};

use super::mmu::UNCACHED_OFFSET;

const UART_PA: u64 = 0x1fe0_01e0;
const THR: u64 = 0;
const IER: u64 = 1;
const FCR: u64 = 2;
const LCR: u64 = 3;
const LSR: u64 = 5;
const LSR_THRE: u8 = 1 << 5;

static BASE: AtomicU64 = AtomicU64::new(0);

/// Select the UART register window.
pub fn set_base(va: u64) {
    BASE.store(va, Ordering::Relaxed);
}

fn reg(offset: u64) -> Option<*mut u8> {
    let base = BASE.load(Ordering::Relaxed);
    (base != 0).then_some((base + offset) as *mut u8)
}

/// Initialise 8N1 and a cleared FIFO. QEMU's firmware leaves the baud divisor valid.
pub fn init() {
    let (Some(ier), Some(fcr), Some(lcr)) = (reg(IER), reg(FCR), reg(LCR)) else {
        return;
    };
    // SAFETY: the compiler selects the contiguous registers in the UART peripheral.
    unsafe {
        ier.write_volatile(0);
        lcr.write_volatile(0x03);
        fcr.write_volatile(0x07);
    }
}

/// Block until the transmit holding register is empty, then write one byte.
pub fn write_byte(byte: u8) {
    let (Some(lsr), Some(thr)) = (reg(LSR), reg(THR)) else {
        return;
    };
    // SAFETY: only the UART line-status and transmit-holding registers are accessed.
    unsafe {
        while lsr.read_volatile() & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        thr.write_volatile(byte);
    }
}

/// Early access before paging is enabled.
pub fn init_physical() {
    BASE.store(UART_PA, Ordering::Relaxed);
    init();
}

/// Access after the direct-map windows have been installed.
pub fn init_mapped() {
    BASE.store(UNCACHED_OFFSET.wrapping_add(UART_PA), Ordering::Relaxed);
    init();
}
