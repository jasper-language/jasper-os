//! LoongArch64 本地周期定时器与稳定计数器。

use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu::{self, TCFG_EN, TCFG_PERIOD, TCFG_VAL_SHIFT};

static INTERVAL: AtomicU64 = AtomicU64::new(0);

/// Program the local timer and unmask its ECFG input.
pub fn init(hz: u32) {
    let frequency = cpu::timer_frequency().max(1);
    let interval = (frequency / u64::from(hz.max(1))).max(1);
    INTERVAL.store(interval, Ordering::Relaxed);
    // SAFETY: writes only this processor's local timer state.
    unsafe {
        cpu::write_csr!("0x44", 1u64);
        cpu::write_csr!("0x41", (interval << TCFG_VAL_SHIFT) | TCFG_PERIOD | TCFG_EN);
        cpu::set_csr_bits(cpu::CSR_ECFG, cpu::ECFG_TIMER);
    }
}

/// Acknowledge and re-arm the periodic timer.
pub fn rearm() {
    let interval = INTERVAL.load(Ordering::Relaxed);
    if interval == 0 {
        return;
    }
    // SAFETY: writes only this processor's timer clear/config registers.
    unsafe {
        cpu::write_csr!("0x44", 1u64);
        cpu::write_csr!("0x41", (interval << TCFG_VAL_SHIFT) | TCFG_PERIOD | TCFG_EN);
    }
}

/// Delay the next local tick by `ticks` periods.
pub fn stretch(ticks: u32) -> bool {
    let interval = INTERVAL.load(Ordering::Relaxed);
    if interval == 0 {
        return false;
    }
    let count = interval.saturating_mul(u64::from(ticks.max(1)));
    // SAFETY: writes only this processor's local timer state.
    unsafe {
        cpu::write_csr!("0x44", 1u64);
        cpu::write_csr!(
            "0x41",
            ((count & ((1u64 << 46) - 1)) << TCFG_VAL_SHIFT) | TCFG_PERIOD | TCFG_EN
        );
    }
    true
}

/// Stable timer counter.
#[inline(always)]
pub fn counter() -> u64 {
    cpu::read_time()
}
