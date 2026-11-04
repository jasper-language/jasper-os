#![no_main]
//! 定时器前进保证：任意事件序列下与参照实现差分，并检查连续短窗口的完整事务不超过宽限。
use kernel_core::timer_progress::{Progress, GRACE, MAX_SETTLE};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let cap = u64::from_le_bytes(data[..8].try_into().unwrap());
    let mut p = Progress::default();
    let mut short_run = 0u32;
    // 每 16 字节一个事件：时刻（可能倒退）与事务结束时刻
    for ch in data[8..].chunks_exact(16) {
        let now = u64::from_le_bytes(ch[..8].try_into().unwrap());
        let exit = u64::from_le_bytes(ch[8..].try_into().unwrap());
        let reference = if now < p.last_exit { 0 } else { (p.last_exit as i128 + p.cost as i128 - now as i128).max(0) as u64 };
        assert_eq!(p.remaining(now), reference);
        assert!(p.remaining(now) <= p.cost);
        if p.admit(now) {
            short_run = if p.remaining(now) != 0 { short_run + 1 } else { 0 };
            assert!(short_run <= GRACE);
            assert!(p.take_deferred() <= MAX_SETTLE);
            assert_eq!(p.deferred, 0);
            p.record(now, exit, cap);
            assert!(p.cost <= cap);
            assert_eq!(p.last_exit, exit);
            assert_eq!(p.short, short_run);
        } else {
            let before = p.deferred;
            p.defer();
            assert_eq!(p.deferred, before.saturating_add(1));
        }
    }
});
