#![no_main]
// CreditLedger：任意操作序列下守恒、切入后记账有界、失败不改动。
use kernel_core::timer_units::CreditLedger;
libfuzzer_sys::fuzz_target!(|b: &[u8]| {
    if b.len() < 10 {
        return;
    }
    let origin = u64::from_le_bytes(b[0..8].try_into().unwrap()) >> 2;
    let period = u64::from(b[8]) + 1;
    let Ok(mut l) = CreditLedger::new(origin, period) else { panic!("period ≥ 1 must be accepted") };
    let (mut now, mut delivered, mut last_switch) = (origin, 0u64, None::<u64>);
    for &x in &b[9..] {
        let dt = u64::from(x >> 1) * u64::from(x & 0x3f).max(1);
        if x & 0x80 != 0 && now > origin {
            // 倒退的时刻必须被拒且不改动
            let before = l;
            assert_eq!(l.settle_idle(now - 1), Err(kernel_core::timer_units::CreditError::TimeReversed));
            assert_eq!(l, before);
        }
        now = now.saturating_add(dt);
        if x & 1 == 1 {
            l.settle_idle(now).unwrap();
            last_switch = Some(now);
        } else {
            let (charge, d) = l.event(now).unwrap();
            assert!(d >= charge);
            if let Some(s) = last_switch.take() {
                assert!(u128::from(charge) * u128::from(period) < u128::from(now - s) + u128::from(period));
            }
            delivered += d;
        }
    }
    assert_eq!(delivered + l.idle_pending(), (now - origin) / period);
});
