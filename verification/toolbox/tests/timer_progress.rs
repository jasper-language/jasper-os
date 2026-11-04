//! 定时器前进保证的差分性质测试与 Miri 固定序列。参照实现用 128 位整数直接写出规格。
use kernel_core::timer_progress::{Progress, GRACE, MAX_SETTLE};
use proptest::prelude::*;

fn reference_remaining(p: &Progress, now: u64) -> u64 {
    let (now, last, cost) = (now as i128, p.last_exit as i128, p.cost as i128);
    if now < last {
        0
    } else {
        (last + cost - now).max(0) as u64
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, failure_persistence: None, ..ProptestConfig::default() })]

    /// 判定与参照实现一致；放行 ⇔ 宽限内或剩余为 0；剩余不超过开销。
    #[test]
    fn remaining_matches_reference(last_exit in any::<u64>(), cost in any::<u64>(), now in any::<u64>(), short in 0u32..4) {
        let p = Progress { last_exit, cost, deferred: 0, short };
        prop_assert_eq!(p.remaining(now), reference_remaining(&p, now));
        prop_assert_eq!(p.admit(now), short < GRACE || p.remaining(now) == 0);
        prop_assert!(p.remaining(now) <= cost);
    }

    /// 模拟任意事务开销与事件到达：连续短窗口的完整事务不超过宽限，
    /// 欠账全部结算或按上限丢弃，时钟单调时不会连续拒绝超过 cap。
    #[test]
    fn simulated_events_keep_the_window(
        cap in 1u64..10_000,
        steps in prop::collection::vec((0u64..5_000, 0u64..5_000), 1..200),
    ) {
        let mut p = Progress::default();
        let mut now = 0u64;
        let mut refused_since = None;
        let mut short_run = 0u32;
        for (gap, work) in steps {
            now += gap;
            if p.admit(now) {
                short_run = if p.remaining(now) != 0 { short_run + 1 } else { 0 };
                prop_assert!(short_run <= GRACE);
                let taken = p.take_deferred();
                prop_assert!(taken <= MAX_SETTLE);
                prop_assert_eq!(p.deferred, 0);
                let entry = now;
                now += work;
                p.record(entry, now, cap);
                prop_assert!(p.cost <= cap);
                prop_assert_eq!(p.short, short_run);
                refused_since = None;
            } else {
                p.defer();
                let since = *refused_since.get_or_insert(now);
                prop_assert!(now - since < cap);
                prop_assert_eq!(now + p.remaining(now), p.last_exit + p.cost);
            }
        }
    }

    /// 时钟倒退不会让定时器停摆。
    #[test]
    fn backward_clock_fails_open(entry in any::<u64>(), exit in any::<u64>(), cap in any::<u64>(), back in 1u64..1000) {
        let mut p = Progress::default();
        p.record(entry, exit, cap);
        p.short = GRACE;
        prop_assert!(exit < back || p.admit(exit - back));
        if exit < entry { prop_assert_eq!(p.cost, 0); }
    }
}

/// Miri 固定序列：一次拒绝、补记、再放行，覆盖边界值。
#[test]
fn fixed_sequence_under_miri() {
    let mut p = Progress::default();
    assert!(p.admit(0));
    p.record(10, 30, 100);
    assert_eq!(p.remaining(30), 20);
    assert!(p.admit(30));
    p.short = GRACE;
    assert!(!p.admit(49));
    p.defer();
    p.defer();
    assert!(p.admit(50));
    assert_eq!(p.take_deferred(), 2);
    assert_eq!(p.take_deferred(), 0);
    p.record(0, u64::MAX, 7);
    assert_eq!(p.cost, 7);
    assert_eq!(p.remaining(u64::MAX), 7);
    p.record(u64::MAX, 0, 7);
    assert_eq!(p.cost, 0);
    p.deferred = u32::MAX;
    p.defer();
    assert_eq!(p.take_deferred(), MAX_SETTLE);
}
