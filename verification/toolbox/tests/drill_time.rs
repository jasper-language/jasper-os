// counter_ns（hrtime 计数→纳秒换算）与 drill 判据：参考模型差分 + 固定序列（Miri）。
use kernel_core::drill::{preempt_step_continues, refill_consistent};
use kernel_core::timer_units::counter_ns;
use proptest::prelude::*;

/// 参考：按补充语义模拟——补充置满额，之后运行的每个 tick 扣 1（至 0 为止）。
fn simulated_remaining(quota: u32, refill_to: u32, charged: u64) -> u32 {
    refill_to.saturating_sub(u32::try_from(charged.min(u64::from(quota))).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn counter_ns_matches_wide_reference(e in any::<u64>(), hz in any::<u64>(), d in any::<u64>()) {
        let r = counter_ns(e, hz);
        if hz == 0 {
            prop_assert_eq!(r, None);
        } else {
            let wide = u128::from(e) * 1_000_000_000 / u128::from(hz);
            prop_assert_eq!(r, u64::try_from(wide).ok());
            let e2 = e.saturating_add(d);
            if let (Some(a), Some(b)) = (r, counter_ns(e2, hz)) { prop_assert!(b >= a); }
            if r.is_none() { prop_assert_eq!(counter_ns(e2, hz), None); }
        }
    }
    #[test]
    fn correct_refill_always_accepted(quota in 1u32..32, start in 0u64..1 << 40, lag in 0u64..64, charged_frac in 0u64..64) {
        // 补充正确：观测滞后 lag 个 tick，其间运行 charged ≤ lag 个 tick，剩余 > 0 时任务才可能在运行中观测。
        let charged = charged_frac.min(lag);
        let remaining = simulated_remaining(quota, quota, charged);
        prop_assume!(remaining > 0);
        prop_assert!(refill_consistent(quota, remaining, start, start + lag));
    }
    #[test]
    fn short_refill_rejected_without_lag(quota in 1u32..32, short in 1u32..32, start in 0u64..1 << 40) {
        // 缺陷模型：补充只恢复到 quota-short；在补充的同一 tick 观测必被拒。
        let remaining = quota.saturating_sub(short);
        prop_assert!(!refill_consistent(quota, remaining, start, start));
    }
    #[test]
    fn preempt_loop_reference(steps in 0u32..16, min_steps in 0u32..16, sw in 0u64..32, msw in 0u64..32, now in 0u64..64, dl in 0u64..64) {
        let reference = steps < min_steps || (sw < msw && now < dl);
        prop_assert_eq!(preempt_step_continues(steps, min_steps, sw, msw, now, dl), reference);
    }
}

#[test]
fn fixed_sequence_under_miri() {
    assert_eq!(counter_ns(1, 3), Some(333_333_333));
    assert_eq!(counter_ns(u64::MAX, 999_999_999), None);
    assert_eq!(counter_ns(7, 0), None);
    // 抢占演练：8 步后切换数不足继续，达到 12 或到截止即停。
    let mut sw = 0u64;
    let mut step = 0u32;
    let mut now = 0u64;
    while preempt_step_continues(step, 8, sw, 12, now, 2000) {
        step += 1;
        now += 1;
        if now % 2 == 0 { sw += 1; }
    }
    assert_eq!((step, sw), (24, 12));
    assert!(refill_consistent(3, 3, 10, 10));
    assert!(refill_consistent(3, 2, 10, 11));
    assert!(!refill_consistent(3, 2, 10, 10));
}
