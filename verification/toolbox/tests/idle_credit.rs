// CreditLedger（高精度模式下空闲 tick 在切入前结算）：参考模型差分 + 固定序列（Miri）。
use kernel_core::timer_units::{CreditError, CreditLedger};
use proptest::prelude::*;

/// 一步操作：true = 空闲结束、任务切入（settle_idle），false = 高精度事件（event）；时间增量 dt。
fn ops() -> impl Strategy<Value = Vec<(bool, u64)>> {
    prop::collection::vec((any::<bool>(), 0u64..400), 0..48)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]
    /// 守恒：任意序列后，已交付 + 待交付 = 自起点按周期折算的总 tick（不铸造、不丢失）；
    /// 已记账（空闲结算 + 事件记账）同样等于总 tick。
    #[test]
    fn conserves_ticks_across_any_sequence(origin in 0u64..1 << 40, period in 1u64..64, seq in ops()) {
        let mut l = CreditLedger::new(origin, period).unwrap();
        let (mut now, mut delivered, mut accounted) = (origin, 0u64, 0u64);
        for (switch_in, dt) in seq {
            now += dt;
            if switch_in {
                let k = l.settle_idle(now).unwrap();
                accounted += k;
            } else {
                let (charge, d) = l.event(now).unwrap();
                prop_assert!(d >= charge);
                accounted += charge;
                delivered += d;
                prop_assert_eq!(l.idle_pending(), 0);
            }
        }
        let total = (now - origin) / period;
        prop_assert_eq!(delivered + l.idle_pending(), total);
        prop_assert_eq!(accounted, total);
    }
    /// 切入的任务只被记切入之后的 tick：charge × 周期 < (t − s) + 周期，与此前空闲多久无关。
    #[test]
    fn incoming_task_not_charged_idle_stretch(origin in 0u64..1 << 40, period in 1u64..64, idle in 0u64..100_000, run in 0u64..10_000) {
        let mut l = CreditLedger::new(origin, period).unwrap();
        let s = origin + idle;
        let settled = l.settle_idle(s).unwrap();
        let (charge, delivered) = l.event(s + run).unwrap();
        prop_assert!(charge * period < run + period);
        prop_assert_eq!(delivered, charge + settled);
        prop_assert_eq!(settled + charge, (idle + run) / period);
    }
    /// 时间倒退被拒且不改动。
    #[test]
    fn reversed_time_rejected_unchanged(origin in 1u64..1 << 40, period in 1u64..64, back in 1u64..1000) {
        let mut l = CreditLedger::new(origin, period).unwrap();
        let before = l;
        let at = origin.saturating_sub(back);
        prop_assert_eq!(l.settle_idle(at), Err(CreditError::TimeReversed));
        prop_assert_eq!(l.event(at), Err(CreditError::TimeReversed));
        prop_assert_eq!(l, before);
    }
}

#[test]
fn fixed_sequence_under_miri() {
    // 修复前的行为（只有经过时间时钟，切入不结算）：空闲 15 个 tick 后切入，第一次事件把 16 个 tick 记给任务。
    let mut old = kernel_core::timer_units::PeriodicCredit::new(0, 10).unwrap();
    assert_eq!(old.advance(160), Ok(16));
    // 现在：切入时 15 个 tick 记为空闲，事件只记 1 个给任务，交付合计仍为 16。
    let mut l = CreditLedger::new(0, 10).unwrap();
    assert_eq!(l.settle_idle(155), Ok(15));
    assert_eq!(l.event(160), Ok((1, 16)));
    assert_eq!(CreditLedger::new(0, 0), Err(CreditError::ZeroPeriod));
    let mut m = CreditLedger::new(u64::MAX - 1, 1).unwrap();
    assert_eq!(m.settle_idle(u64::MAX), Ok(1));
    assert_eq!(m.event(u64::MAX), Ok((0, 1)));
}
