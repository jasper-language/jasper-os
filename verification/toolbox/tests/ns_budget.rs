//! 纳秒预算的差分性质测试与 Miri 固定序列。参照实现用 128 位整数按周期直接写出规格。
use kernel_core::ns_budget::{utilisation, Budget, Error};
use proptest::prelude::*;

/// 参照实现：逐字段按规格计算；结果超出 u64 时为 Overflow。
fn reference(b: Budget, start: u64, end: u64, running: bool) -> Result<Budget, Error> {
    if end < start {
        return Err(Error::TimeReversed);
    }
    if !b.enabled {
        return Ok(b);
    }
    let (start, end, next, period) = (start as i128, end as i128, b.next as i128, b.period as i128);
    if end < next {
        let remaining = if running { (b.remaining as i128 - (end - start)).max(0) } else { b.remaining as i128 };
        return Ok(Budget { remaining: remaining as u64, ..b });
    }
    // 第一个严格大于 end 的周期边界。
    let periods = (end - next) / period + 1;
    if periods * period > u64::MAX as i128 || next + periods * period > u64::MAX as i128 {
        return Err(Error::Overflow);
    }
    let new_next = next + periods * period;
    let remaining = if running {
        (b.quota as i128 - (end - start.max(new_next - period))).max(0)
    } else {
        b.quota as i128
    };
    Ok(Budget { remaining: remaining as u64, next: new_next as u64, ..b })
}

fn budget() -> impl Strategy<Value = Budget> {
    (1u64..=u64::MAX, 1u64..=u64::MAX, any::<u64>(), any::<u64>(), any::<bool>()).prop_map(|(a, c, rem, next, enabled)| {
        let (quota, period) = (a.min(c), a.max(c));
        Budget { quota, period, remaining: rem.min(quota), next, enabled }
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, failure_persistence: None, ..ProptestConfig::default() })]

    /// 全宽度输入下 settle 与参照实现一致；错误不改状态；成功后剩余不超过配额。
    #[test]
    fn settle_matches_reference(b in budget(), start in any::<u64>(), end in any::<u64>(), running in any::<bool>()) {
        let mut got = b;
        let r = got.settle(start, end, running);
        match reference(b, start, end, running) {
            Ok(want) => { prop_assert_eq!(r, Ok(())); prop_assert_eq!(got, want); prop_assert!(got.remaining <= got.quota); }
            Err(e) => { prop_assert_eq!(r, Err(e)); prop_assert_eq!(got, b); }
        }
    }

    /// 小周期下多数输入跨越边界：相位不变，next 落在 (end, end + period]。
    #[test]
    fn boundary_keeps_phase(quota in 1u64..50, extra in 0u64..50, next in 0u64..1000, start in 0u64..2000, len in 0u64..2000, running in any::<bool>()) {
        let period = quota + extra;
        let mut b = Budget { quota, period, remaining: quota, next, enabled: true };
        let end = start + len;
        b.settle(start, end, running).unwrap();
        prop_assert!(b.next > end || b.next == next);
        if end >= next {
            prop_assert!(b.next - period <= end);
            prop_assert_eq!((b.next - next) % period, 0);
        }
    }

    /// 把一段运行拆成两次结算，扣费不比一次结算少，配额不会因切分多出来（同一周期内相等）。
    #[test]
    fn splitting_within_a_period_is_equivalent(quota in 1u64..1000, extra in 0u64..1000, a in 0u64..500, b_len in 0u64..500) {
        let period = quota + extra + 1001;
        let mut one = Budget { quota, period, remaining: quota, next: period, enabled: true };
        let mut two = one;
        one.settle(0, a + b_len, true).unwrap();
        two.settle(0, a, true).unwrap();
        two.settle(a, a + b_len, true).unwrap();
        prop_assert_eq!(one, two);
    }

    /// 向上取整、不超过 1000、形状错误被拒。
    #[test]
    fn utilisation_is_conservative(q in any::<u64>(), p in any::<u64>()) {
        match utilisation(q, p) {
            Ok(u) => {
                prop_assert!(q != 0 && p != 0 && q <= p);
                prop_assert!(u <= 1000);
                prop_assert!(u128::from(u) * u128::from(p) >= u128::from(q) * 1000);
                prop_assert!((u128::from(u) - 1) * u128::from(p) < u128::from(q) * 1000);
            }
            Err(e) => { prop_assert_eq!(e, Error::Shape); prop_assert!(q == 0 || p == 0 || q > p); }
        }
    }

    /// 运行检查点取配额耗尽与周期边界较早者；剩余为零时不再由已过去的配额点触发。
    #[test]
    fn running_checkpoint_matches_reference(
        quota in 1u64..=u64::MAX,
        period in 1u64..=u64::MAX,
        remaining in any::<u64>(),
        next in any::<u64>(),
        start in any::<u64>(),
        enabled in any::<bool>(),
    ) {
        let (quota, period) = (quota.min(period), quota.max(period));
        let b = Budget { quota, period, remaining: remaining.min(quota), next, enabled };
        let want = if !enabled {
            None
        } else if b.remaining == 0 {
            Some(b.next)
        } else {
            Some(b.next.min(start.saturating_add(b.remaining)))
        };
        prop_assert_eq!(b.running_settle_at(start), want);
    }
}

#[test]
fn fixed_sequence_under_miri() {
    let mut b = Budget::new(0, 3, 10).unwrap();
    b.settle(0, 2, true).unwrap();
    assert_eq!(b.remaining, 1);
    b.settle(9, 12, true).unwrap();
    assert_eq!((b.remaining, b.next), (1, 20));
    let old = b;
    assert_eq!(b.settle(5, 4, true), Err(Error::TimeReversed));
    assert_eq!(b, old);
    b.disable();
    b.settle(100, 200, true).unwrap();
    assert_eq!((b.remaining, b.next), (0, 20));
    assert_eq!(Budget::new(u64::MAX, 1, 1), Err(Error::Overflow));
    // 周期数本身溢出：相位 0、周期 1、end 取满。
    let mut b = Budget { quota: 1, period: 1, remaining: 1, next: 0, enabled: true };
    let old = b;
    assert_eq!(b.settle(0, u64::MAX, true), Err(Error::Overflow));
    assert_eq!(b, old);
    assert_eq!(Budget::new(0, 2, 1), Err(Error::Shape));
    let mut b = Budget::new(0, 3, 10).unwrap();
    assert_eq!(b.running_settle_at(2), Some(5));
    b.remaining = 0;
    assert_eq!(b.running_settle_at(2), Some(10));
    assert_eq!(b.running_settle_at(u64::MAX), Some(10));
}
