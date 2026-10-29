// CpuLimit::charge_batch（处理器事件推迟时一次补交多个 tick）：与逐个扣费差分 + 固定序列（Miri）。
use kernel_core::sched::limit::{CpuLimit, CpuLimitStats, MAX_BURST_TICKS, UNLIMITED};
use proptest::prelude::*;

/// 参考：从新建的组出发，按操作序列推进（true = 运行一个 tick 并补充，false = 只补充）。
fn walk(limit: u32, burst: u32, ops: &[(bool, bool)]) -> CpuLimit {
    let mut l = CpuLimit::new(limit, burst).unwrap();
    for &(charge, ran) in ops {
        if charge { l.charge(); } else { l.on_tick(ran, true); }
    }
    l
}

/// 逐个扣费，迟到 = 第一个之后扣费前已不可选中的个数。
fn single(mut l: CpuLimit, ticks: u64) -> (CpuLimit, u64) {
    let mut late = 0;
    for i in 0..ticks {
        if i > 0 && !l.eligible() { late += 1; }
        l.charge();
    }
    (l, late)
}

fn without_late(s: CpuLimitStats) -> CpuLimitStats { CpuLimitStats { late_ticks: 0, ..s } }

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn batch_equals_single_charges(limit in prop_oneof![1u32..1000, Just(UNLIMITED)], burst in 1u32..=MAX_BURST_TICKS,
        ops in proptest::collection::vec((any::<bool>(), any::<bool>()), 0..64), ticks in 0u64..200) {
        let base = walk(limit, burst, &ops);
        let mut batch = base;
        let late = batch.charge_batch(ticks);
        let (reference, ref_late) = single(base, ticks);
        prop_assert_eq!(late, ref_late);
        prop_assert_eq!(batch.stats().late_ticks, base.stats().late_ticks + late);
        prop_assert_eq!(without_late(batch.stats()), without_late(reference.stats()));
        prop_assert_eq!(batch.eligible(), reference.eligible());
        prop_assert_eq!(batch.deferred_tick_credits(u32::MAX), reference.deferred_tick_credits(u32::MAX));
        prop_assert!(late <= ticks.saturating_sub(1));
        if limit == UNLIMITED { prop_assert_eq!(late, 0); }
    }
    #[test]
    fn on_time_batches_never_late(limit in 1u32..1000, burst in 1u32..=MAX_BURST_TICKS, rounds in 1usize..400) {
        // 准时事件每次只交付 1 个 tick：无论组被限速多少次，迟到计数恒为 0（原界的判别力不受影响）。
        let mut l = CpuLimit::new(limit, burst).unwrap();
        for _ in 0..rounds {
            if l.eligible() { prop_assert_eq!(l.charge_batch(1), 0); }
            l.on_tick(false, true);
        }
        prop_assert_eq!(l.stats().late_ticks, 0);
    }
}

#[test]
fn fixed_sequence_under_miri() {
    // 上限 250‰、桶 4：满桶 4000 → 一次补交 6 个 tick，前 4 个扣费前余额为正，后 2 个迟到。
    let mut l = CpuLimit::new(250, 4).unwrap();
    assert_eq!(l.charge_batch(6), 2);
    assert!(!l.eligible());
    assert_eq!((l.stats().used_ticks, l.stats().late_ticks), (6, 2));
    // 余额已不为正：再补交 3 个，第一个照常（准时事件也会扣它），其后 2 个迟到。
    assert_eq!(l.charge_batch(3), 2);
    assert_eq!(l.charge_batch(0), 0);
    assert_eq!(l.stats().late_ticks, 4);
    // 不限速的组没有迟到。
    let mut u = CpuLimit::new(UNLIMITED, 1).unwrap();
    assert_eq!(u.charge_batch(1000), 0);
    assert_eq!(u.stats().used_ticks, 1000);
    // 饱和：余额与计数都不溢出。
    let mut d = CpuLimit::new(1, 1).unwrap();
    assert_eq!(d.charge_batch(u64::MAX), u64::MAX - 1);
    assert_eq!(d.charge_batch(u64::MAX), u64::MAX - 1);
    assert_eq!(d.stats().late_ticks, u64::MAX);
    assert_eq!(d.stats().used_ticks, u64::MAX);
}
