// counter_ns（hrtime 计数→纳秒换算）与 drill 判据：参考模型差分 + 固定序列（Miri）。
use kernel_core::drill::{dispatch_mask, hog_continues, preempt_step_continues, refill_consistent};
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
    #[test]
    fn hog_loop_reference_and_bounded(start in 0u64..1 << 40, win in 0u64..256, grace in 0u64..256,
        want in 0u32..9, arrivals in proptest::collection::vec((0u32..8, 0u64..512), 0..16)) {
        // 参考模拟：时钟逐 tick 前进，各核在给定 tick 首次轮到（宿主 vCPU 停顿 = 很晚才轮到）。
        let (end, cutoff) = (start + win, start + win + grace);
        let mut covered = 0u32;
        let mut now = start;
        loop {
            for &(cpu, at) in &arrivals { if start + at <= now { covered |= 1 << cpu; } }
            let reference = now < end || (covered.count_ones() < want && now < cutoff);
            let go = hog_continues(now, end, covered, want, cutoff);
            prop_assert_eq!(go, reference);
            if !go { break; }
            now += 1;
        }
        // 停止时刻 = max(窗口末, min(截止, 首次覆盖够数的 tick))：覆盖够了立即停，不够等到截止为止。
        let seen = |t: u64| arrivals.iter().filter(|&&(_, at)| start + at <= t).fold(0u32, |m, &(c, _)| m | 1 << c);
        let t_cover = (start..=cutoff).find(|&t| seen(t).count_ones() >= want).unwrap_or(u64::MAX);
        prop_assert_eq!(now, end.max(cutoff.min(t_cover)));
        if want == 0 { prop_assert_eq!(now, end); }
    }
    #[test]
    fn dispatch_mask_matches_reference(busy in proptest::collection::vec(prop_oneof![Just(0u64), any::<u64>()], 0..40)) {
        // 参考：逐核判断，只看前 32 个处理器；被分派过的核数不超过处理器数，且总运行量为正时至少一个核。
        let m = dispatch_mask(&busy);
        for i in 0..32 {
            prop_assert_eq!(m >> i & 1 == 1, i < busy.len() && busy[i] > 0);
        }
        prop_assert!(m.count_ones() as usize <= busy.len().min(32));
        let head: u128 = busy.iter().take(32).map(|&b| u128::from(b)).sum();
        prop_assert_eq!(m == 0, head == 0);
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
    // 吃满任务：窗口 60，8 核里第 8 个核在窗口之后第 100 tick 才轮到，截止 1260。
    let mut covered = 0x7fu32;
    let mut now = 0u64;
    while hog_continues(now, 60, covered, 8, 1260) {
        now += 1;
        if now == 160 { covered |= 0x80; }
    }
    assert_eq!(now, 160);
    let mut now = 0u64;
    while hog_continues(now, 60, 0x7f, 8, 1260) { now += 1; }
    assert_eq!(now, 1260);
    // 跨核上限：S-2 实测 8 核各核运行 tick 均为正（任务体只自报 3 个核），按分派判为 8 个核。
    assert_eq!(dispatch_mask(&[14, 19, 23, 19, 17, 15, 14, 8]).count_ones(), 8);
    assert_eq!(dispatch_mask(&[0, 0, 5, 0]), 0b100);
}
