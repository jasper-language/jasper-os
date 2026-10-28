//! 演练判据（QEMU 只判正确性）：把演练里与观测时机有关的判断写成纯函数，
//! 使「观测晚了几个 tick」不改变结论，同时保留对真实缺陷的判别力。
//! English: drill judgements that stay correct when observation lags by some ticks.

/// 周期补充后的观测是否与「补充把剩余额度恢复为满额」一致。
///
/// `period_start` 是新周期起点（tick），`now` 是观测时刻。补充之后任务每运行一个 tick 扣 1，
/// 所以已扣额度不超过 `now - period_start`；在补充的同一 tick 内观测（流逝 0）时必须恰为满额。
/// 剩余为 0 的任务被节流、不会运行，观测不到，按不一致处理。
pub fn refill_consistent(quota: u32, remaining: u32, period_start: u64, now: u64) -> bool {
    let elapsed = now.saturating_sub(period_start);
    remaining >= 1 && remaining <= quota && u64::from(quota - remaining) <= elapsed
}

/// 抢占演练任务是否还要走下一步：没走满 `min_steps`，或 tick 切换数没到 `min_switches` 且没到截止 tick。
/// 走满步数之后，到达切换数或截止二者之一即停止，所以截止保证演练有界结束。
pub fn preempt_step_continues(step: u32, min_steps: u32, switches: u64, min_switches: u64, now: u64, deadline: u64) -> bool {
    step < min_steps || (switches < min_switches && now < deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refill_exact_in_refill_tick_and_bounded_after() {
        assert!(refill_consistent(3, 3, 100, 100));
        assert!(!refill_consistent(3, 2, 100, 100));
        assert!(refill_consistent(3, 2, 100, 101));
        assert!(!refill_consistent(3, 1, 100, 101));
        assert!(!refill_consistent(3, 0, 100, 200));
        assert!(!refill_consistent(3, 4, 100, 200));
        assert!(refill_consistent(3, 3, 100, 50));
        assert!(!refill_consistent(0, 0, 0, 0));
    }
    #[test]
    fn preempt_demo_is_bounded() {
        assert!(preempt_step_continues(0, 8, 99, 12, 999, 10));
        assert!(preempt_step_continues(8, 8, 11, 12, 9, 10));
        assert!(!preempt_step_continues(8, 8, 12, 12, 9, 10));
        assert!(!preempt_step_continues(8, 8, 0, 12, 10, 10));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn refill_judgement_full_domain() {
        let (q, r, s, n): (u32, u32, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any());
        let ok = refill_consistent(q, r, s, n);
        if ok {
            assert!(r >= 1 && r <= q);
            assert!(u64::from(q - r) <= n.saturating_sub(s));
        }
        if n <= s {
            assert_eq!(ok, r == q && q >= 1);
        }
        if r == q && q >= 1 {
            assert!(ok);
        }
    }
    #[kani::proof]
    fn preempt_loop_terminates_full_domain() {
        let (st, ms, sw, msw, n, d): (u32, u32, u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        let go = preempt_step_continues(st, ms, sw, msw, n, d);
        if st >= ms && (n >= d || sw >= msw) {
            assert!(!go);
        }
        if !go {
            assert!(st >= ms);
        }
        if st < ms {
            assert!(go);
        }
    }
}
