// 分时策略最低份额保护（preempt_rule）：与修正前规则的差分 + 「派发后、第一个 tick 前的任意重新判定」下的份额与有界性。
use kernel_core::sched::timeshare::{preempt_rule, Owed};
use kernel_core::sched::{ClassMask, Preempt, Qos, QosParams, Requeue, SchedEntity, SchedPolicy, TimeSharePolicy, TimeShareState};
use proptest::prelude::*;

/// 修正前的判定（参考）。
fn old_rule(used: u32, quantum: u32, higher: bool, owed: Owed, others: bool) -> Option<Preempt> {
    if higher {
        Some(Preempt::Higher)
    } else if owed == Owed::Other {
        Some(Preempt::Owed)
    } else if used >= quantum && others {
        Some(Preempt::Quantum)
    } else {
        None
    }
}

fn owed_of(b: u8) -> Owed {
    match b % 3 { 0 => Owed::None, 1 => Owed::Current, _ => Owed::Other }
}

/// 两个吃满任务（用户发起 + 后台）在一个处理器上；事件序列：true = tick，false = 重新判定（重新调度请求等）。
/// 返回（后台运行 tick 数，后台连续运行的最长 tick 数，tick 总数）。
fn simulate(events: &[bool]) -> (u64, u64, u64) {
    let mut p = TimeSharePolicy::new(QosParams::DEFAULT);
    let mut e = [SchedEntity::new(Qos::UserInitiated, TimeShareState::INITIAL), SchedEntity::new(Qos::Background, TimeShareState::INITIAL)];
    let mask = |q: Qos| { let mut m = ClassMask::EMPTY; m.insert(q); m };
    let mut cur = 0usize;
    p.dispatched(&mut e[0]);
    let (mut used, mut quantum) = (0u32, p.default_quantum());
    let (mut bg, mut run, mut longest, mut ticks) = (0u64, 0u64, 0u64, 0u64);
    for &tick in events {
        let other = 1 - cur;
        let waiting = mask(e[other].qos);
        if tick {
            p.on_tick(Some(&mut e[cur]), waiting);
            used += 1;
            ticks += 1;
            if cur == 1 { bg += 1; run += 1; longest = longest.max(run); } else { run = 0; }
        }
        if p.should_preempt(Some(&e[cur]), used, quantum, waiting).is_some() {
            p.requeue(&mut e[cur], Requeue::Preempted);
            let mut it = e.iter().enumerate();
            let c = p.choose(&mut it).expect("两个任务都可运行");
            if c.slot != cur { run = 0; }
            cur = c.slot;
            p.dispatched(&mut e[cur]);
            used = 0;
            quantum = c.quantum;
        }
    }
    (bg, longest, ticks)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn rule_differs_from_old_only_in_guard(used in 0u32..4, quantum in 0u32..4, higher: bool, owed in any::<u8>(), others: bool) {
        let o = owed_of(owed);
        let r = preempt_rule(used, quantum, higher, o, others);
        if used == 0 && o == Owed::Current {
            prop_assert_eq!(r, None);
        } else {
            prop_assert_eq!(r, old_rule(used, quantum, higher, o, others));
        }
    }

    #[test]
    fn share_and_bound_under_any_redecide(events in proptest::collection::vec(any::<bool>(), 0..4000)) {
        let (bg, longest, ticks) = simulate(&events);
        // 后台档每等满 50 个 tick（20‰）补给 1 个：任意重新判定插在哪里都不能让它少拿
        prop_assert!(bg * 51 + 51 >= ticks, "bg={} ticks={}", bg, ticks);
        // 保护至多一个 tick：用户发起档一直可运行时后台从不连续运行 2 个 tick
        prop_assert!(longest <= 1, "longest={}", longest);
    }
}

#[test]
fn every_tick_redecided_fixed_sequence_under_miri() {
    // 每个 tick 之间插一次重新判定（S-2 失败运行里观察到的形态）
    let events: Vec<bool> = (0..600).flat_map(|_| [true, false]).collect();
    let (bg, longest, ticks) = simulate(&events);
    assert_eq!(ticks, 600);
    assert!(bg >= 11 && longest == 1, "bg={bg} longest={longest}");
}
