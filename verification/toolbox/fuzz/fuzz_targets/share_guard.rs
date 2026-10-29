#![no_main]
// 分时策略 preempt_rule 与修正前规则只在「补给档、本片未记 tick」处不同；任意事件序列下后台份额与连续运行有界。
use kernel_core::sched::timeshare::{preempt_rule, Owed};
use kernel_core::sched::{ClassMask, Preempt, Qos, QosParams, Requeue, SchedEntity, SchedPolicy, TimeSharePolicy, TimeShareState};
libfuzzer_sys::fuzz_target!(|b: &[u8]| {
    if b.len() < 4 { return; }
    let used = u32::from(b[0] % 5);
    let quantum = u32::from(b[1] % 5);
    let higher = b[2] & 1 != 0;
    let others = b[2] & 2 != 0;
    let owed = match b[3] % 3 { 0 => Owed::None, 1 => Owed::Current, _ => Owed::Other };
    let r = preempt_rule(used, quantum, higher, owed, others);
    let old = if higher { Some(Preempt::Higher) } else if owed == Owed::Other { Some(Preempt::Owed) }
        else if used >= quantum && others { Some(Preempt::Quantum) } else { None };
    if used == 0 && owed == Owed::Current { assert_eq!(r, None); } else { assert_eq!(r, old); }

    // 事件序列：每位 1 = tick，0 = 重新判定
    let mut p = TimeSharePolicy::new(QosParams::DEFAULT);
    let mut e = [SchedEntity::new(Qos::UserInitiated, TimeShareState::INITIAL), SchedEntity::new(Qos::Background, TimeShareState::INITIAL)];
    let mut cur = 0usize;
    p.dispatched(&mut e[0]);
    let (mut u, mut q) = (0u32, p.default_quantum());
    let (mut bg, mut run, mut ticks) = (0u64, 0u64, 0u64);
    for byte in &b[4..] {
        for bit in 0..8 {
            let tick = byte >> bit & 1 != 0;
            let mut waiting = ClassMask::EMPTY;
            waiting.insert(e[1 - cur].qos);
            if tick {
                p.on_tick(Some(&mut e[cur]), waiting);
                u += 1;
                ticks += 1;
                if cur == 1 { bg += 1; run += 1; assert!(run <= 1); } else { run = 0; }
            }
            if p.should_preempt(Some(&e[cur]), u, q, waiting).is_some() {
                p.requeue(&mut e[cur], Requeue::Preempted);
                let c = p.choose(&mut e.iter().enumerate()).unwrap();
                if c.slot != cur { run = 0; }
                cur = c.slot;
                p.dispatched(&mut e[cur]);
                u = 0;
                q = c.quantum;
            }
        }
    }
    assert!(bg * 51 + 51 >= ticks, "bg={bg} ticks={ticks}");
});
