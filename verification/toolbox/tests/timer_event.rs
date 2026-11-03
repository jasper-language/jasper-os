// issue #3 统一定时事件契约：Proptest 差分、Miri 确定性用例、Loom 取消/到期竞争。
// Unified timer-event contract: Proptest differential, Miri cases, Loom cancel/expire race.
use kernel_core::timer_event::*;
use proptest::prelude::*;

fn urgency(precise: bool, slack: u64) -> Urgency {
    if precise { Urgency::Precise } else { Urgency::Tolerant { slack_ns: slack } }
}

// 参考模型：每个槽位记录 (代数, 所有者, 状态)。 / Reference model per slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RefState { Free, Idle, Armed(Request) }

const N: usize = 4;
struct Model { gen: [u64; N], owner: [u32; N], state: [RefState; N], budget: [u32; 2], limit: u32 }

fn run(ops: &[(u8, u8, u8, u64)]) -> Result<(), TestCaseError> {
    let mut t = TimerTable::<N>::new();
    let mut budgets = [OwnerBudget::new(3), OwnerBudget::new(3)];
    let mut m = Model { gen: [0; N], owner: [0; N], state: [RefState::Free; N], budget: [0; 2], limit: 3 };
    let mut ids: Vec<TimerId> = Vec::new();
    for &(op, sel, owner, x) in ops {
        let owner = u32::from(owner % 2);
        let id = if ids.is_empty() { TimerId { slot: u32::from(sel) % 5, generation: x % 3 } } else { ids[sel as usize % ids.len()] };
        let live = |m: &Model, id: TimerId| -> Result<usize, Error> {
            let s = id.slot as usize;
            if s >= N || m.gen[s] != id.generation || m.state[s] == RefState::Free { return Err(Error::Stale); }
            if m.owner[s] != owner { return Err(Error::NotOwner); }
            Ok(s)
        };
        match op % 5 {
            0 => {
                let got = t.create(owner, &mut budgets[owner as usize]);
                let free = (0..N).rev().find(|&s| m.state[s] == RefState::Free);
                match got {
                    Ok(new) => {
                        let s = new.slot as usize;
                        prop_assert!(free.is_some() && m.state[s] == RefState::Free && m.budget[owner as usize] < m.limit);
                        prop_assert_eq!(new.generation, m.gen[s] + 1);
                        m.gen[s] += 1; m.owner[s] = owner; m.state[s] = RefState::Idle; m.budget[owner as usize] += 1;
                        ids.push(new);
                    }
                    Err(Error::Full) => prop_assert!(free.is_none()),
                    Err(Error::Quota) => prop_assert!(free.is_some() && m.budget[owner as usize] == m.limit),
                    Err(e) => prop_assert!(false, "create {:?}", e),
                }
            }
            1 => {
                let r = Request { at: (x >> 4) & 0xffff, urgency: urgency(x & 1 == 0, x >> 40), period_ns: (x >> 1) & 7 };
                let want = live(&m, id).map(|s| { let old = match m.state[s] { RefState::Armed(o) => Some(o), _ => None }; m.state[s] = RefState::Armed(r); old });
                prop_assert_eq!(t.arm(id, owner, r), want);
            }
            2 => {
                let want = live(&m, id).map(|s| match m.state[s] { RefState::Armed(o) => { m.state[s] = RefState::Idle; Cancelled::Disarmed(o) } _ => Cancelled::NotArmed });
                prop_assert_eq!(t.cancel(id, owner), want);
            }
            3 => {
                let want = live(&m, id).map(|s| { let old = match m.state[s] { RefState::Armed(o) => Some(o), _ => None }; m.state[s] = RefState::Free; m.budget[owner as usize] -= 1; old });
                prop_assert_eq!(t.close(id, owner, &mut budgets[owner as usize]), want);
            }
            _ => {
                let now = (x >> 3) & 0x1ffff;
                let s = id.slot as usize;
                let want = if s < N && m.gen[s] == id.generation {
                    match m.state[s] {
                        RefState::Armed(r) if r.at <= now => {
                            if r.period_ns == 0 { m.state[s] = RefState::Idle; Some(Fired { owner: m.owner[s], at: r.at, next: None }) }
                            else {
                                let mut next = r.at;
                                while next <= now { next += r.period_ns; }
                                m.state[s] = RefState::Armed(Request { at: next, ..r });
                                Some(Fired { owner: m.owner[s], at: r.at, next: Some(next) })
                            }
                        }
                        _ => None,
                    }
                } else { None };
                prop_assert_eq!(t.expire(id, now), Ok(want));
            }
        }
        let armed = m.state.iter().filter(|s| matches!(s, RefState::Armed(_))).count();
        let live = m.state.iter().filter(|s| **s != RefState::Free).count();
        prop_assert_eq!((t.armed(), t.live()), (armed, live));
        prop_assert_eq!([budgets[0].used(), budgets[1].used()], m.budget);
        for (k, &id) in ids.iter().enumerate() {
            let s = id.slot as usize;
            let want = match m.state[s] { RefState::Armed(r) if m.gen[s] == id.generation => Some(r), _ => None };
            prop_assert_eq!(t.armed_request(id), want, "id {}", k);
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn table_matches_reference_model(ops in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>(), 0u64..(1 << 48)), 0..64)) {
        run(&ops)?;
    }

    #[test]
    fn arbiter_is_min_of_latest_instants(srcs in prop::collection::vec((any::<u64>(), any::<bool>(), any::<u64>()), 0..16)) {
        let mut arb = Arbiter::new();
        for &(at, p, slack) in &srcs { arb.offer(at, urgency(p, slack)); }
        let want = srcs.iter().map(|&(at, p, slack)| if p { at } else { at.saturating_add(slack) }).min();
        prop_assert_eq!(arb.program_at(), want);
        for &(at, p, _) in &srcs { if p { prop_assert!(arb.program_at().unwrap() <= at); } }
    }

    #[test]
    fn arm_delay_is_clamped_remaining_time(at in any::<u64>(), now in any::<u64>(), max in any::<u64>()) {
        let d = arm_delay(at, now, max);
        prop_assert!(d >= 1 && d <= max.max(1));
        if at > now && at - now <= max { prop_assert_eq!(d, at - now); }
    }

    #[test]
    fn next_boundary_matches_period_walk(previous in 0u64..1 << 20, now in 0u64..1 << 21, period in 1u64..64) {
        let mut want = previous;
        while want <= now { want += period; }
        prop_assert_eq!(next_boundary(now, previous, period), Some(want));
        prop_assert_eq!(kernel_core::deadline::next_period(now, previous, period as u32), Some(want));
    }

    #[test]
    fn next_boundary_full_domain(now in any::<u64>(), previous in any::<u64>(), period in any::<u64>()) {
        match next_boundary(now, previous, period) {
            None => prop_assert!(period == 0 || (previous <= now && u128::from(previous) + (u128::from(now - previous) / u128::from(period) + 1) * u128::from(period) > u128::from(u64::MAX))),
            Some(next) => {
                prop_assert!(period > 0 && next > now);
                if previous <= now { prop_assert!((next - previous) % period == 0 && next - period <= now); } else { prop_assert_eq!(next, previous); }
            }
        }
    }
}

#[test]
fn timer_lifecycle_under_miri() {
    let mut t = TimerTable::<4>::new();
    let mut task = OwnerBudget::new(2);
    let mut general = OwnerBudget::new(1);
    let a = t.create(1, &mut task).unwrap();
    let b = t.create(1, &mut task).unwrap();
    let g = t.create(9, &mut general).unwrap();
    assert_eq!(t.create(1, &mut task), Err(Error::Quota));
    let precise = Request { at: 100, urgency: Urgency::Precise, period_ns: 0 };
    let loose = Request { at: 90, urgency: Urgency::Tolerant { slack_ns: 40 }, period_ns: 25 };
    t.arm(a, 1, precise).unwrap();
    t.arm(b, 1, loose).unwrap();
    let mut arb = Arbiter::new();
    arb.offer(precise.at, precise.urgency);
    arb.offer(loose.at, loose.urgency);
    assert_eq!(arb.program_at(), Some(100));
    assert_eq!(t.expire(b, 100), Ok(Some(Fired { owner: 1, at: 90, next: Some(115) })));
    assert_eq!(t.expire(a, 100), Ok(Some(Fired { owner: 1, at: 100, next: None })));
    assert_eq!(t.expire(a, 100), Ok(None));
    assert_eq!(t.close(b, 1, &mut task), Ok(Some(Request { at: 115, ..loose })));
    let b2 = t.create(1, &mut task).unwrap();
    assert_eq!(t.cancel(b, 1), Err(Error::Stale));
    assert_eq!(t.cancel(g, 1), Err(Error::NotOwner));
    assert_eq!(t.cancel(b2, 1), Ok(Cancelled::NotArmed));
    for id in [a, b2] { t.close(id, 1, &mut task).unwrap(); }
    t.close(g, 9, &mut general).unwrap();
    assert_eq!((t.live(), t.armed(), task.used(), general.used()), (0, 0, 0, 0));
}

// 取消与到期竞争：在调用方锁下二者恰有一方生效，交付至多一次。
// Cancel vs expiry under the caller's lock: exactly one wins, delivery at most once.
#[test]
fn cancel_expire_race_delivers_at_most_once() {
    loom::model(|| {
        use loom::sync::{Arc, Mutex};
        let mut table = TimerTable::<1>::new();
        let mut budget = OwnerBudget::new(1);
        let id = table.create(4, &mut budget).unwrap();
        table.arm(id, 4, Request { at: 10, urgency: Urgency::Precise, period_ns: 0 }).unwrap();
        let shared = Arc::new(Mutex::new(table));
        let other = shared.clone();
        let fire = loom::thread::spawn(move || other.lock().unwrap().expire(id, 10).unwrap());
        let cancel = shared.lock().unwrap().cancel(id, 4).unwrap();
        let fired = fire.join().unwrap();
        match cancel {
            Cancelled::Disarmed(_) => assert_eq!(fired, None),
            Cancelled::NotArmed => assert_eq!(fired, Some(Fired { owner: 4, at: 10, next: None })),
        }
        assert_eq!(shared.lock().unwrap().armed(), 0);
    });
}

// 关闭与周期到期竞争：关闭后不再有交付，资源计数归零。
// Close vs periodic expiry: no delivery after close, counters return to zero.
#[test]
fn close_periodic_race_releases_once() {
    loom::model(|| {
        use loom::sync::{Arc, Mutex};
        let mut table = TimerTable::<1>::new();
        let mut budget = OwnerBudget::new(1);
        let id = table.create(4, &mut budget).unwrap();
        table.arm(id, 4, Request { at: 10, urgency: Urgency::Tolerant { slack_ns: 5 }, period_ns: 10 }).unwrap();
        let shared = Arc::new(Mutex::new((table, budget)));
        let other = shared.clone();
        let fire = loom::thread::spawn(move || { let mut g = other.lock().unwrap(); g.0.expire(id, 25).unwrap() });
        let closed = { let mut g = shared.lock().unwrap(); let (t, b) = &mut *g; t.close(id, 4, b).unwrap() };
        let fired = fire.join().unwrap();
        match fired {
            Some(f) => { assert_eq!(f.next, Some(30)); assert_eq!(closed.map(|r| r.at), Some(30)); }
            None => assert_eq!(closed.map(|r| r.at), Some(10)),
        }
        let g = shared.lock().unwrap();
        assert_eq!((g.0.live(), g.0.armed(), g.1.used()), (0, 0, 0));
        assert_eq!(g.0.clone().expire(id, u64::MAX), Ok(None));
    });
}
