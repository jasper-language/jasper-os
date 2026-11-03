//! issue #2：DeadlineForest::sync（增量期限同步）与既有 set/remove/pop_due 的性质测试。
//! Proptest：随机操作序列对独立参考模型差分；Miri：固定序列；Loom：全局锁串行化下两核并发 sync。
use kernel_core::deadline::{Deadline, HeapError, ABSENT};
use kernel_core::deadline_forest::{DeadlineForest, SyncOutcome, SyncStats};
use proptest::prelude::*;

const C: usize = 3;
const N: usize = 6;

#[derive(Clone, Copy, Debug)]
enum Op { Sync(usize, u64, Option<(usize, u64)>), Set(usize, usize, u64, u64), Remove(usize, u64), Pop(usize, u64) }

struct World {
    forest: DeadlineForest<C>,
    entries: [Deadline; C * N],
    positions: [usize; N],
    owners: [usize; N],
    reference: [Option<(usize, Deadline)>; N],
    stats: SyncStats,
}

impl World {
    fn new() -> Self {
        Self { forest: DeadlineForest::new(), entries: [Deadline::EMPTY; C * N], positions: [ABSENT; N],
            owners: [ABSENT; N], reference: [None; N], stats: SyncStats::default() }
    }
    fn snapshot(&self) -> ([Deadline; C * N], [usize; N], [usize; N], [Option<usize>; C]) {
        (self.entries, self.positions, self.owners, core::array::from_fn(|c| self.forest.len(c)))
    }
    fn stale(&self, slot: usize, generation: u64) -> bool {
        self.reference[slot].is_some_and(|(_, d)| d.generation != generation)
    }
    /// 执行一步并与参考模型比对；返回 Err 说明违例。
    fn step(&mut self, op: Op) -> Result<(), String> {
        let before = self.snapshot();
        let failed = match op {
            Op::Sync(slot, generation, wanted) => {
                let expected = if slot >= N { Err(HeapError::Slot) }
                    else if self.stale(slot, generation) { Err(HeapError::Stale) }
                    else { match (self.reference[slot], wanted) {
                        (None, None) => Ok(SyncOutcome::Unchanged),
                        (Some(_), None) => Ok(SyncOutcome::Removed),
                        (_, Some((cpu, _))) if cpu >= C => Err(HeapError::Slot),
                        (Some((oc, d)), Some((cpu, at))) if oc == cpu && d.at == at => Ok(SyncOutcome::Unchanged),
                        (None, Some(_)) => Ok(SyncOutcome::Inserted),
                        (Some((oc, _)), Some((cpu, _))) => Ok(if oc == cpu { SyncOutcome::Rescheduled } else { SyncOutcome::Moved }),
                    } };
                let actual = self.forest.sync(&mut self.entries, &mut self.positions, &mut self.owners, slot, generation, wanted);
                if actual != expected { return Err(format!("sync {op:?}: {actual:?} != {expected:?}")); }
                if let Ok(outcome) = actual {
                    self.stats.record(outcome);
                    if !outcome.wrote() && before != self.snapshot() { return Err(format!("unchanged wrote {op:?}")); }
                    self.reference[slot] = wanted.map(|(cpu, at)| (cpu, Deadline { at, slot, generation }));
                }
                actual.is_err()
            }
            Op::Set(cpu, slot, at, generation) => {
                let expected = if cpu >= C || slot >= N { Err(HeapError::Slot) }
                    else if self.stale(slot, generation) { Err(HeapError::Stale) } else { Ok(()) };
                let event = Deadline { at, slot, generation };
                let actual = self.forest.set(&mut self.entries, &mut self.positions, &mut self.owners, cpu, event);
                if actual != expected { return Err(format!("set {op:?}: {actual:?} != {expected:?}")); }
                if actual.is_ok() { self.reference[slot] = Some((cpu, event)); }
                actual.is_err()
            }
            Op::Remove(slot, generation) => {
                let expected = if slot >= N { Err(HeapError::Slot) }
                    else if self.stale(slot, generation) { Err(HeapError::Stale) }
                    else { Ok(self.reference[slot].map(|(_, d)| d)) };
                let actual = self.forest.remove(&mut self.entries, &mut self.positions, &mut self.owners, slot, generation);
                if actual != expected { return Err(format!("remove {op:?}: {actual:?} != {expected:?}")); }
                if actual.is_ok() { self.reference[slot] = None; }
                actual.is_err()
            }
            Op::Pop(cpu, now) => {
                let expected = if cpu >= C { Err(HeapError::Slot) } else {
                    Ok(self.reference.iter().flatten().filter(|(o, _)| *o == cpu).map(|(_, d)| *d)
                        .min_by_key(|d| (d.at, d.slot)).filter(|d| d.at <= now))
                };
                let actual = self.forest.pop_due(&mut self.entries, &mut self.positions, &mut self.owners, cpu, now);
                if actual != expected { return Err(format!("pop {op:?}: {actual:?} != {expected:?}")); }
                if let Ok(Some(d)) = actual { self.reference[d.slot] = None; }
                actual.is_err()
            }
        };
        if failed && before != self.snapshot() { return Err(format!("failure mutated {op:?}")); }
        self.check()
    }
    fn check(&self) -> Result<(), String> {
        for cpu in 0..C {
            let min = self.reference.iter().flatten().filter(|(o, _)| *o == cpu).map(|(_, d)| *d).min_by_key(|d| (d.at, d.slot));
            if self.forest.peek(&self.entries, &self.positions, &self.owners, cpu) != Ok(min) { return Err(format!("min cpu{cpu}")); }
            let count = self.reference.iter().flatten().filter(|(o, _)| *o == cpu).count();
            if self.forest.len(cpu) != Some(count) { return Err(format!("count cpu{cpu}")); }
        }
        for s in 0..N {
            match self.reference[s] {
                Some((c, d)) => if self.owners[s] != c || self.entries[c * N + self.positions[s]] != d { return Err(format!("slot {s}")); },
                None => if self.owners[s] != ABSENT || self.positions[s] != ABSENT { return Err(format!("absent {s}")); },
            }
        }
        if !self.stats.balanced() { return Err("stats".into()); }
        Ok(())
    }
}

fn op() -> impl Strategy<Value = Op> {
    let wanted = prop_oneof![1 => Just(None), 4 => (0usize..C + 1, 0u64..8).prop_map(Some)];
    prop_oneof![
        4 => (0usize..N + 1, 0u64..3, wanted).prop_map(|(s, g, w)| Op::Sync(s, g, w)),
        1 => (0usize..C + 1, 0usize..N, 0u64..8, 0u64..3).prop_map(|(c, s, a, g)| Op::Set(c, s, a, g)),
        1 => (0usize..N + 1, 0u64..3).prop_map(|(s, g)| Op::Remove(s, g)),
        1 => (0usize..C + 1, 0u64..8).prop_map(|(c, n)| Op::Pop(c, n)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// 随机序列下 sync/set/remove/pop_due 与参考模型一致，失败与 Unchanged 都不写存储。
    #[test]
    fn sync_and_forest_match_reference(ops in proptest::collection::vec(op(), 1..200)) {
        let mut w = World::new();
        for o in ops { if let Err(e) = w.step(o) { prop_assert!(false, "{}", e); } }
    }

    /// 同一目标重复 sync：第一次之后全部 Unchanged，存储逐字不变。
    #[test]
    fn repeated_sync_is_idempotent(slot in 0usize..N, generation in 0u64..4, cpu in 0usize..C, at in any::<u64>(), repeats in 1usize..50) {
        let mut w = World::new();
        prop_assert!(w.step(Op::Sync(slot, generation, Some((cpu, at)))).is_ok());
        let first = w.snapshot();
        for _ in 0..repeats { prop_assert!(w.step(Op::Sync(slot, generation, Some((cpu, at)))).is_ok()); }
        prop_assert_eq!(first, w.snapshot());
        prop_assert_eq!(w.stats.unchanged, repeats as u64);
        prop_assert_eq!(w.stats.writes(), 1);
    }

    /// 迁移：所有者改变时旧堆立即失去该节点（同一槽位不会出现在两个堆里）。
    #[test]
    fn move_leaves_no_node_in_old_owner(slot in 0usize..N, from in 0usize..C, to in 0usize..C, at in 0u64..100, later in 0u64..100) {
        prop_assume!(from != to);
        let mut w = World::new();
        prop_assert!(w.step(Op::Sync(slot, 1, Some((from, at)))).is_ok());
        prop_assert!(w.step(Op::Sync(slot, 1, Some((to, later)))).is_ok());
        prop_assert_eq!(w.forest.len(from), Some(0));
        prop_assert_eq!(w.stats.moved, 1);
    }
}

/// Miri：固定序列覆盖插入/改期/迁移/删除/过期代次/越界与 pop_due。
#[test]
fn fixed_sequence_under_miri() {
    let mut w = World::new();
    let ops = [
        Op::Sync(0, 1, Some((0, 5))), Op::Sync(0, 1, Some((0, 5))), Op::Sync(0, 1, Some((0, 3))),
        Op::Sync(0, 1, Some((2, 3))), Op::Sync(1, 0, Some((2, 1))), Op::Sync(0, 2, None),
        Op::Sync(N, 0, None), Op::Sync(2, 0, Some((C, 1))), Op::Pop(2, 2), Op::Sync(0, 1, None),
        Op::Sync(0, 1, None), Op::Set(1, 3, 7, 0), Op::Sync(3, 0, Some((1, 7))), Op::Remove(3, 1), Op::Pop(1, 9),
    ];
    for o in ops { w.step(o).unwrap(); }
    assert_eq!(w.stats, SyncStats { passes: 0, synced: 8, unchanged: 3, inserted: 2, rescheduled: 1, moved: 1, removed: 1 });
}

/// Loom：森林由全局锁串行化（与内核相同）；两核同时 sync 各自槽位，任何交错下
/// 最终每核最早项与计数守恒都成立。
#[test]
fn race_two_cpus_sync_under_global_lock() {
    loom::model(|| {
        let world = loom::sync::Arc::new(loom::sync::Mutex::new(World::new()));
        world.lock().unwrap().step(Op::Sync(0, 1, Some((0, 9)))).unwrap();
        let a = world.clone();
        let t = loom::thread::spawn(move || {
            a.lock().unwrap().step(Op::Sync(0, 1, Some((1, 4)))).unwrap();
            a.lock().unwrap().step(Op::Sync(0, 1, Some((1, 4)))).unwrap();
        });
        world.lock().unwrap().step(Op::Sync(1, 1, Some((1, 6)))).unwrap();
        world.lock().unwrap().step(Op::Pop(1, 3)).unwrap();
        t.join().unwrap();
        let w = world.lock().unwrap();
        w.check().unwrap();
        assert_eq!(w.forest.len(0), Some(0));
        assert_eq!(w.stats.unchanged, 1);
        assert_eq!(w.stats.synced, 4);
    });
}
