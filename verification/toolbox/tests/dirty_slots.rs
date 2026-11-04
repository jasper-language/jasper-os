//! 脏位图的差分性质测试与 Miri 固定序列；并验证「只同步脏槽位」与「全表扫描」的堆结果等价。
use kernel_core::deadline::{Deadline, ABSENT};
use kernel_core::deadline_forest::DeadlineForest;
use kernel_core::dirty_slots::{is_marked, mark, mark_first, take_next, words_for};
use proptest::prelude::*;
use std::collections::BTreeSet;

const SLOTS: usize = 130;
const CPUS: usize = 3;

fn word_ops(ops: &[(u8, usize)]) {
    let mut w = vec![0u64; words_for(SLOTS)];
    let mut reference = BTreeSet::new();
    for &(op, arg) in ops {
        let s = arg % (SLOTS + 70);
        match op % 3 {
            0 => {
                assert_eq!(mark(&mut w, s), s < w.len() * 64);
                if s < w.len() * 64 {
                    reference.insert(s);
                }
            }
            1 => {
                let expected = reference.range(s..).next().copied();
                assert_eq!(take_next(&mut w, s), expected);
                if let Some(e) = expected {
                    reference.remove(&e);
                }
            }
            _ => {
                let n = s.min(w.len() * 64);
                mark_first(&mut w, s);
                reference.extend(0..n);
            }
        }
        for t in 0..w.len() * 64 {
            assert_eq!(is_marked(&w, t), reference.contains(&t));
        }
    }
}

/// 一个槽位的输入：所有者处理器与时刻（`None` 表示没有事件）。
type Wanted = Option<(usize, u64)>;

#[derive(Clone, Copy, Debug)]
enum Op {
    /// 状态迁移：改写应发布的事件（迁移、到期时刻变化、退出）并标脏。
    Change(usize, Wanted),
    /// 被标脏但事件没变（可变访问只碰了别的字段）。
    Touch(usize),
    /// 弹出某处理器堆顶到期节点并标脏（未被唤醒的任务要重新发布）。
    Pop(usize, u64),
    /// 一轮刷新。
    Refresh,
}

struct Forest {
    forest: DeadlineForest<CPUS>,
    entries: Vec<Deadline>,
    positions: Vec<usize>,
    owners: Vec<usize>,
}

impl Forest {
    fn new(n: usize) -> Self {
        Self {
            forest: DeadlineForest::new(),
            entries: vec![Deadline::EMPTY; CPUS * n],
            positions: vec![ABSENT; n],
            owners: vec![ABSENT; n],
        }
    }
    fn sync(&mut self, slot: usize, wanted: Wanted) {
        self.forest.sync(&mut self.entries, &mut self.positions, &mut self.owners, slot, 1, wanted).unwrap();
    }
    fn published(&self, slot: usize) -> Wanted {
        self.forest.published(&self.entries, &self.positions, &self.owners, slot).unwrap().map(|(c, e)| (c, e.at))
    }
    fn root(&self, cpu: usize) -> Option<u64> {
        self.forest.peek(&self.entries, &self.positions, &self.owners, cpu).unwrap().map(|e| e.at)
    }
}

/// 同一串操作分别走脏集合与全表扫描：每轮刷新之后，所有节点与堆顶都相同，且脏集合只碰被标记的槽位。
fn dirty_equals_full_scan(n: usize, ops: &[Op]) {
    let mut wanted: Vec<Wanted> = vec![None; n];
    let mut dirty = vec![0u64; words_for(n)];
    let (mut incremental, mut full) = (Forest::new(n), Forest::new(n));
    for &op in ops {
        match op {
            Op::Change(s, w) => {
                wanted[s % n] = w.map(|(c, at)| (c % CPUS, at));
                assert!(mark(&mut dirty, s % n));
            }
            Op::Touch(s) => assert!(mark(&mut dirty, s % n)),
            Op::Pop(c, now) => {
                let c = c % CPUS;
                while let Some(e) = incremental.forest.pop_due(&mut incremental.entries, &mut incremental.positions, &mut incremental.owners, c, now).unwrap() {
                    assert!(mark(&mut dirty, e.slot));
                }
                while full.forest.pop_due(&mut full.entries, &mut full.positions, &mut full.owners, c, now).unwrap().is_some() {}
            }
            Op::Refresh => {
                let mut from = 0;
                while let Some(s) = take_next(&mut dirty, from) {
                    from = s + 1;
                    incremental.sync(s, wanted[s]);
                }
                for (s, &w) in wanted.iter().enumerate() {
                    full.sync(s, w);
                }
                for s in 0..n {
                    assert_eq!(incremental.published(s), full.published(s), "slot {s}");
                    assert_eq!(incremental.published(s), wanted[s], "slot {s}");
                }
                for c in 0..CPUS {
                    assert_eq!(incremental.root(c), full.root(c), "cpu {c}");
                }
            }
        }
    }
}

fn op() -> impl Strategy<Value = Op> {
    let wanted = proptest::option::of((0usize..CPUS, 0u64..16));
    prop_oneof![
        (0usize..70, wanted).prop_map(|(s, w)| Op::Change(s, w)),
        (0usize..70).prop_map(Op::Touch),
        (0usize..CPUS, 0u64..16).prop_map(|(c, now)| Op::Pop(c, now)),
        Just(Op::Refresh),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, failure_persistence: None, ..ProptestConfig::default() })]

    /// 位图与有序集合参照实现差分。
    #[test]
    fn bitmap_matches_reference(ops in proptest::collection::vec((any::<u8>(), any::<usize>()), 0..64)) {
        word_ops(&ops);
    }

    /// 只同步脏槽位的结果等于全表扫描。
    #[test]
    fn dirty_sync_equals_full_scan(n in 1usize..70, ops in proptest::collection::vec(op(), 0..96)) {
        dirty_equals_full_scan(n, &ops);
    }
}

#[test]
fn fixed_sequence_under_miri() {
    word_ops(&[(0, 129), (0, 3), (1, 0), (1, 4), (2, 65), (1, 64), (1, 200), (0, 199)]);
    dirty_equals_full_scan(4, &[
        Op::Change(0, Some((0, 5))),
        Op::Change(1, Some((1, 3))),
        Op::Refresh,
        Op::Pop(0, 7),
        Op::Refresh,
        Op::Change(1, Some((2, 9))),
        Op::Touch(3),
        Op::Refresh,
        Op::Change(0, None),
        Op::Refresh,
    ]);
}
