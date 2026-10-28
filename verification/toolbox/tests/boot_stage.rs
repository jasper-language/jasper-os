//! issue #7 第一片：启动阶段图（graph_well_formed / closure）与跟踪器（Tracker）的差分性质测试与 Miri 固定序列；
//! 补链既有 capacity 记录 encode/parse。参照实现用标准库直接写出规格。
use std::collections::HashSet;

use kernel_core::boot_stage::{closure, graph_well_formed, Stage, StageError, StageSpec, Tracker, GRAPH};
use kernel_core::capacity::{encode, parse, Overrides, RecordError, RECORD_LEN, RECORD_MAGIC};
use proptest::prelude::*;

/// 参照：DFS 求传递依赖。Reference transitive closure by DFS.
fn reference_closure(g: &[StageSpec], s: usize) -> u32 {
    let mut seen = 0u32;
    let mut stack = vec![s];
    while let Some(i) = stack.pop() {
        for j in 0..Stage::COUNT {
            if g[i].requires & (1 << j) != 0 && seen & (1 << j) == 0 {
                seen |= 1 << j;
                stack.push(j);
            }
        }
    }
    seen
}

fn reference_well_formed(g: &[StageSpec]) -> bool {
    if g.len() != Stage::COUNT {
        return false;
    }
    let names: HashSet<&str> = g.iter().map(|x| x.name).collect();
    names.len() == g.len()
        && g.iter().enumerate().all(|(i, x)| x.stage.index() == i && !x.name.is_empty() && x.requires >> i == 0)
}

/// 参照跟踪器。Reference tracker model.
#[derive(Default)]
struct Model {
    started: u32,
    done: u32,
    running: Option<Stage>,
    failed: Option<Stage>,
}

impl Model {
    fn begin(&mut self, s: Stage) -> Result<(), StageError> {
        if let Some(f) = self.failed {
            return Err(StageError::Halted { failed: f });
        }
        if let Some(r) = self.running {
            return Err(StageError::Busy { running: r });
        }
        if self.started & s.bit() != 0 {
            return Err(StageError::Duplicate(s));
        }
        let missing: Vec<Stage> =
            Stage::ALL.iter().copied().filter(|d| GRAPH[s.index()].requires & d.bit() != 0 && self.done & d.bit() == 0).collect();
        if let Some(&m) = missing.first() {
            return Err(StageError::MissingDependency { stage: s, missing: m });
        }
        self.started |= s.bit();
        self.running = Some(s);
        Ok(())
    }
    fn finish(&mut self, s: Stage, ok: bool) -> bool {
        if self.running != Some(s) {
            return false;
        }
        self.running = None;
        if ok {
            self.done |= s.bit();
        } else {
            self.failed = Some(s);
        }
        true
    }
}

fn drive(ops: &[(u8, u8)]) {
    let mut t = Tracker::new();
    let mut m = Model::default();
    for &(op, si) in ops {
        let s = Stage::ALL[si as usize % Stage::COUNT];
        match op % 3 {
            0 => assert_eq!(t.begin(s), m.begin(s)),
            1 => assert_eq!(t.complete(s).is_ok(), m.finish(s, true)),
            _ => assert_eq!(t.fail(s).is_ok(), m.finish(s, false)),
        }
        assert_eq!(t.done_mask(), m.done);
        assert_eq!(t.failed(), m.failed);
        if let Some(f) = m.failed {
            // 被阻断集合 = 传递依赖失败阶段的阶段。Blocked = stages transitively depending on the failure.
            let expect = Stage::ALL
                .iter()
                .filter(|x| reference_closure(&GRAPH, x.index()) & f.bit() != 0)
                .fold(0u32, |a, x| a | x.bit());
            assert_eq!(t.blocked_mask(), expect);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// 跟踪器与参照模型在任意操作序列上逐步一致。Tracker matches the model step by step.
    #[test]
    fn tracker_matches_model(ops in proptest::collection::vec((any::<u8>(), any::<u8>()), 0..64)) {
        drive(&ops);
    }

    /// 变异阶段图：良构判定与参照一致；良构 ⇒ closure 等于 DFS 闭包且不含自身（无环）。
    #[test]
    fn graph_check_matches_reference(edits in proptest::collection::vec((0usize..10, any::<u32>(), 0usize..10, any::<bool>()), 0..4)) {
        let mut g = GRAPH;
        for (i, req, j, swap) in edits {
            if swap { g.swap(i, j) } else { g[i].requires = req & 0x3ff }
        }
        prop_assert_eq!(graph_well_formed(&g), reference_well_formed(&g));
        if graph_well_formed(&g) {
            for s in Stage::ALL {
                let c = closure(&g, s);
                prop_assert_eq!(c, reference_closure(&g, s.index()));
                prop_assert_eq!(c & s.bit(), 0);
            }
        }
    }

    /// 补链：任意 32 字节记录，parse 成功 ⇒ 规范形（encode 回同一字节）；任意覆盖值往返。
    #[test]
    fn capacity_record_round_trip(r in proptest::array::uniform32(any::<u8>()), o in any::<u32>(), t in any::<u32>(), x in any::<u32>()) {
        if let Ok(ov) = parse(&r) {
            prop_assert_eq!(encode(ov), r);
        }
        let nz = |v: u32| if v == 0 { None } else { Some(v) };
        let ov = Overrides { objects: nz(o), tasks: nz(t), rt: nz(x) };
        prop_assert_eq!(parse(&encode(ov)), Ok(ov));
        let mut bad = encode(ov);
        bad[13] ^= 1;
        prop_assert_eq!(parse(&bad), Err(RecordError::BadReserved));
    }
}

/// Miri 固定序列：生产顺序、重复、缺依赖、失败阻断、容量记录损坏。
#[test]
fn fixed_sequence_under_miri() {
    let mut ops = Vec::new();
    for s in 0..Stage::COUNT as u8 {
        ops.extend([(0, s), (0, s), (1, s), (1, s)]);
    }
    drive(&ops);
    drive(&[(0, 5), (0, 0), (1, 0), (0, 1), (2, 1), (0, 2), (0, 8)]);
    assert!(graph_well_formed(&GRAPH));
    let mut r = encode(Overrides { objects: Some(4096), tasks: None, rt: Some(16) });
    assert_eq!(parse(&r).unwrap().tasks, None);
    r[0] = !RECORD_MAGIC[0];
    assert_eq!(parse(&r), Err(RecordError::BadMagic));
    let mut v = encode(Overrides::default());
    v[8] = 2;
    assert_eq!(parse(&v), Err(RecordError::BadVersion(2)));
    assert_eq!(v.len(), RECORD_LEN);
}
