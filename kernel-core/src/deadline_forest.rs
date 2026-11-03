//! Author: chatgpt. Serialized per-owner indexed heaps. One global slot may
//! appear in only one owner's heap; moving it removes the old node immediately.
//! Storage is C*N entries plus N positions and N owners, with no lazy nodes.
//! Caller initializes positions/owners to ABSENT and preserves coherent slices.
use crate::deadline::{Deadline, DeadlineHeap, HeapError, ABSENT};
pub struct DeadlineForest<const C: usize> { heaps: [DeadlineHeap; C] }
/// [`DeadlineForest::sync`] 的结果；除 `Unchanged` 外都写了一次堆。
/// Outcome of a sync; everything except `Unchanged` performed one heap write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncOutcome { Unchanged, Inserted, Rescheduled, Moved, Removed }
impl SyncOutcome {
    /// 是否写了堆存储 / whether heap storage was written.
    pub fn wrote(self) -> bool { self != SyncOutcome::Unchanged }
}
/// 一轮或多轮增量同步的计数：`synced` 次 sync 调用中，`unchanged` 次未写堆，其余按种类计。
/// 不变量：`synced == unchanged + inserted + rescheduled + moved + removed`。
/// Sync counters; invariant: synced equals the sum of all outcome counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncStats {
    /// 刷新轮数 / refresh passes.
    pub passes: u64,
    /// sync 调用数（=被检查的槽位数）/ sync calls (slots examined).
    pub synced: u64,
    pub unchanged: u64,
    pub inserted: u64,
    pub rescheduled: u64,
    pub moved: u64,
    pub removed: u64,
}
impl SyncStats {
    /// 记下一次 sync 结果（饱和计数）/ record one outcome (saturating).
    pub fn record(&mut self, outcome: SyncOutcome) {
        self.synced = self.synced.saturating_add(1);
        let c = match outcome {
            SyncOutcome::Unchanged => &mut self.unchanged,
            SyncOutcome::Inserted => &mut self.inserted,
            SyncOutcome::Rescheduled => &mut self.rescheduled,
            SyncOutcome::Moved => &mut self.moved,
            SyncOutcome::Removed => &mut self.removed,
        };
        *c = c.saturating_add(1);
    }
    /// 写堆次数 / heap writes.
    pub fn writes(&self) -> u64 {
        self.inserted.saturating_add(self.rescheduled).saturating_add(self.moved).saturating_add(self.removed)
    }
    /// 计数守恒（未饱和时成立）/ counter conservation while unsaturated.
    pub fn balanced(&self) -> bool { self.unchanged.checked_add(self.writes()) == Some(self.synced) }
}
impl<const C: usize> DeadlineForest<C> {
    pub const fn new() -> Self { Self { heaps: [const { DeadlineHeap::new() }; C] } }
    pub fn len(&self, cpu: usize) -> Option<usize> { self.heaps.get(cpu).map(DeadlineHeap::len) }
    fn shape(entries: &[Deadline], positions: &[usize], owners: &[usize]) -> Result<usize, HeapError> {
        let n = positions.len();
        if owners.len() != n || n.checked_mul(C) != Some(entries.len()) { return Err(HeapError::Corrupt); }
        Ok(n)
    }
    fn locate(&self, entries: &[Deadline], positions: &[usize], owners: &[usize], slot: usize)
        -> Result<Option<(usize, Deadline)>, HeapError> {
        let n = Self::shape(entries, positions, owners)?;
        let &cpu = owners.get(slot).ok_or(HeapError::Slot)?;
        if cpu == ABSENT {
            return if positions[slot] == ABSENT { Ok(None) } else { Err(HeapError::Corrupt) };
        }
        let heap = self.heaps.get(cpu).ok_or(HeapError::Corrupt)?;
        let p = positions[slot];
        if heap.len() > n || p >= heap.len() { return Err(HeapError::Corrupt); }
        let event = entries[cpu*n+p];
        if event.slot != slot { return Err(HeapError::Corrupt); }
        Ok(Some((cpu, event)))
    }
    pub fn peek(&self, entries: &[Deadline], positions: &[usize], owners: &[usize], cpu: usize)
        -> Result<Option<Deadline>, HeapError> {
        let n = Self::shape(entries, positions, owners)?;
        let heap = self.heaps.get(cpu).ok_or(HeapError::Slot)?;
        if heap.len() > n { return Err(HeapError::Corrupt); }
        if heap.is_empty() { return Ok(None); }
        let event = entries[cpu*n];
        if owners.get(event.slot) != Some(&cpu) || positions.get(event.slot) != Some(&0) { return Err(HeapError::Corrupt); }
        Ok(Some(event))
    }
    /// All rejecting branches precede mutation, including stale-generation moves.
    pub fn set(&mut self, entries: &mut [Deadline], positions: &mut [usize], owners: &mut [usize], cpu: usize, event: Deadline)
        -> Result<(), HeapError> {
        let n = Self::shape(entries, positions, owners)?;
        if cpu >= C { return Err(HeapError::Slot); }
        let old = self.locate(entries, positions, owners, event.slot)?;
        if old.is_some_and(|(_, e)| e.generation != event.generation) { return Err(HeapError::Stale); }
        if self.heaps[cpu].len() > n { return Err(HeapError::Corrupt); }
        if old.is_none_or(|(c, _)| c != cpu) && self.heaps[cpu].len() == n { return Err(HeapError::Full); }
        if let Some((old_cpu, _)) = old.filter(|(c, _)| *c != cpu) {
            self.heaps[old_cpu].remove(&mut entries[old_cpu*n..(old_cpu+1)*n], positions, event.slot, event.generation)
                .expect("validated source node");
            owners[event.slot] = ABSENT;
        }
        self.heaps[cpu].set(&mut entries[cpu*n..(cpu+1)*n], positions, event)?;
        owners[event.slot] = cpu;
        Ok(())
    }
    pub fn remove(&mut self, entries: &mut [Deadline], positions: &mut [usize], owners: &mut [usize], slot: usize, generation: u64)
        -> Result<Option<Deadline>, HeapError> {
        let n = Self::shape(entries, positions, owners)?;
        let Some((cpu, event)) = self.locate(entries, positions, owners, slot)? else { return Ok(None) };
        if event.generation != generation { return Err(HeapError::Stale); }
        let removed = self.heaps[cpu].remove(&mut entries[cpu*n..(cpu+1)*n], positions, slot, generation);
        assert_eq!(removed, Some(event));
        owners[slot] = ABSENT;
        Ok(removed)
    }
    /// 增量同步一个槽位的期限事件（issue #2）：`wanted` 为 `Some((owner_cpu, at))` 或 `None`。
    /// 现有节点与目标完全相同（同一所有者、同一时刻、同一代次），或两边都不存在时，
    /// 不写任何存储，返回 `Unchanged`；否则恰好做一次 set 或 remove。
    /// 现有节点代次不同 ⇒ `Stale`；越界 CPU/槽位、坏形状 ⇒ 对应错误；所有失败都不改状态。
    /// Incremental sync of one slot's deadline: identical (owner, at, generation)
    /// or absent-on-both-sides writes nothing; otherwise exactly one set/remove.
    /// Every failure leaves storage untouched.
    pub fn sync(&mut self, entries: &mut [Deadline], positions: &mut [usize], owners: &mut [usize],
        slot: usize, generation: u64, wanted: Option<(usize, u64)>) -> Result<SyncOutcome, HeapError> {
        let old = self.locate(entries, positions, owners, slot)?;
        if old.is_some_and(|(_, e)| e.generation != generation) { return Err(HeapError::Stale); }
        match (old, wanted) {
            (None, None) => Ok(SyncOutcome::Unchanged),
            (Some(_), None) => {
                self.remove(entries, positions, owners, slot, generation)?;
                Ok(SyncOutcome::Removed)
            }
            (Some((c, e)), Some((cpu, at))) if c == cpu && e.at == at => Ok(SyncOutcome::Unchanged),
            (old, Some((cpu, at))) => {
                self.set(entries, positions, owners, cpu, Deadline { at, slot, generation })?;
                Ok(match old {
                    None => SyncOutcome::Inserted,
                    Some((c, _)) if c == cpu => SyncOutcome::Rescheduled,
                    Some(_) => SyncOutcome::Moved,
                })
            }
        }
    }
    pub fn pop_due(&mut self, entries: &mut [Deadline], positions: &mut [usize], owners: &mut [usize], cpu: usize, now: u64)
        -> Result<Option<Deadline>, HeapError> {
        let Some(event) = self.peek(entries, positions, owners, cpu)? else { return Ok(None) };
        if event.at > now { return Ok(None); }
        self.remove(entries, positions, owners, event.slot, event.generation)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn move_reject_stale_cancel_and_last_timestamp() {
        let mut h = DeadlineForest::<2>::new();
        let mut e = [Deadline::EMPTY; 4]; let mut p = [ABSENT; 2]; let mut o = [ABSENT; 2];
        let a = Deadline { slot: 0, at: u64::MAX, generation: u64::MAX };
        h.set(&mut e, &mut p, &mut o, 0, a).unwrap();
        let snapshot = (e,p,o);
        assert_eq!(h.set(&mut e, &mut p, &mut o, 1, Deadline { generation: 0, ..a }), Err(HeapError::Stale));
        assert_eq!((e,p,o), snapshot);
        h.set(&mut e, &mut p, &mut o, 1, a).unwrap();
        assert_eq!(h.peek(&e,&p,&o,0), Ok(None));
        assert_eq!(h.pop_due(&mut e,&mut p,&mut o,1,u64::MAX-1), Ok(None));
        assert_eq!(h.pop_due(&mut e,&mut p,&mut o,1,u64::MAX), Ok(Some(a)));
        assert_eq!(p, [ABSENT;2]); assert_eq!(o, [ABSENT;2]);
        assert_eq!(h.set(&mut e[..3],&mut p,&mut o,0,a), Err(HeapError::Corrupt));
        assert_eq!(h.set(&mut e,&mut p,&mut o,2,a), Err(HeapError::Slot));
        let mut z = DeadlineForest::<0>::new();
        assert_eq!(z.set(&mut [],&mut [],&mut [],0,a), Err(HeapError::Slot));
    }
    #[derive(Clone, Copy, Debug)]
    enum Op { Set(usize, Deadline), Remove(usize,u64), Pop(usize,u64) }
    fn replay(ops: &[Op]) -> Result<(), &'static str> {
        let mut h = DeadlineForest::<3>::new();
        let mut e = [Deadline::EMPTY; 24]; let mut p = [ABSENT;8]; let mut o = [ABSENT;8];
        let mut reference: [Option<(usize,Deadline)>;8] = [None;8];
        for &op in ops {
            let before = (e,p,o,[h.len(0),h.len(1),h.len(2)]);
            let failed = match op {
                Op::Set(c,event) => {
                    let expected = if c >= 3 || event.slot >= 8 { Err(HeapError::Slot) }
                        else if reference[event.slot].is_some_and(|(_,old)| old.generation != event.generation) { Err(HeapError::Stale) } else { Ok(()) };
                    let actual = h.set(&mut e,&mut p,&mut o,c,event);
                    if actual != expected { return Err("set result"); }
                    if expected.is_ok() { reference[event.slot] = Some((c,event)); }
                    actual.is_err()
                }
                Op::Remove(s,g) => {
                    let expected = if s >= 8 { Err(HeapError::Slot) }
                        else if reference[s].is_some_and(|(_,old)| old.generation != g) { Err(HeapError::Stale) }
                        else { Ok(reference[s].map(|(_,old)|old)) };
                    let actual = h.remove(&mut e,&mut p,&mut o,s,g);
                    if actual != expected { return Err("remove result"); }
                    if actual.is_ok() && s < 8 { reference[s] = None; }
                    actual.is_err()
                }
                Op::Pop(c,now) => {
                    let expected = if c >= 3 { Err(HeapError::Slot) } else { Ok(reference.iter().flatten().filter(|(owner,_)| *owner == c)
                        .map(|(_,old)|*old).min_by_key(|old|(old.at,old.slot)).filter(|old|old.at <= now)) };
                    let actual = h.pop_due(&mut e,&mut p,&mut o,c,now);
                    if actual != expected { return Err("pop result"); }
                    if let Ok(Some(old)) = actual { reference[old.slot] = None; }
                    actual.is_err()
                }
            };
            if failed && before != (e,p,o,[h.len(0),h.len(1),h.len(2)]) { return Err("failure mutation"); }
            for c in 0..3 {
                let wanted = reference.iter().flatten().filter(|(owner,_)|*owner == c).map(|(_,old)|*old).min_by_key(|old|(old.at,old.slot));
                if h.peek(&e,&p,&o,c) != Ok(wanted) { return Err("minimum"); }
                if h.len(c) != Some(reference.iter().flatten().filter(|(owner,_)|*owner==c).count()) { return Err("count"); }
            }
            for s in 0..8 {
                match reference[s] {
                    Some((c,event)) => if o[s] != c || p[s] >= h.len(c).unwrap() || e[c*8+p[s]] != event { return Err("slot ownership"); },
                    None => if o[s] != ABSENT || p[s] != ABSENT { return Err("absent"); },
                }
            }
        }
        Ok(())
    }
    #[test]
    fn fixed_seed_reference_and_deletion_shrink() {
        const SEED:u64 = 0x44454144464f5231;
        let mut seed=SEED; let mut ops=std::vec::Vec::new();
        for _ in 0..20_000 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            let c=(seed>>4) as usize % 4; let s=(seed>>8) as usize % 10; let g=(seed>>12)%3;
            let at=if seed%31==0 {u64::MAX} else {(seed>>16)%32};
            ops.push(match seed%3 {0=>Op::Set(c,Deadline{slot:s,at,generation:g}),1=>Op::Remove(s,g),_=>Op::Pop(c,at)});
        }
        if let Err(error)=replay(&ops) {
            let mut chunk=ops.len()/2;
            while chunk>0 {
                let mut start=0;
                while start<ops.len() {
                    let mut candidate=ops.clone(); candidate.drain(start..(start+chunk).min(candidate.len()));
                    if replay(&candidate).is_err() {ops=candidate;} else {start+=chunk;}
                }
                chunk/=2;
            }
            panic!("seed={SEED:#x}, {error}, reduced={ops:?}");
        }
    }
    /// sync 与独立参考模型差分：结果种类、错误不改状态、Unchanged 不写任何存储、计数守恒。
    #[test]
    fn sync_matches_reference_and_unchanged_writes_nothing() {
        let mut h = DeadlineForest::<3>::new();
        let mut e = [Deadline::EMPTY; 24]; let mut p = [ABSENT;8]; let mut o = [ABSENT;8];
        let mut reference: [Option<(usize,Deadline)>;8] = [None;8];
        let mut stats = SyncStats::default();
        let mut seed = 0x5359_4e43_4e53_4556u64;
        for _ in 0..20_000 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            let s = (seed>>8) as usize % 9; let g = (seed>>12)%3; let c = (seed>>16) as usize % 4;
            let wanted = if seed % 5 == 0 { None } else { Some((c, (seed>>20)%6)) };
            let before = (e,p,o,[h.len(0),h.len(1),h.len(2)]);
            let expected = if s >= 8 { Err(HeapError::Slot) }
                else if reference[s].is_some_and(|(_,old)| old.generation != g) { Err(HeapError::Stale) }
                else { match (reference[s], wanted) {
                    (None, None) => Ok(SyncOutcome::Unchanged),
                    (Some(_), None) => Ok(SyncOutcome::Removed),
                    (_, Some((cpu,_))) if cpu >= 3 => Err(HeapError::Slot),
                    (Some((oc,old)), Some((cpu,at))) if oc == cpu && old.at == at => Ok(SyncOutcome::Unchanged),
                    (None, Some(_)) => Ok(SyncOutcome::Inserted),
                    (Some((oc,_)), Some((cpu,_))) => Ok(if oc == cpu { SyncOutcome::Rescheduled } else { SyncOutcome::Moved }),
                } };
            let actual = h.sync(&mut e,&mut p,&mut o,s,g,wanted);
            assert_eq!(actual, expected, "slot={s} gen={g} wanted={wanted:?}");
            match actual {
                Ok(outcome) => {
                    stats.record(outcome);
                    if !outcome.wrote() { assert_eq!(before, (e,p,o,[h.len(0),h.len(1),h.len(2)]), "unchanged must not write"); }
                    reference[s] = wanted.map(|(cpu,at)| (cpu, Deadline { at, slot: s, generation: g }));
                }
                Err(_) => assert_eq!(before, (e,p,o,[h.len(0),h.len(1),h.len(2)]), "failure must not write"),
            }
            for cpu in 0..3 {
                let min = reference.iter().flatten().filter(|(owner,_)|*owner==cpu).map(|(_,d)|*d).min_by_key(|d|(d.at,d.slot));
                assert_eq!(h.peek(&e,&p,&o,cpu), Ok(min));
            }
        }
        assert!(stats.balanced() && stats.unchanged > 0 && stats.writes() > 0, "{stats:?}");
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    fn small() -> u64 { u64::from(kani::any::<u8>()) }
    type Snap = ([Deadline; 4], [usize; 2], [usize; 2], Option<usize>, Option<usize>);
    /// 逐元素比较（避免数组比较落到 memcmp 字节循环）/ element-wise, avoids memcmp unwinding.
    fn same(a: &Snap, b: &Snap) -> bool {
        a.0[0] == b.0[0] && a.0[1] == b.0[1] && a.0[2] == b.0[2] && a.0[3] == b.0[3]
            && a.1[0] == b.1[0] && a.1[1] == b.1[1] && a.2[0] == b.2[0] && a.2[1] == b.2[1]
            && a.3 == b.3 && a.4 == b.4
    }
    /// 两核两槽、至多一个已存在节点；时刻与代次取 8 位值域（有界）。
    /// 位置（槽、核）逐例枚举、不用符号值：符号下标的乘除让 CBMC 公式膨胀到 10 GB 以上。
    fn world(pre: Option<(usize, usize)>) -> (DeadlineForest<2>, [Deadline; 4], [usize; 2], [usize; 2]) {
        let mut h = DeadlineForest::<2>::new();
        let mut e = [Deadline::EMPTY; 4]; let mut p = [ABSENT; 2]; let mut o = [ABSENT; 2];
        if let Some((pre_slot, pre_cpu)) = pre {
            h.set(&mut e, &mut p, &mut o, pre_cpu, Deadline { at: small(), slot: pre_slot, generation: small() }).unwrap();
        }
        (h, e, p, o)
    }
    /// 枚举目标槽（含越界的 2）与目标核（不要、0、1、越界的 2），每一分支都是具体下标。
    fn each_target(check: impl Fn(usize, Option<usize>)) {
        match kani::any::<u8>() {
            0 => check(0, None), 1 => check(0, Some(0)), 2 => check(0, Some(1)), 3 => check(0, Some(2)),
            4 => check(1, None), 5 => check(1, Some(0)), 6 => check(1, Some(1)), 7 => check(1, Some(2)),
            8 => check(2, None), 9 => check(2, Some(0)), 10 => check(2, Some(1)), _ => check(2, Some(2)),
        }
    }
    /// sync 返回 Unchanged 或失败时不写任何存储。
    fn unchanged_or_failed_never_writes(pre: Option<(usize, usize)>) {
        each_target(|slot, cpu| {
            let (mut h, mut e, mut p, mut o) = world(pre);
            let before = (e, p, o, h.len(0), h.len(1));
            let r = h.sync(&mut e, &mut p, &mut o, slot, small(), cpu.map(|c| (c, small())));
            if r.is_err() || r == Ok(SyncOutcome::Unchanged) { assert!(same(&before, &(e, p, o, h.len(0), h.len(1)))); }
        });
    }
    /// sync 成功后该槽恰好按目标发布，且只在一个所有者堆中（迁移不留旧节点）。
    fn success_publishes_target_in_one_heap(pre: Option<(usize, usize)>) {
        each_target(|slot, cpu| {
            let (mut h, mut e, mut p, mut o) = world(pre);
            let (generation, at) = (small(), small());
            if h.sync(&mut e, &mut p, &mut o, slot, generation, cpu.map(|c| (c, at))).is_ok() {
                match cpu {
                    None => assert!(o[slot] == ABSENT && p[slot] == ABSENT),
                    Some(c) => {
                        assert!(o[slot] == c);
                        let d = e[c * 2 + p[slot]];
                        assert!(d.slot == slot && d.at == at && d.generation == generation);
                        let other = pre.is_some_and(|(pre_slot, _)| pre_slot != slot && o[pre_slot] == 1 - c);
                        assert!(h.len(1 - c) == Some(usize::from(other)));
                    }
                }
            }
        });
    }
    #[kani::proof] #[kani::unwind(5)] fn sync_unchanged_empty() { unchanged_or_failed_never_writes(None); }
    #[kani::proof] #[kani::unwind(5)] fn sync_unchanged_s0_c0() { unchanged_or_failed_never_writes(Some((0, 0))); }
    #[kani::proof] #[kani::unwind(5)] fn sync_unchanged_s0_c1() { unchanged_or_failed_never_writes(Some((0, 1))); }
    #[kani::proof] #[kani::unwind(5)] fn sync_unchanged_s1_c0() { unchanged_or_failed_never_writes(Some((1, 0))); }
    #[kani::proof] #[kani::unwind(5)] fn sync_unchanged_s1_c1() { unchanged_or_failed_never_writes(Some((1, 1))); }
    #[kani::proof] #[kani::unwind(5)] fn sync_success_empty() { success_publishes_target_in_one_heap(None); }
    #[kani::proof] #[kani::unwind(5)] fn sync_success_s0_c0() { success_publishes_target_in_one_heap(Some((0, 0))); }
    #[kani::proof] #[kani::unwind(5)] fn sync_success_s0_c1() { success_publishes_target_in_one_heap(Some((0, 1))); }
    #[kani::proof] #[kani::unwind(5)] fn sync_success_s1_c0() { success_publishes_target_in_one_heap(Some((1, 0))); }
    #[kani::proof] #[kani::unwind(5)] fn sync_success_s1_c1() { success_publishes_target_in_one_heap(Some((1, 1))); }
    /// 既有 set（补链）：代次不同的节点不能被改期或迁移，拒绝时存储不变。
    #[kani::proof]
    #[kani::unwind(5)]
    fn set_rejects_stale_generation_atomically() {
        fn check(slot: usize, c0: usize, c1: usize) {
            let mut h = DeadlineForest::<2>::new();
            let mut e = [Deadline::EMPTY; 4]; let mut p = [ABSENT; 2]; let mut o = [ABSENT; 2];
            let old = Deadline { at: small(), slot, generation: small() };
            h.set(&mut e, &mut p, &mut o, c0, old).unwrap();
            let generation = small(); kani::assume(generation != old.generation);
            let before = (e, p, o, h.len(0), h.len(1));
            assert!(h.set(&mut e, &mut p, &mut o, c1, Deadline { at: small(), slot, generation }) == Err(HeapError::Stale));
            assert!(same(&before, &(e, p, o, h.len(0), h.len(1))));
        }
        match kani::any::<u8>() {
            0 => check(0, 0, 0), 1 => check(0, 0, 1), 2 => check(0, 1, 0), 3 => check(0, 1, 1),
            4 => check(1, 0, 0), 5 => check(1, 0, 1), 6 => check(1, 1, 0), _ => check(1, 1, 1),
        }
    }
    /// 既有 pop_due（补链）：两节点同核时先弹出 (at, slot) 最小者，且只在已到期时弹出。
    #[kani::proof]
    #[kani::unwind(5)]
    fn pop_due_returns_earliest_only_when_due() {
        let mut h = DeadlineForest::<2>::new();
        let mut e = [Deadline::EMPTY; 4]; let mut p = [ABSENT; 2]; let mut o = [ABSENT; 2];
        let a = Deadline { at: small(), slot: 0, generation: small() };
        let b = Deadline { at: small(), slot: 1, generation: small() };
        h.set(&mut e, &mut p, &mut o, 1, a).unwrap();
        h.set(&mut e, &mut p, &mut o, 1, b).unwrap();
        let now = small();
        let first = if (a.at, a.slot) <= (b.at, b.slot) { a } else { b };
        let got = h.pop_due(&mut e, &mut p, &mut o, 1, now).unwrap();
        if first.at <= now { assert!(got == Some(first) && o[first.slot] == ABSENT); } else { assert!(got.is_none() && h.len(1) == Some(2)); }
    }
}
