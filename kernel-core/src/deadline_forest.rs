//! Author: chatgpt. Serialized per-owner indexed heaps. One global slot may
//! appear in only one owner's heap; moving it removes the old node immediately.
//! Storage is C*N entries plus N positions and N owners, with no lazy nodes.
//! Caller initializes positions/owners to ABSENT and preserves coherent slices.
use crate::deadline::{Deadline, DeadlineHeap, HeapError, ABSENT};
pub struct DeadlineForest<const C: usize> { heaps: [DeadlineHeap; C] }
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
}
