//! Author: chatgpt. Bounded indexed deadline heap; no allocations or stale-node
//! accumulation. Caller owns boot-sized coherent storage and serializes access.
//! One entry per slot, generation-checked removal. Updating a reused generation
//! requires removing its previous entry first. Ordering is (deadline, slot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline { pub at: u64, pub slot: usize, pub generation: u64 }
impl Deadline { pub const EMPTY: Self = Self { at: 0, slot: usize::MAX, generation: 0 }; }
pub const ABSENT: usize = usize::MAX;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapError { Slot, Full, Stale, Corrupt }
#[derive(Debug)]
pub struct DeadlineHeap { len: usize }
impl Default for DeadlineHeap { fn default() -> Self { Self::new() } }
impl DeadlineHeap {
    /// positions must initially contain ABSENT; entries beyond len are ignored.
    pub const fn new() -> Self { Self { len: 0 } }
    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn next_at(&self, entries: &[Deadline]) -> Option<u64> {
        if self.len == 0 { None } else { entries.first().map(|e| e.at) }
    }
    fn key(e: Deadline) -> (u64, usize) { (e.at, e.slot) }
    fn swap(entries: &mut [Deadline], positions: &mut [usize], a: usize, b: usize) {
        entries.swap(a, b);
        positions[entries[a].slot] = a;
        positions[entries[b].slot] = b;
    }
    fn repair(&self, entries: &mut [Deadline], positions: &mut [usize], mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if Self::key(entries[parent]) <= Self::key(entries[i]) { break; }
            Self::swap(entries, positions, parent, i); i = parent;
        }
        loop {
            let Some(left) = i.checked_mul(2).and_then(|x| x.checked_add(1)) else { break };
            if left >= self.len { break; }
            let right = left + 1;
            let child = if right < self.len && Self::key(entries[right]) < Self::key(entries[left]) { right } else { left };
            if Self::key(entries[i]) <= Self::key(entries[child]) { break; }
            Self::swap(entries, positions, i, child); i = child;
        }
    }
    pub fn set(&mut self, entries: &mut [Deadline], positions: &mut [usize], e: Deadline) -> Result<(), HeapError> {
        let p = *positions.get(e.slot).ok_or(HeapError::Slot)?;
        if self.len > entries.len() { return Err(HeapError::Corrupt); }
        let i = if p == ABSENT {
            if self.len == entries.len() { return Err(HeapError::Full); }
            let i = self.len; self.len += 1; positions[e.slot] = i; i
        } else {
            if p >= self.len || entries[p].slot != e.slot { return Err(HeapError::Corrupt); }
            if entries[p].generation != e.generation { return Err(HeapError::Stale); }
            p
        };
        entries[i] = e;
        self.repair(entries, positions, i);
        Ok(())
    }
    pub fn remove(&mut self, entries: &mut [Deadline], positions: &mut [usize], slot: usize, generation: u64) -> Option<Deadline> {
        let i = *positions.get(slot)?;
        if self.len > entries.len() || i >= self.len || entries[i].slot != slot || entries[i].generation != generation { return None; }
        let removed = entries[i];
        self.len -= 1;
        positions[slot] = ABSENT;
        if i != self.len {
            entries[i] = entries[self.len];
            positions[entries[i].slot] = i;
            self.repair(entries, positions, i);
        }
        Some(removed)
    }
    pub fn pop_due(&mut self, entries: &mut [Deadline], positions: &mut [usize], now: u64) -> Option<Deadline> {
        if self.next_at(entries)? > now { return None; }
        let e = entries[0];
        self.remove(entries, positions, e.slot, e.generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn update_cancel_generation_and_boundaries() {
        let mut h = DeadlineHeap::new();
        let mut e = [Deadline::EMPTY; 2]; let mut p = [ABSENT; 3];
        let a = Deadline { at: u64::MAX, slot: 0, generation: u64::MAX };
        h.set(&mut e, &mut p, a).unwrap();
        assert!(h.pop_due(&mut e, &mut p, u64::MAX - 1).is_none());
        let before = (h.len(), e, p);
        assert_eq!(h.set(&mut e, &mut p, Deadline { generation: 0, ..a }), Err(HeapError::Stale));
        assert_eq!((h.len(), e, p), before);
        assert_eq!(h.remove(&mut e, &mut p, 0, 0), None);
        assert_eq!(h.pop_due(&mut e, &mut p, u64::MAX), Some(a));
        assert_eq!(h.next_at(&e), None);
        for slot in 0..2 { h.set(&mut e, &mut p, Deadline { slot, at: 10, generation: 1 }).unwrap(); }
        let before = (h.len(), e, p);
        assert_eq!(h.set(&mut e, &mut p, Deadline { slot: 2, at: 0, generation: 1 }), Err(HeapError::Full));
        assert_eq!((h.len(), e, p), before);
        assert_eq!(h.pop_due(&mut e, &mut p, 10).unwrap().slot, 0);
        assert_eq!(h.pop_due(&mut e, &mut p, 10).unwrap().slot, 1);
    }
    // Differential reference with fixed seed; failures shrink the operation
    // trace by removing operations, then print the minimal reproducible input.
    fn check(ops: &[u64]) -> Result<(), usize> {
        let mut h = DeadlineHeap::new();
        let mut entries = [Deadline::EMPTY; 8]; let mut positions = [ABSENT; 8];
        let mut reference = [None::<Deadline>; 8];
        for (step, &op) in ops.iter().enumerate() {
            let slot = ((op >> 8) as usize) % 8;
            let generation = (op >> 16) & 3;
            match op & 3 {
                0 | 1 => {
                    let e = Deadline { slot, generation, at: op >> 24 };
                    let expected = if reference[slot].is_some_and(|old| old.generation != generation) {
                        Err(HeapError::Stale)
                    } else { reference[slot] = Some(e); Ok(()) };
                    if h.set(&mut entries, &mut positions, e) != expected { return Err(step); }
                }
                2 => {
                    let expected = reference[slot].filter(|e| e.generation == generation);
                    if expected.is_some() { reference[slot] = None; }
                    if h.remove(&mut entries, &mut positions, slot, generation) != expected { return Err(step); }
                }
                _ => {
                    let now = op >> 24;
                    let expected = reference.iter().flatten().copied().min_by_key(|e| (e.at, e.slot)).filter(|e| e.at <= now);
                    if let Some(e) = expected { reference[e.slot] = None; }
                    if h.pop_due(&mut entries, &mut positions, now) != expected { return Err(step); }
                }
            }
            if h.len() != reference.iter().flatten().count() { return Err(step); }
            for (slot, expected) in reference.iter().enumerate() {
                if let Some(e) = expected {
                    if positions[slot] >= h.len() || entries[positions[slot]] != *e { return Err(step); }
                } else if positions[slot] != ABSENT { return Err(step); }
            }
            for i in 1..h.len() {
                if DeadlineHeap::key(entries[(i - 1) / 2]) > DeadlineHeap::key(entries[i]) { return Err(step); }
            }
            if h.next_at(&entries) != reference.iter().flatten().map(|e| e.at).min() { return Err(step); }
        }
        Ok(())
    }
    fn shrink(mut ops: std::vec::Vec<u64>) -> std::vec::Vec<u64> {
        let mut i = 0;
        while i < ops.len() {
            let mut candidate = ops.clone(); candidate.remove(i);
            if check(&candidate).is_err() { ops = candidate; i = 0; } else { i += 1; }
        }
        ops
    }
    #[test]
    fn seeded_differential_with_shrinking() {
        let mut seed = 0x4b52_4e32_4845_4150u64;
        let mut ops = std::vec::Vec::new();
        for _ in 0..20000 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; ops.push(seed);
        }
        if let Err(step) = check(&ops) { panic!("deadline seed=0x4b524e3248454150 step={step} minimal={:?}", shrink(ops[..=step].to_vec())); }
    }
}

/// First strictly future boundary of a periodic timer, preserving its phase.
/// None means period zero or the next boundary cannot be represented. Skipped
/// periods do not create accumulated budget grants. Author: chatgpt.
pub fn next_period(now: u64, previous: u64, period: u32) -> Option<u64> {
    if period == 0 { return None; }
    if previous > now { return Some(previous); }
    let steps = (now as u128 - previous as u128) / period as u128 + 1;
    u64::try_from(previous as u128 + steps * period as u128).ok()
}
#[cfg(test)]
mod periodic_tests {
    use super::next_period;
    #[test]
    fn phase_and_overflow_boundaries() {
        assert_eq!(next_period(0, 10, 5), Some(10));
        assert_eq!(next_period(10, 10, 5), Some(15));
        assert_eq!(next_period(27, 10, 5), Some(30));
        assert_eq!(next_period(u64::MAX, 0, 1), None);
        assert_eq!(next_period(0, 0, 0), None);
        assert_eq!(next_period(u64::MAX-1, u64::MAX-1, 1), Some(u64::MAX));
    }
    #[test]
    fn exhaustive_small_reference() {
        for previous in 0..32u64 { for now in 0..64u64 { for period in 1..16u32 {
            let mut expected = previous;
            while expected <= now { expected += period as u64; }
            assert_eq!(next_period(now, previous, period), Some(expected));
        } } }
    }
}
