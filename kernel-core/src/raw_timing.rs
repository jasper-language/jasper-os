//! Author: chatgpt. Bounded raw diagnostic storage; no clocks or synchronization.
//! The caller must serialize access. No sample is silently overwritten. Raw
//! counters are retained even when CPU identity or counter order forbids a delta.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint { pub cpu: usize, pub counter: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub path: u16,
    pub slot: usize,
    pub generation: u64,
    pub wait_round: u64,
    pub start: Endpoint,
    pub end: Endpoint,
}
impl Sample {
    /// Merely a same-CPU, nondecreasing raw counter difference. This does not
    /// establish instruction serialization, counter calibration, or wall time.
    pub fn local_delta(&self) -> Option<u64> {
        if self.start.cpu != self.end.cpu { return None; }
        self.end.counter.checked_sub(self.start.counter)
    }
}

#[derive(Clone, Copy)]
pub struct Samples<const N: usize> {
    entries: [Option<Sample>; N],
    len: usize,
    dropped: u64,
}
impl<const N: usize> Default for Samples<N> { fn default() -> Self { Self::new() } }
impl<const N: usize> Samples<N> {
    pub const fn new() -> Self { Self { entries: [None; N], len: 0, dropped: 0 } }
    /// Returns the rejected original sample when full; never overwrites history.
    /// Dropped count saturates, so u64::MAX means at least that many rejections.
    pub fn push(&mut self, sample: Sample) -> Result<(), Sample> {
        if self.len == N {
            self.dropped = self.dropped.saturating_add(1);
            return Err(sample);
        }
        self.entries[self.len] = Some(sample);
        self.len += 1;
        Ok(())
    }
    pub fn entries(&self) -> &[Option<Sample>] { &self.entries[..self.len] }
    pub fn dropped(&self) -> u64 { self.dropped }
    pub fn complete(&self) -> bool { self.dropped == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(counter: u64) -> Sample {
        Sample { path: 3, slot: 7, generation: 9, wait_round: 11,
            start: Endpoint { cpu: 1, counter }, end: Endpoint { cpu: 1, counter: counter + 1 } }
    }
    #[test]
    fn identity_and_invalid_endpoints_are_preserved() {
        let mut store = Samples::<3>::new();
        let mut migrated = sample(100); migrated.end.cpu = 2;
        let mut backwards = sample(100); backwards.end.counter = 99;
        for s in [sample(100), migrated, backwards] { assert_eq!(store.push(s), Ok(())); }
        assert_eq!(store.entries(), &[Some(sample(100)), Some(migrated), Some(backwards)]);
        assert_eq!(sample(100).local_delta(), Some(1));
        assert_eq!(migrated.local_delta(), None);
        assert_eq!(backwards.local_delta(), None);
        assert!(store.complete());
        let mut edge = sample(0); edge.end.counter = u64::MAX;
        assert_eq!(edge.local_delta(), Some(u64::MAX));
    }
    #[test]
    fn full_zero_capacity_and_counter_saturation() {
        let mut zero = Samples::<0>::new();
        assert_eq!(zero.push(sample(1)), Err(sample(1)));
        assert_eq!(zero.entries(), &[]); assert_eq!(zero.dropped(), 1);
        assert!(!zero.complete());
        let mut one = Samples::<1>::new();
        assert_eq!(one.push(sample(1)), Ok(()));
        for n in 2..100 { assert_eq!(one.push(sample(n)), Err(sample(n))); }
        assert_eq!(one.entries(), &[Some(sample(1))]); assert_eq!(one.dropped(), 98);
        one.dropped = u64::MAX;
        assert_eq!(one.push(sample(3)), Err(sample(3)));
        assert_eq!(one.dropped(), u64::MAX);
    }
}

/// Author: chatgpt. Serialized diagnostic pairing for one task incarnation.
/// Caller owns the Token lifecycle. A new begin never overwrites pending data.
#[derive(Clone, Copy)]
pub struct WakePair { sequence: u64, pending: Option<Sample> }
impl Default for WakePair { fn default() -> Self { Self::new() } }
impl WakePair {
    pub const fn new() -> Self { Self { sequence: 0, pending: None } }
    pub fn begin(&mut self, token: crate::task_index::Token, start: Endpoint) -> Option<u64> {
        if self.pending.is_some() { return None; }
        let Some(round) = self.sequence.checked_add(1) else { return None; };
        self.sequence = round;
        self.pending = Some(Sample { path: 2, slot: token.slot, generation: token.generation,
            wait_round: round, start, end: start });
        Some(round)
    }
    pub fn finish(&mut self, token: crate::task_index::Token, round: u64, end: Endpoint) -> Option<Sample> {
        let pending = self.pending?;
        if pending.slot != token.slot || pending.generation != token.generation || pending.wait_round != round { return None; }
        let mut sample = self.pending.take()?;
        sample.end = end;
        Some(sample)
    }
}
#[cfg(test)]
mod wake_tests {
    use super::*;
    use crate::task_index::Token;
    #[test]
    fn duplicate_stale_and_repeated_rounds() {
        let token = Token { slot: 7, generation: 9 };
        let stale = Token { slot: 7, generation: 8 };
        let start = Endpoint { cpu: 0, counter: 100 };
        let end = Endpoint { cpu: 1, counter: 90 };
        let mut pair = WakePair::new();
        for round in 1..=100 {
            assert_eq!(pair.begin(token, start), Some(round));
            assert_eq!(pair.begin(stale, end), None);
            assert_eq!(pair.finish(stale, round, end), None);
            assert_eq!(pair.finish(token, round - 1, end), None);
            let s = pair.finish(token, round, end).unwrap();
            assert_eq!((s.slot,s.generation,s.wait_round,s.path), (7,9,round,2));
            assert_eq!((s.start,s.end), (start,end));
            assert_eq!(s.local_delta(), None);
            assert_eq!(pair.finish(token, round, end), None);
        }
        pair.sequence = u64::MAX;
        assert_eq!(pair.begin(token,start),None);
        assert_eq!(pair.finish(token,100,end),None);
    }
}
