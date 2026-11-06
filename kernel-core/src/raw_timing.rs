//! Author: chatgpt. Bounded raw diagnostic storage; no clocks or synchronization.
//! The caller must serialize access. No sample is silently overwritten. Raw
//! counters are retained even when CPU identity or counter order forbids a delta.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockDomain {
    /// Architecture counter without a cross-CPU synchronization claim.
    Raw,
    /// Serialized, boot-calibrated shared nanosecond domain. Cross-CPU
    /// comparability remains a platform assumption that TCG cannot prove.
    SharedNs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint { pub cpu: usize, pub counter: u64, pub clock: ClockDomain }
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
        if self.start.clock != ClockDomain::Raw || self.end.clock != ClockDomain::Raw
            || self.start.cpu != self.end.cpu { return None; }
        self.end.counter.checked_sub(self.start.counter)
    }

    /// Delta in the calibrated shared nanosecond domain. Unlike raw counters,
    /// this may cross CPUs, subject to the platform's synchronized-counter
    /// assumption.
    pub fn shared_ns_delta(&self) -> Option<u64> {
        if self.start.clock != ClockDomain::SharedNs || self.end.clock != ClockDomain::SharedNs {
            return None;
        }
        self.end.counter.checked_sub(self.start.counter)
    }
}

/// 一个高精度期限唤醒的五个中间端点；期限本身是第六个时间点。
/// Five intermediate endpoints for one high-resolution deadline wake; the
/// deadline timestamp itself is the sixth point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeadlineTimeline {
    pub deadline: Endpoint,
    pub interrupt_entry: Endpoint,
    pub lock_acquired: Endpoint,
    pub wake_start: Endpoint,
    pub queue_published: Endpoint,
}

impl DeadlineTimeline {
    /// 只接受同一共享纳秒时钟上的非递减端点。失败样本不得进入任何直方图。
    /// Accepts only nondecreasing endpoints from the shared nanosecond clock.
    pub fn new(
        deadline: Endpoint,
        interrupt_entry: Endpoint,
        lock_acquired: Endpoint,
        wake_start: Endpoint,
        queue_published: Endpoint,
    ) -> Option<Self> {
        let points = [deadline, interrupt_entry, lock_acquired, wake_start, queue_published];
        let shared = points
            .iter()
            .all(|p| p.clock == ClockDomain::SharedNs);
        let ordered = points
            .windows(2)
            .all(|w| w[0].counter <= w[1].counter);
        (shared && ordered).then_some(Self {
            deadline,
            interrupt_entry,
            lock_acquired,
            wake_start,
            queue_published,
        })
    }

    /// 队列发布后即可观测的四个累计区间：期限到中断、取锁、唤醒起点和发布。
    /// Four cumulative intervals observable once the queue publication is complete.
    pub fn samples_to_published(
        &self,
        slot: usize,
        generation: u64,
        wait_round: u64,
    ) -> [Sample; 4] {
        let make = |path, end| Sample {
            path,
            slot,
            generation,
            wait_round,
            start: self.deadline,
            end,
        };
        [
            make(5, self.interrupt_entry),
            make(6, self.lock_acquired),
            make(7, self.wake_start),
            make(8, self.queue_published),
        ]
    }

    /// 恢复端点仍须在同一共享时钟上且不早于队列发布。
    /// The resume endpoint must share the clock and follow queue publication.
    pub fn sample_to_resume(
        &self,
        slot: usize,
        generation: u64,
        wait_round: u64,
        resume: Endpoint,
    ) -> Option<Sample> {
        (resume.clock == ClockDomain::SharedNs
            && self.deadline.clock == ClockDomain::SharedNs
            && resume.counter >= self.queue_published.counter)
            .then_some(Sample {
                path: 9,
                slot,
                generation,
                wait_round,
                start: self.deadline,
                end: resume,
            })
    }
}

/// Ten-microsecond buckets up to `(N-2)*10` us, with the final bucket retaining
/// all larger observations and the exact maximum. This records every completed
/// sample without allocating or replacing earlier observations while keeping
/// the boot-time scheduler object bounded.
#[derive(Clone, Copy)]
pub struct NanoHistogram<const N: usize> {
    buckets: [u64; N],
    count: u64,
    invalid: u64,
    max_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NanoSummary {
    pub count: u64,
    pub invalid: u64,
    pub p50_us: u64,
    pub p99_us: u64,
    pub p999_us: u64,
    pub max_ns: u64,
}

/// 六个期限唤醒时间点对应的累计延迟汇总。
/// Cumulative summaries for the six deadline-to-resume points.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakePhaseSummaries {
    pub deadline_to_interrupt: NanoSummary,
    pub deadline_to_lock: NanoSummary,
    pub deadline_to_wake: NanoSummary,
    pub deadline_to_runnable: NanoSummary,
    pub deadline_to_resume: NanoSummary,
    pub late_settlement: u64,
    pub early_timer: u64,
    pub invalid_order: u64,
    pub invalid_resume: u64,
}

impl<const N: usize> NanoHistogram<N> {
    pub const fn new() -> Self {
        Self { buckets: [0; N], count: 0, invalid: 0, max_ns: 0 }
    }

    pub fn record(&mut self, sample: &Sample) {
        let Some(ns) = sample.shared_ns_delta() else {
            self.invalid = self.invalid.saturating_add(1);
            return;
        };
        if N == 0 {
            self.invalid = self.invalid.saturating_add(1);
            return;
        }
        let ten_us = ns.div_ceil(10_000);
        let bucket = usize::try_from(ten_us).unwrap_or(usize::MAX).min(N - 1);
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.max_ns = self.max_ns.max(ns);
    }

    fn percentile_us(&self, permille: u64) -> u64 {
        if self.count == 0 || N == 0 { return 0; }
        let need = (u128::from(self.count) * u128::from(permille.min(1_000)))
            .div_ceil(1_000).max(1) as u64;
        let mut seen = 0u64;
        for (i, n) in self.buckets.iter().copied().enumerate() {
            seen = seen.saturating_add(n);
            if seen >= need {
                return if i == N - 1 { self.max_ns.div_ceil(1_000) } else { i as u64 * 10 };
            }
        }
        self.max_ns.div_ceil(1_000)
    }

    pub fn summary(&self) -> NanoSummary {
        NanoSummary {
            count: self.count,
            invalid: self.invalid,
            p50_us: self.percentile_us(500),
            p99_us: self.percentile_us(990),
            p999_us: self.percentile_us(999),
            max_ns: self.max_ns,
        }
    }
}

impl<const N: usize> Default for NanoHistogram<N> {
    fn default() -> Self { Self::new() }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn shared(counter: u64) -> Endpoint {
        Endpoint {
            cpu: 1,
            counter,
            clock: ClockDomain::SharedNs,
        }
    }

    #[kani::proof]
    fn ordered_shared_timeline_preserves_all_six_points() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        let c: u64 = kani::any();
        let d: u64 = kani::any();
        let e: u64 = kani::any();
        kani::assume(a <= b && b <= c && c <= d && d <= e);
        let timeline = DeadlineTimeline::new(shared(a), shared(b), shared(c), shared(d), shared(e))
            .expect("ordered shared timeline");
        let samples = timeline.samples_to_published(3, 7, 11);
        assert_eq!(samples[0].end.counter, b);
        assert_eq!(samples[1].end.counter, c);
        assert_eq!(samples[2].end.counter, d);
        assert_eq!(samples[3].end.counter, e);
        assert_eq!(samples[0].start.counter, a);
        assert_eq!(
            timeline.sample_to_resume(3, 7, 11, shared(e)).unwrap().end.counter,
            e
        );
    }

    #[kani::proof]
    fn reversed_endpoint_is_rejected() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        kani::assume(b < a);
        assert!(DeadlineTimeline::new(
            shared(a),
            shared(b),
            shared(a),
            shared(a),
            shared(a),
        )
        .is_none());
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
            start: Endpoint { cpu: 1, counter, clock: ClockDomain::Raw },
            end: Endpoint { cpu: 1, counter: counter + 1, clock: ClockDomain::Raw } }
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

    #[test]
    fn shared_histogram_is_complete_and_reports_p999() {
        let mut hist = NanoHistogram::<2049>::new();
        for n in 1..=2_000u64 {
            let sample = Sample {
                path: 3, slot: 1, generation: 2, wait_round: n,
                start: Endpoint { cpu: 0, counter: 10_000, clock: ClockDomain::SharedNs },
                end: Endpoint { cpu: (n as usize) & 1, counter: 10_000 + n * 1_000,
                    clock: ClockDomain::SharedNs },
            };
            hist.record(&sample);
        }
        let s = hist.summary();
        assert_eq!(s.count, 2_000);
        assert_eq!(s.invalid, 0);
        assert_eq!(s.p50_us, 1_000);
        assert_eq!(s.p99_us, 1_980);
        assert_eq!(s.p999_us, 2_000);
        assert_eq!(s.max_ns, 2_000_000);
        let mut raw = sample(1);
        raw.start.clock = ClockDomain::SharedNs;
        hist.record(&raw);
        assert_eq!(hist.summary().invalid, 1);
    }

    #[test]
    fn deadline_timeline_requires_clock_and_order() {
        let point = |counter| Endpoint {
            cpu: 3,
            counter,
            clock: ClockDomain::SharedNs,
        };
        let timeline = DeadlineTimeline::new(
            point(100),
            point(120),
            point(140),
            point(170),
            point(190),
        )
        .expect("ordered shared timeline");
        let samples = timeline.samples_to_published(7, 9, 11);
        assert_eq!(samples.map(|s| s.path), [5, 6, 7, 8]);
        assert_eq!(
            samples.map(|s| s.shared_ns_delta().unwrap()),
            [20, 40, 70, 90]
        );
        assert_eq!(
            timeline
                .sample_to_resume(7, 9, 11, point(220))
                .unwrap()
                .shared_ns_delta(),
            Some(120)
        );
        assert!(timeline.sample_to_resume(7, 9, 11, point(189)).is_none());

        assert!(DeadlineTimeline::new(
            point(100),
            point(99),
            point(140),
            point(170),
            point(190),
        )
        .is_none());
        let mut raw = point(120);
        raw.clock = ClockDomain::Raw;
        assert!(DeadlineTimeline::new(
            point(100),
            raw,
            point(140),
            point(170),
            point(190),
        )
        .is_none());
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
        let start = Endpoint { cpu: 0, counter: 100, clock: ClockDomain::Raw };
        let end = Endpoint { cpu: 1, counter: 90, clock: ClockDomain::Raw };
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
