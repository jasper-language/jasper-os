//! Host benchmark and differential check for the ordinary-timeout storage decision.
//!
//! The production candidate is the existing fixed-capacity indexed deadline heap.
//! The comparison candidate is a fixed-capacity, three-level hierarchical wheel.
//! It is test-only: no public timer backend is added and no production object stores
//! duplicate authoritative state. Both implementations receive the same deterministic
//! deadlines and cancellation set, and must emit the same surviving slots.

use std::hint::black_box;
use std::time::{Duration, Instant};

use kernel_core::deadline::{Deadline, DeadlineHeap, ABSENT};

const BITS: usize = 6;
const BUCKETS: usize = 1 << BITS;
const MASK: usize = BUCKETS - 1;
const LEVELS: usize = 3;

struct HeapCandidate {
    heap: DeadlineHeap,
    entries: Vec<Deadline>,
    positions: Vec<usize>,
}

impl HeapCandidate {
    fn new(n: usize) -> Self {
        Self {
            heap: DeadlineHeap::new(),
            entries: vec![Deadline::EMPTY; n],
            positions: vec![ABSENT; n],
        }
    }

    fn set(&mut self, slot: usize, at: u64) {
        self.heap
            .set(
                &mut self.entries,
                &mut self.positions,
                Deadline {
                    at,
                    slot,
                    generation: 1,
                },
            )
            .unwrap();
    }

    fn remove(&mut self, slot: usize) {
        assert!(self
            .heap
            .remove(&mut self.entries, &mut self.positions, slot, 1)
            .is_some());
    }

    fn drain_step(&mut self, now: u64, expired: &mut usize) {
        while self
            .heap
            .pop_due(&mut self.entries, &mut self.positions, now)
            .is_some()
        {
            *expired += 1;
        }
    }

    fn memory_bytes(n: usize) -> usize {
        std::mem::size_of::<Self>()
            + n * std::mem::size_of::<Deadline>()
            + n * std::mem::size_of::<usize>()
    }
}

/// Fixed-capacity hierarchical wheel. A coarse bucket is visited only at its
/// boundary and promotes its entries to finer buckets; finer buckets are visited
/// once per logical tick. Lists are intrusive, so cancellation is O(1).
struct WheelCandidate {
    heads: [[isize; BUCKETS]; LEVELS],
    next: Vec<isize>,
    prev: Vec<isize>,
    at: Vec<u64>,
    level: Vec<u8>,
    bucket: Vec<u8>,
    armed: Vec<bool>,
    current: u64,
}

impl WheelCandidate {
    fn new(n: usize) -> Self {
        Self {
            heads: [[-1; BUCKETS]; LEVELS],
            next: vec![-1; n],
            prev: vec![-1; n],
            at: vec![0; n],
            level: vec![0; n],
            bucket: vec![0; n],
            armed: vec![false; n],
            current: 0,
        }
    }

    fn level_for(delta: u64) -> usize {
        if delta < (1 << BITS) {
            0
        } else if delta < (1 << (2 * BITS)) {
            1
        } else {
            2
        }
    }

    fn place(&mut self, slot: usize) {
        let level = Self::level_for(self.at[slot] - self.current);
        let bucket = ((self.at[slot] >> (level * BITS)) as usize) & MASK;
        let old = self.heads[level][bucket];
        self.prev[slot] = -1;
        self.next[slot] = old;
        if old >= 0 {
            self.prev[old as usize] = slot as isize;
        }
        self.heads[level][bucket] = slot as isize;
        self.level[slot] = level as u8;
        self.bucket[slot] = bucket as u8;
        self.armed[slot] = true;
    }

    fn set(&mut self, slot: usize, at: u64) {
        assert!(!self.armed[slot]);
        assert!(at > self.current);
        self.at[slot] = at;
        self.place(slot);
    }

    fn unlink(&mut self, slot: usize) {
        let level = self.level[slot] as usize;
        let bucket = self.bucket[slot] as usize;
        let prev = self.prev[slot];
        let next = self.next[slot];
        if prev >= 0 {
            self.next[prev as usize] = next;
        } else {
            self.heads[level][bucket] = next;
        }
        if next >= 0 {
            self.prev[next as usize] = prev;
        }
        self.prev[slot] = -1;
        self.next[slot] = -1;
    }

    fn take_head(&mut self, level: usize, bucket: usize) -> Option<usize> {
        let slot = self.heads[level][bucket];
        if slot < 0 {
            return None;
        }
        self.unlink(slot as usize);
        Some(slot as usize)
    }

    fn remove(&mut self, slot: usize) -> bool {
        if !self.armed[slot] {
            return false;
        }
        self.unlink(slot);
        self.armed[slot] = false;
        true
    }

    fn advance_step(&mut self, now: u64, expired: &mut usize) {
        self.current = now;
        for level in (1..LEVELS).rev() {
            let unit = 1u64 << (level * BITS);
            if now % unit != 0 {
                continue;
            }
            let bucket = ((now >> (level * BITS)) as usize) & MASK;
            while let Some(slot) = self.take_head(level, bucket) {
                self.place(slot);
            }
        }
        let bucket = (now as usize) & MASK;
        while let Some(slot) = self.take_head(0, bucket) {
            if self.at[slot] <= now {
                self.armed[slot] = false;
                *expired += 1;
            } else {
                self.place(slot);
            }
        }
    }

    fn memory_bytes(n: usize) -> usize {
        std::mem::size_of::<Self>()
            + LEVELS * BUCKETS * std::mem::size_of::<isize>()
            + n * (2 * std::mem::size_of::<isize>()
                + std::mem::size_of::<u64>()
                + 3 * std::mem::size_of::<u8>())
    }
}

fn next_random(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn percentile(samples: &mut [u64], per_mille: usize) -> u64 {
    samples.sort_unstable();
    let rank = (samples.len() * per_mille).div_ceil(1000).max(1);
    samples[rank - 1]
}

fn nanos(d: Duration) -> u64 {
    d.as_nanos().min(u64::MAX as u128) as u64
}

fn total_ns(samples: &[u64]) -> u64 {
    samples
        .iter()
        .fold(0u64, |sum, value| sum.saturating_add(*value))
}

fn run_case(n: usize, horizon: u64) {
    let mut seed = 0x5449_4d45_5257_4845 ^ n as u64;
    let deadlines: Vec<u64> = (0..n)
        .map(|_| next_random(&mut seed) % horizon + 1)
        .collect();

    let mut heap = HeapCandidate::new(n);
    let mut heap_insert = Vec::with_capacity(n);
    for (slot, &at) in deadlines.iter().enumerate() {
        let start = Instant::now();
        heap.set(slot, at);
        heap_insert.push(nanos(start.elapsed()));
    }

    let mut wheel = WheelCandidate::new(n);
    let mut wheel_insert = Vec::with_capacity(n);
    for (slot, &at) in deadlines.iter().enumerate() {
        let start = Instant::now();
        wheel.set(slot, at);
        wheel_insert.push(nanos(start.elapsed()));
    }

    let cancellations: Vec<usize> = (0..n).step_by(3).collect();
    let mut heap_cancel = Vec::with_capacity(cancellations.len());
    for &slot in &cancellations {
        let start = Instant::now();
        heap.remove(slot);
        heap_cancel.push(nanos(start.elapsed()));
    }

    let mut wheel_cancel = Vec::with_capacity(cancellations.len());
    for &slot in &cancellations {
        let start = Instant::now();
        assert!(wheel.remove(slot));
        wheel_cancel.push(nanos(start.elapsed()));
    }

    let mut heap_expired = 0;
    let mut heap_drain = Vec::with_capacity(horizon as usize);
    for now in 1..=horizon {
        let start = Instant::now();
        heap.drain_step(now, &mut heap_expired);
        heap_drain.push(nanos(start.elapsed()));
    }

    let mut wheel_expired = 0;
    let mut wheel_drain = Vec::with_capacity(horizon as usize);
    for now in 1..=horizon {
        let start = Instant::now();
        wheel.advance_step(now, &mut wheel_expired);
        wheel_drain.push(nanos(start.elapsed()));
    }

    let expected = n - cancellations.len();
    assert_eq!(heap_expired, expected);
    assert_eq!(wheel_expired, expected);
    assert!(wheel.armed.iter().all(|armed| !armed));
    black_box((&heap_insert, &wheel_insert));

    println!(
        concat!(
            "[TIMER-ALGO] n={} horizon={} expected={} ",
            "heap_insert_ns={}/{}/{}/{} wheel_insert_ns={}/{}/{}/{} ",
            "heap_cancel_ns={}/{}/{}/{} wheel_cancel_ns={}/{}/{}/{} ",
            "heap_drain_step_ns={}/{}/{}/{} wheel_drain_step_ns={}/{}/{}/{} ",
            "heap_cpu_ns={} wheel_cpu_ns={} heap_bytes={} wheel_bytes={}"
        ),
        n,
        horizon,
        expected,
        percentile(&mut heap_insert, 500),
        percentile(&mut heap_insert, 990),
        percentile(&mut heap_insert, 999),
        percentile(&mut heap_insert, 1000),
        percentile(&mut wheel_insert, 500),
        percentile(&mut wheel_insert, 990),
        percentile(&mut wheel_insert, 999),
        percentile(&mut wheel_insert, 1000),
        percentile(&mut heap_cancel, 500),
        percentile(&mut heap_cancel, 990),
        percentile(&mut heap_cancel, 999),
        percentile(&mut heap_cancel, 1000),
        percentile(&mut wheel_cancel, 500),
        percentile(&mut wheel_cancel, 990),
        percentile(&mut wheel_cancel, 999),
        percentile(&mut wheel_cancel, 1000),
        percentile(&mut heap_drain, 500),
        percentile(&mut heap_drain, 990),
        percentile(&mut heap_drain, 999),
        percentile(&mut heap_drain, 1000),
        percentile(&mut wheel_drain, 500),
        percentile(&mut wheel_drain, 990),
        percentile(&mut wheel_drain, 999),
        percentile(&mut wheel_drain, 1000),
        total_ns(&heap_insert)
            .saturating_add(total_ns(&heap_cancel))
            .saturating_add(total_ns(&heap_drain)),
        total_ns(&wheel_insert)
            .saturating_add(total_ns(&wheel_cancel))
            .saturating_add(total_ns(&wheel_drain)),
        HeapCandidate::memory_bytes(n),
        WheelCandidate::memory_bytes(n),
    );
}

#[test]
fn indexed_heap_and_hierarchical_wheel_are_equivalent() {
    run_case(64, 8_192);
    run_case(256, 32_768);
    run_case(4_096, 131_072);
}
