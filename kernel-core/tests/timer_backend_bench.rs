use std::time::Instant;

use kernel_core::deadline::{Deadline, DeadlineHeap, ABSENT};

const N: usize = 65_536;

fn percentiles(mut values: Vec<u64>) -> (u64, u64, u64, u64) {
    values.sort_unstable();
    (
        values[values.len() / 2],
        values[values.len() * 99 / 100],
        values[values.len() * 999 / 1000],
        *values.last().expect("non-empty samples"),
    )
}

fn timed(op: impl FnOnce(), samples: &mut Vec<u64>) {
    let start = Instant::now();
    op();
    samples.push(start.elapsed().as_nanos() as u64);
}

#[test]
fn mixed_large_deadline_heap_workload() {
    let mut heap = Box::new(DeadlineHeap::new());
    let mut entries = vec![Deadline::EMPTY; N];
    let mut positions = vec![ABSENT; N];
    let mut seed = 0x5449_4d45_5248_4541u64;
    let mut samples = Vec::with_capacity(N * 3);

    for slot in 0..N {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let at = seed & ((1 << 40) - 1);
        timed(
            || {
                heap.set(
                    &mut entries,
                    &mut positions,
                    Deadline {
                        at,
                        slot,
                        generation: 1,
                    },
                )
                .expect("preallocated heap slot");
            },
            &mut samples,
        );
    }
    for slot in (0..N).step_by(2) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let at = seed & ((1 << 40) - 1);
        timed(
            || {
                heap.set(
                    &mut entries,
                    &mut positions,
                    Deadline {
                        at,
                        slot,
                        generation: 1,
                    },
                )
                .expect("update live heap slot");
            },
            &mut samples,
        );
    }
    for slot in (0..N).step_by(4) {
        timed(
            || {
                assert!(
                    heap.remove(&mut entries, &mut positions, slot, 1)
                        .is_some()
                );
            },
            &mut samples,
        );
    }
    let mut popped = 0usize;
    loop {
        let start = Instant::now();
        let due = heap.pop_due(&mut entries, &mut positions, u64::MAX);
        let elapsed = start.elapsed().as_nanos() as u64;
        let Some(_) = due else { break };
        samples.push(elapsed);
        popped += 1;
    }
    assert_eq!(popped, N - N / 4);
    assert_eq!(heap.len(), 0);
    assert!(positions.iter().all(|position| *position == ABSENT));
    let ops = samples.len();
    let (p50, p99, p999, max) = percentiles(samples);
    println!(
        "timer-backend-heap n={} ops={} p50_ns={} p99_ns={} p999_ns={} max_ns={} entry_bytes={} index_bytes={}",
        N,
        ops,
        p50,
        p99,
        p999,
        max,
        core::mem::size_of::<Deadline>(),
        N * (core::mem::size_of::<Deadline>() + core::mem::size_of::<usize>()),
    );
}
