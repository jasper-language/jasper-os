#![no_main]
//! issue #2：任意字节流驱动 DeadlineForest::sync / pop_due，对参考模型差分；
//! 检查结果种类、失败与 Unchanged 不写存储、每核最早项与计数守恒。
use kernel_core::deadline::{Deadline, HeapError, ABSENT};
use kernel_core::deadline_forest::{DeadlineForest, SyncOutcome, SyncStats};

const C: usize = 4;
const N: usize = 8;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut forest = DeadlineForest::<C>::new();
    let mut e = [Deadline::EMPTY; C * N];
    let mut p = [ABSENT; N];
    let mut o = [ABSENT; N];
    let mut reference: [Option<(usize, Deadline)>; N] = [None; N];
    let mut stats = SyncStats::default();
    for op in data.chunks_exact(4) {
        let slot = (op[0] & 0x0f) as usize % (N + 1);
        let generation = u64::from(op[0] >> 4) % 3;
        let cpu = (op[1] & 0x07) as usize % (C + 1);
        let at = u64::from(op[2]) | (u64::from(op[3]) << 8);
        let before = (e, p, o, core::array::from_fn::<_, C, _>(|c| forest.len(c)));
        if op[1] & 0x80 != 0 {
            let expected = if cpu >= C { Err(HeapError::Slot) } else {
                Ok(reference.iter().flatten().filter(|(c, _)| *c == cpu).map(|(_, d)| *d)
                    .min_by_key(|d| (d.at, d.slot)).filter(|d| d.at <= at))
            };
            let actual = forest.pop_due(&mut e, &mut p, &mut o, cpu, at);
            assert_eq!(actual, expected);
            if let Ok(Some(d)) = actual { reference[d.slot] = None; }
        } else {
            let wanted = if op[1] & 0x40 != 0 { None } else { Some((cpu, at)) };
            let expected = if slot >= N { Err(HeapError::Slot) }
                else if reference[slot].is_some_and(|(_, d)| d.generation != generation) { Err(HeapError::Stale) }
                else { match (reference[slot], wanted) {
                    (None, None) => Ok(SyncOutcome::Unchanged),
                    (Some(_), None) => Ok(SyncOutcome::Removed),
                    (_, Some((c, _))) if c >= C => Err(HeapError::Slot),
                    (Some((oc, d)), Some((c, a))) if oc == c && d.at == a => Ok(SyncOutcome::Unchanged),
                    (None, Some(_)) => Ok(SyncOutcome::Inserted),
                    (Some((oc, _)), Some((c, _))) => Ok(if oc == c { SyncOutcome::Rescheduled } else { SyncOutcome::Moved }),
                } };
            let actual = forest.sync(&mut e, &mut p, &mut o, slot, generation, wanted);
            assert_eq!(actual, expected);
            match actual {
                Ok(outcome) => {
                    stats.record(outcome);
                    if !outcome.wrote() { assert!(before == (e, p, o, core::array::from_fn(|c| forest.len(c)))); }
                    reference[slot] = wanted.map(|(c, a)| (c, Deadline { at: a, slot, generation }));
                }
                Err(_) => assert!(before == (e, p, o, core::array::from_fn(|c| forest.len(c)))),
            }
        }
        for c in 0..C {
            let min = reference.iter().flatten().filter(|(x, _)| *x == c).map(|(_, d)| *d).min_by_key(|d| (d.at, d.slot));
            assert_eq!(forest.peek(&e, &p, &o, c), Ok(min));
            assert_eq!(forest.len(c), Some(reference.iter().flatten().filter(|(x, _)| *x == c).count()));
        }
    }
    assert!(stats.balanced());
});
