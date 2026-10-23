//! Shared worker/seed contract used by the real user probes.
use kernel_core::argcase::{s2_probes, s2_seed, s2_workers, Prng, S2_TOTAL_PROBES, S2_MAX_WORKERS};
#[test]
fn s2_stream_contract() {
    assert_eq!(S2_MAX_WORKERS, 8);
    assert_eq!(S2_TOTAL_PROBES, 1_000_000);
    assert_eq!(s2_workers(0), 1);
    assert_eq!(s2_workers(1), 1);
    assert_eq!(s2_workers(2), 2);
    assert_eq!(s2_workers(4), 4);
    assert_eq!(s2_workers(8), 8);
    assert_eq!(s2_workers(16), 8);
    assert_eq!(s2_probes(0), None);
    assert_eq!(s2_probes(3), None);
    assert_eq!(s2_probes(16), None);
    for workers in [1u64, 2, 4, 8] {
        let probes = s2_probes(workers).unwrap();
        assert_eq!(workers * probes, S2_TOTAL_PROBES);
        assert_eq!(probes, S2_TOTAL_PROBES / workers);
    }
    assert_eq!(s2_seed(0), None);
    assert_eq!(s2_seed(9), None);
    assert_eq!(s2_seed(u64::MAX), None);
    let mut seen = Vec::new();
    for worker in 1..=S2_MAX_WORKERS {
        let seed = s2_seed(worker).unwrap();
        assert_ne!(seed, 0);
        assert!(!seen.contains(&seed)); seen.push(seed);
        // Replaying the same fixed seed must produce the same bounded stream.
        let (mut a, mut b) = (Prng::new(seed), Prng::new(seed));
        for _ in 0..1024 { assert_eq!(a.next_u64(), b.next_u64()); }
    }
}
