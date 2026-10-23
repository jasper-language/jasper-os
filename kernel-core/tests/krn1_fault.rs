//! Reproducibility and concurrent single-fire contract.
use kernel_core::fault::FaultPoint;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
#[test]
fn krn1_seeded_fault_is_one_shot() {
    for seed in 0..256 {
        let p = FaultPoint::new();
        assert!(!p.hit());
        let nth = p.arm(seed, 17).unwrap();
        for i in 1..=34 { assert_eq!(p.hit(), i == nth); }
        assert_eq!(p.arm(seed, 17), Ok(nth));
        p.disarm();
        assert!(!p.hit());
        assert!(p.arm(seed, 0).is_err());
        assert!(!p.hit());
    }
}
#[test]
fn krn1_concurrent_fault_fires_once() {
    let p = Arc::new(FaultPoint::new());
    p.arm(0xb001, 31).unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let (p, hits) = (p.clone(), hits.clone());
            scope.spawn(move || { for _ in 0..64 {
                if p.hit() { hits.fetch_add(1, Ordering::SeqCst); }
            }});
        }
    });
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
