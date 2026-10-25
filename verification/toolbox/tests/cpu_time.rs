use kernel_core::cpu_time::{Ledger,Totals};
use proptest::prelude::*;
proptest! {
    #![proptest_config(ProptestConfig {failure_persistence:None,..ProptestConfig::default()})]
    #[test]
    fn residency_matches_partition_reference(events in prop::collection::vec((any::<u16>(),any::<bool>()),0..65)) {
        let mut ledger=Ledger::new(0,false);let mut now=0u64;let mut busy=false;let mut reference=Totals::default();
        for (delta,next) in events {
            now+=delta as u64;
            if busy {reference.busy+=delta as u64;} else {reference.idle+=delta as u64;}
            ledger.transition(now,next).unwrap();busy=next;
            prop_assert_eq!(ledger.snapshot(now).unwrap(),reference);
            prop_assert_eq!(reference.busy+reference.idle,now);
            let saved=ledger;let snapshot=ledger.snapshot(now+1).unwrap();prop_assert_eq!(snapshot.busy+snapshot.idle,now+1);prop_assert_eq!(ledger,saved);
        }
    }
}

#[test]
fn concurrent_reference_snapshots_are_non_consuming() {
    loom::model(|| {
        let ledger=loom::sync::Arc::new(loom::sync::Mutex::new(Ledger::new(0,false)));
        let other=ledger.clone();
        let worker=loom::thread::spawn(move || {other.lock().unwrap().transition(1,true).unwrap();});
        {let value=ledger.lock().unwrap();let saved=*value;let total=value.snapshot(1).unwrap();assert_eq!(total.busy+total.idle,1);assert_eq!(*value,saved);}
        worker.join().unwrap();
        assert_eq!(ledger.lock().unwrap().snapshot(2).unwrap(),Totals {busy:1,idle:1});
    });
}
