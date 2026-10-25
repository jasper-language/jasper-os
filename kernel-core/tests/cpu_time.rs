use kernel_core::cpu_time::{Ledger,Totals,Error};
#[test]
fn clock_sequences_match_reference_and_live_snapshot_does_not_consume() {
    for a in 0..5 {for b in a..5 {for c in b..5 {for mask in 0..8 {
        let mut ledger=Ledger::new(0,false);let mut before=0;let mut busy=false;let mut reference=Totals::default();
        for (i,now) in [a,b,c].into_iter().enumerate() {
            if busy {reference.busy+=now-before;}else{reference.idle+=now-before;}
            let next=mask&(1<<i)!=0;
            ledger.transition(now,next).unwrap();before=now;busy=next;
            let saved=ledger;
            assert_eq!(ledger.snapshot(now).unwrap(),reference);assert_eq!(ledger,saved);
            let total=ledger.snapshot(5).unwrap();assert_eq!(total.busy+total.idle,5);
        }
    }}}}
}
#[test]
fn reversed_time_refuses_atomically_and_reset_preserves_current_state() {
    let mut ledger=Ledger::new(10,true);let before=ledger;
    assert_eq!(ledger.transition(9,false),Err(Error::TimeReversed));assert_eq!(ledger,before);
    assert_eq!(ledger.reset(9),Err(Error::TimeReversed));assert_eq!(ledger,before);
    ledger.transition(13,false).unwrap();ledger.reset(14).unwrap();
    assert_eq!(ledger.snapshot(20).unwrap(),Totals {busy:0,idle:6});
    let end=Ledger::new(u64::MAX,false);assert_eq!(end.snapshot(u64::MAX).unwrap(),Totals::default());
}
#[test]
fn local_irq_count_plus_partial_stopped_credit_is_not_wall_time() {
    // Actual diagnostic tuple: global=120, local=58, stopped compensation=51.
    // The old sum reconciles but cannot prove reference-clock coverage.
    assert!(58+51+4+2<120);
    let mut ledger=Ledger::new(0,false);
    for now in [1,7,20,70,119] {ledger.transition(now,false).unwrap();}
    assert_eq!(ledger.snapshot(120).unwrap(),Totals {busy:0,idle:120});
}
