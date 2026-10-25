#![no_main]
use kernel_core::cpu_time::{Ledger,Totals};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut ledger=Ledger::new(0,false);let mut now=0u64;let mut busy=false;let mut reference=Totals::default();
    for event in data.chunks_exact(3).take(64) {
        let delta=u16::from_le_bytes([event[0],event[1]]) as u64;now+=delta;
        if busy {reference.busy+=delta;} else {reference.idle+=delta;}
        busy=event[2]&1!=0;ledger.transition(now,busy).unwrap();
        assert_eq!(ledger.snapshot(now).unwrap(),reference);
    }
});
