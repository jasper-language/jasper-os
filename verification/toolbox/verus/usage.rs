// Companion arithmetic proof. Production Usage uses checked_add+limit filtering;
// this file proves an alternate subtraction guard equivalent over mathematical sums.
// It does NOT by itself verify Rust Usage or its locks/Arc/hardware.
use vstd::prelude::*;
verus! {
fn admit(m:u64,p:u64,am:u64,ap:u64,lm:u64,lp:u64) -> (r: Option<(u64,u64)>)
    ensures
        r.is_some() <==> (m as int + am as int <= lm as int && p as int + ap as int <= lp as int),
        r.is_some() ==> (r.unwrap().0 as int == m as int + am as int && r.unwrap().1 as int == p as int + ap as int),
{
    if am > lm || m > lm-am || ap > lp || p > lp-ap { None }
    else { Some((m+am,p+ap)) }
}
fn main() {}
}
// The arithmetic companion above does not verify the Rust HandleTable.
verus! {
proof fn rights_intersection_cannot_escalate(held:u32,requested:u32)
    ensures ((held & requested) & !held) == 0u32,
{ assert(((held & requested) & !held) == 0u32) by(bit_vector); }
}

// Mathematical partition companion; not a verification of the Rust Ledger body.
verus! {
proof fn residency_partition(b:int,i:int,delta:int,busy:bool)
    requires b>=0, i>=0, delta>=0,
    ensures (if busy { b+delta+i } else { b+i+delta }) == b+i+delta,
{}
}
// Companion only: checked publication must be monotonic and refuse MAX.
verus! {
proof fn subscription_sequence_step(version:u64)
    ensures version < u64::MAX ==> (version as int + 1 > version as int && version as int + 1 <= u64::MAX as int),
{}
}
// Descriptor arithmetic companion, not Rust decoder verification.
verus! {
proof fn event_batch_bytes(capacity:u32)
 requires capacity>=1, capacity<=16,
 ensures capacity as int*32>=32, capacity as int*32<=512,
{}
}

// Accounting partition only; not verification of timer IRQ attribution.
verus! {
proof fn limit_partition(start:int,cutoff:int,total:int)
 requires 0<=start, start<=cutoff, cutoff<=total,
 ensures 0<=cutoff-start, 0<=total-cutoff,
         (cutoff-start)+(total-cutoff)==total-start,
{}
}
