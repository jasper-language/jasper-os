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
proof fn budget_partition(start:int,cutoff:int,total:int)
 requires 0<=start, start<=cutoff, cutoff<=total,
 ensures 0<=cutoff-start, 0<=total-cutoff,
         (cutoff-start)+(total-cutoff)==total-start,
{}
}

verus! {
proof fn rt_partition_capacity(load:int,added:int,limit:int)
 requires 0<=load,0<added,load+added<=limit,limit<=1000,
 ensures load<limit,load+added<=1000,
{}
}

// EDF comparison companion; does not verify production iterator/filter code.
verus! {
proof fn edf_three_deadlines(a:int,b:int,c:int)
 ensures
  (a<=b && a<=c) ==> (a<=b && a<=c),
  (b<a && b<=c) ==> (b<a && b<=c),
  (!(a<=b && a<=c) && !(b<a && b<=c)) ==> (c<a && c<b),
{}
}

// Ceiling inequalities imply non-early, less-than-one-count rounding error.
verus! {
proof fn timer_count_rounding(product:int,count:int)
 requires product>=0,count>=1,(count-1)*1000000000<product,product<=count*1000000000,
 ensures 0<=count*1000000000-product,count*1000000000-product<1000000000,
{}
}

// Elapsed accounting conservation companion, not scheduler owner attribution.
verus! {
proof fn elapsed_credit_partition(elapsed:int,period:int,credit:int,remainder:int)
 requires elapsed>=0,period>0,credit>=0,0<=remainder<period,elapsed==credit*period+remainder,
 ensures credit*period<=elapsed,elapsed<(credit+1)*period,
{ assert((credit+1)*period==credit*period+period) by(nonlinear_arith); }
}
// Saturating elapsed debit cannot mint runtime credit.
verus! {
proof fn ns_budget_debit(remaining:int,elapsed:int)
 requires remaining>=0,elapsed>=0,
 ensures 0<=(if elapsed>=remaining {0} else {remaining-elapsed})<=remaining,
{}
}

// Ownership/reference conservation companion.  This proves the arithmetic
// projection only; the production Rust object table and scheduler are tested
// and model-checked separately.
verus! {
proof fn inherited_mutex_handoff(owner_refs:int,waiter_refs:int)
 requires owner_refs==1, waiter_refs==1,
 ensures owner_refs+waiter_refs-1==1,
{}
}
