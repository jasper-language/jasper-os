// FV-3 Verus pilot for the Handle/Rights decision.
//
// This is an executable Verus implementation of the small, pure rights
// transition used by HandleTable::reduce_rights.  The production Rust table
// cannot be imported into Verus unchanged (const-generic arrays, Option<(V,
// Rights)>, iterators, mutation through slot references and no_std traits all
// require a second implementation).  Keeping this file separate makes that
// rewrite cost visible instead of claiming the arithmetic companion verifies
// kernel-core/src/object.rs.
use vstd::prelude::*;

verus! {

const RIGHTS_ALL: u32 = 0x1ff;

proof fn intersection_subset_left(a: u32, b: u32)
    ensures a & (a & b) == a & b,
{
    assert(a & (a & b) == a & b) by(bit_vector);
}

fn truncate(bits: u32) -> (out: u32)
    ensures out == RIGHTS_ALL & bits,
            RIGHTS_ALL & out == out,
{
    let out = RIGHTS_ALL & bits;
    proof {
        intersection_subset_left(RIGHTS_ALL, bits);
    }
    out
}

fn contains(held: u32, requested: u32) -> (out: bool)
    requires RIGHTS_ALL & held == held,
             RIGHTS_ALL & requested == requested,
    ensures out <==> held & requested == requested,
{
    held & requested == requested
}

fn intersect(held: u32, mask: u32) -> (out: u32)
    requires RIGHTS_ALL & held == held,
             RIGHTS_ALL & mask == mask,
    ensures out == held & mask,
            held & out == out,
{
    let out = held & mask;
    proof {
        intersection_subset_left(held, mask);
    }
    out
}

#[derive(PartialEq, Eq)]
struct SlotState {
    live: bool,
    generation: u32,
    rights: u32,
}

enum ReduceResult {
    Reduced(SlotState),
    RightsDenied(SlotState),
}

// Exact transition corresponding to HandleTable::reduce_rights after handle
// identity validation.  Failure returns the old state so atomicity is part of
// the postcondition rather than an assumption in a test.
fn reduce_rights(old: SlotState, requested: u32) -> (result: ReduceResult)
    requires old.live,
             RIGHTS_ALL & old.rights == old.rights,
             RIGHTS_ALL & requested == requested,
    ensures match result {
        ReduceResult::Reduced(next) =>
            next.live
            && next.generation == old.generation
            && next.rights == requested
            && old.rights & next.rights == next.rights,
        ReduceResult::RightsDenied(next) => next == old,
    },
    matches!(result, ReduceResult::Reduced(_))
            <==> old.rights & requested == requested,
{
    if contains(old.rights, requested) {
        ReduceResult::Reduced(SlotState {
            live: true,
            generation: old.generation,
            rights: requested,
        })
    } else {
        ReduceResult::RightsDenied(old)
    }
}

// The duplicate-and-restrict operation uses intersection, so arbitrary masks
// can never add a right even when the mask contains unknown bits after ABI
// truncation.
fn duplicate_rights(held: u32, raw_mask: u32) -> (out: u32)
    requires RIGHTS_ALL & held == held,
    ensures held & out == out,
{
    let mask = truncate(raw_mask);
    intersect(held, mask)
}

fn main() {
}

}
