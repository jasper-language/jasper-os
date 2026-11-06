// Companion model for the production ObjectTable release transition.
// Differential tests execute the Rust implementation; this file proves the arithmetic invariants.
use vstd::prelude::*;

verus! {

/// Outcome of one owner release: `(accepted, remaining_owners)`.
fn release_owner(owners: u32) -> (r: (bool, u32))
    ensures
        r.0 <==> owners > 0,
        r.0 ==> r.1 == owners - 1,
        !r.0 ==> r.1 == owners,
{
    if owners == 0 {
        (false, owners)
    } else {
        (true, owners - 1)
    }
}

/// A last-owner event occurs exactly when a positive owner count reaches zero.
fn became_unowned(before: u32) -> (r: bool)
    ensures r <==> before == 1,
{
    before == 1
}

/// Death is observable only after the hook finished and both reference classes are zero.
fn may_die(owners: u32, internal: u32, hook_finished: bool) -> (r: bool)
    ensures r <==> (owners == 0 && internal == 0 && hook_finished),
{
    owners == 0 && internal == 0 && hook_finished
}

/// Duplicate close is rejected without changing either reference count.
fn duplicate_close(owners: u32, internal: u32) -> (r: (bool, u32, u32))
    ensures
        r.0 <==> owners > 0,
        r.1 == owners,
        r.2 == internal,
{
    (owners > 0, owners, internal)
}

fn main() {}
}
