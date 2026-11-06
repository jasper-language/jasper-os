// Deliberately wrong negative: death ignores whether the typed closing hook finished.
// The postcondition must fail for an otherwise dead-looking object.
use vstd::prelude::*;

verus! {

fn bad_may_die(owners: u32, internal: u32, finished: bool) -> (r: bool)
    ensures r ==> finished,
{
    owners == 0 && internal == 0
}

fn main() {}
}
