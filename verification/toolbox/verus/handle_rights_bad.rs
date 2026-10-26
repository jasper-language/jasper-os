// Deliberately incorrect FV-3 negative: replacing intersection with union
// must fail the no-escalation postcondition.  The runner accepts only a Verus
// verification error mentioning that postcondition.
use vstd::prelude::*;

verus! {
const RIGHTS_ALL: u32 = 0x1ff;

fn bad_duplicate_rights(held: u32, mask: u32) -> (out: u32)
    requires RIGHTS_ALL & held == held,
             RIGHTS_ALL & mask == mask,
    ensures held & out == out,
{
    held | mask
}

fn main() {
}
}
