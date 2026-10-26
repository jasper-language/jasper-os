use vstd::prelude::*;

verus! {

spec fn matches(slot: nat, generation: int, token_slot: nat, token_generation: int) -> bool {
    slot == token_slot && generation == token_generation
}

proof fn reused_generation_rejects_stale(
    slot: nat,
    old_generation: int,
    new_generation: int,
)
    requires old_generation != new_generation
    ensures
        matches(slot, new_generation, slot, new_generation),
        !matches(slot, new_generation, slot, old_generation),
{
}

proof fn wrong_slot_rejects_owner(
    owner_slot: nat,
    wrong_slot: nat,
    generation: int,
)
    requires owner_slot != wrong_slot
    ensures
        matches(owner_slot, generation, owner_slot, generation),
        !matches(owner_slot, generation, wrong_slot, generation),
{
}

fn main() {}
}
