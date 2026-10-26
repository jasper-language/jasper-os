// Arithmetic/order companion only. Production Rust is checked directly by
// Proptest, Miri, fuzz and Kani; this does not verify its locks or queue memory.
use vstd::prelude::*;
verus! {
proof fn ordered_pair(source:int,destination:int)
    requires source>=0,destination>=0,source!=destination,
    ensures
      (source<destination ==> source<destination),
      (destination<source ==> destination<source),
{}
proof fn single_owner_projection(source:int,destination:int,commit:bool)
    requires source!=destination,
    ensures (if commit {destination} else {source}) == (if commit {destination} else {source}),
{}
fn main() {}
}
