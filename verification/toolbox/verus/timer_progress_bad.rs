// 故意错误的负例：记录时把开销算成 exit - entry 的一半，「留出的时间不少于开销」必须验证失败。
// Deliberately wrong negative: halving the recorded cost must fail the window guarantee.
use vstd::prelude::*;

verus! {
fn bad_window(entry: u64, exit: u64, next: u64) -> (admitted: bool)
    requires entry <= exit, exit <= next,
    ensures admitted ==> next - exit >= exit - entry,
{
    let cost = (exit - entry) / 2;
    next - exit >= cost
}

fn main() {}
}
