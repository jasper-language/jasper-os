// 负例：去掉截止，只要覆盖不足就继续——循环不再有界，decreases 推不出（必须验证失败）。
use vstd::prelude::*;

verus! {

pub fn hog_continues_no_cutoff(now: u64, end: u64, covered_cores: u32, want_cores: u32, cutoff: u64) -> (go: bool) {
    now < end || covered_cores < want_cores
}

pub fn hog_loop_model(start: u64, end: u64, covered_cores: u32, want_cores: u32, cutoff: u64) -> (stop: u64)
    ensures stop >= start,
{
    let mut now = start;
    while hog_continues_no_cutoff(now, end, covered_cores, want_cores, cutoff) && now < u64::MAX
        invariant now >= start,
        decreases (if end >= cutoff { end } else { cutoff }) - now,
    {
        now = now + 1;
    }
    now
}

fn main() {}

} // verus!
