// 负例：在 u32 上回绕相加的 range_within 必须无法通过验证（证明伴随规格不是空洞的）。
use vstd::prelude::*;

verus! {

fn range_within_wrapping(off: u32, len: u32, total: u64) -> (r: bool)
    ensures r == (off as int + len as int <= total as int)
{
    let end: u32 = off.wrapping_add(len);
    (end as u64) <= total
}

fn main() {}
}
