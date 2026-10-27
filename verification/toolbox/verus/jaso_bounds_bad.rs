// 负例：回绕加法版本的 range_within 必须无法通过验证（证明伴随规格不是空洞的）。
use vstd::prelude::*;

verus! {

fn range_within_wrapping(off: u32, len: u32, total: u64) -> (r: bool)
    requires total <= 0x1_0000_0000
    ensures r == (off as int + len as int <= total as int)
{
    let end: u32 = off.wrapping_add(len);
    (end as u64) <= total
}

fn main() {}
}
