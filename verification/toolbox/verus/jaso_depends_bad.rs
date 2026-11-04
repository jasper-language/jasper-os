// 负例：去掉「只查前 32 项」的窗口后，比较次数不再有常数上界，必须无法通过验证。
use vstd::prelude::*;

verus! {

fn scan_unwindowed(names: &Vec<u64>) -> (cmp: u64)
    ensures cmp <= 1024,
{
    let mut i: usize = 0;
    let mut cmp: u64 = 0;
    while i < names.len()
        invariant i <= names.len(), cmp <= 1024,
        decreases names.len() - i,
    {
        let mut j: usize = 0;
        while j < i
            invariant j <= i, cmp <= 1024,
            decreases i - j,
        {
            cmp = cmp + 1;
            j = j + 1;
        }
        i = i + 1;
    }
    cmp
}

fn main() {}
}
