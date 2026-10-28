// 故意错误的负例：把「下标 < 表项数」放宽为「下标 <= 表项数」后，
// 「整表在文件内 ⇒ 表项在文件内」必须不成立；运行脚本只接受 Verus 报出的验证错误。
// Deliberately wrong negative: an off-by-one index bound must break the table-admits-entry lemma.
use vstd::prelude::*;

verus! {

proof fn bad_table_admits_one_past_end(len: int, shoff: int, ent: int, n: int, index: int)
    requires
        0 <= shoff,
        0 <= ent,
        0 <= index <= n,
        shoff + n * ent <= len,
    ensures
        shoff + index * ent + ent <= len,
{
    assert(index * ent + ent <= n * ent) by (nonlinear_arith)
        requires 0 <= index <= n, 0 <= ent;
}

fn main() {}
}
