// 故意错误的负例：漏掉可转移性检查，「Allowed ⇒ 含 TRANSFER 时可转移」后置条件必须验证失败。
// Deliberately wrong negative: omitting the transferability check must fail the postcondition.
use vstd::prelude::*;

verus! {
pub const TRANSFER: u32 = 0x40;

fn bad_check_grant(type_ok: bool, transferable: bool, ceiling: u32, rights: u32) -> (r: u8)
    ensures r == 0 ==> (rights & TRANSFER != 0 ==> transferable),
{
    if !type_ok {
        return 1;
    }
    if ceiling & rights != rights {
        return 3;
    }
    0
}

fn main() {}
}
