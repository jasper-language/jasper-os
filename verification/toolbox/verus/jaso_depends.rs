// `core.depends` 逐项扫描的模型（jaso/src/manifest.rs `Manifest::parse`）：名字用非零整数表示，0 表示取值不合法。
// 性质：前 32 项重名必被发现，接受的列表 ≤32 项且无重名；比较次数有与项数无关的常数上界。
use vstd::prelude::*;

verus! {

#[derive(PartialEq, Eq)]
pub enum Outcome { Accept, BadValue, Duplicate, Limit }

fn scan(names: &Vec<u64>) -> (r: (Outcome, u64))
    ensures
        r.1 <= 1024,
        r.0 == Outcome::Accept ==> names.len() <= 32
            && (forall|a: int| 0 <= a < names.len() ==> names[a] != 0)
            && (forall|a: int, b: int| 0 <= a < b < names.len() ==> names[a] != names[b]),
        r.0 == Outcome::Limit ==> names.len() > 32
            && (forall|a: int| 0 <= a < names.len() ==> names[a] != 0)
            && (forall|a: int, b: int| 0 <= a < b < 32 ==> names[a] != names[b]),
        // 不超过上限的列表只要合法且不重名就一定接受
        names.len() <= 32 && (forall|a: int| 0 <= a < names.len() ==> names[a] != 0)
            && (forall|a: int, b: int| 0 <= a < b < names.len() ==> names[a] != names[b])
            ==> r.0 == Outcome::Accept,
{
    let mut i: usize = 0;
    let mut cmp: u64 = 0;
    while i < names.len()
        invariant
            i <= names.len(),
            forall|a: int| 0 <= a < i ==> names[a] != 0,
            forall|a: int, b: int| 0 <= a < b < i && b < 32 ==> names[a] != names[b],
            cmp <= 32 * (if i <= 32 { i as int } else { 32int }),
        decreases names.len() - i,
    {
        if names[i] == 0 {
            return (Outcome::BadValue, cmp);
        }
        if i < 32 {
            let mut j: usize = 0;
            while j < i
                invariant
                    i < 32,
                    i < names.len(),
                    j <= i,
                    forall|a: int| 0 <= a < j ==> names[a] != names[i as int],
                    cmp <= 32 * (i as int) + (j as int),
                decreases i - j,
            {
                cmp = cmp + 1;
                if names[j] == names[i] {
                    return (Outcome::Duplicate, cmp);
                }
                j = j + 1;
            }
        }
        i = i + 1;
    }
    if i > 32 {
        (Outcome::Limit, cmp)
    } else {
        (Outcome::Accept, cmp)
    }
}

fn main() {}
}
