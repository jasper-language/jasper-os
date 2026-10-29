// 分时策略抢占判定 preempt_rule：最低份额保护（补给档在本片记 tick 前不被抢占）与原规则的关系。
// 规格：old_rule = 修正前的判定；实现 = kernel-core preempt_rule（同一分支次序）。
use vstd::prelude::*;

verus! {

pub enum Preempt { Quantum, Higher, Owed }

pub enum Owed { None, Current, Other }

pub open spec fn old_rule(used: u32, quantum: u32, higher: bool, owed: Owed, others: bool) -> Option<Preempt> {
    if higher { Some(Preempt::Higher) }
    else if owed is Other { Some(Preempt::Owed) }
    else if used >= quantum && others { Some(Preempt::Quantum) }
    else { None }
}

pub fn preempt_rule(used: u32, quantum: u32, higher: bool, owed: Owed, others: bool) -> (r: Option<Preempt>)
    ensures
        // 保护：补给档在本片第一个 tick 记账之前，任何重新判定都不换下它
        used == 0 && owed is Current ==> r is None,
        // 保护至多一个 tick：其余情形与原规则逐位一致
        !(used == 0 && owed is Current) ==> r == old_rule(used, quantum, higher, owed, others),
        // 记过 tick 后，更高档在等必然抢占（严格优先恢复）
        used >= 1 && higher ==> r == Some(Preempt::Higher),
        // 没有别的可运行实体时从不因时间片换下
        !higher && !(owed is Other) && !others ==> r is None,
{
    if used == 0 && (match owed { Owed::Current => true, _ => false }) {
        return None;
    }
    if higher {
        return Some(Preempt::Higher);
    }
    if match owed { Owed::Other => true, _ => false } {
        return Some(Preempt::Owed);
    }
    if used >= quantum && others {
        return Some(Preempt::Quantum);
    }
    None
}

fn main() {}

} // verus!
