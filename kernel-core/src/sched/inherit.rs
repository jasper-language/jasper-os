//! 优先级继承（turnstile 式）的纯决策部分：等待关系图的校验、有效档位的计算、交接对象的选择。
//! Priority inheritance (turnstile style): wait-graph validation, effective-class resolution, successor choice.
//!
//! # 职责边界
//! 这里只处理「谁在等谁」这张图：给定每个槽位的自身档位与它正在等的持有者，算出每个槽位的**有效档位**
//! （自身档位与全部直接、间接等待者档位中的最高者）。图存放在哪里、何时阻塞与唤醒、锁归谁，
//! 都是内核调度机制的事；本模块不碰任务表，因此能在宿主上做确定性测试。
//!
//! # 为什么需要继承（优先级反转）
//! 经典场景：低档任务 L 持有一把锁，高档任务 H 来要这把锁而阻塞，中档任务 M 吃满处理器——
//! 严格优先下 L 拿不到处理器、放不了锁，H 的等待时长于是取决于 M 跑多久，没有上界。
//! 继承让 L 在 H 等它期间按 H 的档位运行：M 无法再挡住 L，H 的等待只取决于 L 剩余的临界区长度。
//! 等待链是传递的（H 等 M2、M2 等 L ⇒ L 继承 H 的档位）。持有者放锁或退出后，借来的档位随等待关系一起消失。
//!
//! # 约束
//! * 不允许自等、成环（死锁）与超过 [`MAX_CHAIN`] 的等待链：建立等待关系前由 [`check_edge`] 判定，
//!   被拒时调用方不得改动任何状态。
//! * 有效档位总是由当前等待图**整体重算**（[`resolve`]）而不是增量加减——借出与归还不会因为
//!   漏掉某一步而残留。

use super::Qos;

/// 允许的最长等待链（从新的等待者算起的边数）。链再长就拒绝建立等待关系，
/// 防止继承传播的代价与死锁检测的深度失控。
pub const MAX_CHAIN: usize = 8;

/// 建立等待关系被拒绝的原因。
/// Why a wait edge was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeError {
    /// 等待者与持有者是同一个槽位（例如递归加锁、等待自己退出）。
    SelfWait,
    /// 持有者（直接或间接）正在等这个等待者：建立后成环，即死锁。
    Cycle,
    /// 等待链超过 [`MAX_CHAIN`]。
    ChainTooLong,
    /// 槽位编号越界。
    NoSuchSlot,
}

/// 判定能否建立「`waiter` 等 `owner`」的等待关系；能则返回建立后从 `waiter` 起的链长（边数）。
///
/// `waits_for[i] = Some(j)` 表示槽位 `i` 正在等槽位 `j`。本函数只读，不修改图。
/// Checks whether `waiter -> owner` may be added; returns the resulting chain length.
pub fn check_edge(waits_for: &[Option<usize>], waiter: usize, owner: usize) -> Result<usize, EdgeError> {
    if waiter >= waits_for.len() || owner >= waits_for.len() {
        return Err(EdgeError::NoSuchSlot);
    }
    if waiter == owner {
        return Err(EdgeError::SelfWait);
    }
    let mut node = owner;
    let mut depth = 1;
    loop {
        if node == waiter {
            return Err(EdgeError::Cycle);
        }
        match waits_for[node] {
            None => return Ok(depth),
            Some(next) => {
                depth += 1;
                if depth > MAX_CHAIN || next >= waits_for.len() {
                    return Err(if next >= waits_for.len() { EdgeError::NoSuchSlot } else { EdgeError::ChainTooLong });
                }
                node = next;
            }
        }
    }
}

/// 按等待图重算全部槽位的有效档位，写入 `effective`。
///
/// * `base[i]`：槽位 `i` 的自身档位（`None` = 空槽位或不参与调度的槽位，它不借出也不接受档位）
/// * `waits_for[i]`：槽位 `i` 正在等的持有者
/// * `enabled = false` 时不传播（有效档位 = 自身档位），供对照测量使用
///
/// 三个切片长度不同时只处理公共长度。即使图中有环（调用方本应用 [`check_edge`] 拒绝），
/// 每条链也最多走切片长度步，必定终止。
/// Recomputes every slot's effective class from the wait graph.
pub fn resolve(base: &[Option<Qos>], waits_for: &[Option<usize>], enabled: bool, effective: &mut [Option<Qos>]) {
    let n = base.len().min(waits_for.len()).min(effective.len());
    effective[..n].copy_from_slice(&base[..n]);
    if !enabled {
        return;
    }
    // 每个等待者把自己的档位沿链向下传：持有者的有效档位因此是全部直接、间接等待者档位的最大值。
    for (i, b) in base[..n].iter().enumerate() {
        let Some(q) = *b else { continue };
        let mut next = waits_for[i];
        let mut steps = 0;
        while let Some(j) = next {
            if j >= n || steps >= n {
                break;
            }
            if let Some(e) = effective[j] {
                effective[j] = Some(e.higher(q));
            }
            next = waits_for[j];
            steps += 1;
        }
    }
}

/// 从同一把锁的等待者中选出交接对象：有效档位最高者优先，同档取等待序号最小（等得最久）者。
///
/// 候选为 `(槽位, 有效档位, 等待序号)`；没有候选时返回 `None`（锁变为空闲）。
/// Picks the waiter that receives the lock on release.
pub fn pick_successor(candidates: impl Iterator<Item = (usize, Qos, u64)>) -> Option<usize> {
    candidates.min_by_key(|&(_, q, seq)| (q, seq)).map(|(slot, _, _)| slot)
}

#[cfg(test)]
mod tests {
    use super::super::{ClassMask, QosParams, QosPolicy, SchedEntity, SchedPolicy};
    use super::*;
    use Qos::*;

    #[test]
    fn edge_ok_and_chain_length() {
        // 2 等 1，现在 3 要等 2：链 3→2→1，长 2
        let w = [None, None, Some(1), None];
        assert_eq!(check_edge(&w, 3, 2), Ok(2));
        assert_eq!(check_edge(&w, 3, 1), Ok(1));
    }

    #[test]
    fn edge_refused_self_cycle_range() {
        let w = [None, Some(2), None];
        assert_eq!(check_edge(&w, 1, 1), Err(EdgeError::SelfWait));
        // 1 在等 2；2 再等 1 ⇒ 成环
        assert_eq!(check_edge(&w, 2, 1), Err(EdgeError::Cycle));
        assert_eq!(check_edge(&w, 0, 9), Err(EdgeError::NoSuchSlot));
        assert_eq!(check_edge(&w, 9, 0), Err(EdgeError::NoSuchSlot));
        // 判定不修改图
        assert_eq!(w, [None, Some(2), None]);
    }

    #[test]
    fn edge_refused_long_chain() {
        // 1→2→…→MAX_CHAIN：从 0 等 1 起链长 MAX_CHAIN 可以，再长一格不行
        let mut w = [None; MAX_CHAIN + 3];
        for (i, slot) in w.iter_mut().enumerate().take(MAX_CHAIN).skip(1) {
            *slot = Some(i + 1);
        }
        assert_eq!(check_edge(&w, 0, 1), Ok(MAX_CHAIN));
        w[MAX_CHAIN] = Some(MAX_CHAIN + 1);
        assert_eq!(check_edge(&w, 0, 1), Err(EdgeError::ChainTooLong));
    }

    #[test]
    fn resolve_direct_transitive_and_max() {
        // 0 空槽位；1 后台持有者；2 工具档等 1；3 交互档等 2；4 用户发起档等 1
        let base = [None, Some(Background), Some(Utility), Some(Interactive), Some(UserInitiated)];
        let w = [None, None, Some(1), Some(2), Some(1)];
        let mut eff = [None; 5];
        resolve(&base, &w, true, &mut eff);
        assert_eq!(eff, [None, Some(Interactive), Some(Interactive), Some(Interactive), Some(UserInitiated)]);
    }

    #[test]
    fn resolve_returns_on_release_and_disabled() {
        let base = [Some(Background), Some(Interactive)];
        let mut eff = [None; 2];
        resolve(&base, &[None, Some(0)], true, &mut eff);
        assert_eq!(eff[0], Some(Interactive));
        // 等待关系解除 ⇒ 借来的档位全部归还
        resolve(&base, &[None, None], true, &mut eff);
        assert_eq!(eff, base);
        // 关闭继承 ⇒ 有效档位就是自身档位
        resolve(&base, &[None, Some(0)], false, &mut eff);
        assert_eq!(eff, base);
    }

    #[test]
    fn resolve_never_lowers_and_terminates_on_cycle() {
        // 低档等待者不会拉低高档持有者
        let base = [Some(Interactive), Some(Background)];
        let mut eff = [None; 2];
        resolve(&base, &[None, Some(0)], true, &mut eff);
        assert_eq!(eff, [Some(Interactive), Some(Background)]);
        // 环（本应被 check_edge 拒绝）也必须终止
        resolve(&base, &[Some(1), Some(0)], true, &mut eff);
        assert_eq!(eff, [Some(Interactive), Some(Interactive)]);
    }

    #[test]
    fn successor_highest_then_oldest() {
        assert_eq!(pick_successor([(3, Utility, 1), (5, Interactive, 9), (7, Interactive, 4)].into_iter()), Some(7));
        assert_eq!(pick_successor(core::iter::empty()), None);
    }

    /// 经典三任务反转的逐 tick 模拟（与内核机制同序：先决策、再运行一个 tick、再记账）。
    /// 返回 H 从阻塞到拿到锁的 tick 数。
    fn inversion(enabled: bool) -> u64 {
        const L: usize = 0;
        const M: usize = 1;
        const H: usize = 2;
        const WORK: u32 = 4; // L 临界区剩余的 CPU tick
        const H_START: u64 = 2; // H 在此刻来要锁
        const HOG_END: u64 = 150; // M 吃满 CPU 到此刻
        let mut policy = QosPolicy::new(QosParams::DEFAULT);
        let base = [Some(Background), Some(Utility), Some(Interactive)];
        let mut e = [SchedEntity::new(Background), SchedEntity::new(Utility), SchedEntity::new(Interactive)];
        let mut runnable = [true, true, false];
        let mut waits_for: [Option<usize>; 3] = [None; 3];
        let mut left = WORK;
        let (mut cur, mut used, mut quantum): (Option<usize>, u32, u32) = (None, 0, 1);
        let apply = |e: &mut [SchedEntity; 3], w: &[Option<usize>; 3]| {
            let mut eff = [None; 3];
            resolve(&base, w, enabled, &mut eff);
            for (x, q) in e.iter_mut().zip(eff) {
                x.qos = q.unwrap_or(x.qos);
            }
        };
        let waiting = |e: &[SchedEntity; 3], r: &[bool; 3], cur: Option<usize>| {
            let mut m = ClassMask::EMPTY;
            for i in 0..3 {
                if r[i] && Some(i) != cur {
                    m.insert(e[i].qos);
                }
            }
            m
        };
        for t in 0..10_000u64 {
            if t == H_START {
                // H 要锁，锁在 L 手里 ⇒ H 阻塞并把档位借给 L
                assert_eq!(check_edge(&waits_for, H, L), Ok(1));
                waits_for[H] = Some(L);
                apply(&mut e, &waits_for);
            }
            let w = waiting(&e, &runnable, cur);
            let resched = match cur {
                Some(c) if runnable[c] => policy.should_preempt(Some(&e[c]), used, quantum, w).is_some(),
                _ => true,
            };
            if resched {
                let mut it = (0..3).filter(|&i| runnable[i]).map(|i| (i, &e[i]));
                let c = policy.choose(&mut it).expect("总有可运行任务");
                cur = Some(c.slot);
                quantum = c.quantum;
                used = 0;
                policy.dispatched(&mut e[c.slot]);
            }
            let c = cur.unwrap();
            if c == H {
                return t - H_START;
            }
            if c == L {
                left -= 1;
                if left == 0 {
                    // 放锁：交给 H，L 的借来档位随等待关系一起归还
                    runnable[L] = false;
                    waits_for[H] = None;
                    runnable[H] = true;
                    policy.woken(&mut e[H]);
                    apply(&mut e, &waits_for);
                    assert_eq!(e[L].qos, Background);
                }
            }
            if c == M && t + 1 >= HOG_END {
                runnable[M] = false;
            }
            let w = waiting(&e, &runnable, Some(c));
            policy.on_tick(Some(&mut e[c]), w);
            used += 1;
        }
        panic!("H 一直没拿到锁");
    }

    #[test]
    fn classic_inversion_bounded_with_inheritance() {
        let with = inversion(true);
        let without = inversion(false);
        // 有继承：等待 = L 剩余临界区（4 tick），与 M 跑多久无关
        assert!(with <= 5, "with={with}");
        // 无继承：L 只拿到后台档的最低份额，H 实际上要等 M 跑完
        assert!(without > 10 * with, "with={with} without={without}");
    }
}
