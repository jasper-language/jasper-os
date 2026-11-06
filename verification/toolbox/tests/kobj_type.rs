//! issue #4 第一片：对象类型登记表（check_grant / kind_for_handle / registry_well_formed）与
//! 既有 Rights 位运算（补链）的差分性质测试与 Miri 固定序列。参照实现用标准库直接写出规格。
use std::collections::HashSet;

use kernel_core::kobj_type::{
    check_grant, closing_locks_match, destroy_hook_matches, destroy_locks_match, kind_for_handle,
    registry_well_formed, Carry, Closing, ClosingLocks, Contract, Destroy, DestroyLocks, GrantCheck, Kind,
    REGISTRY,
};
use kernel_core::object::{ObjectType, Rights};
use proptest::prelude::*;

fn reference_grant(k: Kind, ty: ObjectType, r: Rights) -> GrantCheck {
    let c = REGISTRY.iter().find(|c| c.kind == k).unwrap();
    if c.handle != Some(ty) {
        GrantCheck::WrongType
    } else if r.bits() & Rights::TRANSFER.bits() != 0 && !c.transferable {
        GrantCheck::NotTransferable
    } else if r.bits() & !c.rights.bits() != 0 {
        GrantCheck::RightsDenied
    } else {
        GrantCheck::Allowed
    }
}

/// 从 k 出发经强边可达的种类（含 k）。
fn reach(reg: &[Contract], k: usize) -> HashSet<usize> {
    let mut seen = HashSet::new();
    let mut stack = vec![k];
    while let Some(i) = stack.pop() {
        if seen.insert(i) {
            stack.extend(reg[i].strong.iter().map(|s| s.index()));
        }
    }
    seen
}

fn reference_well_formed(reg: &[Contract]) -> bool {
    if reg.len() != Kind::COUNT || reg.iter().enumerate().any(|(i, c)| c.kind.index() != i) {
        return false;
    }
    let names: HashSet<&str> = reg.iter().map(|c| c.name).collect();
    let handles: Vec<ObjectType> = reg.iter().filter_map(|c| c.handle).collect();
    let distinct: HashSet<u8> = handles.iter().map(|h| *h as u8).collect();
    if names.len() != reg.len() || distinct.len() != handles.len() {
        return false;
    }
    for c in reg {
        let ok_handle = match c.handle {
            None => c.rights.bits() == 0 && !c.transferable && c.closing == Closing::None,
            Some(ty) => {
                c.rights.bits() != 0
                    && c.transferable == (c.rights.bits() & Rights::TRANSFER.bits() != 0)
                    && c.transferable == ty.is_transferable_v1()
            }
        };
        let ordered = c.strong.iter().all(|s| s.index() > c.kind.index());
        let tree_ok = !c.tree_self || c.carries == Carry::AnyClosedOnExit;
        let holds = !c.strong.is_empty() || c.tree_self || c.carries != Carry::Nothing;
        let released = c.closing == Closing::InLock || c.destroy == Destroy::OutsideLock;
        let locked = closing_locks_match(c.closing, c.closing_locks)
            && destroy_locks_match(c.destroy, c.destroy_locks);
        if !(ok_handle && ordered && tree_ok && locked && (!holds || released)) {
            return false;
        }
    }
    reg.iter().enumerate().all(|(k, c)| !c.transferable || reach(reg, k).iter().all(|&i| reg[i].carries == Carry::Nothing))
}

/// 良构 ⇒ 强引用图（不含树形自边）无环：从任何种类出发都回不到自己。
fn acyclic(reg: &[Contract]) -> bool {
    (0..reg.len()).all(|k| reg[k].strong.iter().all(|s| !reach(reg, s.index()).contains(&k)))
}

const EDGE_SETS: [&[Kind]; 6] = [
    &[],
    &[Kind::EventSource],
    &[Kind::ExitState],
    &[Kind::Process],
    &[Kind::Endpoint, Kind::Task],
    &[Kind::Ring, Kind::Device],
];
const CARRIES: [Carry; 3] = [Carry::Nothing, Carry::TransferableOnly, Carry::AnyClosedOnExit];

/// 按字节对生产表做一处变异（字段、强边、交换顺序、改名）。
fn mutate(reg: &mut [Contract; Kind::COUNT], m: (u8, u8, u8, u32)) {
    let (field, at, choice, bits) = m;
    let i = at as usize % Kind::COUNT;
    let c = &mut reg[i];
    match field % 11 {
        0 => c.transferable = !c.transferable,
        1 => c.rights = Rights::from_bits_truncate(bits),
        2 => c.strong = EDGE_SETS[choice as usize % EDGE_SETS.len()],
        3 => c.carries = CARRIES[choice as usize % CARRIES.len()],
        4 => c.closing = if c.closing == Closing::None { Closing::InLock } else { Closing::None },
        5 => c.destroy = if c.destroy == Destroy::None { Destroy::OutsideLock } else { Destroy::None },
        6 => c.handle = if choice % 3 == 0 { None } else { Some(ObjectType::ALL[choice as usize % ObjectType::ALL.len()]) },
        7 => c.tree_self = !c.tree_self,
        8 => reg.swap(i, choice as usize % Kind::COUNT),
        9 => {
            c.closing_locks = if c.closing_locks == ClosingLocks::None {
                ClosingLocks::ObjectTableThenScheduler
            } else {
                ClosingLocks::None
            }
        }
        _ => {
            c.destroy_locks = if c.destroy_locks == DestroyLocks::None {
                DestroyLocks::AfterObjectTable
            } else {
                DestroyLocks::None
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// check_grant 与参照实现一致；kind_for_handle 与登记表一致。
    #[test]
    fn grant_matches_reference(k in 0usize..Kind::COUNT, t in 0usize..ObjectType::ALL.len(), bits in any::<u32>()) {
        let (k, ty, r) = (Kind::ALL[k], ObjectType::ALL[t], Rights::from_bits_truncate(bits));
        prop_assert_eq!(check_grant(k, ty, r), reference_grant(k, ty, r));
        prop_assert_eq!(kind_for_handle(ty), REGISTRY.iter().find(|c| c.handle == Some(ty)).map(|c| c.kind));
    }

    /// 良构判定与参照实现一致；良构时强引用图无环。
    #[test]
    fn well_formed_matches_reference(ms in prop::collection::vec((any::<u8>(), any::<u8>(), any::<u8>(), any::<u32>()), 0..4)) {
        let mut reg = REGISTRY;
        for m in ms {
            mutate(&mut reg, m);
        }
        let wf = registry_well_formed(&reg);
        prop_assert_eq!(wf, reference_well_formed(&reg));
        if wf {
            prop_assert!(acyclic(&reg));
        }
    }

    /// 既有 Rights 位运算（补链）：与 u32 位运算一致，交集被两边包含，截断只留已定义位。
    #[test]
    fn rights_algebra_matches_bits(a in any::<u32>(), b in any::<u32>()) {
        let all = Rights::ALL.bits();
        let (ra, rb) = (Rights::from_bits_truncate(a), Rights::from_bits_truncate(b));
        prop_assert_eq!(ra.bits(), a & all);
        prop_assert_eq!(ra.union(rb).bits(), (a | b) & all);
        prop_assert_eq!(ra.intersect(rb).bits(), a & b & all);
        prop_assert_eq!(ra.difference(rb).bits(), a & !b & all);
        prop_assert_eq!(ra.contains(rb), (a & all) & (b & all) == (b & all));
        prop_assert!(ra.contains(ra.intersect(rb)) && rb.contains(ra.intersect(rb)));
        prop_assert_eq!(ra.is_empty(), a & all == 0);
    }

    /// Destroy::None 只能对应空销毁动作；OutsideLock 必须对应非空模块入口。
    #[test]
    fn destroy_hook_presence_matches_registry(
        declared in prop_oneof![Just(Destroy::None), Just(Destroy::OutsideLock)],
        hook_present in any::<bool>(),
    ) {
        prop_assert_eq!(
            destroy_hook_matches(declared, hook_present),
            hook_present == (declared == Destroy::OutsideLock)
        );
    }

    /// closing / destroy 动作存在性与锁路径声明一致。
    #[test]
    fn lock_path_presence_matches_actions(
        closing in prop_oneof![Just(Closing::None), Just(Closing::InLock)],
        destroy in prop_oneof![Just(Destroy::None), Just(Destroy::OutsideLock)],
        close_locks in prop_oneof![Just(ClosingLocks::None), Just(ClosingLocks::ObjectTableThenScheduler)],
        destroy_locks in prop_oneof![Just(DestroyLocks::None), Just(DestroyLocks::AfterObjectTable)],
    ) {
        prop_assert_eq!(
            closing_locks_match(closing, close_locks),
            (closing == Closing::InLock) == (close_locks != ClosingLocks::None)
        );
        prop_assert_eq!(
            destroy_locks_match(destroy, destroy_locks),
            (destroy == Destroy::OutsideLock) == (destroy_locks == DestroyLocks::AfterObjectTable)
        );
    }
}

/// Miri 固定序列：生产表良构、每个种类每个句柄类型的检查结论、若干变异必被拒。
#[test]
fn fixed_sequence_under_miri() {
    assert!(registry_well_formed(&REGISTRY));
    assert!(reference_well_formed(&REGISTRY) && acyclic(&REGISTRY));
    assert!(destroy_hook_matches(Destroy::None, false));
    assert!(!destroy_hook_matches(Destroy::None, true));
    assert!(destroy_hook_matches(Destroy::OutsideLock, true));
    assert!(!destroy_hook_matches(Destroy::OutsideLock, false));
    assert!(closing_locks_match(Closing::InLock, ClosingLocks::ObjectTableThenScheduler));
    assert!(!closing_locks_match(Closing::None, ClosingLocks::ObjectTable));
    assert!(destroy_locks_match(Destroy::OutsideLock, DestroyLocks::AfterObjectTable));
    for k in Kind::ALL {
        for ty in ObjectType::ALL {
            for r in [Rights::NONE, Rights::WAIT, Rights::TRANSFER, Rights::ALL, k.contract().rights] {
                assert_eq!(check_grant(k, ty, r), reference_grant(k, ty, r));
            }
        }
    }
    let mut seen = 0;
    for field in 0..11u8 {
        for at in 0..Kind::COUNT as u8 {
            let mut reg = REGISTRY;
            mutate(&mut reg, (field, at, at.wrapping_mul(7), 0x1ff));
            assert_eq!(registry_well_formed(&reg), reference_well_formed(&reg));
            seen += 1;
        }
    }
    assert_eq!(seen, 11 * Kind::COUNT);
}
