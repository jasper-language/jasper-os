//! issue #5 第一片：Ring 后端登记表（route / routes_well_formed / Kind::contract）与 quota 准入（补链）的
//! 差分性质测试与 Miri 固定序列。参照实现用标准库集合直接写出规格。
use std::collections::HashSet;

use kernel_core::async_ring::Exec;
use kernel_core::quota::{reserve_u32, reserve_usize};
use kernel_core::ring_backend::{route, routes_well_formed, Kind, Route};
use proptest::prelude::*;

fn reference_route(routes: &[Route], op: u32) -> Option<Kind> {
    routes.iter().find(|r| r.op == op).map(|r| r.kind)
}

fn reference_well_formed(routes: &[Route]) -> bool {
    let ops: HashSet<u32> = routes.iter().map(|r| r.op).collect();
    let kinds: HashSet<usize> = routes.iter().map(|r| r.kind.index()).collect();
    ops.len() == routes.len() && !ops.contains(&0) && kinds.len() == Kind::ALL.len()
}

fn table(raw: &[(u32, u8)]) -> Vec<Route> {
    raw.iter().map(|&(op, k)| Route { op, kind: Kind::ALL[k as usize % Kind::ALL.len()] }).collect()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// 查找与参照实现一致（操作编号取小值域，使命中与重复都常见）。
    #[test]
    fn route_matches_reference(raw in prop::collection::vec((0u32..24, any::<u8>()), 0..16), op in 0u32..28) {
        let t = table(&raw);
        prop_assert_eq!(route(&t, op), reference_route(&t, op));
    }

    /// 良构判定与参照实现一致；良构时每条路由都能按编号唯一查回。
    #[test]
    fn well_formed_matches_reference(raw in prop::collection::vec((0u32..24, any::<u8>()), 0..16)) {
        let t = table(&raw);
        let wf = routes_well_formed(&t);
        prop_assert_eq!(wf, reference_well_formed(&t));
        if wf {
            for r in &t {
                prop_assert_eq!(route(&t, r.op), Some(r.kind));
            }
        }
    }

    /// 准入不回绕、不越限，且等于数学和。
    #[test]
    fn quota_reserve_matches_math(c in any::<u32>(), a in any::<u32>(), l in any::<u32>(), cu in any::<usize>(), au in any::<usize>(), lu in any::<usize>()) {
        let sum = c as u64 + a as u64;
        prop_assert_eq!(reserve_u32(c, a, l), if sum <= l as u64 { Some(sum as u32) } else { None });
        let sumu = cu as u128 + au as u128;
        prop_assert_eq!(reserve_usize(cu, au, lu), if sumu <= lu as u128 { Some(sumu as usize) } else { None });
    }
}

/// Miri 固定序列：遍历全部后端契约、良构 / 非良构表与边界准入。
#[test]
fn fixed_sequence_under_miri() {
    for k in Kind::ALL {
        let c = k.contract();
        assert_eq!(Kind::ALL[k.index()], k);
        assert!(!c.uses_buffer || (c.exec == Exec::Abortable && !c.settles_at_submit));
        assert!(!c.settles_at_submit || c.exec == Exec::NonAbortable);
    }
    let good = table(&[(1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (6, 4), (7, 5), (8, 6)]);
    assert!(routes_well_formed(&good));
    for r in &good {
        assert_eq!(route(&good, r.op), Some(r.kind));
    }
    assert_eq!(route(&good, 0), None);
    assert_eq!(route(&good, 9), None);
    let dup = table(&[(1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (1, 5), (7, 6)]);
    assert!(!routes_well_formed(&dup));
    assert_eq!(route(&dup, 1), Some(Kind::Now));
    assert!(!routes_well_formed(&table(&[(1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (6, 5)])));
    assert!(!routes_well_formed(&table(&[(0, 0), (2, 1), (3, 2), (4, 3), (5, 4), (6, 5), (7, 6)])));
    assert_eq!(reserve_u32(u32::MAX, 1, u32::MAX), None);
    assert_eq!(reserve_u32(3, 4, 7), Some(7));
    assert_eq!(reserve_u32(3, 5, 7), None);
    assert_eq!(reserve_usize(usize::MAX - 1, 1, usize::MAX), Some(usize::MAX));
}
