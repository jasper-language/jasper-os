#![no_main]
//! issue #5 第一片：后端登记表查找 / 良构判定与参照实现的差分；quota 准入补链。
use kernel_core::quota::reserve_u32;
use kernel_core::ring_backend::{route, routes_well_formed, Kind, Route};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let word = |i: usize| u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
    let (c, a, l, op) = (word(0), word(4), word(8), word(12));
    let sum = c as u64 + a as u64;
    assert_eq!(reserve_u32(c, a, l), if sum <= l as u64 { Some(sum as u32) } else { None });
    // 其余字节每 5 个一条路由；编号取低 5 位，使重复与命中常见
    let routes: Vec<Route> = data[16..]
        .chunks_exact(5)
        .take(16)
        .map(|ch| Route { op: u32::from_le_bytes(ch[..4].try_into().unwrap()) & 0x1f, kind: Kind::ALL[ch[4] as usize % Kind::ALL.len()] })
        .collect();
    let op = op & 0x1f;
    assert_eq!(route(&routes, op), routes.iter().find(|r| r.op == op).map(|r| r.kind));
    let mut ops: Vec<u32> = routes.iter().map(|r| r.op).collect();
    ops.sort_unstable();
    ops.dedup();
    let covered = Kind::ALL.iter().all(|k| routes.iter().any(|r| r.kind == *k));
    let expect = ops.len() == routes.len() && !ops.contains(&0) && covered;
    assert_eq!(routes_well_formed(&routes), expect);
});
