//! issue #1：生产 `SyscallSet` 与 `spawn_abi::{SpawnDesc, check}` 对照独立参考模型（`BTreeSet`）的性质测试。
//! Property tests of the production capability set and spawn admission against a BTreeSet reference.
//!
//! 参考模型不复用生产代码的任何位运算：集合用 `BTreeSet<u32>`，准入规则按 ABI 文档逐条重写。
use kernel_core::spawn_abi::{check, SpawnDesc, SpawnReject, CPU_UNLIMITED, MAX_IMAGE_BYTES, MIN_CPU_LIMIT, SPAWN_DESC_SIZE};
use kernel_core::syscall_set::{CallIdError, SetError, SyscallSet, MAX_IDS};
use proptest::prelude::*;
use std::collections::BTreeSet;

/// ID 偏向容量边界（0/63/64/127/128/191/192/255）与越界值，其余均匀取。
fn id() -> impl Strategy<Value = u32> {
    prop_oneof![
        prop::sample::select(vec![0u32, 1, 62, 63, 64, 65, 126, 127, 128, 191, 192, 254, 255, 256, 257, 4096, u32::MAX]),
        0u32..300,
    ]
}

/// 容量内 ID（偏向字边界），用于准入规则：保证每个用例都真正执行比较。
fn valid_id() -> impl Strategy<Value = u32> {
    prop_oneof![prop::sample::select(vec![0u32, 63, 64, 127, 128, 191, 192, 255]), 0u32..MAX_IDS as u32]
}

/// 一半用例全部在容量内，一半混入越界 ID（验证整体拒绝、不截断）。
fn ids() -> impl Strategy<Value = Vec<u32>> {
    prop_oneof![prop::collection::vec(valid_id(), 0..24), prop::collection::vec(id(), 0..24)]
}

fn valid_ids() -> impl Strategy<Value = Vec<u32>> {
    prop::collection::vec(valid_id(), 0..24)
}

/// 严格构造输入：包含容量边界、`u32` 宽度之外的越界值和均匀随机值。
fn strict_ids() -> impl Strategy<Value = Vec<u64>> {
    let one = prop_oneof![
        valid_id().prop_map(u64::from),
        prop::sample::select(vec![255u64, 256, 257, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX]),
    ];
    prop::collection::vec(one, 0..24)
}

/// 参考构造：任一 ID 越界 ⇒ 整体拒绝（不截断）。
fn reference(ids: &[u32]) -> Option<BTreeSet<u32>> {
    if ids.iter().any(|&i| i as usize >= MAX_IDS) {
        return None;
    }
    Some(ids.iter().copied().collect())
}

fn assert_same(set: SyscallSet, model: &BTreeSet<u32>) -> Result<(), TestCaseError> {
    for probe in 0u64..(MAX_IDS as u64 + 8) {
        prop_assert_eq!(set.contains(probe), probe < MAX_IDS as u64 && model.contains(&(probe as u32)));
    }
    prop_assert!(!set.contains(u64::MAX));
    prop_assert_eq!(set.count(), model.len());
    prop_assert_eq!(set.ids().collect::<Vec<_>>(), model.iter().copied().collect::<Vec<_>>());
    Ok(())
}

/// 独立按顺序重写严格构造规则；错误值只描述拒绝原因，不参与位图计算。
fn reference_strict(ids: &[u64], known: &BTreeSet<u32>) -> Result<BTreeSet<u32>, CallIdError> {
    let mut set = BTreeSet::new();
    for &id in ids {
        if id >= MAX_IDS as u64 {
            return Err(CallIdError::OutOfRange(id));
        }
        if !known.contains(&(id as u32)) {
            return Err(CallIdError::Unknown(id));
        }
        if !set.insert(id as u32) {
            return Err(CallIdError::Duplicate(id));
        }
    }
    Ok(set)
}

/// 按 ABI 文档重写的准入判定（规则顺序与拒绝原因一一对应）。
fn reference_check(d: &SpawnDesc, calls: &BTreeSet<u32>, caller: &BTreeSet<u32>, known: &BTreeSet<u32>) -> Result<(), SpawnReject> {
    if d.magic != 0x4A53_5032 || d.version != 2 || d.size != 88 {
        return Err(SpawnReject::Format);
    }
    if d.flags != 0 {
        return Err(SpawnReject::Reserved);
    }
    if d.image_len == 0 || d.image_len > 2 * 1024 * 1024 {
        return Err(SpawnReject::ImageSize);
    }
    if !calls.is_subset(known) {
        return Err(SpawnReject::UnknownCall);
    }
    if !calls.is_subset(caller) {
        return Err(SpawnReject::Escalation);
    }
    if !(10..=1000).contains(&d.cpu_limit_permille) {
        return Err(SpawnReject::CpuLimit);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn set_operations_match_reference(a in ids(), b in ids()) {
        let (ra, rb) = (reference(&a), reference(&b));
        prop_assert_eq!(SyscallSet::try_of(&a).is_some(), ra.is_some());
        prop_assert_eq!(SyscallSet::try_of(&b).is_some(), rb.is_some());
        let (Some(ra), Some(rb)) = (ra, rb) else { return Ok(()); };
        let (sa, sb) = (SyscallSet::try_of(&a).unwrap(), SyscallSet::try_of(&b).unwrap());
        assert_same(sa, &ra)?;
        assert_same(sa.union(sb), &ra.union(&rb).copied().collect())?;
        assert_same(sa.intersection(sb), &ra.intersection(&rb).copied().collect())?;
        assert_same(sa.difference(sb), &ra.difference(&rb).copied().collect())?;
        prop_assert_eq!(sa.is_subset_of(sb), ra.is_subset(&rb));
        prop_assert_eq!(sa.is_empty(), ra.is_empty());
        let mut buf = [0u8; 32];
        sa.encode(&mut buf);
        prop_assert_eq!(SyscallSet::decode(&buf), sa);
    }

    #[test]
    fn strict_construction_matches_reference(ids in strict_ids(), known in valid_ids()) {
        let model_known: BTreeSet<u32> = known.iter().copied().collect();
        let got = SyscallSet::try_from_ids(&ids, SyscallSet::try_of(&known).unwrap());
        let want = reference_strict(&ids, &model_known);
        match (got, want) {
            (Ok(set), Ok(model)) => assert_same(set, &model)?,
            (Err(got), Err(want)) => prop_assert_eq!(got, want),
            (got, want) => prop_assert!(false, "result mismatch: got={:?} want={:?}", got, want),
        }
    }

    #[test]
    fn task_set_admission_matches_reference(
        requested in valid_ids(), caller in valid_ids(), registered in valid_ids()
    ) {
        let requested: BTreeSet<u32> = requested.into_iter().collect();
        let caller: BTreeSet<u32> = caller.into_iter().collect();
        let registered: BTreeSet<u32> = registered.into_iter().collect();
        let want = if !requested.is_subset(&registered) {
            Err(SetError::Unregistered)
        } else if !requested.is_subset(&caller) {
            Err(SetError::Escalation)
        } else {
            Ok(())
        };
        let got = SyscallSet::check_set(
            SyscallSet::try_of(&requested.iter().copied().collect::<Vec<_>>()).unwrap(),
            SyscallSet::try_of(&caller.iter().copied().collect::<Vec<_>>()).unwrap(),
            SyscallSet::try_of(&registered.iter().copied().collect::<Vec<_>>()).unwrap(),
        );
        prop_assert_eq!(got, want);
    }

    #[test]
    fn spawn_admission_matches_reference(
        calls in valid_ids(), caller in valid_ids(), known in valid_ids(),
        header in prop::sample::select(vec![(0x4A53_5032u32, 2u16, 88u16), (0x4A53_5031, 2, 88), (0x4A53_5032, 1, 88), (0x4A53_5032, 2, 56), (0, 0, 0)]),
        flags in prop_oneof![Just(0u32), any::<u32>()],
        image_len in prop_oneof![Just(0u64), Just(1u64), Just(MAX_IMAGE_BYTES), Just(MAX_IMAGE_BYTES + 1), any::<u64>()],
        cpu in prop_oneof![Just(MIN_CPU_LIMIT - 1), Just(MIN_CPU_LIMIT), Just(CPU_UNLIMITED), Just(CPU_UNLIMITED + 1), any::<u32>()],
        arg in any::<u64>(),
    ) {
        let (rc, rp, rk) = (reference(&calls).unwrap(), reference(&caller).unwrap(), reference(&known).unwrap());
        let d = SpawnDesc {
            magic: header.0, version: header.1, size: header.2,
            image_ptr: 0x1000, image_len, calls: SyscallSet::try_of(&calls).unwrap(), arg,
            cpu_limit_permille: cpu, flags, out_process: 0, out_channel: 0,
        };
        let got = check(&d, SyscallSet::try_of(&caller).unwrap(), SyscallSet::try_of(&known).unwrap());
        prop_assert_eq!(got, reference_check(&d, &rc, &rp, &rk));
        // 序列化往返：合法头部解码后逐字节还原；非法头部一律 Format。
        let raw = d.encode();
        prop_assert_eq!(raw.len(), SPAWN_DESC_SIZE);
        match SpawnDesc::decode(&raw) {
            Ok(back) => { prop_assert_eq!(back, d); prop_assert_eq!(header, (0x4A53_5032, 2, 88)); }
            Err(e) => { prop_assert_eq!(e, SpawnReject::Format); prop_assert_ne!(header, (0x4A53_5032, 2, 88)); }
        }
    }
}

/// 多级 spawn：每一级都通过准入 ⇒ 孙进程 ⊆ 祖先（固定链，供 Miri 逐条执行）。
#[test]
fn multi_level_spawn_never_escalates() {
    let root = SyscallSet::of(&[1, 63, 64, 127, 200, 255]);
    let known = SyscallSet::FULL;
    let ok = |calls: SyscallSet| SpawnDesc { image_len: 64, calls, cpu_limit_permille: CPU_UNLIMITED, ..Default::default() };
    let child = SyscallSet::of(&[63, 64, 255]);
    assert_eq!(check(&ok(child), root, known), Ok(()));
    let grandchild = SyscallSet::of(&[64, 255]);
    assert_eq!(check(&ok(grandchild), child, known), Ok(()));
    assert!(grandchild.is_subset_of(root));
    // 孙进程请求祖先有、父进程没有的 ID 127 ⇒ 提权被拒。
    assert_eq!(check(&ok(SyscallSet::of(&[127])), child, known), Err(SpawnReject::Escalation));
}

/// 登记高编号操作 ID 64 在 v2 参数块的第二个字中保持独立，并且只在双向子集成立时准入。
#[test]
fn registered_high_id_64_roundtrips_through_spawn_v2() {
    let high = SyscallSet::of(&[64]);
    let parent = SyscallSet::of(&[64, 127]);
    let known = SyscallSet::of(&[63, 64, 127, 255]);
    let desc = SpawnDesc {
        image_len: 64,
        calls: high,
        cpu_limit_permille: CPU_UNLIMITED,
        ..Default::default()
    };
    let raw = desc.encode();
    assert_eq!(&raw[32..40], &1u64.to_le_bytes());
    assert_eq!(SpawnDesc::decode(&raw), Ok(desc));
    assert_eq!(check(&desc, parent, known), Ok(()));
    assert_eq!(check(&desc, SyscallSet::of(&[63, 127]), known), Err(SpawnReject::Escalation));
    assert_eq!(check(&desc, parent, SyscallSet::of(&[63, 127])), Err(SpawnReject::UnknownCall));
}
