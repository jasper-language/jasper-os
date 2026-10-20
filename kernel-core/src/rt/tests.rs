//! 实时预算与准入的宿主测试。
//! Host tests for real-time quota and admission.

use super::*;

#[test]
fn admits_within_the_utilisation_bound() {
    let mut set = RtSet::for_test(DEFAULT_UTILISATION_PERMILLE, 8);
    assert_eq!(set.admit(1, 2, 10, 0), Ok(())); // 200‰
    assert_eq!(set.admit(2, 3, 10, 0), Ok(())); // +300‰ = 500‰
    assert_eq!(set.utilisation_permille(), 500);
    assert_eq!(set.len(), 2);
}

#[test]
fn refuses_when_the_bound_would_be_exceeded() {
    let mut set = RtSet::for_test(500, 8);
    assert_eq!(set.admit(1, 4, 10, 0), Ok(())); // 400‰
    assert_eq!(set.admit(2, 2, 10, 0), Err(RtError::OverUtilised)); // 累计 600‰
    assert_eq!(set.len(), 1, "被拒的任务不得留在表里");
}

#[test]
fn shape_errors_are_rejected() {
    let mut set = RtSet::for_test(DEFAULT_UTILISATION_PERMILLE, 8);
    assert_eq!(set.admit(1, 0, 10, 0), Err(RtError::BadShape));
    assert_eq!(set.admit(1, 5, 0, 0), Err(RtError::BadShape));
    assert_eq!(set.admit(1, 11, 10, 0), Err(RtError::BadShape), "预算不得大于周期");
}

#[test]
fn duplicates_and_unknown_are_reported() {
    let mut set = RtSet::for_test(DEFAULT_UTILISATION_PERMILLE, 8);
    set.admit(1, 1, 10, 0).unwrap();
    assert_eq!(set.admit(1, 1, 10, 0), Err(RtError::Duplicate));
    assert_eq!(set.charge(9, 1), Err(RtError::Unknown));
    assert_eq!(set.release(9), Err(RtError::Unknown));
}

#[test]
fn full_table_is_reported() {
    let mut set = RtSet::for_test(1000, 8);
    for id in 0..set.capacity() as u32 {
        set.admit(id, 1, 1000, 0).expect("每项 1‰，应能放下");
    }
    assert_eq!(set.admit(99, 1, 1000, 0), Err(RtError::Full));
}

#[test]
fn quota_exhaustion_throttles() {
    let mut set = RtSet::for_test(DEFAULT_UTILISATION_PERMILLE, 8);
    set.admit(1, 3, 10, 0).unwrap();
    assert_eq!(set.charge(1, 1), Ok(Charge::Within));
    assert_eq!(set.charge(1, 2), Ok(Charge::Exhausted));
    assert_eq!(set.get(1).unwrap().remaining, 0);
    assert_eq!(set.get(1).unwrap().throttles, 1);
    // 预算已空，再记账仍然是耗尽。
    assert_eq!(set.charge(1, 1), Ok(Charge::Exhausted));
}

#[test]
fn replenish_resets_and_never_accumulates() {
    let mut set = RtSet::for_test(DEFAULT_UTILISATION_PERMILLE, 8);
    set.admit(1, 4, 10, 0).unwrap();
    set.charge(1, 4).unwrap();
    assert_eq!(set.get(1).unwrap().remaining, 0);
    // 跳过三个周期：仍然只补到一份预算。
    assert_eq!(set.replenish(35), 3);
    assert_eq!(set.get(1).unwrap().remaining, 4);
    assert_eq!(set.get(1).unwrap().next_period, 40);
}

#[test]
fn release_frees_utilisation_for_others() {
    let mut set = RtSet::for_test(500, 8);
    set.admit(1, 4, 10, 0).unwrap();
    assert_eq!(set.admit(2, 2, 10, 0), Err(RtError::OverUtilised));
    set.release(1).unwrap();
    assert_eq!(set.utilisation_permille(), 0);
    assert_eq!(set.admit(2, 2, 10, 0), Ok(()), "释放后应能接纳新任务");
}

#[test]
fn utilisation_rounds_up() {
    let mut set = RtSet::for_test(1000, 8);
    // 1/3 ≈ 334‰（向上取整），两个加起来 668‰。
    set.admit(1, 1, 3, 0).unwrap();
    set.admit(2, 1, 3, 0).unwrap();
    assert_eq!(set.utilisation_permille(), 668);
}

#[test]
fn edf_picks_the_earliest_deadline() {
    let mut set = RtSet::for_test(1000, 8);
    set.admit(1, 1, 50, 0).unwrap(); // 截止期 50
    set.admit(2, 1, 20, 0).unwrap(); // 截止期 20
    assert_eq!(set.pick_edf(0), Some(2), "更早的截止期优先");
}

#[test]
fn edf_skips_throttled_tasks() {
    let mut set = RtSet::for_test(1000, 8);
    set.admit(1, 1, 10, 0).unwrap();
    set.admit(2, 1, 20, 0).unwrap();
    set.charge(1, 1).unwrap(); // 1 号预算耗尽
    assert_eq!(set.pick_edf(0), Some(2), "预算耗尽的任务不参与选择");
    set.replenish(10);
    assert_eq!(set.pick_edf(10), Some(1), "补充后重新参与");
}

#[test]
fn priority_pick_prefers_larger_quota_ratio() {
    let mut set = RtSet::for_test(1000, 8);
    set.admit(1, 1, 10, 0).unwrap(); // 100‰
    set.admit(2, 4, 10, 0).unwrap(); // 400‰
    assert_eq!(set.pick_priority(), Some(2));
}

#[test]
fn uninstalled_set_refuses_admission_safely() {
    let mut set = RtSet::new(1000);
    assert_eq!(set.capacity(), 0);
    assert_eq!(set.admit(1, 1, 10, 0), Err(RtError::Full), "未安装存储 ⇒ 安全失败");
}

#[test]
fn install_rules_and_boot_sized_capacity() {
    let mut set = RtSet::new(1000);
    assert_eq!(set.install(Box::leak(Vec::new().into_boxed_slice())), Err(InstallError::Empty));
    let dirty = Box::leak(vec![None, Some(RtTask { id: 1, quota: 1, period: 2, remaining: 1, next_period: 2, throttles: 0 })].into_boxed_slice());
    assert_eq!(set.install(dirty), Err(InstallError::NotVacant));
    assert_eq!(set.capacity(), 0, "被拒后保持为空");
    assert_eq!(set.install(Box::leak(vec![None; 64].into_boxed_slice())), Ok(64));
    assert_eq!(set.install(Box::leak(vec![None; 4].into_boxed_slice())), Err(InstallError::AlreadyInstalled));
    for id in 0..64 {
        set.admit(id, 1, 1000, 0).expect("64 个 1‰ 的任务应全部被接纳");
    }
    assert_eq!(set.admit(99, 1, 1000, 0), Err(RtError::Full));
    assert_eq!(set.len(), 64);
}
