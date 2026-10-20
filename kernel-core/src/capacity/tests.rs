//! 启动期容量的宿主测试：记录编解码、损坏记录、范围 / 一致性 / 内存预算的拒绝路径。
//! Host tests for boot-time capacities.

use super::*;

const DEFAULTS: BootCapacity = BootCapacity { objects: 1024, tasks: 64, rt: 8 };
const COST: MemoryCost = MemoryCost { per_object: 128, per_task: 70 * 1024, per_rt: 32, mem_limit: 32 * 1024 * 1024 };

#[test]
fn default_record_keeps_profile_defaults() {
    let r = encode(Overrides::default());
    let ov = parse(&r).unwrap();
    assert_eq!(ov, Overrides::default());
    assert_eq!(resolve(DEFAULTS, ov, COST), Ok((DEFAULTS, Source::Default)));
}

#[test]
fn record_round_trips_and_overrides_apply() {
    let ov = Overrides { objects: Some(16384), tasks: Some(256), rt: Some(64) };
    let r = encode(ov);
    assert_eq!(&r[..8], &RECORD_MAGIC);
    assert_eq!(parse(&r), Ok(ov));
    let (cap, src) = resolve(DEFAULTS, ov, COST).unwrap();
    assert_eq!(cap, BootCapacity { objects: 16384, tasks: 256, rt: 64 });
    assert_eq!(src, Source::Override);
    // 只覆盖一项，其余取默认值。
    let (cap, _) = resolve(DEFAULTS, Overrides { tasks: Some(128), ..Overrides::default() }, COST).unwrap();
    assert_eq!(cap, BootCapacity { tasks: 128, ..DEFAULTS });
}

#[test]
fn malformed_records_are_rejected() {
    let good = encode(Overrides::default());
    let mut r = good;
    r[0] ^= 0xFF;
    assert_eq!(parse(&r), Err(RecordError::BadMagic));
    let mut r = good;
    r[8] = 2;
    assert_eq!(parse(&r), Err(RecordError::BadVersion(2)));
    let mut r = good;
    r[12] = 1;
    assert_eq!(parse(&r), Err(RecordError::BadReserved));
    let mut r = good;
    r[31] = 1;
    assert_eq!(parse(&r), Err(RecordError::BadReserved));
}

#[test]
fn out_of_range_values_are_rejected_with_structured_reasons() {
    let too_many_tasks = Overrides { tasks: Some(bounds::MAX_TASKS as u32 + 1), ..Overrides::default() };
    let e = resolve(DEFAULTS, too_many_tasks, COST).unwrap_err();
    assert_eq!((e.field, e.reason), ("tasks", CapReason::OutOfRange));
    assert_eq!((e.min, e.max), (bounds::MIN_TASKS as u64, bounds::MAX_TASKS as u64));
    let few_objects = Overrides { objects: Some(bounds::MIN_OBJECTS as u32 - 1), ..Overrides::default() };
    assert_eq!(resolve(DEFAULTS, few_objects, COST).unwrap_err().field, "objects");
    let rt_too_big = Overrides { rt: Some(bounds::MAX_RT as u32 + 1), ..Overrides::default() };
    assert_eq!(resolve(DEFAULTS, rt_too_big, COST).unwrap_err().reason, CapReason::OutOfRange);
}

#[test]
fn realtime_table_may_not_exceed_task_slots() {
    let ov = Overrides { tasks: Some(16), rt: Some(16), ..Overrides::default() };
    let e = resolve(DEFAULTS, ov, COST).unwrap_err();
    assert_eq!((e.field, e.reason, e.max), ("rt", CapReason::Inconsistent, 15));
}

#[test]
fn configurations_that_do_not_fit_in_memory_are_rejected() {
    // 256 个任务 × 70 KiB ≈ 17.5 MiB；预算只给 8 MiB。
    let tight = MemoryCost { mem_limit: 8 * 1024 * 1024, ..COST };
    let ov = Overrides { tasks: Some(256), ..Overrides::default() };
    let e = resolve(DEFAULTS, ov, tight).unwrap_err();
    assert_eq!((e.field, e.reason), ("total", CapReason::ExceedsMemory));
    assert!(e.value > e.max);
}

#[test]
fn magic_appears_only_inverted_in_the_parser() {
    // 解析器比较的是取反后的标记；取反两次必须还原。
    assert_eq!(invert(MAGIC_INVERTED), RECORD_MAGIC);
    assert_ne!(MAGIC_INVERTED, RECORD_MAGIC);
}
