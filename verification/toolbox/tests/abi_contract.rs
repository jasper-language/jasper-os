//! ABI 完整契约快照的性质测试（issue #8 第二片）。
//! Property tests for complete ABI contract snapshots (issue #8, slice 2).

use kernel_core::abi_contract::{self, Snapshot, SnapshotError};
use kernel_core::abi_version::AbiVersion;
use proptest::prelude::*;
use std::sync::OnceLock;

const REGISTRY: &str = include_str!("../../../abi/system-ids.txt");

fn render() -> String {
    let mut text = String::new();
    abi_contract::render_current(REGISTRY, &mut text).unwrap();
    text
}

fn current() -> &'static str {
    static CURRENT: OnceLock<String> = OnceLock::new();
    CURRENT.get_or_init(render)
}

fn snapshot(version: AbiVersion, text: &str) -> Snapshot<'_> {
    Snapshot { version, text }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// 对当前版本快照的任意正文行做单字节追加，都不能再被当成当前源码契约。
    #[test]
    fn any_snapshot_body_mutation_is_rejected(line_index in any::<usize>()) {
        let current = current();
        let mut lines: Vec<&str> = current.lines().collect();
        prop_assume!(lines.len() > 3);
        let index = line_index % lines.len();
        if lines[index].starts_with('#') || lines[index].starts_with("abi=") {
            return Ok(());
        }
        let replacement = format!("{}x", lines[index]);
        lines[index] = &replacement;
        let mutated = lines.join("\n") + "\n";
        let version = kernel_core::abi_version::NATIVE;
        let result = abi_contract::check_snapshot_set(&current, &[snapshot(version, &mutated)]);
        prop_assert!(
            matches!(result, Err(SnapshotError::CurrentDiff) | Err(SnapshotError::Malformed)),
            "mutation was accepted: {:?}",
            result
        );
    }

    /// 任意合法随机 ABI 版本都不能凭空绕过“当前版本必须有同名快照”。
    #[test]
    fn arbitrary_version_without_current_snapshot_fails(major in any::<u16>(), minor in any::<u16>(), patch in any::<u16>()) {
        let mut current = current().to_string();
        let version = AbiVersion::new(major, minor, patch);
        let start = current.find("abi=").unwrap();
        let end = current[start..].find('\n').unwrap() + start;
        current.replace_range(start..end, &format!("abi={}.{}.{}", major, minor, patch));
        prop_assert_eq!(
            abi_contract::check_snapshot_set(&current, &[]),
            Err(SnapshotError::MissingCurrent(version))
        );
    }
}

/// Miri 下的确定性路径：精确快照通过，同主版本的只增快照通过，改旧条目失败。
#[test]
fn contract_snapshot_rules_under_miri() {
    // Miri 只执行解析/比较的确定性路径；不渲染全部 57 个操作，避免解释器在纯表扫描上耗时。
    let current = "format=1\nabi=1.0.0\niface|1|op|system.time.now|1|read\nop|system.time.now|args=-|result=u64:tick\nsemantics|test.rule|stable\n";
    let native = kernel_core::abi_version::NATIVE;
    assert_eq!(
        abi_contract::check_snapshot_set(current, &[snapshot(native, current)]),
        Ok(()),
        "当前仓库版本不是 1.0.0 时，更新本 Miri 固定样本的版本头"
    );

    let current_minor = "format=1\nabi=1.1.0\niface|1|op|system.time.now|1|read\nop|system.time.now|args=-|result=u64:tick\nsemantics|test.rule|stable\nsemantics|test.addition|allowed\n";
    let old = "format=1\nabi=1.0.0\niface|1|op|system.time.now|1|read\nop|system.time.now|args=-|result=u64:tick\nsemantics|test.rule|stable\n";
    assert_eq!(
        abi_contract::check_snapshot_set(
            current_minor,
            &[
                snapshot(AbiVersion::new(1, 0, 0), old),
                snapshot(AbiVersion::new(1, 1, 0), current_minor),
            ],
        ),
        Ok(())
    );
    let changed = "format=1\nabi=1.1.0\niface|1|op|system.time.now|1|read\nop|system.time.now|args=-|result=u64:tick\nsemantics|test.rule|changed\nsemantics|test.addition|allowed\n";
    assert_eq!(
        abi_contract::check_snapshot_set(
            changed,
            &[
                snapshot(AbiVersion::new(1, 0, 0), old),
                snapshot(AbiVersion::new(1, 1, 0), changed),
            ],
        ),
        Err(SnapshotError::ContractChanged)
    );
}
