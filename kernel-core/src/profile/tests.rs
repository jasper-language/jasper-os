//! Profile 解析与校验的宿主测试。
//! Host tests for profile resolution.

use super::*;
use crate::config::KernelConfig;

/// 仅取名字的模块声明。
const fn named(name: &'static str) -> ModuleDecl {
    ModuleDecl {
        name,
        provides: &[],
        requires: &[],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    }
}

/// 取全部字段的模块声明（测试样例用）。
const fn full(
    name: &'static str,
    provides: &'static [&'static str],
    requires: &'static [&'static str],
    services: &'static [&'static str],
    hot_load: bool,
    min_tasks: usize,
    min_objects: usize,
) -> ModuleDecl {
    ModuleDecl {
        name,
        provides,
        requires,
        services,
        hot_load,
        sched_class: SchedClass::Interactive,
        min_tasks,
        min_objects,
    }
}

/// 用给定模块表拼一份测试 Profile（参数档固定为 standard）。
const fn sample(modules: &'static [ModuleDecl]) -> SystemProfile {
    SystemProfile {
        name: "test",
        display_zh: "测试",
        display_en: "Test",
        config: KernelConfig::STANDARD,
        modules,
        guarantees: &[],
        hot_load: false,
    }
}

fn codes(errors: &ProfileErrors) -> [Option<ProfileErrorCode>; MAX_ERRORS] {
    let mut out = [None; MAX_ERRORS];
    for (index, error) in errors.iter().enumerate() {
        out[index] = Some(error.code);
    }
    out
}

fn has(errors: &ProfileErrors, code: ProfileErrorCode, subject: &str) -> bool {
    errors.iter().any(|e| e.code == code && e.subject == subject)
}

#[test]
fn builtin_profiles_resolve() {
    for profile in BUILTIN {
        if let Err(errors) = resolve(profile) {
            panic!("{} 校验失败：{:?}", profile.name, codes(&errors));
        }
    }
}

#[test]
fn builtin_profiles_expose_different_service_sets() {
    let full = resolve(&HEADLESS).expect("headless");
    let min = resolve(&HEADLESS_MIN).expect("headless-min");
    assert!(full.services().len() > min.services().len());
    assert!(full.services().contains(&"system.async"));
    assert!(full.services().contains(&"system.channel"));
    assert!(!min.services().contains(&"system.async"));
    assert!(!min.services().contains(&"system.channel"));
    // 两者都必须保留核心服务。
    assert!(min.services().contains(&"system.task"));
    assert!(min.services().contains(&"system.profile"));
}

#[test]
fn capability_sets_are_sorted_and_unique() {
    let resolved = resolve(&HEADLESS).expect("headless");
    let capabilities = resolved.capabilities();
    let mut sorted = [""; MAX_CAPABILITIES];
    sorted[..capabilities.len()].copy_from_slice(capabilities);
    sorted[..capabilities.len()].sort_unstable();
    assert_eq!(&sorted[..capabilities.len()], capabilities);
    let mut unique = [""; MAX_CAPABILITIES];
    unique[..capabilities.len()].copy_from_slice(capabilities);
    let mut count = 1;
    for index in 1..capabilities.len() {
        if unique[index] != unique[index - 1] {
            unique[count] = unique[index];
            count += 1;
        }
    }
    assert_eq!(count, capabilities.len());
}

#[test]
fn service_prefix_matching_respects_boundaries() {
    let resolved = resolve(&HEADLESS).expect("headless");
    assert!(resolved.allows_op("system.async.ring.create"));
    assert!(resolved.allows_op("system.async.cancel"));
    assert!(resolved.allows_op("system.channel.send"));
    assert!(!resolved.allows_op("system.asynchronous.thing"));
    assert!(!resolved.allows_op("system.unknown.op"));

    let min = resolve(&HEADLESS_MIN).expect("headless-min");
    assert!(!min.allows_op("system.async.ring.create"));
    assert!(!min.allows_op("system.channel.create"));
    assert!(min.allows_op("system.time.now"));
}

#[test]
fn empty_profile_is_rejected() {
    let errors = resolve(&sample(&[])).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::NoModules, "test"));
}

#[test]
fn duplicate_module_is_rejected() {
    const MODULES: &[ModuleDecl] = &[named("core"), named("core")];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::DuplicateModule, "core"));
}

#[test]
fn missing_capability_is_rejected() {
    const MODULES: &[ModuleDecl] = &[full("core", &[], &["memory.virtual"], &[], false, 0, 0)];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::MissingCapability, "memory.virtual"));
}

#[test]
fn duplicate_capability_is_rejected() {
    const MODULES: &[ModuleDecl] = &[
        full("a", &["kernel.core"], &[], &[], false, 0, 0),
        full("b", &["kernel.core"], &[], &[], false, 0, 0),
    ];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::DuplicateCapability, "kernel.core"));
}

#[test]
fn provide_and_require_same_capability_is_a_conflict() {
    const MODULES: &[ModuleDecl] = &[full("a", &["kernel.core"], &["kernel.core"], &[], false, 0, 0)];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::CapabilityConflict, "kernel.core"));
}

#[test]
fn duplicate_service_is_rejected() {
    const MODULES: &[ModuleDecl] = &[
        full("a", &[], &[], &["system.time"], false, 0, 0),
        full("b", &[], &[], &["system.time"], false, 0, 0),
    ];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::ServiceConflict, "system.time"));
}

#[test]
fn service_must_use_system_prefix() {
    const MODULES: &[ModuleDecl] = &[full("a", &[], &[], &["app.time"], false, 0, 0)];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::InvalidName, "app.time"));
}

#[test]
fn resource_floor_above_parameter_profile_is_rejected() {
    const TOO_MANY_TASKS: &[ModuleDecl] = &[full("a", &[], &[], &[], false, 4096, 0)];
    let errors = resolve(&sample(TOO_MANY_TASKS)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::UnsatisfiableTasks, "test"));

    const TOO_MANY_OBJECTS: &[ModuleDecl] = &[full("a", &[], &[], &[], false, 0, 1_000_000)];
    let errors = resolve(&sample(TOO_MANY_OBJECTS)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::UnsatisfiableObjects, "test"));
}

#[test]
fn hot_load_requires_profile_opt_in() {
    const MODULES: &[ModuleDecl] = &[full("a", &[], &[], &[], true, 0, 0)];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::HotLoadNotAllowed, "a"));

    const OPT_IN: SystemProfile = SystemProfile {
        name: "test",
        display_zh: "测试",
        display_en: "Test",
        config: KernelConfig::STANDARD,
        modules: MODULES,
        guarantees: &[],
        hot_load: true,
    };
    let resolved = resolve(&OPT_IN).expect("开启热加载后应通过");
    assert_eq!(resolved.hot_load_modules, 1);
}

#[test]
fn invalid_names_are_rejected() {
    const MODULES: &[ModuleDecl] = &[named("Core_Module")];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::InvalidName, "Core_Module"));
}

#[test]
fn all_problems_are_reported_at_once() {
    const MODULES: &[ModuleDecl] = &[
        full("core", &[], &["a.b"], &[], false, 0, 0),
        full("core", &[], &["c.d"], &[], false, 0, 0),
    ];
    let errors = resolve(&sample(MODULES)).unwrap_err();
    assert!(has(&errors, ProfileErrorCode::DuplicateModule, "core"));
    assert!(has(&errors, ProfileErrorCode::MissingCapability, "a.b"));
    assert!(has(&errors, ProfileErrorCode::MissingCapability, "c.d"));
    assert!(!errors.truncated());
}

#[test]
fn kebab_and_capability_rules_are_strict() {
    assert!(is_kebab("dry-run"));
    assert!(!is_kebab("dry--run"));
    assert!(!is_kebab("-run"));
    assert!(!is_kebab("run-"));
    assert!(!is_kebab("Run"));
    assert!(!is_kebab(""));
    assert!(is_capability("kernel.core"));
    assert!(!is_capability("kernel..core"));
    assert!(!is_capability("kernel.Core"));
}
