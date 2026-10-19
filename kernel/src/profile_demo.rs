//! 系统 Profile 的验收演练：生效 Profile、内建表、服务门与结构化拒绝。
//! Drill for system profiles: the active profile, the built-in table, the service
//! gate and structured rejections.
//!
//! # 覆盖
//! 1. 生效 Profile 通过校验并报告参数档、模块数、服务数、能力数、保证数；
//! 2. 内建表两份 Profile 的**服务面真实不同**：`headless` 暴露异步环与通道，
//!    `headless-min` 不暴露——判定用的是同一份 [`ResolvedProfile::allows_op`]；
//! 3. 四类非法 Profile 各自被拒，且拒绝原因是结构化的（码 + 主体）：
//!    缺依赖、能力自相冲突、资源下限超出参数档、未获授权的热加载；
//! 4. `system.profile.get` 的渲染器能把 Profile 写成「键=值」文本，且拒绝过小的缓冲区。
//!
//! 每项打印 `[JSR-PROFILE]` 标记并当场断言；最后输出 `checks=<n> failed=<m>`。
//!
//! # 边界
//! 是 Profile 机制的「客户」：删掉本文件与 `kmain` 中的一行调用不影响机制本身。
//! 不初始化模块、不改调度策略、不含 ISA 代码。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::profile::{
    self, ModuleDecl, ProfileErrorCode, SchedClass, SystemProfile,
};

use crate::{kprintln, profile as active};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 断言：失败时计数并打印哪一条不成立。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-PROFILE-FAIL] {}", what);
    }
}

/// 本演练的失败断言数（`kmain` 汇总进 `[JSR-EXIT] failure`）。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 构造模块声明的辅助函数（`const fn`，用于下面的非法样例）。
const fn module(
    name: &'static str,
    provides: &'static [&'static str],
    requires: &'static [&'static str],
    services: &'static [&'static str],
    hot_load: bool,
    min_tasks: usize,
) -> ModuleDecl {
    ModuleDecl {
        name,
        provides,
        requires,
        services,
        hot_load,
        sched_class: SchedClass::Interactive,
        min_tasks,
        min_objects: 0,
    }
}

// 四类非法 Profile：每一份都是真实数据，交给真实的 `resolve` 判定。
const BAD_MISSING: &[ModuleDecl] = &[module("core", &[], &["memory.virtual"], &[], false, 0)];
const BAD_CONFLICT: &[ModuleDecl] = &[module("core", &["kernel.core"], &["kernel.core"], &[], false, 0)];
const BAD_UNSATISFIABLE: &[ModuleDecl] = &[module("core", &[], &[], &[], false, 4096)];
const BAD_HOT_LOAD: &[ModuleDecl] = &[module("core", &[], &[], &[], true, 0)];

/// 用给定模块表拼一份测试用 Profile（名字固定，校验只看内容）。
const fn sample_profile(name: &'static str, modules: &'static [ModuleDecl]) -> SystemProfile {
    SystemProfile {
        name,
        display_zh: "非法样例",
        display_en: "Invalid sample",
        config: kernel_core::config::KernelConfig::STANDARD,
        modules,
        guarantees: &[],
        hot_load: false,
    }
}

/// 跑一遍四类非法样例，逐条打印结构化拒绝原因，并断言码对得上。
fn reject_case(name: &'static str, modules: &'static [ModuleDecl], want: ProfileErrorCode) {
    let sample = sample_profile(name, modules);
    match profile::resolve(&sample) {
        Ok(_) => check(false, "非法 Profile 竟然通过了校验"),
        Err(errors) => {
            let hit = errors.iter().find(|e| e.code == want);
            match hit {
                Some(e) => {
                    kprintln!(
                        "[JSR-PROFILE] reject case={} code={} subject={} total={}",
                        name,
                        e.code.as_str(),
                        e.subject,
                        errors.len()
                    );
                    for extra in errors.iter() {
                        kprintln!(
                            "[JSR-PROFILE] reason case={} code={} subject={}",
                            name,
                            extra.code.as_str(),
                            extra.subject
                        );
                    }
                    check(true, "非法样例被拒");
                }
                None => {
                    kprintln!(
                        "[JSR-PROFILE] reject case={} code=unexpected total={}",
                        name,
                        errors.len()
                    );
                    check(false, "非法样例的拒绝原因与预期不符");
                }
            }
        }
    }
}

/// 演练入口。
pub fn run() {
    let active_resolved = active::resolved();
    check(active_resolved.is_some(), "生效 Profile 未通过校验");
    let Some(active_services) = active_resolved else {
        kprintln!("[JSR-PROFILE] summary profiles=0 rejects=0 gates=0 renders=0 failed={}", failed());
        return;
    };
    kprintln!(
        "[JSR-PROFILE] effective name={} params={} services={} capabilities={} min_tasks={} min_objects={}",
        active::ACTIVE.name,
        active::ACTIVE.config.name,
        active_services.services().len(),
        active_services.capabilities().len(),
        active_services.min_tasks,
        active_services.min_objects
    );
    for service in active_services.services() {
        kprintln!("[JSR-PROFILE] service name={}", service);
    }

    // 内建表：两份 Profile 的服务面必须真实不同（用同一份判定函数）。
    let full = profile::resolve(&profile::HEADLESS).ok();
    let min = profile::resolve(&profile::HEADLESS_MIN).ok();
    check(full.is_some() && min.is_some(), "内建 Profile 解析失败");
    if let (Some(full), Some(min)) = (full, min) {
        let ring_op = "system.async.ring.create";
        let time_op = "system.time.now";
        kprintln!(
            "[JSR-PROFILE] gate profile=headless op={} allowed={}",
            ring_op,
            full.allows_op(ring_op)
        );
        kprintln!(
            "[JSR-PROFILE] gate profile=headless-min op={} allowed={}",
            ring_op,
            min.allows_op(ring_op)
        );
        kprintln!(
            "[JSR-PROFILE] gate profile=headless-min op={} allowed={}",
            time_op,
            min.allows_op(time_op)
        );
        check(full.allows_op(ring_op), "headless 应暴露异步环");
        check(!min.allows_op(ring_op), "headless-min 不该暴露异步环");
        check(min.allows_op(time_op), "headless-min 应保留时间服务");
        check(full.services().len() > min.services().len(), "两份 Profile 的服务数应不同");
    }

    // 四类非法样例。
    reject_case("missing-capability", BAD_MISSING, ProfileErrorCode::MissingCapability);
    reject_case("capability-conflict", BAD_CONFLICT, ProfileErrorCode::CapabilityConflict);
    reject_case("params-too-small", BAD_UNSATISFIABLE, ProfileErrorCode::UnsatisfiableTasks);
    reject_case("hot-load-not-allowed", BAD_HOT_LOAD, ProfileErrorCode::HotLoadNotAllowed);

    // 渲染器：真实写出键=值文本，并拒绝过小的缓冲区。
    let mut buf = [0u8; 2048];
    let mut renders = 0u32;
    for index in 0..active::count() {
        match active::render(index, &mut buf) {
            Some(len) => {
                renders += 1;
                let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                let head = text.lines().next().unwrap_or("");
                kprintln!("[JSR-PROFILE] render idx={} bytes={} head={}", index, len, head);
                check(text.contains("display_zh=") && text.contains("services="), "渲染结果缺少必需字段");
            }
            None => check(false, "渲染内建 Profile 失败"),
        }
    }
    let mut tiny = [0u8; 16];
    check(active::render(0, &mut tiny).is_none(), "过小的缓冲区应被拒绝");
    check(active::render(active::count(), &mut buf).is_none(), "越界下标应被拒绝");

    kprintln!(
        "[JSR-PROFILE] summary profiles={} rejects=4 gates=3 renders={} checks={} failed={}",
        active::count(),
        renders,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}
