//! 内核生效配置：在构建期从两个配置档中选定一个，并在编译期校验。
//! Effective kernel configuration, chosen at build time and validated at compile time.
//!
//! 职责：只做「选哪一个档」与「启动时把生效参数作为结构化事件输出」。参数的定义、两个配置档的取值
//! 与约束校验在与硬件无关的 `kernel_core::config`（宿主可测）。各模块以 `const` 从 [`ACTIVE`] 取值，
//! 因此数组容量等编译期常量同样随配置档变化，运行期没有额外开销。
//!
//! 选择方式：默认 `standard`；以 cargo 特性 `profile-compact` 构建得到 `compact`。
//! 不合法的配置档在编译期就会失败（见下方 `const` 断言），不可能带着错误参数启动。

use kernel_core::config::KernelConfig;

use crate::{kprint, kprintln};

/// 本次构建生效的配置档。
#[cfg(all(not(feature = "profile-compact"), not(feature = "evt1-verify")))]
pub const ACTIVE: KernelConfig = KernelConfig::STANDARD;
/// 本次构建生效的配置档。
#[cfg(all(feature = "profile-compact", not(feature = "evt1-verify")))]
pub const ACTIVE: KernelConfig = KernelConfig::COMPACT;

/// Author: chatgpt。独立EVT机制验证容量：1000等待者、控制器和引导槽；默认档不变。
#[cfg(feature = "evt1-verify")]
pub const ACTIVE: KernelConfig = {
    let mut c = KernelConfig::STANDARD;
    c.sched.max_tasks = 1024;
    c.memory.heap_max = 128 * 1024 * 1024;
    c
};

const _: () = assert!(ACTIVE.validate().is_ok(), "所选配置档未通过参数校验");

/// 输出生效参数：一行 `[JSR-CONFIG] profile=<名> valid=ok params=<个数>`，再逐项一行
/// `[JSR-CONFIG] <名>=<值>`（结构化事件：名 + 键值，便于工具直接解析）。
/// Print the effective parameters as structured events.
pub fn report() {
    let mut n = 0u32;
    ACTIVE.for_each_field(|_, _| n += 1);
    let valid = if ACTIVE.validate().is_ok() { "ok" } else { "error" };
    kprintln!("[JSR-CONFIG] profile={} valid={} params={}", ACTIVE.name, valid, n);
    ACTIVE.for_each_field(|name, value| {
        kprint!("[JSR-CONFIG] {}={}\n", name, value);
    });
    // 容量概览（HARDEN-1）：把"实验期定下的容量"显式打印出来，便于逐轮审计与对比。
    kprintln!(
        "[JSR-CAP] cpus={} tasks={} objects={} handles={} frames={} rings={} endpoints={}",
        kernel_core::smp::MAX_CPUS,
        ACTIVE.sched.max_tasks,
        ACTIVE.objects.max_objects,
        ACTIVE.objects.handles_per_process,
        ACTIVE.memory.max_process_frames,
        ACTIVE.ring.max_rings_per_process,
        ACTIVE.ipc.max_endpoints_per_process
    );
}
