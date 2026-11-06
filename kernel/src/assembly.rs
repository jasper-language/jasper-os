//! 生效 Profile 的服务装配：把声明的模块绑定到内核里真实的就绪检查，按依赖顺序启动，
//! 只把启动成功的模块所提供的能力发布给能力查询（issue #6）。
//! Service assembly of the effective profile: bind each declared module to a real readiness check,
//! start them in dependency order and publish only the capabilities of modules that came up.
//!
//! # 发布方式
//! 装配在单处理器启动期完成（尚未启动从核、尚无用户程序），完成后把发布掩码以 Release 写入
//! [`PUBLISHED`]；任何核上的 [`available`] 以 Acquire 读取。掩码在本切片里只写一次：
//! 读到某位为 1 ⇒ 对应模块的激活已经完成且对读者可见。装配前读到的掩码是 0，
//! 因此「装配前查询」一律得到不可用，而不是回落到声明表。
//!
//! # 绑定的含义
//! 启动阶段只建立有真实硬件顺序约束的基础（堆、定时器、PCI 配置空间访问者等）。对象表、
//! 任务表、实时表、作业队列和 PCI 设备表由对应模块的激活函数建立；激活成功后才发布能力。
//! 这些模块都是启动期常驻服务，没有停用函数（停用请求会得到 `permanent`）。
//!
//! # 锁序
//! 不持有任何装配锁；激活函数只在启动期单处理器上调用，各自短暂取用子系统自己的锁
//! （对象表、任务表、堆、作业队列），互不嵌套。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::assembly::{self, Assembly, AuditError, Binding, Policy};

use crate::{bootcap, clock, job, kprintln, pci, profile};

/// 生效 Profile 的静态副本（装配保存 `&'static` 引用）。
static ACTIVE: kernel_core::profile::SystemProfile = profile::ACTIVE;

/// 发布掩码：第 b 位 = 生效 Profile 解析后 `capabilities()[b]` 可用。
static PUBLISHED: AtomicU32 = AtomicU32::new(0);

/// 内核能构建的全部模块的绑定（生效 Profile 未声明的条目被忽略）。
static BINDINGS: [Binding; 9] = [
    Binding { module: "core", activate: core_activate, deactivate: None },
    Binding { module: "memory", activate: memory_ready, deactivate: None },
    Binding { module: "time", activate: time_ready, deactivate: None },
    Binding { module: "sched", activate: sched_activate, deactivate: None },
    Binding { module: "channel", activate: channel_ready, deactivate: None },
    Binding { module: "realtime", activate: realtime_activate, deactivate: None },
    Binding { module: "job", activate: job_activate, deactivate: None },
    Binding { module: "async", activate: async_ready, deactivate: None },
    Binding { module: "devices", activate: devices_activate, deactivate: None },
];

/// `core` 模块激活时安装对象表，并执行销毁分派登记一致性检查。
/// Install the object table and verify the destroy-dispatch registry.
fn core_activate() -> Result<(), &'static str> {
    let cap = bootcap::requested()?;
    match crate::kobj::install(cap.objects) {
        Ok(_) => {}
        Err(None) => return Err("object table allocation failed"),
        Err(Some(e)) => return Err(e.as_str()),
    }
    match crate::kobj::verify_destroy_dispatch() {
        Ok((outside, none)) => kprintln!(
            "[JSR-LIFE] destroy_dispatch outside_lock={} none={} none_empty=true destroyed_when_none=0 hooks_match_registry=true",
            outside,
            none
        ),
        Err(reason) => {
            kprintln!(
                "[JSR-LIFE] destroy_dispatch consistency=failed reason={} none_empty=false destroyed_when_none=unknown hooks_match_registry=false",
                reason
            );
            return Err(reason);
        }
    }
    match crate::kobj::verify_release_dispatch() {
        Ok((outside, none)) => kprintln!(
            "[JSR-LIFE] release_dispatch closing_locks=true outside_lock={} none={} none_empty=true destroyed_when_none=0 hooks_match_registry=true",
            outside,
            none
        ),
        Err(reason) => {
            kprintln!(
                "[JSR-LIFE] release_dispatch consistency=failed reason={} closing_locks=false none_empty=false destroyed_when_none=unknown hooks_match_registry=false",
                reason
            );
            return Err(reason);
        }
    }
    kprintln!("[JSR-ASSEMBLY] activate module=core objects={}", crate::kobj::capacity());
    Ok(())
}

/// 内存服务需要内核堆已初始化（映射服务先于堆建立，堆可用即映射可用）。
fn memory_ready() -> Result<(), &'static str> {
    let (total, _, _, mapped) = crate::mm::heap::stats();
    if total == 0 || mapped == 0 {
        return Err("kernel heap not initialized");
    }
    Ok(())
}

/// 单调时间服务需要定时器中断已经在推进时钟。
fn time_ready() -> Result<(), &'static str> {
    if clock::ticks() == 0 {
        return Err("timer not ticking");
    }
    Ok(())
}

/// `sched` 模块激活时把任务表扩到启动期容量，并为新槽位预留内核栈。
/// Grow the task table and reserve kernel stacks during scheduler-module activation.
fn sched_activate() -> Result<(), &'static str> {
    let cap = bootcap::requested()?;
    let stacks = match crate::sched::grow(cap.tasks) {
        Ok(n) if n == cap.tasks => n,
        Ok(_) => return Err("task table capacity mismatch"),
        Err(crate::sched::GrowError::OutOfMemory { .. }) => return Err("task table allocation failed"),
        Err(crate::sched::GrowError::Shrink) => return Err("task table shrink"),
        Err(crate::sched::GrowError::NotQuiescent) => return Err("task table not quiescent"),
    };
    if crate::sched::capacity() < 2 {
        return Err("task table too small");
    }
    kprintln!("[JSR-ASSEMBLY] activate module=sched tasks={} stacks={}", crate::sched::capacity(), stacks);
    Ok(())
}

/// 通道是对象表中的对象，消息队列在内核堆上。
fn channel_ready() -> Result<(), &'static str> {
    if crate::kobj::capacity() == 0 {
        return Err("object table not installed");
    }
    Ok(())
}

/// `realtime` 模块激活时安装实时准入表容量。
/// Install the real-time admission-table capacity.
fn realtime_activate() -> Result<(), &'static str> {
    let cap = bootcap::requested()?;
    match crate::rt::install(cap.rt) {
        Ok(_) => {}
        Err(None) => return Err("realtime table allocation failed"),
        Err(Some(e)) => return Err(e.as_str()),
    }
    kprintln!("[JSR-ASSEMBLY] activate module=realtime rt={}", crate::rt::capacity());
    Ok(())
}

/// `job` 模块激活时建立本次启动唯一的空作业队列。
/// Establish the single empty boot-time job queue.
fn job_activate() -> Result<(), &'static str> {
    job::activate()?;
    let s = job::stats();
    if !job::active() || s.total != 0 {
        return Err("job queue not empty at boot");
    }
    kprintln!("[JSR-ASSEMBLY] activate module=job queue=empty");
    Ok(())
}

/// `devices` 模块激活时建立 PCI 只读设备表。
/// Build the read-only PCI device table during device-module activation.
fn devices_activate() -> Result<(), &'static str> {
    pci::activate()?;
    let table = pci::table();
    kprintln!(
        "[JSR-ASSEMBLY] activate module=devices pci={} functions={}",
        table.mechanism.as_str(),
        table.functions()
    );
    Ok(())
}

/// 异步环是对象表中的对象。
fn async_ready() -> Result<(), &'static str> {
    if crate::kobj::capacity() == 0 {
        return Err("object table not installed");
    }
    Ok(())
}

/// 启动期装配：构造、按依赖顺序启动（全有全无）、审计、发布。
///
/// 返回失败数（0 = 全部模块就绪且发布掩码通过审计）；任何失败都意味着声明的能力不能兑现，
/// 调用方必须拒绝继续启动。每个模块输出一行 `[JSR-ASSEMBLY] module=…`。
/// English: assemble, audit and publish; returns the number of failures.
pub fn boot() -> u32 {
    let Some(declared) = profile::resolved() else {
        kprintln!("[JSR-ASSEMBLY] error={}", assembly::AssemblyError::ProfileInvalid.name());
        return 1;
    };
    let mut asm = match Assembly::new(&ACTIVE, &BINDINGS) {
        Ok(a) => a,
        Err(e) => {
            kprintln!("[JSR-ASSEMBLY] error={}", e.name());
            return 1;
        }
    };
    let pre = PUBLISHED.load(Ordering::Acquire);
    let report = match asm.start(Policy::AllOrNothing) {
        Ok(r) => r,
        Err(e) => {
            kprintln!("[JSR-ASSEMBLY] error={}", e.name());
            return 1;
        }
    };
    bootcap::restore_heap();
    bootcap::report_boot();
    for k in 0..asm.len() {
        let Some(name) = asm.order(k) else { break };
        let (state, reason) = asm.state(name).unwrap_or((assembly::State::Declared, ""));
        kprintln!("[JSR-ASSEMBLY] module={} order={} state={} reason={}", name, k, state.as_str(), reason);
    }
    let mask = asm.published_mask(&declared);
    let audit = asm.audit(&declared, mask);
    // 只有审计通过才发布；失败时掩码保持 0（所有能力不可用），由调用方拒绝启动。
    if audit.is_ok() && report.failed == 0 && report.blocked == 0 {
        PUBLISHED.store(mask, Ordering::Release);
    }
    // 重复启动必须被拒绝且不再调用任何激活函数。
    let again = asm.start(Policy::AllOrNothing).err().map_or("none", |e| e.name());
    let stop = asm.stop("core").err().map_or("none", |e| e.name());
    kprintln!(
        "[JSR-ASSEMBLY] summary profile={} modules={} ready={} failed={} blocked={} declared={} published={} pre_publish={} audit={} restart={} stop_core={}",
        ACTIVE.name,
        asm.len(),
        report.ready,
        report.failed,
        report.blocked,
        declared.capabilities().len(),
        PUBLISHED.load(Ordering::Acquire).count_ones(),
        pre,
        audit_name(audit),
        again,
        stop
    );
    u32::from(report.failed) + u32::from(report.blocked) + u32::from(audit.is_err())
}

fn audit_name(a: Result<(), AuditError>) -> &'static str {
    match a {
        Ok(()) => "ok",
        Err(AuditError::PublishedNotReady(_)) => "published_not_ready",
        Err(AuditError::ReadyNotPublished(_)) => "ready_not_published",
        Err(AuditError::UnknownBit(_)) => "unknown_bit",
        Err(AuditError::DependencyNotReady(_)) => "dependency_not_ready",
    }
}

/// 运行时能力查询：只有已装配就绪并发布的能力为真；装配前恒为假。
/// English: true only for capabilities published by the boot-time assembly.
pub fn available(capability: &str) -> bool {
    let mask = PUBLISHED.load(Ordering::Acquire);
    mask != 0 && profile::resolved().is_some_and(|r| assembly::mask_has(&r, mask, capability))
}

/// 当前发布掩码（供 `system.profile.get` 渲染）。
pub fn published_mask() -> u32 {
    PUBLISHED.load(Ordering::Acquire)
}
