//! 生效 Profile 的服务装配：把声明的模块绑定到内核里真实的就绪检查，按依赖顺序启动，
//! 只把启动成功的模块所提供的能力发布给能力查询（issue #6）。
//! Service assembly of the effective profile: bind each declared module to a real readiness check,
//! start them in dependency order and publish only the capabilities of modules that came up.
//!
//! # 发布方式
//! 装配在单处理器启动期完成（尚未启动从核、尚无用户程序），完成后把发布掩码写入可撤回发布门
//! [`PUBLICATIONS`]。服务入口必须经 [`acquire`] 取得租约；停用或健康失效先清位，再等待已有租约
//! 退出，最后才运行停用函数。装配前掩码是 0，因此查询不会回落到声明表。
//!
//! # 绑定的含义
//! 启动阶段只建立有真实硬件顺序约束的基础（堆、定时器、PCI 配置空间访问者等）。对象表、
//! 任务表、实时表、作业队列和 PCI 设备表由对应模块的激活函数建立；激活成功后才发布能力。
//! 这些模块都是启动期常驻服务，没有停用函数（停用请求会得到 `permanent`），但常驻服务仍可
//! 因健康失效被撤出发布面。机制演练另用可停用装配验证真实撤位、排空和停用顺序。
//!
//! # 锁序
//! 激活函数只在启动期单处理器上调用，各自短暂取用子系统自己的锁（对象表、任务表、堆、
//! 作业队列），互不嵌套。运行期健康/停用只在装配锁内复制或提交状态；等待读者排空时不持锁，
//! 因而可以让出处理器。停用函数不得重新进入装配锁。

use core::sync::atomic::{AtomicBool, Ordering};

use kernel_core::assembly::{self, Assembly, AuditError, Binding, Health, Policy, State};
use kernel_core::service_gate::{Gate, Lease};

use crate::sync::IrqSpinLock;
use crate::{bootcap, clock, job, kprintln, pci, profile, sched};

/// 生效 Profile 的静态副本（装配保存 `&'static` 引用）。
static ACTIVE: kernel_core::profile::SystemProfile = profile::ACTIVE;

/// 发布掩码：第 b 位 = 生效 Profile 解析后 `capabilities()[b]` 可用。
static PUBLICATIONS: Gate = Gate::new();

/// 启动装配的持久状态；运行期健康与停用需要更新模块生命周期。
static RUNTIME: IrqSpinLock<Option<Assembly>> =
    IrqSpinLock::ranked(crate::lockorder::ASSEMBLY, None);

/// 生命周期写者互斥：不与运行队列锁重叠，等待读者排空时可以让出处理器。
static LIFECYCLE_WRITER: AtomicBool = AtomicBool::new(false);

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
    let pre = PUBLICATIONS.mask();
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
    // 重复启动必须被拒绝且不再调用任何激活函数。
    let again = asm.start(Policy::AllOrNothing).err().map_or("none", |e| e.name());
    let stop = asm.stop("core").err().map_or("none", |e| e.name());
    let stop_devices = asm.preflight_stop("devices").err().map_or("none", |e| e.name());
    let publish = audit.is_ok() && report.failed == 0 && report.blocked == 0;
    *RUNTIME.lock() = Some(asm);
    if publish {
        PUBLICATIONS.publish(mask);
    }
    kprintln!(
        "[JSR-ASSEMBLY] summary profile={} modules={} ready={} failed={} blocked={} declared={} published={} pre_publish={} audit={} restart={} stop_core={} stop_devices={} generation={} readers={}",
        ACTIVE.name,
        ACTIVE.modules.len(),
        report.ready,
        report.failed,
        report.blocked,
        declared.capabilities().len(),
        PUBLICATIONS.mask().count_ones(),
        pre,
        audit_name(audit),
        again,
        stop,
        stop_devices,
        PUBLICATIONS.epoch(),
        PUBLICATIONS.readers()
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
        Err(AuditError::UnknownModule) => "unknown_module",
    }
}

/// 当前发布掩码（供 `system.profile.get` 渲染）。
pub fn published_mask() -> u32 {
    PUBLICATIONS.mask()
}

/// 取得一项已发布能力的服务租约。返回 `None` 时调用者不得进入对应服务。
///
/// 租约必须覆盖真正的服务操作；只查询 [`published_mask`] 后释放租约不能阻止同一时刻的停用。
/// English: acquire a lease covering the actual service operation.
pub fn acquire(capability: &str) -> Option<Lease<'static>> {
    let declared = profile::resolved()?;
    let bit = declared.capabilities().iter().position(|c| *c == capability)?;
    PUBLICATIONS.acquire(bit as u32)
}

/// 系统调用进入模块服务的门：该操作属于生效 Profile 的某个模块服务时，租约必须覆盖整次执行；
/// 不属于任何声明服务的操作由各自的调用授权处理。
/// English: hold the serving module's publication lease across the operation.
pub enum ServiceEntry {
    /// 持有对应模块能力租约。
    Held(Lease<'static>),
    /// 该操作不属于任何 Profile 模块服务。
    Ungated,
}

/// 为系统调用名取得服务租约；声明了服务但当前不可发布时返回 `None`。
/// Acquire the service lease for an operation; `None` means a declared service is unavailable.
pub fn enter_service(operation: &str) -> Option<ServiceEntry> {
    for module in ACTIVE.modules {
        let serves = module.services.iter().any(|service| {
            operation
                .strip_prefix(service)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        });
        if !serves {
            continue;
        }
        for capability in module.provides {
            if let Some(lease) = acquire(capability) {
                return Some(ServiceEntry::Held(lease));
            }
        }
        return None;
    }
    Some(ServiceEntry::Ungated)
}

/// 运行期健康与停用时的快照；不返回锁内引用。
/// Runtime lifecycle snapshot copied outside the assembly lock.
#[derive(Clone, Copy)]
pub struct ModuleStatus {
    /// 模块名。
    pub name: &'static str,
    /// 生命周期状态。
    pub state: State,
    /// 自身健康状态。
    pub health: Health,
    /// 模块自身与依赖的生效健康状态。
    pub effective_health: Health,
    /// 模块能力当前是否至少有一项进入发布面。
    pub available: bool,
    /// 失败或被阻断的原因。
    pub reason: &'static str,
}

/// 固定容量的模块状态快照。
#[derive(Clone, Copy)]
pub struct StatusSnapshot {
    modules: [Option<ModuleStatus>; assembly::MAX_MODULES],
    len: usize,
}

impl StatusSnapshot {
    /// 有效模块状态。
    pub fn modules(&self) -> impl Iterator<Item = ModuleStatus> + '_ {
        self.modules[..self.len].iter().filter_map(|m| *m)
    }
}

/// 读取持久装配的逐模块状态。装配尚未完成时返回空快照。
/// Read the persistent per-module status; empty before boot-time assembly completes.
pub fn statuses() -> StatusSnapshot {
    let runtime = RUNTIME.lock();
    let mut snapshot = StatusSnapshot { modules: [None; assembly::MAX_MODULES], len: 0 };
    let Some(asm) = runtime.as_ref() else {
        return snapshot;
    };
    let published = PUBLICATIONS.mask();
    for k in 0..asm.len() {
        let Some(name) = asm.order(k) else { break };
        let (state, reason) = asm.state(name).unwrap_or((State::Declared, ""));
        let health = asm.health(name).unwrap_or(Health::Unknown);
        let effective_health = asm.effective_health(name).unwrap_or(Health::Unknown);
        let available = asm.module_mask(name).is_some_and(|bits| bits & published != 0);
        snapshot.modules[snapshot.len] = Some(ModuleStatus {
            name,
            state,
            health,
            effective_health,
            available,
            reason,
        });
        snapshot.len += 1;
    }
    snapshot
}

/// 是否有编译期绑定支持这个模块。
/// Whether a compile-time binding exists for this module.
pub fn feature_compiled(module: &str) -> bool {
    BINDINGS.iter().any(|binding| binding.module == module)
}

/// 生命周期写者令牌；析构时释放互斥，错误路径不会遗留忙状态。
struct LifespanWriter;

impl Drop for LifespanWriter {
    fn drop(&mut self) {
        LIFECYCLE_WRITER.store(false, Ordering::Release);
    }
}

fn begin_lifespan_change() -> Result<LifespanWriter, assembly::AssemblyError> {
    LIFECYCLE_WRITER
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| LifespanWriter)
        .map_err(|_| assembly::AssemblyError::Busy)
}

/// 更新模块运行时健康。先撤销将失效的发布位，等待已有租约退出，再修改健康；
/// 恢复时先修改健康再发布新增位。常驻模块也可以降级或恢复。
///
/// English: update health with withdraw-before-change and publish-after-recovery ordering.
pub fn report_health(module: &str, health: Health) -> Result<(), assembly::AssemblyError> {
    if health == Health::Unknown {
        return Err(assembly::AssemblyError::InvalidHealth);
    }
    let _writer = begin_lifespan_change()?;
    let declared = profile::resolved().ok_or(assembly::AssemblyError::ProfileInvalid)?;
    let (old_mask, next_mask) = {
        let runtime = RUNTIME.lock();
        let asm = runtime.as_ref().ok_or(assembly::AssemblyError::NotStarted)?;
        if asm.health(module).is_none() {
            return Err(assembly::AssemblyError::UnknownModule);
        }
        if asm.state(module).map(|s| s.0) != Some(State::Ready) {
            return Err(assembly::AssemblyError::NotReady(
                asm.state(module).map(|s| s.0).unwrap_or(State::Declared),
            ));
        }
        let old = asm.published_mask(&declared);
        let next = asm
            .mask_with_health(module, health, &declared)
            .ok_or(assembly::AssemblyError::UnknownModule)?;
        if let Err(why) = asm.audit_with_health(module, health, &declared, next) {
            kprintln!(
                "[JSR-ASSEMBLY] health_audit phase=pre module={} mask={:#x} reason={}",
                module,
                next,
                audit_name(Err(why))
            );
            return Err(assembly::AssemblyError::AuditFailed);
        }
        (old, next)
    };
    let removed = old_mask & !next_mask;
    let added = next_mask & !old_mask;
    if removed != 0 {
        PUBLICATIONS.withdraw_and_wait(removed, || sched::yield_now());
    }
    let (from, published, readers) = {
        let mut runtime = RUNTIME.lock();
        let asm = runtime.as_mut().ok_or(assembly::AssemblyError::NotStarted)?;
        let from = asm.set_health(module, health)?;
        if PUBLICATIONS.mask() != old_mask & !removed {
            kprintln!(
                "[JSR-ASSEMBLY] health_audit phase=withdraw module={} expected={:#x} actual={:#x}",
                module,
                old_mask & !removed,
                PUBLICATIONS.mask()
            );
            return Err(assembly::AssemblyError::AuditFailed);
        }
        if added != 0 {
            PUBLICATIONS.publish(added);
        }
        let published = asm.published_mask(&declared);
        if published != next_mask || asm.audit(&declared, published).is_err() {
            let reason = asm.audit(&declared, published).err().map(|e| audit_name(Err(e))).unwrap_or("mask_mismatch");
            kprintln!(
                "[JSR-ASSEMBLY] health_audit phase=post module={} expected={:#x} actual={:#x} reason={}",
                module,
                next_mask,
                published,
                reason
            );
            return Err(assembly::AssemblyError::AuditFailed);
        }
        (from, published, PUBLICATIONS.readers())
    };
    kprintln!(
        "[JSR-ASSEMBLY] health module={} from={} to={} removed={:#x} published={:#x} readers={}",
        module,
        from.as_str(),
        health.as_str(),
        removed,
        published,
        readers
    );
    Ok(())
}

/// 停用一个运行时模块：检查依赖与常驻约束，撤位并等待读者排空后调用停用函数。
/// English: stop a runtime module only after withdrawal and reader quiescence.
pub fn stop(module: &str) -> Result<(), assembly::AssemblyError> {
    let _writer = begin_lifespan_change()?;
    let bits = {
        let runtime = RUNTIME.lock();
        let asm = runtime.as_ref().ok_or(assembly::AssemblyError::NotStarted)?;
        asm.preflight_stop(module)?
    };
    if bits != 0 {
        PUBLICATIONS.withdraw_and_wait(bits, || sched::yield_now());
    }
    let (published, readers) = {
        let mut runtime = RUNTIME.lock();
        let asm = runtime.as_mut().ok_or(assembly::AssemblyError::NotStarted)?;
        asm.stop_with(module, |_| {})?;
        let declared = profile::resolved().ok_or(assembly::AssemblyError::ProfileInvalid)?;
        let published = asm.published_mask(&declared);
        if asm.audit(&declared, published).is_err() || PUBLICATIONS.mask() & bits != 0 {
            return Err(assembly::AssemblyError::AuditFailed);
        }
        (published, PUBLICATIONS.readers())
    };
    kprintln!(
        "[JSR-ASSEMBLY] stop module={} withdrawn={:#x} published={:#x} readers={}",
        module,
        bits,
        published,
        readers
    );
    Ok(())
}
