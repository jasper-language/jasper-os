//! M1.5 机制演练：在真机（QEMU）上逐一调用 `kernel-core` 的机制，打印验收标记并**当场断言**。
//!
//! # 职责
//! 作为一个普通内核任务（名为 `mech`）运行，依次演练：
//! 对象/句柄/权限 → 等待（真实定时器 tick）→ 异步 ring → 地址空间记账 → 模块装配 →
//! 系统调用分发 → 关中断自旋锁 → 结构化追踪；每一项既打印 `[JSR-*]` 标记，又用 [`Checker`]
//! 校验结果。最后输出 `[JSR-MECH] checks=<n> failed=<m>`，验收脚本要求 `failed=0`。
//!
//! # 边界（为什么放在这里、为什么可删）
//! 这是机制的「客户」，与机制分离（同 `sched/demo.rs`）：删掉本文件与 `kmain` 里的一行调用，
//! 机制本身不受影响。宿主单元测试证明机制在宿主上正确；本文件证明它们在 `no_std` 目标、
//! 真实中断与调度下同样工作。不含 ISA 代码：硬件只经 `arch::*` 与 `sched::*`。
//!
//! 注意：本任务不打印 `[JSR-TASK] name=<大写字母>` 行，以免干扰 M1.3 验收对 A/B/C 的统计。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::assembly::{Assembly, Binding, Health, Policy, State};
use kernel_core::config::KernelConfig;
use kernel_core::io::{IoBackend, IoOp, IoRequest, MemIoCore, Ring};
use kernel_core::memory::{AddressSpace, SimpleAddressSpace, VmProtection, PAGE_SIZE};
use kernel_core::meta::{Effects, InterfaceMeta};
use kernel_core::object::{HandleError, HandleTable, ObjectManager, ObjectRef, ObjectType, Rights};
use kernel_core::profile::{self, ModuleDecl, SchedClass, SystemProfile};
use kernel_core::trace::Tag;
use kernel_core::trap::{Dispatcher, SysError, SyscallEntry, SysResult, TrapEvent, TrapFrame};
use kernel_core::wait::{Event, TimeSource, Timer, WaitResult, WaitSet};

use crate::sched::{self, TickClock};
use crate::sync::IrqSpinLock;
use crate::task::TaskId;
use crate::{arch, kprintln, ktrace};

/// 演练任务的 ID。
const MECH_TASK_ID: u64 = 21;

/// 断言总数与失败数（任务退出后由引导线程读取汇总）。
static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 极简断言器：失败时打印 `[JSR-MECH-FAIL]` 而不是 panic，让后续机制继续演练、一次看清全部问题。
struct Checker;

impl Checker {
    fn check(&self, ok: bool, what: &str) {
        CHECKS.fetch_add(1, Ordering::Relaxed);
        if !ok {
            FAILED.fetch_add(1, Ordering::Relaxed);
            kprintln!("[JSR-MECH-FAIL] {}", what);
        }
    }
}

/// 对象 / 句柄 / 权限：创建事件对象、放入句柄表、降权、关闭后复用被拒。
fn exercise_objects(c: &Checker) {
    let om = ObjectManager::new();
    let mut table: HandleTable<ObjectRef, 8> = HandleTable::new();
    let Ok(ev) = om.create(ObjectType::Event) else {
        c.check(false, "object: 对象 ID 用尽");
        return;
    };
    let rights = Rights::WAIT.union(Rights::CONTROL);
    let Ok(h) = table.put(ev, rights) else {
        return c.check(false, "object: put");
    };
    let Ok((obj, r)) = table.get(h) else {
        return c.check(false, "object: get");
    };
    kprintln!("[JSR-OBJ] handle={} rights={} type={} id={}", h.raw(), r, obj.ty.type_name(), obj.id.0);
    c.check(r == rights && obj.id == ev.id, "object: get 返回放入的值");

    // 降权：只保留 WAIT，CONTROL 被拒。
    let weak = table.restrict(h, Rights::WAIT);
    let denied = weak.map(|w| table.get_checked(w, Rights::CONTROL));
    c.check(denied == Ok(Err(HandleError::RightsDenied)), "object: restrict 后 CONTROL 被拒");
    if let Ok(w) = weak {
        kprintln!(
            "[JSR-OBJ] restrict handle={} rights={} control={}",
            w.raw(),
            table.get(w).map(|(_, r)| r).unwrap_or(Rights::NONE),
            HandleError::RightsDenied.name()
        );
        let _ = table.remove(w);
    }

    // 关闭后复用：槽位被新对象占用，旧句柄值必须无效。
    c.check(table.remove(h).is_ok(), "object: remove");
    let Ok(timer) = om.create(ObjectType::Timer) else {
        c.check(false, "object: 对象 ID 用尽");
        return;
    };
    let reused = table.put(timer, Rights::WAIT);
    let stale = table.get(h).map(|_| ());
    c.check(stale == Err(HandleError::Invalid), "object: 关闭后复用被拒");
    c.check(reused.is_ok_and(|n| n != h), "object: 新句柄值不同于旧值");
    kprintln!(
        "[JSR-OBJ] stale handle={} rejected err={} new_handle={}",
        h.raw(),
        HandleError::Invalid.name(),
        reused.map(|n| n.raw()).unwrap_or(0)
    );
    ktrace::emit("system.handle.closed", &[Tag::u64("handle", h.raw() as u64)]);
}

/// 等待：事件立即触发；定时器在**真实定时器 tick** 到期后触发；无信号时超时。
fn exercise_wait(c: &Checker) {
    let clock = TickClock;
    // 等待期间让 CPU 停在 hlt，直到下一个中断（定时器）把它唤醒。
    let idle = arch::wait_for_interrupt;

    let ev = Event::new();
    ev.signal();
    let mut ws: WaitSet<'_, 1> = WaitSet::new();
    let _ = ws.add(&ev);
    let r = ws.wait_any(&clock, Some(10), idle);
    c.check(r == Ok(WaitResult::Signaled(0)), "wait: 已触发的事件立即返回");
    kprintln!("[JSR-WAIT] event signalled index=0");

    let quiet = Event::new();
    let timer = Timer::new();
    let start = clock.now();
    timer.arm_after(start, 3);
    let mut ws: WaitSet<'_, 2> = WaitSet::new();
    let _ = ws.add(&quiet);
    let _ = ws.add(&timer);
    let r = ws.wait_any(&clock, Some(100), idle);
    let waited = clock.now() - start;
    c.check(r == Ok(WaitResult::Signaled(1)) && waited >= 3, "wait: 定时器按真实 tick 到期");
    kprintln!("[JSR-WAIT] timer fired index=1 waited_ticks={}", waited);

    let start = clock.now();
    let mut ws: WaitSet<'_, 1> = WaitSet::new();
    let _ = ws.add(&quiet);
    let r = ws.wait_any(&clock, Some(2), idle);
    let waited = clock.now() - start;
    c.check(r == Ok(WaitResult::Timeout) && waited >= 2, "wait: 无信号时超时");
    kprintln!("[JSR-WAIT] timeout ok waited_ticks={}", waited);
    ktrace::emit("system.wait.completed", &[Tag::u64("waited_ticks", waited)]);
}

/// 异步 ring：提交一写一读、取消读、推进、收割——恰好两条完成，被取消者没有执行。
fn exercise_io(c: &Checker) {
    let payload = *b"ping";
    let mut ring: Ring<'_, MemIoCore, 4, 4> = Ring::new(MemIoCore::new());
    let w = ring.submit(IoRequest::new(IoOp::Write, &payload, 1));
    let r = ring.submit(IoRequest::new(IoOp::Read, &[], 2));
    c.check(w.is_ok() && r.is_ok() && ring.pending() == 2, "io: 提交只入队");
    if let Ok(r) = r {
        c.check(ring.cancel(r).is_ok(), "io: 取消未执行的请求");
        c.check(ring.cancel(r).is_err(), "io: 不能重复取消");
    }
    ring.enter(usize::MAX);
    let mut completions = 0;
    while let Some(done) = ring.reap() {
        completions += 1;
        match done.result {
            Ok(bytes) => {
                kprintln!(
                    "[JSR-IO] op={} bytes={} ok={} backend={}",
                    done.op.label(),
                    bytes,
                    done.is_ok(),
                    ring.backend().name()
                );
                c.check(done.op == IoOp::Write && bytes == payload.len(), "io: Write 返回载荷长度");
            }
            Err(e) => kprintln!("[JSR-IO] op={} cancelled err={}", done.op.label(), e.name()),
        }
    }
    c.check(completions == 2, "io: 两个请求恰好两条完成");
    c.check(ring.backend().bytes_written == payload.len(), "io: 被取消的请求未执行");
    kprintln!("[JSR-IO] ring completions={} pending={}", completions, ring.pending());
    ktrace::emit("system.async.completed", &[Tag::u64("completions", completions)]);
}

/// 地址空间记账：映射 64 字节（对齐到一页）、改保护、解除映射。
fn exercise_memory(c: &Checker) {
    let mut asp: SimpleAddressSpace<8> = SimpleAddressSpace::new();
    let Ok(region) = asp.map_anonymous(64, VmProtection::READ_WRITE) else {
        return c.check(false, "vm: map_anonymous");
    };
    kprintln!(
        "[JSR-VM] map anon size=64 base={:#x} aligned={} prot={}",
        region.base,
        region.size,
        region.protection
    );
    c.check(region.size == PAGE_SIZE && region.base % PAGE_SIZE == 0, "vm: 页对齐");
    let p = asp.protect(region.base, VmProtection::READ);
    c.check(p.is_ok_and(|r| r.protection == VmProtection::READ), "vm: protect");
    c.check(asp.find(region.base + 63).is_some(), "vm: find 命中");
    c.check(asp.unmap(region.base).is_ok() && asp.regions().is_empty(), "vm: unmap");
    kprintln!("[JSR-VM] protect prot=r-- unmap ok regions={}", asp.regions().len());
    ktrace::emit("system.memory.unmapped", &[Tag::u64("base", region.base)]);
}

// ---- 系统调用分发（由 hello_syscall 模块「提供」，模块装载时校验分发表） ----

/// 演示调用：返回参数 + 1。`x.` 根 = 本地实验名（命名约定），不进入发布的 Profile。
fn sys_ping(f: &TrapFrame<'_>) -> SysResult {
    Ok(f.args[0] + 1)
}

/// 演示用分发表。
static SYSCALLS: [SyscallEntry; 1] = [SyscallEntry {
    meta: InterfaceMeta::op("x.demo.ping", Rights::NONE, Effects::None, "演示·回声加一").experimental(),
    handler: sys_ping,
}];

/// 分发观察者：把 enter/exit 打印成 `[JSR-SYSCALL]` 行。
fn log_trap(e: &TrapEvent<'_>) {
    match *e {
        TrapEvent::Enter { task_id, name } => kprintln!("[JSR-SYSCALL] enter name={} task={}", name, task_id),
        TrapEvent::Exit { name, result: Ok(v), .. } => kprintln!("[JSR-SYSCALL] exit name={} ret=OK value={}", name, v),
        TrapEvent::Exit { name, result: Err(err), .. } => {
            kprintln!("[JSR-SYSCALL] exit name={} ret={}", name, err.name())
        }
    }
}

// ---- 装配机制 ----

static MECH_MODULES: &[ModuleDecl] = &[
    ModuleDecl {
        name: "syscall-core",
        provides: &["x.mech.syscall-core"],
        requires: &[],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "hello-syscall",
        provides: &["x.mech.syscall-table"],
        requires: &["x.mech.syscall-core"],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "discard",
        provides: &["x.mech.discard"],
        requires: &[],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
];

static MECH_PROFILE: SystemProfile = SystemProfile {
    name: "mech-assembly",
    display_zh: "机制装配",
    display_en: "mechanism assembly",
    config: KernelConfig::STANDARD,
    modules: MECH_MODULES,
    guarantees: &[],
    hot_load: false,
};

static BROKEN_MODULES: &[ModuleDecl] = &[
    ModuleDecl {
        name: "broken-base",
        provides: &["x.mech.broken-base"],
        requires: &[],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "broken",
        provides: &["x.mech.broken"],
        requires: &["x.mech.broken-base"],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "blocked",
        provides: &["x.mech.blocked"],
        requires: &["x.mech.broken"],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
];

static BROKEN_PROFILE: SystemProfile = SystemProfile {
    name: "mech-broken",
    display_zh: "机制失败",
    display_en: "mechanism failure",
    config: KernelConfig::STANDARD,
    modules: BROKEN_MODULES,
    guarantees: &[],
    hot_load: false,
};

static BLOCKED_ACTIVATIONS: AtomicU32 = AtomicU32::new(0);

/// 打印并记录一次成功的模块激活。
fn log_module(module: &'static str) {
    kprintln!("[JSR-MOD] loaded module={}", module);
    ktrace::emit("system.module.loaded", &[Tag::str("module", module)]);
}

fn activate_syscall_core() -> Result<(), &'static str> {
    log_module("syscall-core");
    Ok(())
}

fn activate_hello_syscall() -> Result<(), &'static str> {
    Dispatcher::new(&SYSCALLS)
        .validate()
        .map(|_| log_module("hello-syscall"))
        .map_err(|_| "系统调用表校验失败")
}

fn activate_broken_base() -> Result<(), &'static str> {
    log_module("broken-base");
    Ok(())
}

fn activate_broken() -> Result<(), &'static str> {
    Err("planned activation failure")
}

fn activate_blocked() -> Result<(), &'static str> {
    BLOCKED_ACTIVATIONS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn activate_discard() -> Result<(), &'static str> {
    log_module("discard");
    Ok(())
}

fn deactivate_discard() {
    kprintln!("[JSR-MOD] stopped module=discard");
}

static MECH_BINDINGS: [Binding; 3] = [
    Binding { module: "syscall-core", version: "1.0.0", conflicts: &[], activate: activate_syscall_core, deactivate: None },
    Binding { module: "hello-syscall", version: "1.0.0", conflicts: &[], activate: activate_hello_syscall, deactivate: None },
    Binding { module: "discard", version: "1.0.0", conflicts: &[], activate: activate_discard, deactivate: Some(deactivate_discard) },
];

static BROKEN_BINDINGS: [Binding; 3] = [
    Binding { module: "broken-base", version: "1.0.0", conflicts: &[], activate: activate_broken_base, deactivate: None },
    Binding { module: "broken", version: "1.0.0", conflicts: &[], activate: activate_broken, deactivate: None },
    Binding { module: "blocked", version: "1.0.0", conflicts: &[], activate: activate_blocked, deactivate: None },
];

/// 按依赖顺序激活、审计发布掩码、拒绝重复启动，并验证失败依赖者的激活不被调用。
fn exercise_assembly(c: &Checker) -> Option<Assembly> {
    let declared = match profile::resolve(&MECH_PROFILE) {
        Ok(r) => r,
        Err(_) => {
            c.check(false, "assembly: 机制 Profile 校验");
            return None;
        }
    };
    let mut assembly = match Assembly::new(&MECH_PROFILE, &MECH_BINDINGS) {
        Ok(a) => a,
        Err(_) => {
            c.check(false, "assembly: 构造");
            return None;
        }
    };
    let report = match assembly.start(Policy::AllOrNothing) {
        Ok(r) => r,
        Err(_) => {
            c.check(false, "assembly: 启动");
            return None;
        }
    };
    c.check(report.ready == 3, "assembly: 三个模块就绪");
    c.check(
        assembly.state("hello-syscall").map(|s| s.0) == Some(State::Ready),
        "assembly: hello_syscall 就绪",
    );
    c.check(assembly.audit(&declared, assembly.published_mask(&declared)).is_ok(), "assembly: 发布审计");
    c.check(assembly.start(Policy::AllOrNothing).is_err(), "assembly: 重复启动被拒");
    c.check(
        assembly.preflight_stop("syscall-core") == Err(kernel_core::assembly::AssemblyError::InUse("hello-syscall")),
        "assembly: 被依赖模块停用返回 in_use",
    );
    c.check(
        assembly.preflight_stop("hello-syscall") == Err(kernel_core::assembly::AssemblyError::Permanent),
        "assembly: 常驻模块停用返回 permanent",
    );
    let discard_bits = match assembly.preflight_stop("discard") {
        Ok(bits) => bits,
        Err(_) => {
            c.check(false, "assembly: 可停用模块预检");
            return Some(assembly);
        }
    };
    let stopped = assembly.stop_with("discard", |bits| {
        kprintln!("[JSR-MOD] withdraw module=discard bits={:#x}", bits);
    });
    c.check(
        stopped.is_ok() && discard_bits != 0 && assembly.state("discard").map(|s| s.0) == Some(State::Stopped),
        "assembly: 撤位后排空再停用",
    );
    c.check(
        assembly.set_health("hello-syscall", Health::Unhealthy).is_ok()
            && assembly.state("hello-syscall").map(|s| s.0) == Some(State::Ready),
        "assembly: 健康失效不改变生命周期",
    );
    c.check(
        assembly.published_mask(&declared) & (1 << declared.capabilities().iter().position(|c| *c == "x.mech.syscall-table").unwrap()) == 0,
        "assembly: 不健康能力退出发布面",
    );
    c.check(
        assembly.set_health("hello-syscall", Health::Healthy).is_ok()
            && assembly.audit(&declared, assembly.published_mask(&declared)).is_ok(),
        "assembly: 健康恢复后重新发布",
    );

    BLOCKED_ACTIVATIONS.store(0, Ordering::Relaxed);
    let mut broken = match Assembly::new(&BROKEN_PROFILE, &BROKEN_BINDINGS) {
        Ok(a) => a,
        Err(_) => {
            c.check(false, "assembly: 失败路径构造");
            return Some(assembly);
        }
    };
    let failed = match broken.start(Policy::Partial) {
        Ok(r) => r,
        Err(_) => {
            c.check(false, "assembly: 部分策略启动");
            return Some(assembly);
        }
    };
    c.check(failed.failed == 1 && failed.blocked == 1, "assembly: 失败与阻断计数");
    c.check(
        broken.state("blocked").map(|s| s.0) == Some(State::Blocked),
        "assembly: 依赖失败者被阻断",
    );
    c.check(BLOCKED_ACTIVATIONS.load(Ordering::Relaxed) == 0, "assembly: 阻断模块激活未调用");
    Some(assembly)
}

/// 系统调用：经已装载的 hello_syscall 分发一次已知调用与一次未知调用。
fn exercise_syscalls(c: &Checker, assembly: &Assembly) {
    c.check(
        assembly.state("hello-syscall").map(|s| s.0) == Some(State::Ready),
        "syscall: 提供者模块已装配",
    );
    let mut d = Dispatcher::new(&SYSCALLS);
    d.set_observer(log_trap);
    let task = sched::current().0 .0;
    let ok = d.dispatch(&TrapFrame::new(task, "x.demo.ping", [41, 0, 0, 0]));
    c.check(ok == Ok(42), "syscall: x.demo.ping 返回 42");
    let unknown = d.dispatch(&TrapFrame::new(task, "system.demo.missing", [0; 4]));
    c.check(unknown == Err(SysError::Unsupported), "syscall: 未知调用返回稳定错误");
}

/// 关中断自旋锁：持锁期间中断关闭，释放后恢复。
fn exercise_sync(c: &Checker) {
    static COUNTER: IrqSpinLock<u64> = IrqSpinLock::new(0);
    let (inside, outside);
    {
        let mut g = COUNTER.lock();
        *g += 1;
        inside = !probe_irq_enabled();
    }
    outside = probe_irq_enabled();
    c.check(inside && outside && *COUNTER.lock() == 1, "sync: 持锁关中断、释放后恢复");
    kprintln!("[JSR-SYNC] irq spinlock ok irq_off_inside={} irq_restored={}", inside, outside);
}

/// 读取当前中断开关状态（保存后立即原样恢复，不改变状态）。
fn probe_irq_enabled() -> bool {
    let was = arch::irq_save_disable();
    arch::irq_restore(was);
    was
}

/// 演练任务体。
fn mech_task() {
    // 新任务在关中断状态下被首次切入（非抢占模式下 trampoline 不开中断）；
    // 等待演练需要真实定时器中断，因此在本任务内显式开中断。
    arch::irq_enable();
    let c = Checker;
    exercise_objects(&c);
    exercise_wait(&c);
    exercise_io(&c);
    exercise_memory(&c);
    if let Some(assembly) = exercise_assembly(&c) {
        exercise_syscalls(&c, &assembly);
    }
    exercise_sync(&c);

    let (kept, total) = ktrace::stats();
    let last = ktrace::with(|t| t.iter().last().copied());
    c.check(kept > 0 && total >= kept as u64, "trace: 事件已记录");
    match last {
        Some(ev) => kprintln!("[JSR-TRACE] ring buffer count={} total={} last=\"{}\"", kept, total, ev),
        None => kprintln!("[JSR-TRACE] ring buffer count=0 total={}", total),
    }
    arch::irq_disable();
}

/// 运行 M1.5 演练：以任务 `mech` 运行全部机制，结束后回到引导线程输出汇总。
pub fn run() {
    if sched::spawn(TaskId(MECH_TASK_ID), "mech", mech_task).is_err() {
        kprintln!("[JSR-MECH-FAIL] spawn mech task");
        FAILED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    sched::run();
    kprintln!(
        "[JSR-MECH] checks={} failed={}",
        CHECKS.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed)
    );
}

/// 断言失败数（kmain 据此决定退出码）。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}
