//! 架构无关的内核主流程：引导适配层（`main.rs`）完成平台入口后调用 [`start`]。
//!
//! 只通过 `arch::*` 使用硬件；换 ISA 时本文件不改。
//! 本文件只负责全局阶段转移：[`run_stage`] 是每个阶段的真实初始化，由 `kernel_core::boot_stage` 的
//! 跟踪器检查依赖、拒绝重复初始化，失败即停止启动。执行哪些阶段和用例由 `plan` 决定（构建期选择
//! 生产启动 `production` 或验收清单 `acceptance`，issue #7）。这里不写特性分支，也不写演练。
//! This file only drives global stage transitions. Which stages and cases run comes from `plan`,
//! chosen at build time. No feature branches and no exercises live here.

use crate::arch::{self, ExitStatus};
use crate::boot::BootSpec;
use crate::plan;
use kernel_core::boot_stage::{plan_check, PlanItem, PlanSummary, Stage, StageError, StageState, Tracker};
use crate::{assembly, bootcap, clock, config, irq, kprint, kprintln, mm, pci, profile, sched, smp};

/// 内核版本（横幅中输出）。
pub const VERSION: &str = "0.0.1";
/// 定时器频率（取自配置档）。
const TIMER_HZ: u32 = config::ACTIVE.clock.timer_hz;
/// 启动自检至少等到的 tick 数（取自配置档）。
const BOOT_TICKS: u64 = config::ACTIVE.clock.boot_ticks;
/// 等 tick 的兜底次数：定时器没配好时必须报错退出，而不是永远睡下去。
const MAX_WAITS: u64 = 20_000_000;

/// 计划的一步。计划是静态数据，执行体取得启动上下文。A plan step; the body gets the boot context.
pub type Step = PlanItem<fn(&mut BootCtx)>;

/// 计划在编译期检查：依赖顺序、用例依赖、用例名唯一、恰好一个收尾步。
/// The plan is checked at compile time.
const PLAN_SUMMARY: PlanSummary = match plan_check(plan::PLAN) {
    Ok(s) => s,
    Err(_) => panic!("启动计划不良构"),
};

/// 阶段产生、后续步骤要用的结果。Results of stages that later steps use.
pub struct BootCtx {
    /// 引导交接信息。Boot hand-off information.
    pub boot: &'static BootSpec,
    /// 阶段跟踪器（引导处理器独占）。Stage tracker, owned by the boot processor.
    tracker: Tracker,
    /// `frames` 阶段的页帧统计。Frame statistics from the `frames` stage.
    pub frames: Option<mm::frame::FrameStats>,
    /// `capacity` 阶段的生效容量。Effective capacity from the `capacity` stage.
    pub capacity: Option<kernel_core::capacity::BootCapacity>,
    /// `smp` 阶段的启动结果。Start-up report from the `smp` stage.
    pub smp: Option<smp::StartReport>,
    /// `idle_tick` 阶段生效的停表间隔。Effective divisor from the `idle_tick` stage.
    pub idle_divisor: u32,
}

impl BootCtx {
    /// 已完成阶段的掩码。Mask of completed stages.
    pub fn done_mask(&self) -> u32 {
        self.tracker.done_mask()
    }

    /// 对已完成阶段发起一次重复初始化探针；只有得到 `duplicate` 且状态不变才算通过。
    /// Probe duplicate initialisation of a completed stage; pass only on an unchanged `duplicate` refusal.
    pub(crate) fn probe_duplicate(&mut self, stage: Stage) -> bool {
        let done = self.tracker.done_mask();
        let refused = self.tracker.begin(stage) == Err(StageError::Duplicate(stage));
        refused && self.tracker.done_mask() == done && self.tracker.state(stage) == StageState::Done
    }
}

/// 阶段失败或被拒之后停止启动：验收构建退出模拟器，生产构建停机。
/// Stop after a failed or refused stage: acceptance exits the emulator, production halts.
pub fn stop_boot(status: ExitStatus) -> ! {
    plan::stop(status)
}

fn assembly_rollback(_: &mut BootCtx) -> bool {
    assembly::rollback_boot()
}

/// 可回滚启动阶段的逆动作登记。`None` 表示该阶段只做保存状态或无持久资源。
/// Reverse actions registered for rollback-capable boot stages. `None` means no persistent resource.
const fn stage_rollback(stage: Stage) -> Option<fn(&mut BootCtx) -> bool> {
    match stage {
        Stage::Assembly => Some(assembly_rollback),
        _ => None,
    }
}

/// 在阶段跟踪器下执行一个全局启动阶段（issue #7）。`body` 执行该阶段的真实初始化，返回 `None` 表示失败。
/// 阶段被拒（依赖缺失、重复初始化、已有阶段失败）或失败时如实报告并停止启动：
/// 依赖它的后续阶段永远不会开始。
/// Runs one global boot stage under the stage tracker. `body` performs the real initialisation and
/// returns `None` on failure. A refused or failed stage is reported and boot stops, so no stage
/// that depends on it ever starts.
fn stage(ctx: &mut BootCtx, s: Stage, body: impl FnOnce(&mut BootCtx) -> Option<()>) {
    if let Err(e) = ctx.tracker.begin(s) {
        match e {
            StageError::Halted { failed } => kprintln!(
                "[JSR-BOOT-STAGE] refused stage={} reason={} failed={}",
                s.name(),
                e.as_str(),
                failed.name()
            ),
            StageError::MissingDependency { missing, .. } => kprintln!(
                "[JSR-BOOT-STAGE] refused stage={} reason={} missing={}",
                s.name(),
                e.as_str(),
                missing.name()
            ),
            _ => kprintln!("[JSR-BOOT-STAGE] refused stage={} reason={}", s.name(), e.as_str()),
        }
        kprintln!("[JSR-EXIT] failure boot_stage={}", s.name());
        stop_boot(ExitStatus::Failure);
    }
    if body(ctx).is_some() {
        // begin 刚成功且阶段串行，complete 不会被拒。begin just succeeded; complete cannot be refused.
        let _ = ctx.tracker.complete(s);
        kprintln!("[JSR-BOOT-STAGE] done stage={} done_mask={:#x}", s.name(), ctx.tracker.done_mask());
        return;
    }
    let _ = ctx.tracker.fail(s);
    kprint!("[JSR-BOOT-STAGE] failed stage={} blocked=", s.name());
    let blocked = ctx.tracker.blocked_mask();
    let mut first = true;
    for b in Stage::ALL.iter().filter(|b| blocked & b.bit() != 0) {
        kprint!("{}{}", if first { "" } else { "," }, b.name());
        first = false;
    }
    kprintln!();
    if let Some(rollback) = stage_rollback(s) {
        let resources_baseline = rollback(ctx);
        kprintln!(
            "[JSR-BOOT-STAGE] rollback stage={} action={} resources_baseline={}",
            s.name(),
            s.name(),
            resources_baseline
        );
    }
    if let Some(blocked_stage) = Stage::ALL.iter().find(|candidate| blocked & candidate.bit() != 0) {
        let refusal = ctx.tracker.begin(*blocked_stage);
        let (begin, started) = match refusal {
            Err(e) => (e.as_str(), 0),
            Ok(()) => ("accepted", 1),
        };
        kprintln!(
            "[JSR-BOOT-STAGE] blocked stage={} begin={} started={}",
            blocked_stage.name(),
            begin,
            started
        );
    }
    kprintln!("[JSR-EXIT] failure boot_stage={}", s.name());
    stop_boot(ExitStatus::Failure)
}

/// 每个全局阶段的真实初始化。生产与验收共用这一份。
/// The real initialisation of each global stage, shared by production and acceptance.
fn run_stage(ctx: &mut BootCtx, s: Stage) {
    match s {
        Stage::Console => stage(ctx, s, |_| {
            arch::console_init();
            kprintln!("[JSR-BOOT] jasper-os rust kernel {} {}", VERSION, arch::NAME);
            config::report();
            Some(())
        }),
        Stage::Platform => stage(ctx, s, |_| {
            arch::early_init();
            // 证明异常处理已接通。
            arch::debug_breakpoint();
            Some(())
        }),
        // 中断控制器 + 定时器，开中断后等到足够多的 tick。
        Stage::Timer => stage(ctx, s, |_| {
            arch::irq_init(TIMER_HZ);
            arch::irq_enable();
            let mut waits: u64 = 0;
            while clock::ticks() < BOOT_TICKS {
                arch::wait_for_interrupt();
                irq::poll_and_handle();
                waits += 1;
                if waits > MAX_WAITS {
                    kprintln!("[JSR-TICK-TIMEOUT] n={}", clock::ticks());
                    arch::irq_disable();
                    return None;
                }
            }
            // 收尾关中断，保证随后的协作式演示输出可复现。
            arch::irq_disable();
            Some(())
        }),
        // 物理页帧分配（真实内存图）。没有任何可用帧时启动停止。
        Stage::Frames => stage(ctx, s, |ctx| {
            let stats = mm::frame::init(ctx.boot);
            ctx.frames = Some(stats);
            (stats.usable > 0).then_some(())
        }),
        // 架构无关映射 API（x86_64 由 4 级页表实现）。引导器未提供物理内存映射时启动停止。
        Stage::KernelMap => stage(ctx, s, |ctx| {
            // 多处理器：趁低端内存尚未被占用时预留平台需要的启动帧（平台不需要时什么也不做）。
            if !smp::reserve_start_frame() {
                kprintln!("[JSR-SMP] start_frame unavailable");
            }
            mm::map::init(ctx.boot).then_some(())
        }),
        // 内核堆（Box/Vec/String 可用，按需增长）。首批映射失败时启动停止。
        Stage::Heap => stage(ctx, s, |_| mm::heap::init().ok()),
        // 堆就绪：校验启动期容量记录与内存预算。对象表、实时表和任务表由模块激活安装，
        // 这样阶段只保留容量验证这一真实内存顺序约束。
        Stage::Capacity => stage(ctx, s, |ctx| {
            let cap = bootcap::validate();
            ctx.capacity = Some(cap);
            Some(())
        }),
        // DRV-1B：硬件顺序阶段只取得 PCI 配置空间访问者（ECAM 或传统端口）。总线枚举和
        // 只读设备表属于 `devices` 模块激活；平台没有 PCI 时激活出空表，不算失败。
        Stage::Devices => stage(ctx, s, |ctx| {
            pci::prepare(ctx.boot);
            Some(())
        }),
        // POL-2：系统 Profile（模块面 + 参数档）在堆就绪后立刻校验；不合法就拒绝启动，
        // 因为后面的服务判定、配额与调度类别都以这份声明为前提。
        Stage::Profile => stage(ctx, s, |_| {
            let profile_failed = profile::boot_report();
            if profile_failed > 0 {
                kprintln!("[JSR-EXIT] failure profile_failed={}", profile_failed);
                return None;
            }
            Some(())
        }),
        // issue #6：按依赖顺序装配生效 Profile 的模块；对象、任务、实时、作业与设备服务
        // 的初始化在这里发生。只有激活成功的模块能力被发布。
        Stage::Assembly => stage(ctx, s, |_| {
            let assembly_failed = assembly::boot();
            if assembly_failed > 0 {
                kprintln!("[JSR-EXIT] failure assembly_failed={}", assembly_failed);
                return None;
            }
            Some(())
        }),
        // POL-5：多模式 B（统一仲裁）由 Profile 决定；没有 `sched.arbiter` 时保持单模式 A。
        Stage::SchedMode => stage(ctx, s, |_| {
            let multi_mode = profile::has_capability("sched.arbiter");
            sched::set_arbiter(multi_mode);
            kprintln!("[JSR-SCHED] mode={}", if multi_mode { "multi" } else { "single" });
            Some(())
        }),
        // 内核地址空间：准备失败时不能创建任何独立地址空间。
        Stage::Space => stage(ctx, s, |_| match mm::space::init() {
            Ok(_) => Some(()),
            Err(e) => {
                kprintln!("[JSR-SPACE] kernel space not ready: {:?}", e);
                None
            }
        }),
        // SMP-1：启动其他处理器。部分处理器没上线不算失败，结果由 `StartReport` 报告。
        Stage::Smp => stage(ctx, s, |ctx| {
            let report = smp::start_secondaries(TIMER_HZ);
            #[cfg(feature = "pixel6a-smp-probe")]
            if report.present == 8 && report.online == 8 && report.failed == 0 {
                kprintln!("[JSR-PIXEL6A] smp=8 online=8 action=psci-off");
                crate::arch::aarch64::boot::pixel6a_power_off();
            }
            ctx.smp = Some(report);
            Some(())
        }),
        // 没有高精度时钟源时退回 tick，不算失败。
        Stage::HighRes => stage(ctx, s, |_| {
            let hr = sched::enable_highres();
            kprintln!("[JSR-RT2] high_resolution={} legacy_tick_abi=true", hr);
            Some(())
        }),
        // HARDEN-1E：按配置档的功耗策略启用空闲停表。
        Stage::IdleTick => stage(ctx, s, |ctx| {
            let divisor = sched::configure_idle_tick();
            ctx.idle_divisor = divisor;
            kprintln!(
                "[JSR-NOHZ] configured power={} divisor={} cpus={}",
                config::ACTIVE.policy.power.as_str(),
                divisor,
                sched::online_cpus().len()
            );
            Some(())
        }),
        // 用户运行时只判定「可以装载用户程序」；运行哪些服务由装配决定。
        Stage::UserRuntime => stage(ctx, s, |_| {
            kprintln!("[JSR-STAGE] user_runtime embedded_programs={}", cfg!(feature = "user-programs"));
            mm::space::init().ok().map(|_| ())
        }),
    }
}

/// 内核主流程（永不返回）。`boot` 是引导适配层转换好的交接信息。
pub fn start(boot: &'static BootSpec) -> ! {
    let mut ctx = BootCtx { boot, tracker: Tracker::new(), frames: None, capacity: None, smp: None, idle_divisor: 0 };
    for part in plan::PLAN {
        for step in part.iter() {
            match step {
                PlanItem::Stage(s) => run_stage(&mut ctx, *s),
                PlanItem::Case(spec, run) => {
                    kprintln!("[JSR-PLAN] case name={}", spec.name);
                    run(&mut ctx);
                }
                PlanItem::Finish(run) => {
                    kprintln!(
                        "[JSR-PLAN] finish plan={} stages={:#x} cases={}",
                        plan::NAME,
                        PLAN_SUMMARY.stages,
                        PLAN_SUMMARY.cases
                    );
                    run(&mut ctx);
                }
            }
        }
    }
    // 收尾步按约定不返回；万一返回也不能当作正常结束。The finish step does not return by contract.
    kprintln!("[JSR-EXIT] failure plan_returned");
    stop_boot(ExitStatus::Failure)
}
