//! 生产启动计划（issue #7 第二片）：全部阶段、第一个用户程序，然后等待服务，不退出模拟器。
//! Production boot plan: every stage, the first user program, then wait for services.
//!
//! 只有特性 `production` 打开时编译。生产路径不含任何演练。
//! 现在系统里还没有常驻服务，第一个用户程序是内嵌的 `user-hello`，它证明用户运行时真的可用。
//! Compiled only with the `production` feature; it contains no exercises. There are no long-lived
//! services yet, so the first user program is the embedded `user-hello`.

#[cfg(any(
    feature = "rt1-verify", feature = "rt2-verify", feature = "rt3-verify", feature = "budget-window-verify",
    feature = "krn3-fast-tick-verify", feature = "krn3-postsplit-verify", feature = "krn3-p999-verify",
    feature = "evt1-verify", feature = "evt2-verify", feature = "evt2-broadcast-verify",
    feature = "s3-nohz-verify", feature = "shm1-verify", feature = "s2-fuzz", feature = "krn1-soak",
    feature = "fault-inject", feature = "selftest-inject-failure", feature = "bm1-vm",
))]
compile_error!("production 不能和验收或故障注入特性同开");

use kernel_core::boot_stage::{CaseSpec, PlanItem, Stage};

use crate::arch::{self, ExitStatus};
use crate::kmain::{BootCtx, Step};
use crate::{clock, irq, kprintln};

/// 计划名（输出标记用）。Plan name for markers.
pub const NAME: &str = "production";

/// 进入等待后过多少 tick 报告一次存活（只报告一次）。Ticks before the single alive report.
const ALIVE_AFTER_TICKS: u64 = 100;

/// 生产计划：按声明顺序执行全部阶段。capacity 只校验容量、devices 只准备 PCI 硬件访问，
/// 对象/任务/实时/作业/设备服务表由 assembly 模块激活建立；计划顺序不变。
/// The production plan runs every stage in declaration order; service tables are activated in assembly.
pub const PLAN: &[&[Step]] = &[&[
    PlanItem::Stage(Stage::Console),
    PlanItem::Stage(Stage::Platform),
    PlanItem::Stage(Stage::Timer),
    PlanItem::Stage(Stage::Frames),
    PlanItem::Stage(Stage::KernelMap),
    PlanItem::Stage(Stage::Heap),
    PlanItem::Stage(Stage::Capacity),
    PlanItem::Stage(Stage::Devices),
    PlanItem::Stage(Stage::Profile),
    PlanItem::Stage(Stage::Assembly),
    PlanItem::Stage(Stage::SchedMode),
    PlanItem::Stage(Stage::Space),
    PlanItem::Stage(Stage::Smp),
    PlanItem::Stage(Stage::HighRes),
    PlanItem::Stage(Stage::IdleTick),
    PlanItem::Stage(Stage::UserRuntime),
    PlanItem::Case(
        CaseSpec { name: "first-program", requires: Stage::UserRuntime.bit(), summary: "", timing: false },
        first_program,
    ),
    PlanItem::Finish(wait_for_services),
]];

/// 生产构建的启动失败：报告已经输出，关中断停机。系统生命周期不经过模拟器退出。
/// A production boot failure: the report is already out, so halt with interrupts off.
pub fn stop(_status: ExitStatus) -> ! {
    arch::irq_disable();
    arch::halt_forever()
}

/// 装载并运行第一个用户程序，要求它以退出码 0 结束。Run the first user program; it must exit 0.
#[cfg(feature = "user-programs")]
fn first_program(_ctx: &mut BootCtx) {
    let (state, reclaimed) = crate::user_demo::run_first_program();
    kprintln!("[JSR-PROD] first_program state={:?} reclaimed={}", state, reclaimed);
    if state != Some(crate::proc::ProcState::Exited { code: 0 }) || !reclaimed {
        kprintln!("[JSR-EXIT] failure first_program");
        stop(ExitStatus::Failure);
    }
}

/// 没有内嵌用户程序的构建如实说明。A build without embedded programs says so.
#[cfg(not(feature = "user-programs"))]
fn first_program(_ctx: &mut BootCtx) {
    kprintln!("[JSR-PROD] first_program absent");
}

/// 持续运行：开中断等待。Keep running: wait with interrupts enabled.
fn wait_for_services(_ctx: &mut BootCtx) {
    arch::irq_enable();
    let start = clock::ticks();
    let mut alive_reported = false;
    kprintln!("[JSR-PROD] waiting ticks={}", start);
    loop {
        arch::wait_for_interrupt();
        irq::poll_and_handle();
        if !alive_reported && clock::ticks().wrapping_sub(start) >= ALIVE_AFTER_TICKS {
            alive_reported = true;
            kprintln!("[JSR-PROD] alive ticks={}", clock::ticks());
        }
    }
}
