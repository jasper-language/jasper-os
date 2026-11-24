//! Pixel 6a physical runtime rehearsal.
//!
//! This plan uses the production stage implementations and the small
//! architecture-provided Ring 3/syscall/user-pointer probes. It does not add a
//! Pixel device driver or embed a user-program bundle. Success is externally
//! observable as PSCI SYSTEM_OFF only after all stages complete, all eight CPUs
//! are online, the probes report no failures, and their frames return.

use kernel_core::boot_stage::{PlanItem, Stage};

use crate::arch::{self, ExitStatus};
use crate::kmain::{BootCtx, Step};
use crate::kprintln;

pub const NAME: &str = "pixel6a-runtime"; // JASPER-HARDCODE-REVIEW: issue=33 source=physical-runtime-plan reason=diagnostic-plan-name-not-hardware-fact

const STAGES: &[Step] = &[
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
    PlanItem::Finish(finish),
];

pub const PLAN: &[&[Step]] = &[STAGES];

pub fn stop(status: ExitStatus) -> ! {
    arch::exit_emulator(status)
}

fn finish(ctx: &mut BootCtx) {
    let smp = ctx.smp.as_ref();
    let smp_ok =
        smp.is_some_and(|report| report.present == 8 && report.online == 8 && report.failed == 0);
    if !smp_ok {
        if let Some(report) = smp {
            kprintln!(
                "[JSR-PIXEL6A] runtime=failed reason=smp present={} online={} failed={}", // JASPER-HARDCODE-REVIEW: issue=33 source=actual-smp-report reason=marker-names-platform-test-not-hardware-fact
                report.present,
                report.online,
                report.failed
            );
        } else {
            kprintln!("[JSR-PIXEL6A] runtime=failed reason=smp-missing"); // JASPER-HARDCODE-REVIEW: issue=33 source=runtime-stage-state reason=diagnostic-marker-only
        }
        arch::exit_emulator(ExitStatus::Failure);
    }

    crate::user_demo::run();
    crate::user_demo::run_syscall();
    crate::user_demo::run_user_pointers();
    let user_failed = crate::user_demo::failed();
    let capacity = ctx.capacity;
    if user_failed != 0 {
        kprintln!(
            "[JSR-PIXEL6A] runtime=failed reason=user-probes failed={}", // JASPER-HARDCODE-REVIEW: issue=33 source=user-probe-counter reason=diagnostic-marker-only
            user_failed
        );
        arch::exit_emulator(ExitStatus::Failure);
    }

    kprintln!(
        "[JSR-PIXEL6A] runtime=complete cpus=8 ring3=true syscall=true user_pointers=true user_failed=0 stages={:#x} objects={} tasks={} frames={} heap={} action=psci-reset", // JASPER-HARDCODE-REVIEW: issue=33 source=admitted-smp-report reason=literal-8-is-success-policy-checked-against-runtime-report
        ctx.done_mask(),
        capacity.map(|value| value.objects).unwrap_or(0),
        capacity.map(|value| value.tasks).unwrap_or(0),
        ctx.frames.map(|stats| stats.usable).unwrap_or(0),
        crate::mm::heap::physical_headroom()
    );
    #[cfg(feature = "pixel6a-el2-observable")] // JASPER-HARDCODE-REVIEW: issue=21 source=pixel-el2-observation-window reason=physical-boot-carrier-probe-only
    if crate::arch::aarch64::boot::entry_exception_level() == 2 {
        kprintln!("[JSR-PIXEL6A] el2-observation=available delay_seconds=5"); // JASPER-HARDCODE-REVIEW: issue=21 source=pixel-el2-observation-window reason=host-observable-five-second-delay-probe
        crate::arch::aarch64::boot::wait_el2_observation_window();
    }
    crate::arch::aarch64::boot::pixel6a_reset_now()
}
