//! Focused physical performance and memory-accounting plan.
//!
//! It runs the normal production stages, executes the existing kernel and user
//! microbenchmarks, renders their results to the native framebuffer, and then
//! remains alive so the physical screen can be inspected.

use kernel_core::boot_stage::{PlanItem, Stage};

use crate::arch::{self, ExitStatus};
use crate::kmain::{BootCtx, Step};
use crate::{bench_demo, clock, early, hardware, kprintln, mm, startup};

pub const NAME: &str = "physical-bench";

fn finish(ctx: &mut BootCtx) {
    #[cfg(target_arch = "x86_64")]
    early::results_begin();
    hardware::report();
    startup::headless_ready();
    startup::console_terminal_ready();
    startup::shell_not_verified();
    startup::skipped("remote", "network_service_profile_not_assembled");
    startup::skipped("ui_services", "headless_benchmark_profile");
    startup::skipped("desktop", "headless_benchmark_profile");
    startup::skipped("compat_assembly", "benchmark_excludes_compatibility_profiles");
    let smp_failed = if let Some(report) = ctx.smp.filter(|report| report.online > 1) {
        crate::smp::demo::run(report);
        #[cfg(feature = "bench-smp")]
        {
            crate::smp_performance::run();
            crate::smp_performance::publish_results();
        }
        crate::smp::demo::failed()
    } else {
        0
    };
    #[cfg(feature = "smp-matrix-only")]
    {
        crate::smp_performance::publish_results();
        report_memory("smp-after");
        let line = alloc::format!("SMP MATRIX RESULT FAILED={}\n", smp_failed);
        emit(line.as_str());
        arch::irq_enable();
        let mut ticks = 0u64;
        let mut pet_countdown = 0u32;
        loop {
            if pet_countdown == 0 {
                arch::watchdog_pet_force();
                pet_countdown = 1_000_000;
            } else {
                pet_countdown -= 1;
            }
            core::hint::spin_loop();
            ticks = ticks.wrapping_add(1);
            if ticks % 100_000_000 == 0 {
                kprintln!("[JSR-PERF-SMP] alive ticks={}", clock::ticks());
            }
        }
    }
    report_memory("before");
    bench_demo::run();
    report_memory("after");
    let failed = bench_demo::failed().saturating_add(smp_failed);
    let timing_failed = bench_demo::timing_failed();
    let line = alloc::format!(
        "BENCH RESULT FAILED={} TIMING_FAILED={}\n",
        failed,
        timing_failed
    );
    emit(line.as_str());
    bench_demo::publish_results(failed, timing_failed);
    arch::irq_enable();
    let mut ticks = 0u64;
    let mut pet_countdown = 0u32;
    loop {
        if pet_countdown == 0 {
            arch::watchdog_pet_force();
            pet_countdown = 1_000_000;
        } else {
            pet_countdown -= 1;
        }
        core::hint::spin_loop();
        ticks = ticks.wrapping_add(1);
        if ticks % 100_000_000 == 0 {
            kprintln!("[JSR-PERF] alive ticks={}", clock::ticks());
        }
    }
}

fn report_memory(phase: &str) {
    let usable = mm::frame::usable_frames();
    let free = mm::frame::free_frames();
    let used_bytes = usable
        .saturating_sub(free)
        .saturating_mul(kernel_core::frame::FRAME_SIZE as usize);
    let (heap_total, heap_free, heap_blocks, heap_mapped) = mm::heap::stats();
    let heap_peak = mm::heap::peak_used();
    let line = alloc::format!(
        "MEM {} RAM USABLE {} MIB FREE {} MIB USED {} KIB\nHEAP USED {} KIB PEAK {} KIB FREE {} KIB MAPPED {} KIB PHYSICAL_HEADROOM {} MIB BLOCKS {} GROWTH=on-demand\n",
        phase,
        usable.saturating_mul(4096) / (1024 * 1024),
        free.saturating_mul(4096) / (1024 * 1024),
        used_bytes / 1024,
        heap_total.saturating_sub(heap_free) / 1024,
        heap_peak / 1024,
        heap_free / 1024,
        heap_mapped / 1024,
        mm::heap::physical_headroom() / (1024 * 1024),
        heap_blocks
    );
    kprintln!("[JSR-MEM-USAGE] {}", line.replace('\n', " "));
    emit_screen(line.as_str());
}

fn emit(text: &str) {
    crate::console::write_str(text);
    emit_screen(text);
}

fn emit_screen(text: &str) {
    #[cfg(target_arch = "x86_64")]
    for line in text.lines() {
        early::append_line(line);
    }
}

pub fn stop(_status: ExitStatus) -> ! {
    arch::irq_disable();
    arch::halt_forever()
}

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
    PlanItem::Finish(finish),
]];
