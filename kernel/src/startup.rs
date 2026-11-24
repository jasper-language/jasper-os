//! Issue #78 readiness milestones.
//!
//! Each READY line is emitted only after its real prerequisite checks pass.

use crate::{arch, assembly, clock, early, kprintln, mm, terminal};

#[derive(Clone, Copy)]
pub struct StageStart {
    cycles: u64,
    free_frames: usize,
    heap_used: usize,
    heap_mapped: u64,
}

fn emit(text: &str) {
    kprintln!("{}", text);
    #[cfg(target_arch = "x86_64")]
    early::append_line(text);
}

/// Verify the non-graphical base environment independently of Terminal, Shell,
/// network, GPU, and display services.
pub fn headless_ready() -> bool {
    let frames = mm::frame::usable_frames();
    let free = mm::frame::free_frames();
    let (heap_total, _, _, heap_mapped) = mm::heap::stats();
    let ticks = clock::ticks();
    let published = assembly::published_mask();
    let ready = frames != 0
        && free != 0
        && heap_total != 0
        && heap_mapped != 0
        && ticks != 0
        && published != 0;
    if ready {
        let line = alloc::format!(
            "[READY] HEADLESS bsp=0 raw_records={} enabled_records={} unique_enabled={} unique_disabled={} admitted={} online={} participating={} usable_frames={} free_frames={} heap_mapped={} ticks={} capabilities={:#x}",
            crate::smp::discovered_cpu_count(),
            crate::smp::firmware_enabled_cpu_record_count(),
            crate::smp::unique_enabled_cpu_count(),
            crate::smp::disabled_cpu_count(),
            crate::smp::admitted_cpu_count(),
            crate::smp::online_set().len(),
            crate::smp::online_set().len(),
            frames,
            free,
            heap_mapped,
            ticks,
            published
        );
        emit(&line);
    } else {
        emit("[FAIL] HEADLESS dependencies=memory,time,assembly");
    }
    ready
}

/// Verify that the bounded native terminal session exists. This does not imply
/// Shell Ready or that an interactive login has occurred.
pub fn console_terminal_ready() -> bool {
    if terminal::ready() {
        emit("[READY] CONSOLE / TERMINAL");
        true
    } else {
        emit("[FAIL] CONSOLE / TERMINAL reason=session_unavailable");
        false
    }
}

/// Keep Shell Ready unclaimed unless a real authorized JUCS command was run.
pub fn shell_not_verified() {
    skipped("shell", "authorized_jucs_command_not_run");
}

/// Publish a milestone that was intentionally not entered for this profile.
pub fn skipped(component: &str, reason: &str) {
    kprintln!("[SKIP] {} READY reason={}", component, reason);
    early::append_status("[SKIP] ", component);
    crate::kprintln!(
        "{{\"schema\":\"jasper.boot.v1\",\"kind\":\"stage\",\"boot_id\":{},\"component\":\"{}\",\"status\":\"skipped\",\"reason\":\"{}\"}}",
        early::boot_id(),
        component,
        reason
    );
}

pub fn stage_begin(component: &str) -> StageStart {
    early::mark(component);
    let (heap_total, heap_free, _, heap_mapped) = mm::heap::stats();
    StageStart {
        cycles: arch::measure_cycles(),
        free_frames: mm::frame::free_frames(),
        heap_used: heap_total.saturating_sub(heap_free),
        heap_mapped,
    }
}

pub fn stage_ok(component: &str, start: StageStart) {
    let end = arch::measure_cycles();
    let elapsed_ns = early::tsc_frequency_hz()
        .and_then(|hz| {
            end.checked_sub(start.cycles)
                .map(|cycles| (cycles as u128 * 1_000_000_000u128 / hz as u128) as u64)
        })
        .unwrap_or(0);
    let (heap_total, heap_free, _, heap_mapped) = mm::heap::stats();
    let heap_used = heap_total.saturating_sub(heap_free);
    let heap_peak = mm::heap::peak_used();
    let free_frames = mm::frame::free_frames();
    kprintln!(
        "[ OK ] {} elapsed_ns={} heap_used={} heap_peak={} heap_delta={} mapped_delta={} frame_delta={}",
        component,
        elapsed_ns,
        heap_used,
        heap_peak,
        heap_used as i64 - start.heap_used as i64,
        heap_mapped as i64 - start.heap_mapped as i64,
        start.free_frames as i64 - free_frames as i64
    );
    early::append_status("[ OK ] ", component);
    crate::kprintln!(
        "{{\"schema\":\"jasper.boot.v1\",\"kind\":\"stage\",\"boot_id\":{},\"component\":\"{}\",\"status\":\"ok\",\"elapsed_ns\":{},\"heap_used\":{},\"heap_peak\":{},\"heap_mapped\":{},\"free_frames\":{},\"heap_delta\":{},\"mapped_delta\":{},\"frame_delta\":{}}}",
        early::boot_id(),
        component,
        elapsed_ns,
        heap_used,
        heap_peak,
        heap_mapped,
        free_frames,
        heap_used as i64 - start.heap_used as i64,
        heap_mapped as i64 - start.heap_mapped as i64,
        start.free_frames as i64 - free_frames as i64
    );
}

/// Publish a failed stage with the same resource deltas as a successful stage.
pub fn stage_fail(component: &str, start: StageStart, reason: &str) {
    let end = arch::measure_cycles();
    let elapsed_ns = early::tsc_frequency_hz()
        .and_then(|hz| {
            end.checked_sub(start.cycles)
                .map(|cycles| (cycles as u128 * 1_000_000_000u128 / hz as u128) as u64)
        })
        .unwrap_or(0);
    let (heap_total, heap_free, _, heap_mapped) = mm::heap::stats();
    let heap_used = heap_total.saturating_sub(heap_free);
    let heap_peak = mm::heap::peak_used();
    let free_frames = mm::frame::free_frames();
    kprintln!(
        "[FAIL] {} elapsed_ns={} heap_used={} heap_peak={} reason={}",
        component,
        elapsed_ns,
        heap_used,
        heap_peak,
        reason
    );
    early::append_status("[FAIL] ", component);
    crate::kprintln!(
        "{{\"schema\":\"jasper.boot.v1\",\"kind\":\"stage\",\"boot_id\":{},\"component\":\"{}\",\"status\":\"failed\",\"reason\":\"{}\",\"elapsed_ns\":{},\"heap_used\":{},\"heap_peak\":{},\"heap_mapped\":{},\"free_frames\":{},\"heap_delta\":{},\"mapped_delta\":{},\"frame_delta\":{}}}",
        early::boot_id(),
        component,
        reason,
        elapsed_ns,
        heap_used,
        heap_peak,
        heap_mapped,
        free_frames,
        heap_used as i64 - start.heap_used as i64,
        heap_mapped as i64 - start.heap_mapped as i64,
        start.free_frames as i64 - free_frames as i64
    );
}
