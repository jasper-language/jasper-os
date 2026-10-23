//! Author: chatgpt. Reuse the real 1500-round user IPC/ring/thread/VM drill.
//! Host wall time controls duration; UART stop is checked only between rounds.
use crate::{baseline::baseline, kprintln, longrun_demo, mm, smp};

fn stop_requested() -> bool {
    crate::arch::soak_stop_requested()
}

pub fn run() -> bool {
    if smp::online_set().len() != 8 {
        kprintln!("[JSR-SOAK] failure expected_cpus=8 actual={}", smp::online_set().len());
        return false;
    }
    // Warm up before the measured baseline; heap growth must not hide a leak.
    longrun_demo::run();
    if longrun_demo::failed() != 0 { return false; }
    let before = baseline();
    let heap = mm::heap::stats();
    let mut rounds = 0u64;
    kprintln!("[JSR-SOAK] ready cpus=8 free_frames={} objects={} pending={} heap={:?}",
        before.free_frames, before.objects, before.pending, heap);
    loop {
        longrun_demo::run();
        rounds += 1;
        let after = baseline();
        let after_heap = mm::heap::stats();
        let ok = after == before && after_heap == heap && longrun_demo::failed() == 0;
        kprintln!("[JSR-SOAK] progress rounds={} user_iterations={} free_frames={} objects={} pending={} heap={:?} conserved={}",
            rounds, rounds * 1500, after.free_frames, after.objects, after.pending, after_heap, ok);
        if !ok { kprintln!("[JSR-SOAK] failure resource_or_function"); return false; }
        if stop_requested() {
            kprintln!("[JSR-SOAK] complete rounds={} user_iterations={} conserved=true", rounds, rounds * 1500);
            return true;
        }
    }
}
