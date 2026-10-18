//! 64 位计数单元的自检：中断处理程序与任务共享的 64 位计数在所有目标上都必须正确，包括没有 64 位原子指令的 32 位目标。
//! Self-test of the interrupt-safe 64-bit counter cell on every target, including 32-bit ones without 64-bit atomics.
//!
//! # 验证什么、为什么
//! * **宽值**：跨越 2^32 的递增、递减、取大与存取都保持完整的 64 位（32 位目标上高、低两个字不能各自为政）；
//! * **与中断共享**：在开中断的情况下紧密循环读取调度器的 tick 计数（由定时器中断处理程序递增的同一个实例），
//!   直到它前进若干个 tick。若 64 位单元在 32 位目标上用「不关中断的锁」模拟，中断落在读者持锁期间就会自锁、永不返回；
//!   本检查能结束且读到的值单调不减，即证明实现没有这一缺陷。同一循环里也检查 64 位周期计数器单调不减
//!   （RV32 上它由高、低两半拼成，进位时须重读）。
//!
//! 只输出结构化的 `[JSR-COUNTER64]` 标记；不改动任何全局状态（使用的计数都是本模块私有的或只读的）。

use core::sync::atomic::{AtomicU32, Ordering};

use crate::sync::IrqU64;
use crate::{arch, kprintln, sched};

/// 「与中断共享」检查要求 tick 至少前进的次数。
const SHARED_TICKS: u64 = 10;
/// 读取次数上限：超过仍未前进足够的 tick 即判失败（不会无限等待）。
const MAX_READS: u64 = 50_000_000;

/// 失败的检查数。
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 宽值检查用的私有计数单元。
static WIDE: IrqU64 = IrqU64::new(0);

/// 失败的检查数（汇总用）。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 本目标使用的实现：有 64 位原子指令时为硬件原子，否则为「关中断 + 自旋锁」。
const fn implementation() -> &'static str {
    if cfg!(target_has_atomic = "64") {
        "native"
    } else {
        "irq_locked"
    }
}

/// 宽值检查：返回 (通过数, 失败数)。
fn wide_checks() -> (u32, u32) {
    const BELOW: u64 = (1 << 32) - 2;
    let mut ok = 0;
    let mut bad = 0;
    let mut check = |c: bool| if c { ok += 1 } else { bad += 1 };
    WIDE.store(BELOW, Ordering::Relaxed);
    let olds = [0, 1, 2, 3].map(|_| WIDE.fetch_add(1, Ordering::Relaxed));
    check(olds == [BELOW, BELOW + 1, BELOW + 2, BELOW + 3]);
    check(WIDE.load(Ordering::Relaxed) == (1 << 32) + 2);
    check(WIDE.fetch_sub(3, Ordering::Relaxed) == (1 << 32) + 2);
    check(WIDE.load(Ordering::Relaxed) == (1 << 32) - 1);
    // 取大：较小值不改动；高位更大的值整体写入
    check(WIDE.fetch_max(5, Ordering::Relaxed) == (1 << 32) - 1);
    check(WIDE.load(Ordering::Relaxed) == (1 << 32) - 1);
    WIDE.fetch_max(0x1_0000_0000, Ordering::Relaxed);
    check(WIDE.load(Ordering::Relaxed) == 0x1_0000_0000);
    WIDE.store(0x0123_4567_89ab_cdef, Ordering::Relaxed);
    check(WIDE.load(Ordering::Relaxed) == 0x0123_4567_89ab_cdef);
    // 回绕与原生原子一致
    WIDE.store(u64::MAX, Ordering::Relaxed);
    check(WIDE.fetch_add(1, Ordering::Relaxed) == u64::MAX && WIDE.load(Ordering::Relaxed) == 0);
    (ok, bad)
}

/// 与中断共享的检查：开中断紧密读取 tick 计数与周期计数器。返回 (读取次数, 实际前进的 tick, tick 单调, 周期单调)。
fn shared_with_irq() -> (u64, u64, bool, bool) {
    let was = arch::irq_save_disable();
    arch::irq_enable();
    let start = sched::timer_ticks();
    let (mut last, mut last_cycles) = (start, arch::cycles());
    let (mut ticks_monotonic, mut cycles_monotonic) = (true, true);
    let mut reads = 0;
    while reads < MAX_READS && last - start < SHARED_TICKS {
        let now = sched::timer_ticks();
        let cycles = arch::cycles();
        ticks_monotonic &= now >= last;
        cycles_monotonic &= cycles >= last_cycles;
        last = last.max(now);
        last_cycles = last_cycles.max(cycles);
        reads += 1;
    }
    arch::irq_restore(was);
    (reads, last - start, ticks_monotonic, cycles_monotonic)
}

/// 运行全部检查并输出标记。
pub fn run() {
    let (wide_ok, wide_bad) = wide_checks();
    kprintln!("[JSR-COUNTER64] case=wide impl={} crossed_2_32=true ok={} failed={}", implementation(), wide_ok, wide_bad);
    let (reads, ticks, ticks_mono, cycles_mono) = shared_with_irq();
    let shared_ok = ticks >= SHARED_TICKS && ticks_mono && cycles_mono;
    kprintln!(
        "[JSR-COUNTER64] case=isr_shared reads={} ticks={} ticks_monotonic={} cycles_monotonic={} completed={}",
        reads, ticks, ticks_mono, cycles_mono, shared_ok
    );
    let failed = wide_bad + u32::from(!shared_ok);
    FAILED.store(failed, Ordering::Relaxed);
    kprintln!("[JSR-COUNTER64] summary impl={} checks={} failed={}", implementation(), wide_ok + wide_bad + 1, failed);
}
