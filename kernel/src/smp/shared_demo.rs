//! 去全局串行点演练（与机制分离，可整体删除）：锁顺序登记与检查、控制台跨核整行输出、
//! 调度器锁的跨核并发访问、每核独立的内核栈登记。
//! Exercise for removed global serialisation points: lock order, console, scheduler lock, per-CPU kernel stacks.
//!
//! 只有引导处理器时如实报告，只演练锁顺序部分；断言计入多处理器演练的计数（见 `demo`）。

use kernel_core::lockorder::{validate_registry, LockOrderError};
use kernel_core::smp::MAX_CPUS;

use super::demo::check;
use super::percpu;
use crate::sync::IrqSpinLock;
use crate::{arch, console, kprintln, lockorder, sched};

/// 演练用的三把锁，各借用一个已登记的类别（检查按类别的级别进行，与实例无关）。
static LOW: IrqSpinLock<u32> = IrqSpinLock::ranked(lockorder::PROC_REGISTRY, 0);
static OUTER: IrqSpinLock<u32> = IrqSpinLock::ranked(lockorder::SCHED, 0);
static INNER: IrqSpinLock<u32> = IrqSpinLock::ranked(lockorder::TRACE, 0);

/// 每个处理器在并发输出阶段打印的行数。
const BURST_LINES: u64 = 16;
/// 并发访问调度器阶段每个处理器的访问次数。
const SCHED_ROUNDS: u64 = 2000;
/// 每核内核栈登记演练使用的基值（16 字节对齐，32 位目标上同样可表示）。
const STACK_BASE: u64 = 0x1000_0000;

/// 运行演练。`online` 是在线处理器数。
pub fn run(online: usize) {
    registry();
    order();
    if online > 1 {
        held_per_cpu(online);
        console_burst(online);
        sched_concurrent(online);
        kernel_stacks(online);
    } else {
        kprintln!("[JSR-SMPC] single cpus=1 cross_cpu=skipped");
    }
}

/// 登记表合法，并输出整条链。
fn registry() {
    let ok = validate_registry(lockorder::REGISTRY).is_ok();
    check(ok, "锁顺序登记表不合法");
    kprintln!("[JSR-SMPC] registry locks={} valid={}", lockorder::REGISTRY.len(), ok);
    for c in lockorder::REGISTRY {
        kprintln!("[JSR-SMPC] rank {:>2} {}", c.rank, c.name);
    }
}

/// 顺序检查：按级别递增加锁成功；逆序与重入被拒绝，且不加锁、持有集合与中断状态都不变。
fn order() {
    let held = percpu::this().held_locks();
    let base = held.bits();
    let irq_before = arch::irq_save_disable();
    arch::irq_restore(irq_before);

    // 合法顺序：外层 → 内层
    let ascending = {
        let _o = OUTER.lock();
        let inner = INNER.lock_checked();
        let both = held.bits() == base | (1 << lockorder::SCHED.rank) | (1 << lockorder::TRACE.rank);
        inner.is_ok() && both
    };
    let released = held.bits() == base;
    check(ascending && released, "按级别递增加锁失败或释放后持有集合未恢复");

    // 逆序：持有内层时去拿外层
    let (reverse, reverse_clean) = {
        let _i = INNER.lock();
        let before = held.bits();
        let r = OUTER.lock_checked().map(|_| ());
        (r, held.bits() == before && !outer_is_locked())
    };
    // 重入：同一把锁再加一次
    let (again, again_clean) = {
        let _i = INNER.lock();
        let before = held.bits();
        let r = INNER.lock_checked().map(|_| ());
        (r, held.bits() == before)
    };
    let irq_after = arch::irq_save_disable();
    arch::irq_restore(irq_after);
    let want_rev = Err(LockOrderError::OutOfOrder { acquiring: lockorder::SCHED.rank, highest_held: lockorder::TRACE.rank });
    let want_again = Err(LockOrderError::OutOfOrder { acquiring: lockorder::TRACE.rank, highest_held: lockorder::TRACE.rank });
    check(reverse == want_rev && reverse_clean, "逆序加锁未被拒绝或留下了改动");
    check(again == want_again && again_clean, "同级重入未被拒绝或留下了改动");
    check(held.bits() == base && irq_after == irq_before, "演练后持有集合或中断状态未回到基线");
    kprintln!(
        "[JSR-SMPC] order ascending=ok reverse={} recursive={} unchanged={} held_back={}",
        err_name(reverse),
        err_name(again),
        reverse_clean && again_clean,
        held.bits() == base
    );
}

/// 外层演练锁是否被占用（拒绝路径不得留下已加锁状态）。
fn outer_is_locked() -> bool {
    OUTER.try_lock_bypass().is_none()
}

fn err_name(r: Result<(), LockOrderError>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(e) => e.name(),
    }
}

/// 跨核调用：在执行者上获取最外层的演练锁，返回加锁前本核的持有位图（应为空）。
fn take_low(_: u64) -> u64 {
    let before = percpu::this().held_locks().bits() as u64;
    match LOW.lock_checked() {
        Ok(_g) => before,
        Err(_) => u64::MAX,
    }
}

/// 持有集合每核一份：引导处理器持有中层锁时，其他处理器照样能获取更外层的锁。
fn held_per_cpu(online: usize) {
    let _o = OUTER.lock();
    let mut ok = 0;
    for c in 1..online {
        if super::call_on(c, take_low, 0) == Ok(0) {
            ok += 1;
        }
    }
    check(ok == online - 1, "其他处理器的持有集合受到了引导处理器的影响");
    kprintln!("[JSR-SMPC] held per_cpu independent={}/{}", ok, online - 1);
}

/// 一行固定格式的输出：任何跨核交错都会破坏它的格式。
fn burst_line(cpu: u64, seq: u64) {
    kprintln!("[JSR-SMPC] burst cpu={} seq={:02} abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL end", cpu, seq);
}

/// 跨核调用：连续打印若干行，返回本核编号。
fn print_burst(_: u64) -> u64 {
    let me = arch::cpu_index() as u64;
    for seq in 0..BURST_LINES {
        burst_line(me, seq);
    }
    me
}

/// 控制台：全部处理器同时打印，每行完整、不交错（由验收脚本按行格式核对）。
fn console_burst(online: usize) {
    let before = console::contended();
    let posted = (1..online).filter(|&c| super::post_call(c, print_burst, 0).is_ok()).count();
    for seq in 0..BURST_LINES {
        burst_line(0, seq);
    }
    let done = (1..online).filter(|&c| super::collect_call(c) == Ok(c as u64)).count();
    check(posted == online - 1 && done == online - 1, "并发输出未在全部处理器上完成");
    kprintln!(
        "[JSR-SMPC] console burst cpus={} lines_per_cpu={} total={} contended={}",
        online,
        BURST_LINES,
        online as u64 * BURST_LINES,
        console::contended() - before
    );
}

/// 跨核调用：反复读调度器状态；返回不一致次数（容量变化或切换计数倒退）。
fn sched_reader(rounds: u64) -> u64 {
    let cap = sched::capacity();
    let mut last = sched::switch_count();
    let mut bad = 0;
    for _ in 0..rounds {
        let now = sched::switch_count();
        if sched::capacity() != cap || now < last {
            bad += 1;
        }
        last = now;
        let _ = sched::watchdog_threshold();
    }
    bad
}

/// 调度器锁：其他处理器反复读调度器状态的同时，引导处理器反复改写并让出；无死锁、读到的状态一致、改写如数恢复。
fn sched_concurrent(online: usize) {
    let before = sched::lock_contended();
    let threshold = sched::watchdog_threshold();
    let posted = (1..online).filter(|&c| super::post_call(c, sched_reader, SCHED_ROUNDS).is_ok()).count();
    for i in 0..SCHED_ROUNDS {
        let old = sched::set_watchdog_threshold(threshold + 1 + (i % 7) as u32);
        sched::set_watchdog_threshold(old);
        if i % 256 == 0 {
            sched::yield_now();
        }
    }
    let results: [Option<u64>; MAX_CPUS] = core::array::from_fn(|c| {
        if c >= 1 && c < online {
            super::collect_call(c).ok()
        } else {
            None
        }
    });
    let clean = (1..online).filter(|&c| results[c] == Some(0)).count();
    let restored = sched::watchdog_threshold() == threshold;
    check(posted == online - 1 && clean == online - 1, "并发读调度器时出现不一致或未完成");
    check(restored, "引导处理器的改写未如数恢复");
    kprintln!(
        "[JSR-SMPC] sched concurrent readers={}/{} rounds={} consistent=true restored={} contended={}",
        clean,
        online - 1,
        SCHED_ROUNDS,
        restored,
        sched::lock_contended() - before
    );
}

/// 跨核调用：登记本核内核栈顶并读回（读回走入口实际使用的位置）。
fn set_stack(top: u64) -> u64 {
    arch::set_kernel_stack(top);
    arch::kernel_stack()
}

/// 跨核调用：读本核登记的内核栈顶。
fn read_stack(_: u64) -> u64 {
    arch::kernel_stack()
}

/// 每核内核栈登记：各核（含引导处理器）各写一个不同值，互不覆盖；演练后全部恢复原值。
/// 演练期间引导处理器不让出、不回用户态，临时登记值不会被真正用作栈。
fn kernel_stacks(online: usize) {
    let mine = arch::kernel_stack();
    let bsp_set = set_stack(STACK_BASE) == STACK_BASE;
    let old: [u64; MAX_CPUS] = core::array::from_fn(|c| {
        if c >= 1 && c < online {
            super::call_on(c, read_stack, 0).unwrap_or(u64::MAX)
        } else {
            0
        }
    });
    let want = |c: usize| STACK_BASE + c as u64 * 0x1000;
    // 下标 0 即引导处理器：上面已写入 want(0) = STACK_BASE
    let set = (1..online).filter(|&c| super::call_on(c, set_stack, want(c)) == Ok(want(c))).count();
    // 全部写完后逐核读回：后写的处理器没有覆盖先写的
    let kept = (1..online).filter(|&c| super::call_on(c, read_stack, 0) == Ok(want(c))).count();
    let bsp_kept = bsp_set && arch::kernel_stack() == STACK_BASE;
    arch::set_kernel_stack(mine);
    let restored = (1..online).filter(|&c| super::call_on(c, set_stack, old[c]) == Ok(old[c])).count();
    check(set == online - 1 && kept == online - 1, "每核内核栈登记互相覆盖");
    check(bsp_kept, "引导处理器的内核栈登记被其他处理器改写");
    check(restored == online - 1 && arch::kernel_stack() == mine, "演练后未恢复各处理器的内核栈登记");
    kprintln!(
        "[JSR-SMPC] kstack per_cpu set={}/{} kept={}/{} bsp_unchanged={} restored={}/{}",
        set,
        online - 1,
        kept,
        online - 1,
        bsp_kept,
        restored,
        online - 1
    );
}
