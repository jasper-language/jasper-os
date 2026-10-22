//! 多处理器演练（与机制分离，可整体删除）：启动结果、各核各自计时、核间中断、跨核调用、TLB 击落与拒绝路径。
//! Multiprocessor exercise: start-up, per-CPU clocks, IPIs, cross-CPU calls, TLB shootdown and refusals.
//!
//! 只有引导处理器时（单核仿真或平台尚未接入其他处理器）如实报告并只演练拒绝路径。
//! 所有断言计数，失败数经 [`failed`] 汇总到内核退出码。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::smp::{IpiKind, SmpError};

use super::{percpu, StartReport};
use crate::{arch, kprintln, mm};

static FAILED: AtomicU32 = AtomicU32::new(0);
static CHECKS: AtomicU32 = AtomicU32::new(0);

/// 记一项断言（失败时打印原因）；同目录的其他演练共用计数。
pub(super) fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-SMP-FAIL] {}", what);
    }
}

/// 断言失败数。
/// Number of failed assertions.
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 每个其他处理器至少要走过的本地 tick 数。
const MIN_TICKS: u64 = 10;
/// 击落演练使用的内核虚拟地址（内核空间私有窗口之外、平时不映射）。
const TLB_VA: u64 = arch::KERNEL_PROBE_VA + 0x20_0000;
const PATTERN_A: u64 = 0x534D_505F_4F4C_4441;
const PATTERN_B: u64 = 0x534D_505F_4E45_5742;

/// 跨核调用：返回执行者的逻辑下标。
fn whoami(_: u64) -> u64 {
    arch::cpu_index() as u64
}

/// 跨核调用：在执行者上经虚拟地址读一个 64 位值（经该处理器自己的 TLB）。
fn read_at(va: u64) -> u64 {
    // SAFETY：发起方保证 va 在内核空间中已映射且对齐（演练期间映射不撤销）。
    unsafe { (va as *const u64).read_volatile() }
}

/// 所有处理器各类核间中断计数之和（拒绝路径用它断言「没有发出任何中断」）。
fn ipi_total() -> u32 {
    (0..super::cpu_count())
        .filter_map(percpu::get)
        .map(|p| IpiKind::ALL.iter().map(|&k| p.ipis(k)).sum::<u32>())
        .sum()
}

/// 有界自旋等待条件成立。
fn spin_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..super::WAIT_SPINS {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    cond()
}

/// 运行演练。`report` 是 [`super::start_secondaries`] 的结果。
pub fn run(report: StartReport) {
    kprintln!(
        "[JSR-SMP] start present={} online={} failed={} source={} dropped={} disabled={}",
        report.present,
        report.online,
        report.failed,
        report.source,
        report.dropped,
        report.disabled
    );
    check(report.failed == 0 && report.online == report.present, "有处理器未报到");
    for cpu in 0..report.present {
        if let Some(p) = percpu::get(cpu) {
            kprintln!("[JSR-SMP] cpu index={} hw={} state={}", cpu, p.hw_id(), p.state.get().name());
        }
    }
    let before = ipi_total();
    refusals(report.present);
    check(ipi_total() == before && super::shootdown_idle(), "拒绝路径发出了核间中断或留下了请求");
    if report.online > 1 {
        clocks(report.online);
        reschedule(report.online);
        calls(report.online);
        shootdown(report.online);
    } else {
        kprintln!("[JSR-SMP] single cpus=1 secondary=none");
    }
    super::shared_demo::run(report.online);
    let me = percpu::this();
    check(arch::cpu_index() == 0 && me.current() == 0, "引导处理器的每核数据与当前任务不符");
    kprintln!(
        "[JSR-SMP] summary cpus={} online={} checks={} failed={}",
        report.present,
        super::online_set().len(),
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 拒绝路径：不存在的处理器、发给自己、非法击落范围——全部被拒且不发出任何中断、不留请求。
fn refusals(present: usize) {
    let r1 = super::reschedule(present);
    let r2 = super::reschedule(0);
    let r3 = super::call_on(present + 7, whoami, 0);
    let r4 = super::call_on(0, whoami, 0);
    let r5 = super::tlb_shootdown(TLB_VA + 1, 1);
    let r6 = super::tlb_shootdown(TLB_VA, 0);
    let r7 = super::tlb_shootdown(TLB_VA, u64::MAX);
    check(r1 == Err(SmpError::NoSuchCpu), "向不存在的处理器发重新调度未被拒绝");
    check(r2 == Err(SmpError::SelfTarget), "向自己发核间中断未被拒绝");
    check(r3 == Err(SmpError::NoSuchCpu), "向不存在的处理器投递调用未被拒绝");
    check(r4 == Err(SmpError::SelfTarget), "向自己投递跨核调用未被拒绝");
    check(r5 == Err(SmpError::BadRange) && r6 == Err(SmpError::BadRange) && r7 == Err(SmpError::BadRange), "非法击落范围未被拒绝");
    kprintln!(
        "[JSR-SMP] refuse no_such_cpu={} self={} call_no_such={} call_self={} bad_range={},{},{}",
        err_name(r1),
        err_name(r2),
        err_name(r3.map(|_| ())),
        err_name(r4.map(|_| ())),
        err_name(r5),
        err_name(r6),
        err_name(r7)
    );
}

fn err_name(r: Result<(), SmpError>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(e) => e.name(),
    }
}

/// 各核各自计时：其他处理器的本地 tick 都在走；引导处理器关中断（自己的时钟停住）时它们照走。
fn clocks(online: usize) {
    let start: [u64; kernel_core::smp::MAX_CPUS] = core::array::from_fn(|c| percpu::get(c).map(|p| p.ticks()).unwrap_or(0));
    let ok = spin_until(|| (1..online).all(|c| percpu::get(c).map(|p| p.ticks()).unwrap_or(0) >= start[c] + MIN_TICKS));
    check(ok, "有处理器的本地时钟没有走");
    for c in 1..online {
        let now = percpu::get(c).map(|p| p.ticks()).unwrap_or(0);
        kprintln!("[JSR-SMP] clock cpu={} ticks_before={} ticks_after={} advanced={}", c, start[c], now, now - start[c]);
    }
    // 引导处理器关中断：它的 tick 不再增长，其他处理器的 tick 继续增长 ⇒ 各自计时、互不依赖
    let advanced = arch::without_irq(|| {
        let bsp0 = percpu::get(0).map(|p| p.ticks()).unwrap_or(0);
        let ap0: [u64; kernel_core::smp::MAX_CPUS] = core::array::from_fn(|c| percpu::get(c).map(|p| p.ticks()).unwrap_or(0));
        let ok = spin_until(|| (1..online).all(|c| percpu::get(c).map(|p| p.ticks()).unwrap_or(0) >= ap0[c] + MIN_TICKS));
        let bsp1 = percpu::get(0).map(|p| p.ticks()).unwrap_or(0);
        ok && bsp1 == bsp0
    });
    check(advanced, "引导处理器关中断期间其他处理器的时钟停了（或引导处理器的时钟仍在走）");
    kprintln!("[JSR-SMP] clock independent bsp_frozen=1 others_advanced={}", advanced);
}

/// 「重新调度」核间中断：每个其他处理器各收到一次，并由其空闲执行流消化标志。
fn reschedule(online: usize) {
    let mut delivered = 0;
    for c in 1..online {
        let Some(p) = percpu::get(c) else { continue };
        let before = p.ipis(IpiKind::Reschedule);
        let wakes = p.idle_wakeups();
        let sent = super::reschedule(c);
        let got = spin_until(|| p.ipis(IpiKind::Reschedule) == before + 1 && p.idle_wakeups() > wakes);
        // 标志在空闲执行流醒来后被取走
        let consumed = spin_until(|| !p.resched_pending());
        check(sent.is_ok() && got && consumed, "重新调度核间中断未送达或未被消化");
        if sent.is_ok() && got && consumed {
            delivered += 1;
        }
    }
    kprintln!("[JSR-SMP] ipi reschedule delivered={}/{}", delivered, online - 1);
}

/// 跨核调用：函数确实在目标处理器上执行；其他处理器的「当前任务」是空闲执行流。
fn calls(online: usize) {
    let mut ran = 0;
    for c in 1..online {
        let r = super::call_on(c, whoami, 0);
        let idle = percpu::get(c).map(|p| p.current()) == Some(percpu::IDLE_SLOT);
        check(r == Ok(c as u64) && idle, "跨核调用未在目标处理器上执行或当前任务不是空闲执行流");
        if r == Ok(c as u64) {
            ran += 1;
        }
    }
    kprintln!("[JSR-SMP] call ran_on_target={}/{} current=idle", ran, online - 1);
}

/// TLB 击落：其他处理器先经旧映射读到 A；改映射到 B 后只在本处理器作废时其他处理器可能仍读到 A；
/// 击落之后每个处理器都必须读到 B。演练结束后页帧回到基线。
fn shootdown(online: usize) {
    let page = VirtPage::containing(TLB_VA);
    let (Ok(fa), Ok(fb)) = (mm::frame::allocate(), mm::frame::allocate()) else {
        check(false, "无法为击落演练分配页帧");
        return;
    };
    let write = |f: kernel_core::frame::PhysFrame, v: u64| match mm::phys_to_virt(f.start()) {
        // SAFETY：f 刚分配，经全物理映射可写。
        Some(p) => unsafe { (p as *mut u64).write_volatile(v) },
        None => check(false, "页帧没有物理映射"),
    };
    write(fa, PATTERN_A);
    write(fb, PATTERN_B);
    // 先建一次映射再撤销：中间页表在此建立，之后的基线不含它们
    let warm = mm::map::map(page, fa, MapFlags::WRITE).is_ok() && mm::map::unmap(page).is_ok();
    let base = mm::frame::free_frames();
    check(warm && mm::map::map(page, fa, MapFlags::WRITE).is_ok(), "击落演练映射失败");

    let read_all = || -> u32 {
        (1..online).filter(|&c| super::call_on(c, read_at, TLB_VA) == Ok(PATTERN_A)).count() as u32
    };
    let saw_a = read_all();
    check(saw_a as usize == online - 1, "其他处理器经旧映射没有读到 A");

    // 改映射：本处理器的映射接口只作废本地 TLB
    let remapped = mm::map::unmap(page).is_ok() && mm::map::map(page, fb, MapFlags::WRITE).is_ok();
    check(remapped, "改映射失败");
    let stale = read_all();

    let r = super::tlb_shootdown(page.start(), 1);
    check(r.is_ok(), "击落失败");
    let fresh = (1..online).filter(|&c| super::call_on(c, read_at, TLB_VA) == Ok(PATTERN_B)).count();
    check(fresh == online - 1, "击落之后仍有处理器读到旧映射");
    let acks: u32 = (1..online).filter_map(percpu::get).map(|p| p.ipis(IpiKind::TlbShootdown)).sum();
    check(acks as usize >= online - 1 && super::shootdown_idle(), "击落应答数不符或公告板未清空");
    // SAFETY：本处理器读自己刚改好的映射。
    let local = unsafe { (TLB_VA as *const u64).read_volatile() } == PATTERN_B;
    check(local, "本处理器读到的不是新映射");

    let undone = mm::map::unmap(page).is_ok() && super::tlb_shootdown(page.start(), 1).is_ok();
    let freed = mm::frame::deallocate(fa).is_ok() && mm::frame::deallocate(fb).is_ok();
    let back = mm::frame::free_frames() == base + 2;
    check(undone && freed && back, "击落演练结束后页帧未回到基线");
    kprintln!(
        "[JSR-SMP] tlb va={:#x} before=A:{}/{} stale_without_shootdown={}/{} after_shootdown=B:{}/{} local=B:{} acks={} frames_back={}",
        TLB_VA,
        saw_a,
        online - 1,
        stale,
        online - 1,
        fresh,
        online - 1,
        local,
        acks,
        back
    );
}
