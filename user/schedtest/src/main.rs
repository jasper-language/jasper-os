//! user-schedtest：过载下的响应性验收程序（服务质量分级调度）。
//! Responsiveness under load: QoS scheduling acceptance program.
//!
//! 场景：[`HOGS`] 个线程吃满 CPU（从不睡眠、从不让出），主线程是一个周期性任务——
//! 每次睡 [`PERIOD`] 个 tick，醒来后量一量比预定时刻迟到了多少。
//!
//! | role | 吃满线程的档位 | 期望 |
//! |---|---|---|
//! | 0 `qos` | 自己降到「后台」 | 主线程（用户发起）醒来即抢占，迟到 0 tick；之后主线程自己吃满 CPU 时后台线程仍有进展（最低份额） |
//! | 1 `same_class` | 保持「用户发起」（与主线程同档，对照组） | 同档不抢占：迟到不超过一个时间片 |
//! | 2 `runaway` | 全部线程（含主线程）吃满 CPU [`RUNAWAY_TICKS`] 个 tick、从不睡眠 | 模拟失控进程：由内核侧按进程 CPU 上限限速，本程序只需按时结束 |
//! | 3 `pressure` | —（单线程，降到后台档后申请匿名内存） | 内存紧张时被拒（内存不足错误），且区间内没有留下任何映射 |
//!
//! 两种模式都检查档位规则：未定义的档位数值被拒、没有上限时不能升档、降档后不能升回；
//! 吃满线程退出后再测 [`RECOVERY_ROUNDS`] 轮，确认压力撤销后迟到量立即回到 0（允许一次跨 tick 的读数误差）。
//! 任何一步不符即以该步编号退出；全部通过以 0 退出。延迟的权威测量在内核侧（从唤醒到被选中运行），
//! 本程序打印的是用户态看到的迟到量，二者互相印证。
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use jasper_rt::task::{self, Qos};
use jasper_rt::{entry, mem, println, sys, time, Error};

entry!(main);

/// 吃满 CPU 的线程数（加上主线程共 5 个用户线程：同时存在的任务数超过原先 4 个槽位的上限）。
const HOGS: usize = 4;
/// 周期性测量的轮数。
const ROUNDS: u64 = 40;
/// 每轮睡眠的 tick 数。
const PERIOD: u64 = 2;
/// 主线程自己吃满 CPU 的时长（tick；验证后台线程在更高档的持续负载下仍有进展）。
const BUSY_TICKS: u64 = 150;
/// 吃满阶段每两次读时刻之间的空转次数。
const SPIN_PER_CHECK: u32 = 200_000;
/// 压力撤销后的复测轮数。
const RECOVERY_ROUNDS: u64 = 10;
/// role 2：失控阶段的时长（tick，按墙上时间计；受 CPU 上限限速时实际运行的 tick 少得多）。
const RUNAWAY_TICKS: u64 = 300;
/// role 3：申请的匿名页数与位置（私有窗口内、与运行时堆和线程栈不重叠的区域）。
const PRESSURE_PAGES: u64 = 4;
/// 放在映像之后、堆之前的空隙里（窗口起点 + 48 MiB），各指令集的私有窗口都容得下。
const PRESSURE_BASE: u64 = sys::WINDOW_BASE + (48 << 20);
const _: () = assert!(PRESSURE_BASE + PRESSURE_PAGES * sys::PAGE <= sys::HEAP_BASE);
/// 迟到量直方图桶数（0..=14 各一桶，≥15 合并）。
const BUCKETS: usize = 16;

/// 通知吃满线程结束。
static STOP: AtomicBool = AtomicBool::new(false);
/// 已就绪（档位已设置好）的吃满线程数。
static READY: AtomicUsize = AtomicUsize::new(0);
/// 每个吃满线程的进展计数。
static PROGRESS: [AtomicUsize; HOGS] = [const { AtomicUsize::new(0) }; HOGS];
/// 吃满线程内的档位检查失败计数（线程内不能直接退出进程，汇总给主线程）。
static HOG_ERRORS: AtomicUsize = AtomicUsize::new(0);

/// 检查计数器：失败时以步骤编号退出。
struct Steps(u32);

impl Steps {
    fn check(&mut self, ok: bool) -> Result<(), u32> {
        self.0 += 1;
        if ok {
            Ok(())
        } else {
            Err(self.0)
        }
    }
}

/// 迟到量统计（单位 tick）。
struct Lateness {
    buckets: [u32; BUCKETS],
    count: u32,
    max: u64,
}

impl Lateness {
    fn new() -> Self {
        Lateness { buckets: [0; BUCKETS], count: 0, max: 0 }
    }

    fn record(&mut self, late: u64) {
        self.buckets[(late as usize).min(BUCKETS - 1)] += 1;
        self.count += 1;
        self.max = self.max.max(late);
    }

    /// 第 `permille` 千分位（最小的 v，使迟到 ≤ v 的样本占比 ≥ 该千分比）。
    fn percentile(&self, permille: u64) -> u64 {
        let need = (self.count as u64 * permille).div_ceil(1000).max(1);
        let mut acc = 0u64;
        for (i, &n) in self.buckets.iter().enumerate() {
            acc += n as u64;
            if acc >= need {
                return if i == BUCKETS - 1 { self.max } else { i as u64 };
            }
        }
        self.max
    }
}

fn main(role: u64, _arg: u64) -> i32 {
    let mut s = Steps(0);
    let background = role == 0;
    let (mode, r) = match role {
        2 => ("runaway", runaway(&mut s)),
        3 => ("pressure", pressure(&mut s)),
        _ => {
            let mode = if background { "qos" } else { "same_class" };
            (mode, run(&mut s, background, mode))
        }
    };
    match r {
        Ok(()) => {
            println!("schedtest: mode={} ok checks={}", mode, s.0);
            0
        }
        Err(step) => {
            STOP.store(true, Ordering::Relaxed);
            println!("schedtest: mode={} FAIL step={}", mode, step);
            step as i32
        }
    }
}

/// 吃满 CPU 的线程体：按需降到后台档，然后一直累加进展计数，直到主线程通知结束。
fn hog(i: usize, background: bool) -> u64 {
    if background {
        if task::set_qos(Qos::Background).is_err() {
            HOG_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        // 降档之后不能自己升回去
        if task::set_qos(Qos::UserInitiated) != Err(Error::RIGHTS_DENIED) {
            HOG_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
    READY.fetch_add(1, Ordering::Release);
    while !STOP.load(Ordering::Relaxed) {
        PROGRESS[i].fetch_add(1, Ordering::Relaxed);
    }
    0
}

fn total_progress() -> u64 {
    PROGRESS.iter().map(|p| p.load(Ordering::Relaxed) as u64).sum()
}

fn run(s: &mut Steps, background: bool, mode: &str) -> Result<(), u32> {
    // 档位规则：未定义的数值、没有上限时升档
    s.check(task::set_qos_raw(4) == Err(Error::INVALID_ARGUMENT))?;
    s.check(task::set_qos_raw(u64::MAX) == Err(Error::INVALID_ARGUMENT))?;
    s.check(task::set_qos(Qos::Interactive) == Err(Error::RIGHTS_DENIED))?;
    s.check(task::set_qos(Qos::UserInitiated).is_ok())?; // 不变总是允许
    println!("schedtest: mode={} qos_rules invalid_refused=true raise_refused=true same_ok=true", mode);

    let mut hogs = Vec::new();
    for i in 0..HOGS {
        let h = task::spawn(move || hog(i, background));
        s.check(h.is_ok())?;
        if let Ok(h) = h {
            hogs.push(h);
        }
    }
    // 用睡眠（而不是让出）等吃满线程就绪：让出不会把处理器交给更低档的线程，
    // 降到后台档的线程只能在主线程睡眠时（或靠最低份额）运行。
    while READY.load(Ordering::Acquire) < HOGS {
        s.check(time::sleep(1).is_ok())?;
    }
    s.check(HOG_ERRORS.load(Ordering::Relaxed) == 0)?;

    // 测量阶段：周期性睡眠，量迟到量
    let mut late = Lateness::new();
    let progress_before = total_progress();
    for _ in 0..ROUNDS {
        let t0 = time::now();
        s.check(time::sleep(PERIOD).is_ok())?;
        let t1 = time::now();
        late.record(t1.saturating_sub(t0 + PERIOD));
    }
    let progress_measure = total_progress() - progress_before;
    s.check(late.count as u64 == ROUNDS)?;
    s.check(progress_measure > 0)?; // 主线程睡眠期间吃满线程在运行
    println!(
        "schedtest: mode={} hogs={} rounds={} period={} late_p50={} late_p99={} late_max={} hog_progress={}",
        mode,
        HOGS,
        ROUNDS,
        PERIOD,
        late.percentile(500),
        late.percentile(990),
        late.max,
        progress_measure > 0
    );

    if background {
        // 主线程（用户发起）自己吃满 CPU：后台线程只能拿到最低份额，但不能被饿死
        let before = total_progress();
        let end = time::now() + BUSY_TICKS;
        while time::now() < end {
            // 每读一次时刻先空转一阵：读时刻是系统调用，每次都会产生一行诊断输出
            for _ in 0..SPIN_PER_CHECK {
                core::hint::spin_loop();
            }
        }
        let starved = total_progress() == before;
        s.check(!starved)?;
        println!("schedtest: mode={} busy_ticks={} background_progressed={}", mode, BUSY_TICKS, !starved);
    }

    STOP.store(true, Ordering::Relaxed);
    let mut codes_ok = true;
    for h in hogs {
        codes_ok &= h.join() == Ok(0);
    }
    s.check(codes_ok)?;
    let all_progressed = PROGRESS.iter().all(|p| p.load(Ordering::Relaxed) > 0);
    s.check(all_progressed)?;
    println!("schedtest: mode={} joined={} all_progressed={}", mode, HOGS, all_progressed);

    // 压力撤销：没有吃满线程之后，迟到量立即回到 0
    let mut after = Lateness::new();
    for _ in 0..RECOVERY_ROUNDS {
        let t0 = time::now();
        s.check(time::sleep(1).is_ok())?;
        after.record(time::now().saturating_sub(t0 + 1));
    }
    s.check(after.percentile(500) == 0 && after.max <= 1)?;
    println!("schedtest: mode={} recovery rounds={} late_p50={} late_max={}", mode, RECOVERY_ROUNDS, after.percentile(500), after.max);
    Ok(())
}

/// role 2：失控进程——[`HOGS`] 个线程加主线程一起吃满 CPU，到期后收拢退出。
fn runaway(s: &mut Steps) -> Result<(), u32> {
    let mut hogs = Vec::new();
    for i in 0..HOGS {
        let h = task::spawn(move || hog(i, false));
        s.check(h.is_ok())?;
        if let Ok(h) = h {
            hogs.push(h);
        }
    }
    let end = time::now() + RUNAWAY_TICKS;
    let mut spins = 0u64;
    while time::now() < end {
        // 每读一次时刻先空转一阵（读时刻是系统调用，会产生诊断输出）
        for _ in 0..SPIN_PER_CHECK {
            core::hint::spin_loop();
        }
        spins += 1;
    }
    STOP.store(true, Ordering::Relaxed);
    let mut codes_ok = true;
    for h in hogs {
        codes_ok &= h.join() == Ok(0);
    }
    s.check(codes_ok)?;
    let all_progressed = PROGRESS.iter().all(|p| p.load(Ordering::Relaxed) > 0);
    s.check(all_progressed && spins > 0)?;
    println!("schedtest: mode=runaway threads={} wall_ticks={} all_progressed={}", HOGS + 1, RUNAWAY_TICKS, all_progressed);
    Ok(())
}

/// role 3：内存紧张时后台档的匿名内存申请被拒（内存不足），且没有留下半份映射。
fn pressure(s: &mut Steps) -> Result<(), u32> {
    s.check(task::set_qos(Qos::Background).is_ok())?;
    let r = mem::map(PRESSURE_BASE, PRESSURE_PAGES, mem::WRITE);
    s.check(r == Err(Error::MEMORY_OUT_OF_MEMORY))?;
    // 被拒的申请不留任何映射：取消映射同一区间必须报「地址无效」
    s.check(mem::unmap(PRESSURE_BASE, PRESSURE_PAGES) == Err(Error::MEMORY_INVALID_ADDRESS))?;
    println!("schedtest: mode=pressure qos=background map_refused=true nothing_mapped=true");
    Ok(())
}
