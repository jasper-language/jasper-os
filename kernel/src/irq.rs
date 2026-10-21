//! 中断分发（架构无关）：逻辑中断线、延迟处理队列、立即处理钩子；设备中断的多核路由、每核预算与亲和均衡。
//! Architecture-neutral interrupt dispatch, plus multi-core device-interrupt routing, quotas and balancing.
//!
//! 时钟与核间中断有两条路径，对应 Java 原型 `InterruptController` 的语义并加上抢占：
//! 1. **立即路径**（中断上下文）：`on_hardware_irq` 由 arch 的中断入口在 EOI 之后调用；
//!    只做必须立刻做的事——入队、驱动调度器时间片（可能就地抢占）。
//! 2. **延迟路径**（任务/主循环上下文）：`poll_and_handle` 排空队列，执行可以慢的工作（如打印 tick）。
//!
//! Core 只认 [`IrqLine`]（逻辑中断线），不认向量号；向量号 ↔ 中断线的映射在 `arch/<isa>/` 内。
//!
//! 设备中断（[`on_device_irq`]，见 [`device`] 一节）：
//! * **路由**：每条设备中断线有允许集合（亲和）与当前目标处理器，经 `arch` 写进中断控制器；
//!   可选的均衡策略（`kernel_core::irq::AffinityPolicy`）由引导处理器的时钟周期性地按各线负载重新分配，
//!   设备中断因此分散到多个核，不会全压在一个核上。
//! * **预算**：每个处理器每个 tick 只给设备中断一定比例的时间与次数（`kernel_core::irq::CoreQuota`）；
//!   超出 ⇒ 这条线在中断控制器上被屏蔽，本处理器的下一个 tick 解除。中断风暴因此最多占每核固定比例，
//!   交互任务不会被饿死；风暴撤销后下一个 tick 就完全恢复。
//! * **处理程序**：每条线一个可替换的处理函数（Observer），在中断上下文、EOI 之前调用，不得切换任务。

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use kernel_core::irq::{AffinityPolicy, QuotaParams, Charge, CoreQuota, IrqError, LineLoad, MAX_LINES};
use kernel_core::msi::MsiError;
use kernel_core::smp::{CpuSet, MAX_CPUS};
use spin::Mutex;

use crate::sync::{IrqSpinLock, IrqU64};
use crate::{arch, clock, lockorder, sched};

/// 逻辑中断线。新增设备中断时在这里加一项，并在各 ISA 的中断入口里映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqLine {
    /// 周期定时器（驱动时钟与时间片）。
    Timer,
    /// 本处理器的本地定时器（每个处理器各自计时）。
    LocalTimer,
    /// 核间中断。
    Ipi(kernel_core::smp::IpiKind),
}

/// 延迟处理队列容量。
const QUEUE_LEN: usize = crate::config::ACTIVE.diag.irq_queue_len;

/// 固定容量环形队列（无堆）。满时丢弃新项并计数，绝不阻塞中断上下文。
struct PendingQueue {
    buf: [Option<IrqLine>; QUEUE_LEN],
    head: usize,
    tail: usize,
    dropped: usize,
}

static PENDING: Mutex<PendingQueue> =
    Mutex::new(PendingQueue { buf: [None; QUEUE_LEN], head: 0, tail: 0, dropped: 0 });

/// 中断上下文入口：由 arch 中断处理程序在 **EOI 之后**调用。
///
/// 先入队再通知调度器：调度器可能在这里切走当前任务，入队必须在那之前完成。
///
/// `from_user`：中断是否打断了用户态代码。是 ⇒ 这里也是一个调度点：所属进程已在 exiting 时，
/// 被打断的线程就地停止（与用户态故障一样，从中断上下文经线程退出路径结束，不再返回用户态）。
pub fn on_hardware_irq(line: IrqLine, from_user: bool) {
    match line {
        IrqLine::Timer => {
            crate::smp::on_local_tick();
            device::on_cpu_tick();
            device::on_balance_tick();
            enqueue(line);
            sched::on_timer_interrupt();
        }
        // 每核事件只更新本处理器的每核数据，不进全局延迟队列（那是引导处理器主循环的队列）
        IrqLine::LocalTimer => {
            crate::smp::on_local_tick();
            device::on_cpu_tick();
            sched::on_local_timer();
        }
        IrqLine::Ipi(kind) => crate::smp::on_ipi(kind),
    }
    if from_user && crate::proc::current_exiting() {
        crate::proc::thread_exit(0, "killed");
    }
}

/// 入队（中断上下文中调用，此时中断已关，不会与 `poll_and_handle` 的取队竞争）。
fn enqueue(line: IrqLine) {
    let mut q = PENDING.lock();
    let next = (q.tail + 1) % QUEUE_LEN;
    if next == q.head {
        q.dropped += 1;
        return;
    }
    let tail = q.tail;
    q.buf[tail] = Some(line);
    q.tail = next;
}

/// 排空并处理所有已入队的中断（只在任务/主循环上下文调用，**不要**在中断里调用）。
///
/// 取队列时必须关中断：中断入口要拿同一把 `PENDING` 锁，主循环持锁时若被中断，
/// 单核上中断处理程序会永远自旋 ⇒ 死锁。关中断窗口只覆盖「弹出一项」，处理在开中断下进行。
pub fn poll_and_handle() {
    loop {
        let next = arch::without_irq(|| {
            let mut q = PENDING.lock();
            if q.head == q.tail {
                None
            } else {
                let head = q.head;
                let v = q.buf[head].take();
                q.head = (q.head + 1) % QUEUE_LEN;
                v
            }
        });
        match next {
            Some(line) => handle(line),
            None => return,
        }
    }
}

/// 因队列满而丢弃的中断数（诊断用）。
pub fn dropped_count() -> usize {
    arch::without_irq(|| PENDING.lock().dropped)
}

/// 延迟路径的分发表。
fn handle(line: IrqLine) {
    match line {
        IrqLine::Timer => clock::on_tick(),
        IrqLine::LocalTimer | IrqLine::Ipi(_) => {}
    }
}

// ---------------------------------------------------------------------------
// 设备中断
// ---------------------------------------------------------------------------

/// 设备中断入口：由 arch 在中断上下文、**EOI 之前**调用（`line` 是平台的设备中断线下标）。
/// 不切换任务：处理程序只做必须立刻做的事，可以慢的工作交给服务线程。
/// Device-interrupt entry, called by the platform before end-of-interrupt.
pub fn on_device_irq(line: usize) {
    device::dispatch(line)
}


/// 设备 MSI 的处理函数（中断上下文；处理器与向量由登记位置确定）。
/// MSI handler (interrupt context).
pub type MsiHandler = fn();

/// 可登记 MSI 处理函数的向量个数（与纯向量池的容量一致）。
/// Number of MSI vector slots known to the dispatcher.
pub const MSI_SLOTS: usize = kernel_core::msi::MAX_SLOTS;

/// 每核每个向量绑定的处理函数（0 = 未绑定）。
/// Handler bound to `[cpu][vector]`; zero means unbound.
static MSI_HANDLERS: [[AtomicUsize; MSI_SLOTS]; MAX_CPUS] =
    [const { [const { AtomicUsize::new(0) }; MSI_SLOTS] }; MAX_CPUS];
/// 每核每个向量收到的 MSI 次数（无论是否绑定处理函数）。
/// MSI arrival count per `[cpu][vector]`, bound or not.
static MSI_COUNTS: [[AtomicU32; MSI_SLOTS]; MAX_CPUS] =
    [const { [const { AtomicU32::new(0) }; MSI_SLOTS] }; MAX_CPUS];
/// 每核未绑定处理函数的 MSI 次数（伪 MSI）。
/// Spurious MSI count per processor.
static MSI_SPURIOUS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// 在处理器 `cpu` 上为 `vector` 安装（或以 `None` 清除）处理函数。
///
/// 调用者保证 `cpu` 在线；处理器下标或向量号越界时返回错误且登记表不变。
/// Install or clear the handler of `vector` on `cpu`.
pub fn msi_bind(cpu: usize, vector: u8, handler: Option<MsiHandler>) -> Result<(), MsiError> {
    if cpu >= MAX_CPUS {
        return Err(MsiError::NoSuchCpu);
    }
    if vector as usize >= MSI_SLOTS {
        return Err(MsiError::OutOfRange);
    }
    MSI_HANDLERS[cpu][vector as usize].store(handler.map(|h| h as usize).unwrap_or(0), Ordering::Release);
    Ok(())
}

/// MSI 中断入口：由平台在中断上下文调用（EOI 之前）。
///
/// 只查**当前处理器**的登记表：绑定过就调用处理函数，未绑定就记一次伪 MSI。
/// 不调用设备中断线的任何旧处理函数，也不切换任务。
/// MSI entry point: dispatch on the current processor, counting unbound vectors as spurious.
pub fn on_msi(vector: u8) {
    let cpu = arch::cpu_index().min(MAX_CPUS - 1);
    if vector as usize >= MSI_SLOTS {
        MSI_SPURIOUS[cpu].fetch_add(1, Ordering::Relaxed);
        return;
    }
    MSI_COUNTS[cpu][vector as usize].fetch_add(1, Ordering::Release);
    let h = MSI_HANDLERS[cpu][vector as usize].load(Ordering::Acquire);
    if h == 0 {
        MSI_SPURIOUS[cpu].fetch_add(1, Ordering::Relaxed);
        return;
    }
    // SAFETY：非零值只来自 `msi_bind` 写入的 `MsiHandler` 函数指针。
    let handler: MsiHandler = unsafe { core::mem::transmute::<usize, MsiHandler>(h) };
    handler();
}

/// 处理器 `cpu` 在 `vector` 上收到的 MSI 次数。
/// MSI arrivals of `vector` on `cpu`.
pub fn msi_count(cpu: usize, vector: u8) -> u32 {
    if cpu >= MAX_CPUS || vector as usize >= MSI_SLOTS {
        return 0;
    }
    MSI_COUNTS[cpu][vector as usize].load(Ordering::Acquire)
}

/// 处理器 `cpu` 上的伪 MSI 次数（未绑定处理函数的向量）。
/// Spurious MSI count of `cpu`.
pub fn msi_spurious(cpu: usize) -> u32 {
    MSI_SPURIOUS.get(cpu).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)
}

/// 清零 MSI 计数与伪 MSI 计数（处理函数登记保持不变）。
/// Reset MSI counters, keeping handler bindings.
pub fn reset_msi_stats() {
    for row in MSI_COUNTS.iter() {
        for count in row.iter() {
            count.store(0, Ordering::Relaxed);
        }
    }
    for count in MSI_SPURIOUS.iter() {
        count.store(0, Ordering::Relaxed);
    }
}

/// 设备中断的路由、预算、均衡与统计。
pub mod device {
    use super::*;

    /// 设备中断处理函数（中断上下文；参数为中断线下标）。
    /// Device interrupt handler.
    pub type DeviceHandler = fn(usize);

    /// 引导处理器每隔多少个 tick 运行一次均衡策略。
    /// Ticks between two balancing passes.
    pub const BALANCE_PERIOD: u64 = 8;

    /// 路由表：允许集合、当前目标、启用集合与均衡策略（一把登记过级别的锁）。
    struct Routing {
        allowed: [CpuSet; MAX_LINES],
        target: [Option<usize>; MAX_LINES],
        enabled: u32,
        policy: Option<&'static (dyn AffinityPolicy + Sync)>,
        moves: u32,
    }

    static ROUTING: IrqSpinLock<Routing> = IrqSpinLock::ranked(
        lockorder::IRQ_ROUTING,
        Routing { allowed: [CpuSet::EMPTY; MAX_LINES], target: [None; MAX_LINES], enabled: 0, policy: None, moves: 0 },
    );

    /// 每核预算（只由所属处理器在中断里改写；参数与统计可由其他处理器读写）。
    static QUOTAS: [IrqSpinLock<CoreQuota>; MAX_CPUS] =
        [const { IrqSpinLock::ranked(lockorder::IRQ_QUOTA, CoreQuota::new(QuotaParams::DEFAULT)) }; MAX_CPUS];

    /// 处理函数表（函数指针按地址存放；0 = 只做设备侧确认与计数）。
    static HANDLERS: [AtomicUsize; MAX_LINES] = [const { AtomicUsize::new(0) }; MAX_LINES];
    /// 每条线在每个处理器上被处理的次数。
    static COUNTS: [[AtomicU32; MAX_CPUS]; MAX_LINES] = [const { [const { AtomicU32::new(0) }; MAX_CPUS] }; MAX_LINES];
    /// 每条线本均衡窗口的处理次数（均衡后清零）。
    static WINDOW: [IrqU64; MAX_LINES] = [const { IrqU64::new(0) }; MAX_LINES];
    /// 未知线号的中断数（平台报告了超出范围的线）。
    static STRAY: AtomicU32 = AtomicU32::new(0);

    /// 平台已接好的设备中断线数（不超过 [`MAX_LINES`]）。
    /// Number of device lines provided by the platform.
    pub fn line_count() -> usize {
        arch::device_irq_count().min(MAX_LINES)
    }

    /// 中断线的规范名。
    /// Canonical name of a line.
    pub fn line_name(line: usize) -> &'static str {
        if line < line_count() {
            arch::device_irq_name(line)
        } else {
            "none"
        }
    }

    fn check_line(line: usize) -> Result<(), IrqError> {
        if line < line_count() {
            Ok(())
        } else {
            Err(IrqError::NoLine)
        }
    }

    /// 设置（或以 `None` 清除）一条线的处理函数。
    /// Install or clear the handler of a line.
    pub fn set_handler(line: usize, handler: Option<DeviceHandler>) -> Result<(), IrqError> {
        check_line(line)?;
        HANDLERS[line].store(handler.map(|h| h as usize).unwrap_or(0), Ordering::Release);
        Ok(())
    }

    /// 设置亲和集合并立即路由：当前目标仍合法就不动，否则取集合中下标最小的在线处理器。
    /// 线号不存在、集合为空、集合中没有在线处理器、或中断控制器拒绝时返回错误，路由表与硬件都不变。
    /// 返回路由到的处理器。
    /// Set the affinity of a line and route it.
    pub fn set_affinity(line: usize, set: CpuSet) -> Result<usize, IrqError> {
        check_line(line)?;
        if set.is_empty() {
            return Err(IrqError::EmptySet);
        }
        let online = sched::online_cpus();
        let cands = set.intersect(online);
        let mut r = ROUTING.lock();
        let target = r.target[line].filter(|&c| cands.contains(c)).or_else(|| cands.iter().next()).ok_or(IrqError::Offline)?;
        if r.target[line] != Some(target) {
            arch::device_irq_route(line, target)?;
        }
        r.allowed[line] = set;
        r.target[line] = Some(target);
        Ok(target)
    }

    /// 当前路由到的处理器（尚未路由时为 `None`）。
    /// Processor the line is routed to.
    pub fn routed_to(line: usize) -> Option<usize> {
        if line >= MAX_LINES {
            return None;
        }
        ROUTING.lock().target[line]
    }

    /// 启用 / 停用一条线（启用前必须已路由）。停用时同时关闭设备的持续自触发。
    /// Enable or disable a routed line.
    pub fn set_enabled(line: usize, on: bool) -> Result<(), IrqError> {
        check_line(line)?;
        let mut r = ROUTING.lock();
        if on && r.target[line].is_none() {
            return Err(IrqError::Offline);
        }
        if on {
            r.enabled |= 1 << line;
        } else {
            r.enabled &= !(1 << line);
            let _ = arch::device_irq_self_trigger(line, false);
        }
        arch::device_irq_set_masked(line, !on);
        Ok(())
    }

    /// 已启用的线集合（位图）。
    /// Enabled lines, as a bit map.
    pub fn enabled_lines() -> u32 {
        ROUTING.lock().enabled
    }

    /// 打开 / 关闭设备的持续自触发（中断风暴演练用）；线必须已启用。
    /// Turn the device's continuous self-trigger on or off.
    pub fn set_self_trigger(line: usize, on: bool) -> Result<(), IrqError> {
        check_line(line)?;
        if on && ROUTING.lock().enabled & (1 << line) == 0 {
            return Err(IrqError::Offline);
        }
        arch::device_irq_self_trigger(line, on)
    }

    /// 更换全部处理器的预算参数；不合法时一个都不改。
    /// Replace the quota parameters of every processor.
    pub fn set_quota(params: QuotaParams) -> Result<(), IrqError> {
        let params = params.validate()?;
        for b in QUOTAS.iter() {
            b.lock().set_params(params)?;
        }
        Ok(())
    }

    /// 当前预算参数（取引导处理器的那份；各处理器始终一致）。
    /// Current quota parameters.
    pub fn quota() -> QuotaParams {
        QUOTAS[0].lock().params()
    }

    /// 设置（或以 `None` 关闭）自动均衡策略。
    /// Install or remove the automatic balancing policy.
    pub fn set_balancer(policy: Option<&'static (dyn AffinityPolicy + Sync)>) {
        ROUTING.lock().policy = policy;
    }

    /// 自动均衡累计搬动中断线的次数。
    /// Number of lines moved by automatic balancing.
    pub fn balance_moves() -> u32 {
        ROUTING.lock().moves
    }

    /// 一个处理器的设备中断统计。
    /// Device-interrupt statistics of one processor.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CpuIrqStats {
        /// 处理次数。
        pub handled: u64,
        /// 处理耗时（周期计数）。
        pub cycles: u64,
        /// 节流次数。
        pub throttles: u32,
        /// 测得的 tick 长度（周期计数）。
        pub tick_cycles: u64,
    }

    /// 处理器 `cpu` 的统计。
    /// Statistics of processor `cpu`.
    pub fn cpu_stats(cpu: usize) -> CpuIrqStats {
        match QUOTAS.get(cpu) {
            Some(b) => {
                let b = b.lock();
                let (handled, cycles, throttles) = b.stats();
                CpuIrqStats { handled, cycles, throttles, tick_cycles: b.tick_cycles() }
            }
            None => CpuIrqStats::default(),
        }
    }

    /// 线 `line` 在处理器 `cpu` 上被处理的次数。
    /// Times `line` was handled on `cpu`.
    pub fn count_on(line: usize, cpu: usize) -> u32 {
        match (COUNTS.get(line), cpu < MAX_CPUS) {
            (Some(row), true) => row[cpu].load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// 线号超出范围的中断数。
    /// Interrupts reported for unknown lines.
    pub fn stray_count() -> u32 {
        STRAY.load(Ordering::Relaxed)
    }

    /// 清零全部统计。
    /// Reset all statistics.
    pub fn reset_stats() {
        for b in QUOTAS.iter() {
            b.lock().reset_stats();
        }
        for row in COUNTS.iter() {
            for c in row.iter() {
                c.store(0, Ordering::Relaxed);
            }
        }
        for w in WINDOW.iter() {
            w.store(0, Ordering::Relaxed);
        }
        ROUTING.lock().moves = 0;
    }

    /// 中断上下文：设备侧确认 → 计数 → 处理函数 → 记账；预算用完就屏蔽这条线。
    pub(super) fn dispatch(line: usize) {
        if line >= MAX_LINES {
            STRAY.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let t0 = arch::cycles();
        arch::device_irq_ack(line);
        let cpu = arch::cpu_index().min(MAX_CPUS - 1);
        COUNTS[line][cpu].fetch_add(1, Ordering::Relaxed);
        WINDOW[line].fetch_add(1, Ordering::Relaxed);
        let h = HANDLERS[line].load(Ordering::Acquire);
        if h != 0 {
            // SAFETY：非零值只来自 `set_handler` 写入的 `DeviceHandler` 函数指针。
            let f: DeviceHandler = unsafe { core::mem::transmute::<usize, DeviceHandler>(h) };
            f(line);
        }
        let cost = arch::cycles().wrapping_sub(t0);
        let verdict = QUOTAS[cpu].lock().charge(line, cost);
        if verdict == Charge::Exhausted {
            arch::device_irq_set_masked(line, true);
        }
    }

    /// 每个处理器的 tick（中断上下文）：补充本处理器的预算，解除被节流且仍启用的线的屏蔽。
    pub(super) fn on_cpu_tick() {
        let cpu = arch::cpu_index().min(MAX_CPUS - 1);
        let released = QUOTAS[cpu].lock().on_tick(arch::cycles());
        if released == 0 {
            return;
        }
        let enabled = ROUTING.lock().enabled;
        for line in 0..MAX_LINES {
            if released & enabled & (1 << line) != 0 {
                arch::device_irq_set_masked(line, false);
            }
        }
    }

    /// 本处理器是否还需要周期 tick 来补充设备中断预算（本 tick 处理过设备中断或有被节流的线）。
    /// 空闲停表前查询：是 ⇒ 保持周期 tick，否则风暴下的补充与解除屏蔽会被推迟到停表结束。
    /// Whether this CPU's device quota still needs the periodic tick.
    pub fn cpu_needs_tick() -> bool {
        let cpu = arch::cpu_index().min(MAX_CPUS - 1);
        QUOTAS[cpu].lock().needs_tick()
    }

    /// 引导处理器的 tick：每 [`BALANCE_PERIOD`] 个 tick 按窗口负载运行一次均衡策略。
    pub(super) fn on_balance_tick() {
        if sched::timer_ticks() % BALANCE_PERIOD == 0 {
            let _ = rebalance();
        }
    }

    /// 立即按窗口负载运行一次均衡策略（没有策略时什么都不做），返回搬动的线数。
    /// 策略拒绝（例如某线已无在线处理器）时路由不变并返回错误。
    /// Run the balancing policy once.
    pub fn rebalance() -> Result<u32, IrqError> {
        let n = line_count();
        let online = sched::online_cpus();
        let mut r = ROUTING.lock();
        let Some(policy) = r.policy else {
            return Ok(0);
        };
        let mut lines = [LineLoad { allowed: CpuSet::EMPTY, current: None, load: 0 }; MAX_LINES];
        let mut idx = [0usize; MAX_LINES];
        let mut k = 0;
        for line in 0..n {
            if r.enabled & (1 << line) != 0 {
                lines[k] = LineLoad { allowed: r.allowed[line], current: r.target[line], load: WINDOW[line].swap(0, Ordering::Relaxed) };
                idx[k] = line;
                k += 1;
            }
        }
        let mut out = [0usize; MAX_LINES];
        policy.assign(&lines[..k], online, &[0; MAX_CPUS], &mut out[..k])?;
        let mut moved = 0;
        for i in 0..k {
            let line = idx[i];
            if r.target[line] != Some(out[i]) && arch::device_irq_route(line, out[i]).is_ok() {
                r.target[line] = Some(out[i]);
                moved += 1;
            }
        }
        r.moves += moved;
        Ok(moved)
    }
}
