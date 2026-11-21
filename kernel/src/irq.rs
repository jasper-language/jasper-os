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
//!
//! MSI / MSI-X（[`on_msi`]）：按 `[处理器][向量]` 分发，并在**本处理器**的同一份预算上按向量槽位记账。
//! 超出 ⇒ 调用该槽位登记的屏蔽回调（[`MsiMaskOps`]，由绑定该向量的一方提供，例如屏蔽产生它的 MSI-X 表项），
//! 本处理器下一个 tick 调用解除屏蔽回调；设备在屏蔽期间只置挂起位，解除后重新送达，到达不丢。
//! Core 不知道消息表项在哪里：回调与上下文值由绑定方登记。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use alloc::vec::Vec;
use kernel_core::cpu_bitmap::CpuBitmap;
use kernel_core::cpu_storage::CpuTailLayout;
use kernel_core::irq::{
    plan_runtime_lines, AffinityPolicy, Charge, CoreQuota, IrqError, Keep, LineLoad, QuotaParams,
};
use kernel_core::msi::MsiError;
use kernel_core::smp::{CpuSet, MAX_CPUS};
use spin::{Mutex, Once};

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

static PENDING: Mutex<PendingQueue> = Mutex::new(PendingQueue {
    buf: [None; QUEUE_LEN],
    head: 0,
    tail: 0,
    dropped: 0,
});

/// 中断上下文入口：由 arch 中断处理程序在 **EOI 之后**调用。
///
/// 先入队再通知调度器：调度器可能在这里切走当前任务，入队必须在那之前完成。
///
/// `from_user`：中断是否打断了用户态代码。是 ⇒ 这里也是一个调度点：所属进程已在 exiting 时，
/// 被打断的线程就地停止（与用户态故障一样，从中断上下文经线程退出路径结束，不再返回用户态）。
pub fn on_hardware_irq(line: IrqLine, from_user: bool) {
    match line {
        IrqLine::Timer => {
            let entry = crate::arch::clock_counter();
            if let Some(now) = crate::hrtime::now() {
                crate::user_timer::wake_due(now);
                #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
                crate::linux_abi::settle_posix_timers(now);
            }
            crate::smp::on_local_tick();
            device::on_cpu_tick();
            device::on_balance_tick();
            enqueue(line);
            // 时钟永远前进；调度事务要给被打断的代码留出前进的时间。
            // 推迟时也不做下面的退出检查（它本身就是一次调度事务），留给下一次完整事务。
            if !sched::timer_admit(entry) {
                sched::defer_timer_tick();
                return;
            }
            crate::mm::pressure::sync_events();
            sched::on_timer_interrupt(entry);
        }
        // 每核事件只更新本处理器的每核数据，不进全局延迟队列（那是引导处理器主循环的队列）
        IrqLine::LocalTimer => {
            #[cfg(feature = "rt2-verify")]
            let diagnostic = crate::rt2_demo::timer_irq();
            #[cfg(not(feature = "rt2-verify"))]
            let diagnostic = false;
            if !diagnostic && crate::hrtime::enabled() {
                let entry = crate::arch::clock_counter();
                #[cfg(feature = "krn2-observe")]
                let interrupt_entry = Some(sched::wake_endpoint());
                #[cfg(not(feature = "krn2-observe"))]
                let interrupt_entry = None;
                if !sched::timer_admit(entry) {
                    sched::rearm_after_defer(entry);
                    return;
                }
                settle_user_timers();
                sched::on_highres_timer(entry, interrupt_entry);
            } else if !diagnostic {
                let entry = crate::arch::clock_counter();
                crate::smp::on_local_tick();
                device::on_cpu_tick();
                if !sched::timer_admit(entry) {
                    sched::defer_local_tick();
                    return;
                }
                settle_user_timers();
                sched::on_local_timer(entry);
            } else {
                settle_user_timers();
            }
        }
        IrqLine::Ipi(kind) => crate::smp::on_ipi(kind),
    }
    if from_user && crate::proc::current_exiting() {
        crate::proc::thread_exit(0, "killed");
    }
}

/// Settle userspace deadlines only as part of an admitted timer transaction.
/// 仅在获准的完整定时器事务中结算用户态截止期。
fn settle_user_timers() {
    if let Some(now) = crate::hrtime::now() {
        crate::user_timer::wake_due(now);
        #[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
        crate::linux_abi::settle_posix_timers(now);
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

struct MsiCpuState {
    handlers: [AtomicUsize; MSI_SLOTS],
    counts: [AtomicU32; MSI_SLOTS],
    spurious: AtomicU32,
    detached: AtomicBool,
    detached_arrivals: AtomicU32,
    mask_ops: [AtomicUsize; MSI_SLOTS],
    mask_ctx: [AtomicUsize; MSI_SLOTS],
}

impl MsiCpuState {
    const fn new() -> Self {
        Self {
            handlers: [const { AtomicUsize::new(0) }; MSI_SLOTS],
            counts: [const { AtomicU32::new(0) }; MSI_SLOTS],
            spurious: AtomicU32::new(0),
            detached: AtomicBool::new(false),
            detached_arrivals: AtomicU32::new(0),
            mask_ops: [const { AtomicUsize::new(0) }; MSI_SLOTS],
            mask_ctx: [const { AtomicUsize::new(0) }; MSI_SLOTS],
        }
    }
}

static BOOTSTRAP_MSI_CPUS: [MsiCpuState; MAX_CPUS] =
    [const { MsiCpuState::new() }; MAX_CPUS];
static EXTRA_MSI_CPUS: Once<Result<Vec<MsiCpuState>, MsiStorageError>> = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsiStorageError {
    Allocation,
    AlreadyPreparedTooSmall,
}

impl MsiStorageError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allocation => "system.interrupt.error.msi_storage_allocation",
            Self::AlreadyPreparedTooSmall => "system.interrupt.error.msi_storage_capacity",
        }
    }
}

fn msi_cpu_state(cpu: usize) -> Option<&'static MsiCpuState> {
    let layout = CpuTailLayout::new(MAX_CPUS, crate::smp::cpu_count());
    if cpu >= layout.admitted() {
        return None;
    }
    if !layout.is_tail(cpu) {
        return BOOTSTRAP_MSI_CPUS.get(cpu);
    }
    let extra = layout.tail_index(cpu)?;
    EXTRA_MSI_CPUS.get()?.as_ref().ok()?.get(extra)
}

fn bootstrap_msi_states() -> impl Iterator<Item = &'static MsiCpuState> {
    let layout = CpuTailLayout::new(MAX_CPUS, crate::smp::cpu_count());
    BOOTSTRAP_MSI_CPUS[..layout.bootstrap_len()].iter()
}

fn extra_msi_states(
    cpus: usize,
) -> Option<impl Iterator<Item = &'static MsiCpuState>> {
    let layout = CpuTailLayout::new(MAX_CPUS, cpus);
    let prepared = EXTRA_MSI_CPUS.get()?.as_ref().ok()?.as_slice();
    Some(
        prepared[..layout.tail_len().min(prepared.len())]
            .iter(),
    )
}

fn msi_prepared_count() -> usize {
    let layout = CpuTailLayout::new(MAX_CPUS, crate::smp::cpu_count());
    layout.bootstrap_len()
        + EXTRA_MSI_CPUS
            .get()
            .and_then(|states| states.as_ref().ok())
            .map_or(0, |states| states.len().min(layout.tail_len()))
}

/// Reserve MSI dispatch state before AP startup. Calling twice is idempotent.
pub fn prepare_msi_storage(cpus: usize) -> Result<(), MsiStorageError> {
    let layout = CpuTailLayout::new(MAX_CPUS, cpus);
    let needed = layout.tail_len();
    let states = EXTRA_MSI_CPUS.call_once(|| {
        let mut states = Vec::new();
        states
            .try_reserve_exact(needed)
            .map_err(|_| MsiStorageError::Allocation)?;
        for _ in layout.bootstrap_len()..cpus {
            states.push(MsiCpuState::new());
        }
        Ok(states)
    });
    match states {
        Ok(states) if states.len() >= needed => Ok(()),
        Ok(_) => Err(MsiStorageError::AlreadyPreparedTooSmall),
        Err(error) => Err(*error),
    }
}

/// MSI 槽位的屏蔽 / 解除屏蔽回调（中断上下文调用；参数为处理器、向量与登记时给出的上下文值）。
/// Mask callback of an MSI slot: `(cpu, vector, ctx)`.
pub type MsiMaskFn = fn(usize, u8, usize);

/// 一个 MSI 槽位的预算动作：超预算时屏蔽，下一个 tick 解除屏蔽。
/// Throttle actions of an MSI slot.
pub struct MsiMaskOps {
    /// 屏蔽产生该向量的消息源。
    pub mask: MsiMaskFn,
    /// 解除屏蔽（设备在屏蔽期间置挂起位的，解除后会重新送达）。
    pub unmask: MsiMaskFn,
}

/// 为处理器 `cpu` 上的 `vector` 登记（或以 `None` 清除）预算屏蔽动作。
///
/// 登记要求该向量已绑定处理函数（否则 [`MsiError::NotAllocated`]）；处理器或向量越界返回错误。失败时登记表不变。
/// 解绑处理函数之前必须先清除登记。
/// Register or clear the throttle actions of `vector` on `cpu`.
pub fn msi_set_mask_ops(
    cpu: usize,
    vector: u8,
    ops: Option<(&'static MsiMaskOps, usize)>,
) -> Result<(), MsiError> {
    let state = msi_cpu_state(cpu).ok_or(MsiError::NoSuchCpu)?;
    if vector as usize >= MSI_SLOTS {
        return Err(MsiError::OutOfRange);
    }
    let v = vector as usize;
    match ops {
        Some((ops, ctx)) => {
            if state.detached.load(Ordering::Acquire) {
                return Err(MsiError::NotOnline);
            }
            if state.handlers[v].load(Ordering::Acquire) == 0 {
                return Err(MsiError::NotAllocated);
            }
            // 先写上下文、再发布动作：读者先取动作（Acquire）再读上下文
            state.mask_ctx[v].store(ctx, Ordering::Relaxed);
            state.mask_ops[v].store(ops as *const MsiMaskOps as usize, Ordering::Release);
        }
        None => state.mask_ops[v].store(0, Ordering::Release),
    }
    Ok(())
}

/// 槽位登记的屏蔽动作与上下文值。
fn msi_mask_ops(cpu: usize, vector: usize) -> Option<(&'static MsiMaskOps, usize)> {
    let state = msi_cpu_state(cpu)?;
    let p = state.mask_ops.get(vector)?.load(Ordering::Acquire);
    if p == 0 {
        return None;
    }
    // SAFETY：非零值只来自 `msi_set_mask_ops` 写入的 `&'static MsiMaskOps` 地址。
    let ops = unsafe { &*(p as *const MsiMaskOps) };
    Some((ops, state.mask_ctx[vector].load(Ordering::Relaxed)))
}

/// 处理器 `cpu` 上的 `vector` 是否已绑定处理函数。
/// Whether `vector` on `cpu` has a handler.
pub fn msi_is_bound(cpu: usize, vector: u8) -> bool {
    msi_cpu_state(cpu).is_some_and(|state| {
        (vector as usize) < MSI_SLOTS && state.handlers[vector as usize].load(Ordering::Acquire) != 0
    })
}

/// 在处理器 `cpu` 上为 `vector` 安装（或以 `None` 清除）处理函数。
///
/// 调用者保证 `cpu` 在线；处理器下标或向量号越界时返回错误且登记表不变。
/// Install or clear the handler of `vector` on `cpu`.
pub fn msi_bind(cpu: usize, vector: u8, handler: Option<MsiHandler>) -> Result<(), MsiError> {
    let state = msi_cpu_state(cpu).ok_or(MsiError::NoSuchCpu)?;
    if vector as usize >= MSI_SLOTS {
        return Err(MsiError::OutOfRange);
    }
    if handler.is_some() && state.detached.load(Ordering::Acquire) {
        return Err(MsiError::NotOnline);
    }
    state.handlers[vector as usize].store(
        handler.map_or(0, |handler| handler as usize),
        Ordering::Release,
    );
    Ok(())
}

/// Stop all MSI dispatch on a departing processor and clear every vector binding.
///
/// The flag is published before handlers are removed, so a concurrent bind either
/// observes the departure and fails or completes before the clearing pass.
/// Late arrivals are counted separately and never invoke an old handler.
pub fn msi_quiesce_cpu(cpu: usize) -> Result<usize, MsiError> {
    let state = msi_cpu_state(cpu).ok_or(MsiError::NoSuchCpu)?;
    state.detached.store(true, Ordering::Release);
    let mut cleared = 0;
    for slot in 0..MSI_SLOTS {
        if state.handlers[slot].swap(0, Ordering::AcqRel) != 0 {
            cleared += 1;
        }
        state.mask_ctx[slot].store(0, Ordering::Relaxed);
        state.mask_ops[slot].store(0, Ordering::Release);
    }
    Ok(cleared)
}

/// Reopen MSI dispatch only after the CPU lifecycle has published a new online
/// generation. No vector binding from the previous generation is restored.
pub fn msi_resume_cpu(cpu: usize) -> Result<(), MsiError> {
    msi_cpu_state(cpu)
        .ok_or(MsiError::NoSuchCpu)?
        .detached
        .store(false, Ordering::Release);
    Ok(())
}

/// Arrivals rejected because a handler was racing with CPU MSI quiescence.
pub fn msi_detached_arrivals(cpu: usize) -> u32 {
    msi_cpu_state(cpu).map_or(0, |state| {
        state.detached_arrivals.load(Ordering::Relaxed)
    })
}

/// MSI 中断入口：由平台在中断上下文调用（EOI 之前）。
///
/// 只查**当前处理器**的登记表：绑定过就调用处理函数，未绑定就记一次伪 MSI。
/// 处理之后在本处理器的预算上按槽位记账；超出时调用该槽位登记的屏蔽动作。
/// 不调用设备中断线的任何旧处理函数，也不切换任务。
/// MSI entry point: dispatch on the current processor, then charge the per-CPU quota.
pub fn on_msi(vector: u8) {
    let cpu = arch::cpu_index();
    let Some(state) = msi_cpu_state(cpu) else {
        crate::kprintln!(
            "[JSR-SMP] reject=cpu_index_storage_missing index={} prepared={}",
            cpu,
            msi_prepared_count()
        );
        arch::halt_forever();
    };
    if state.detached.load(Ordering::Acquire) {
        state.detached_arrivals.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if vector as usize >= MSI_SLOTS {
        state.spurious.fetch_add(1, Ordering::Relaxed);
        return;
    }
    count_arrival(&state.counts[vector as usize]);
    let h = state.handlers[vector as usize].load(Ordering::Acquire);
    if h == 0 {
        state.spurious.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let t0 = arch::cycles();
    // SAFETY：非零值只来自 `msi_bind` 写入的 `MsiHandler` 函数指针。
    let handler: MsiHandler = unsafe { core::mem::transmute::<usize, MsiHandler>(h) };
    handler();
    device::charge_msi(cpu, vector, arch::cycles().wrapping_sub(t0));
    // Author: chatgpt。驱动与预算锁均已退出，再交付待处理对象通知；不切换任务。
    crate::interrupt::service_msi(cpu, vector);
}

/// 记一次到达：计数器按模 2³² 回绕递增（读者用模差求增量）。启动自检经同一函数验证回绕。
/// Count one arrival on a wrapping counter; shared with the boot-time wrap self-check.
pub(crate) fn count_arrival(c: &AtomicU32) {
    c.fetch_add(1, Ordering::Release);
}

/// 处理器 `cpu` 在 `vector` 上收到的 MSI 次数。
/// MSI arrivals of `vector` on `cpu`.
pub fn msi_count(cpu: usize, vector: u8) -> u32 {
    msi_cpu_state(cpu)
        .and_then(|state| state.counts.get(vector as usize))
        .map_or(0, |count| count.load(Ordering::Acquire))
}

/// 处理器 `cpu` 上的伪 MSI 次数（未绑定处理函数的向量）。
/// Spurious MSI count of `cpu`.
pub fn msi_spurious(cpu: usize) -> u32 {
    msi_cpu_state(cpu).map_or(0, |state| state.spurious.load(Ordering::Relaxed))
}

/// 清零伪 MSI 计数，以及**没有登记处理函数**的槽位的 MSI 计数。
///
/// 已绑定槽位的计数保持单调：中断对象与演练按「上次读数 → 本次读数」的模差求新到达数，
/// 计数一旦被清零，差值就会把不存在的到达算进去（或把真实到达丢掉）。
/// Reset spurious counts and the counts of unbound slots; bound slots stay monotonic for their readers.
pub fn reset_msi_stats() {
    let reset = |state: &MsiCpuState| {
        for (h, count) in state.handlers.iter().zip(state.counts.iter()) {
            if h.load(Ordering::Acquire) == 0 {
                count.store(0, Ordering::Relaxed);
            }
        }
        state.spurious.store(0, Ordering::Relaxed);
    };
    for state in bootstrap_msi_states() {
        reset(state);
    }
    if let Some(states) = extra_msi_states(crate::smp::cpu_count()) {
        for state in states {
            reset(state);
        }
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
        allowed: Vec<CpuBitmap>,
        target: Vec<Option<usize>>,
        enabled: Vec<bool>,
        policy: Option<&'static (dyn AffinityPolicy + Sync)>,
        moves: u32,
        initialized: bool,
    }

    impl Routing {
        const fn new() -> Self {
            Self {
                allowed: Vec::new(),
                target: Vec::new(),
                enabled: Vec::new(),
                policy: None,
                moves: 0,
                initialized: false,
            }
        }

        fn initialize(
            &mut self,
            allowed: Vec<CpuBitmap>,
            target: Vec<Option<usize>>,
            enabled: Vec<bool>,
        ) -> bool {
            if self.initialized {
                return self.allowed.len() == allowed.len()
                    && self.target.len() == allowed.len()
                    && self.enabled.len() == allowed.len();
            }
            self.allowed = allowed;
            self.target = target;
            self.enabled = enabled;
            self.initialized = true;
            true
        }
    }

    static ROUTING: IrqSpinLock<Routing> =
        IrqSpinLock::ranked(lockorder::IRQ_ROUTING, Routing::new());
    /// Highest represented CPU bit in any admitted IRQ affinity. Affinity
    /// copies reserve this capacity before taking the routing lock.
    static ROUTING_CPU_BITS: AtomicUsize = AtomicUsize::new(0);

    /// 每核预算（只由所属处理器在中断里改写；参数与统计可由其他处理器读写）。
    static QUOTAS: [IrqSpinLock<CoreQuota>; MAX_CPUS] =
        [const { IrqSpinLock::ranked(lockorder::IRQ_QUOTA, CoreQuota::new(QuotaParams::DEFAULT)) };
            MAX_CPUS];
    static EXTRA_QUOTAS: Once<Result<Vec<IrqSpinLock<CoreQuota>>, DeviceCpuStorageError>> =
        Once::new();

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DeviceCpuStorageError {
        Allocation,
        AlreadyPreparedTooSmall,
        QuotaConfiguration,
    }

    impl DeviceCpuStorageError {
        pub const fn name(self) -> &'static str {
            match self {
                Self::Allocation => "system.interrupt.error.device_cpu_storage_allocation",
                Self::AlreadyPreparedTooSmall => {
                    "system.interrupt.error.device_cpu_storage_capacity"
                }
                Self::QuotaConfiguration => {
                    "system.interrupt.error.device_cpu_quota_configuration"
                }
            }
        }
    }

    fn quota_slot(cpu: usize) -> Option<&'static IrqSpinLock<CoreQuota>> {
        let layout = CpuTailLayout::new(MAX_CPUS, crate::smp::cpu_count());
        if cpu >= layout.admitted() {
            return None;
        }
        if !layout.is_tail(cpu) {
            let Some(quota) = QUOTAS.get(cpu) else {
                return None;
            };
            return Some(quota);
        }
        let extra = layout.tail_index(cpu)?;
        EXTRA_QUOTAS.get()?.as_ref().ok()?.get(extra)
    }

    struct LineStorage {
        /// 函数指针按地址存放；0 = 只做设备侧确认与计数。
        handlers: Vec<AtomicUsize>,
        /// 每条线在每个处理器上被处理的次数。
        counts: Vec<Vec<AtomicU32>>,
        /// 每条线本均衡窗口的处理次数（均衡后清零）。
        window: Vec<IrqU64>,
    }

    static LINES: Once<Option<LineStorage>> = Once::new();
    static EXTRA_LINE_COUNTS: Once<Result<Vec<Vec<AtomicU32>>, DeviceCpuStorageError>> =
        Once::new();
    /// 未知线号的中断数（平台报告了超出范围的线）。
    static STRAY: AtomicU32 = AtomicU32::new(0);
    /// Topology admission is immutable after the first successful reservation.
    static TOPOLOGY: Once<LineTopology> = Once::new();

    /// Complete platform-to-routing-table admission facts.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LineTopology {
        pub discovered: usize,
        pub admitted: usize,
        pub rejected: usize,
        pub capacity: usize,
    }

    fn line_cost(cpus: usize) -> usize {
        core::mem::size_of::<CpuBitmap>()
            + core::mem::size_of::<Option<usize>>()
            + core::mem::size_of::<bool>()
            + core::mem::size_of::<AtomicUsize>()
            + core::mem::size_of::<IrqU64>()
            + core::mem::size_of::<Vec<AtomicU32>>()
            + cpus.saturating_mul(core::mem::size_of::<AtomicU32>())
    }

    /// Reserve device-IRQ per-CPU counts and quotas before AP startup.
    pub fn prepare_cpu_storage(cpus: usize) -> Result<(), DeviceCpuStorageError> {
        let layout = CpuTailLayout::new(MAX_CPUS, cpus);
        let needed = layout.tail_len();
        let lines = line_count();
        let counts = EXTRA_LINE_COUNTS.call_once(|| {
            let mut rows = Vec::new();
            rows.try_reserve_exact(needed)
                .map_err(|_| DeviceCpuStorageError::Allocation)?;
            for _ in layout.bootstrap_len()..cpus {
                let mut row = Vec::new();
                row.try_reserve_exact(lines)
                    .map_err(|_| DeviceCpuStorageError::Allocation)?;
                row.resize_with(lines, || AtomicU32::new(0));
                rows.push(row);
            }
            Ok(rows)
        });
        match counts {
            Ok(rows) if rows.len() >= needed => {}
            Ok(_) => return Err(DeviceCpuStorageError::AlreadyPreparedTooSmall),
            Err(error) => return Err(*error),
        }

        let quotas = EXTRA_QUOTAS.call_once(|| {
            let mut quotas = Vec::new();
            quotas
                .try_reserve_exact(needed)
                .map_err(|_| DeviceCpuStorageError::Allocation)?;
            for _ in layout.bootstrap_len()..cpus {
                quotas.push(IrqSpinLock::ranked(
                    lockorder::IRQ_QUOTA,
                    CoreQuota::new(QuotaParams::DEFAULT),
                ));
            }
            Ok(quotas)
        });
        match quotas {
            Ok(quotas) if quotas.len() >= needed => {
                for quota in quotas {
                    quota
                        .lock()
                        .configure_lines(lines)
                        .map_err(|_| DeviceCpuStorageError::QuotaConfiguration)?;
                }
                Ok(())
            }
            Ok(_) => Err(DeviceCpuStorageError::AlreadyPreparedTooSmall),
            Err(error) => Err(*error),
        }
    }

    fn line_count_slot<'a>(
        storage: &'a LineStorage,
        line: usize,
        cpu: usize,
    ) -> Option<&'a AtomicU32> {
        let layout = CpuTailLayout::new(MAX_CPUS, crate::smp::cpu_count());
        if cpu >= layout.admitted() {
            return None;
        }
        if !layout.is_tail(cpu) {
            let row = storage.counts.get(line)?;
            if let Some(count) = row.get(cpu) {
                return Some(count);
            }
            return None;
        }
        let extra_cpu = layout.tail_index(cpu)?;
        EXTRA_LINE_COUNTS
            .get()?
            .as_ref()
            .ok()?
            .get(extra_cpu)?
            .get(line)
    }

    fn reserve_lines(lines: usize) -> bool {
        // Prepare every allocation before acquiring the routing lock. Heap
        // allocation has a lower lock rank than IRQ routing and must never
        // occur while this guard is held.
        // 先完成全部堆分配，再取路由锁；堆锁级别低于 IRQ 路由，持锁分配会
        // 触发真实的锁序失败。
        let mut allowed = Vec::new();
        let mut target = Vec::new();
        let mut enabled = Vec::new();
        if allowed.try_reserve_exact(lines).is_err()
            || target.try_reserve_exact(lines).is_err()
            || enabled.try_reserve_exact(lines).is_err()
        {
            return false;
        }
        allowed.resize_with(lines, CpuBitmap::empty);
        target.resize(lines, None);
        enabled.resize(lines, false);
        let initialized = {
            let mut routing = ROUTING.lock();
            routing.initialize(allowed, target, enabled)
        };
        if !initialized {
            return false;
        }
        let storage = LINES.call_once(|| {
            let mut handlers = Vec::new();
            let mut counts = Vec::new();
            let mut window = Vec::new();
            if handlers.try_reserve_exact(lines).is_err()
                || counts.try_reserve_exact(lines).is_err()
                || window.try_reserve_exact(lines).is_err()
            {
                return None;
            }
            for _ in 0..lines {
                handlers.push(AtomicUsize::new(0));
                let mut row = Vec::new();
                if row.try_reserve_exact(MAX_CPUS).is_err() {
                    return None;
                }
                for _ in 0..MAX_CPUS {
                    row.push(AtomicU32::new(0));
                }
                counts.push(row);
                window.push(IrqU64::new(0));
            }
            Some(LineStorage {
                handlers,
                counts,
                window,
            })
        });
        if storage.is_none() {
            return false;
        }
        for quota in QUOTAS.iter() {
            let words = lines.saturating_add(63) / 64;
            let mut throttled = Vec::new();
            let mut released = Vec::new();
            if throttled.try_reserve_exact(words).is_err()
                || released.try_reserve_exact(lines).is_err()
            {
                return false;
            }
            throttled.resize(words, 0);
            if quota
                .lock()
                .adopt_lines(throttled, released)
                .is_err()
            {
                return false;
            }
        }
        true
    }

    /// Admit the complete firmware inventory into heap-backed routing storage.
    pub fn admit_topology(source: &'static str) -> LineTopology {
        *TOPOLOGY.call_once(|| {
            let discovered = arch::device_irq_count();
            let cost = line_cost(crate::smp::cpu_count()).max(1);
            let metadata_budget = match usize::try_from(crate::mm::heap::limit() / 1024) {
                Ok(budget) => budget,
                Err(_) => 0,
            };
            let admitted = match plan_runtime_lines(discovered, metadata_budget, cost) {
                Some(admitted) => admitted,
                None => 0,
            };
            let topology = LineTopology {
                discovered,
                admitted,
                rejected: discovered - admitted,
                capacity: admitted,
            };
            crate::kprintln!(
                "[JSR-IRQ] topology source={} discovered={} admitted={} rejected={} capacity={} budget={} dynamic=true complete={}",
                source,
                topology.discovered,
                topology.admitted,
                topology.rejected,
                topology.capacity,
                metadata_budget,
                topology.rejected == 0
            );
            if topology.rejected != 0 || !reserve_lines(topology.admitted) {
                crate::kprintln!(
                    "[JSR-IRQ] reject=runtime_line_storage discovered={} admitted={} rejected={} capacity={} budget={}",
                    topology.discovered,
                    topology.admitted,
                    topology.rejected,
                    topology.capacity,
                    metadata_budget
                );
                arch::halt_forever();
            }
            topology
        })
    }

    /// Number of admitted device lines in runtime storage.
    pub fn line_count() -> usize {
        if let Some(topology) = TOPOLOGY.get() {
            return topology.admitted;
        }
        // Discovery-only callers may run before the heap exists, for example
        // while the terminal/display runtime is being initialized. Report the
        // platform inventory without permanently admitting a zero-byte table;
        // the SMP-ready stage performs the real admission after the heap is
        // available.
        //
        // 终端的早期发现可能在堆初始化前查询线数。这里只报告平台库存，
        // 不把“尚未有堆”永久写入准入结果；SMP-ready 阶段再做真实准入。
        arch::device_irq_count()
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
        let storage = LINES
            .get()
            .and_then(Option::as_ref)
            .ok_or(IrqError::NoLine)?;
        let raw = match handler {
            Some(handler) => handler as usize,
            None => 0,
        };
        storage.handlers[line].store(raw, Ordering::Release);
        Ok(())
    }

    /// 设置亲和集合并立即路由：当前目标仍合法就不动，否则取集合中下标最小的在线处理器。
    /// 线号不存在、集合为空、集合中没有在线处理器、或中断控制器拒绝时返回错误，路由表与硬件都不变。
    /// 返回路由到的处理器。
    /// Set the affinity of a line and route it.
    pub fn set_affinity(line: usize, set: CpuSet) -> Result<usize, IrqError> {
        let allowed = CpuBitmap::from_cpu_set(set).map_err(|_| IrqError::NoMemory)?;
        set_affinity_dynamic(line, allowed)
    }

    /// Set a line affinity from the scalable native CPU membership type.
    ///
    /// The legacy `CpuSet` entry point above is an adapter until the system
    /// affinity ABI is versioned. Both paths use the same dynamic routing
    /// authority and hardware transaction.
    pub fn set_affinity_dynamic(
        line: usize,
        allowed: CpuBitmap,
    ) -> Result<usize, IrqError> {
        check_line(line)?;
        if allowed.is_empty() {
            return Err(IrqError::EmptySet);
        }
        let online = CpuBitmap::from_cpu_set(sched::online_cpus())
            .map_err(|_| IrqError::NoMemory)?;
        let cpu_bits = allowed.capacity_bits().map_err(|_| IrqError::NoLine)?;
        let (target, reroute) = {
            let r = ROUTING.lock();
            let target = r.target[line]
                .filter(|&c| allowed.contains(c) && online.contains(c))
                .or_else(|| {
                    allowed
                        .iter()
                        .find(|&c| online.contains(c))
                })
                .ok_or(IrqError::Offline)?;
            (target, r.target[line] != Some(target))
        };
        if reroute {
            arch::device_irq_route(line, target)?;
        }
        let replaced = {
            let mut r = ROUTING.lock();
            let replaced = core::mem::replace(&mut r.allowed[line], allowed);
            r.target[line] = Some(target);
            replaced
        };
        // The previous bitmap may own heap words. Release it only after the
        // IRQ-routing guard is gone so heap lock order remains routing -> heap
        // only outside the protected routing transaction.
        drop(replaced);
        ROUTING_CPU_BITS.fetch_max(cpu_bits, Ordering::Relaxed);
        Ok(target)
    }

    /// Remove one departing processor from every active device-IRQ route.
    ///
    /// The complete route plan is computed before any hardware mutation. A
    /// line with no remaining online affinity rejects the handoff without
    /// changing routes. Affected lines are masked while moved, and remain
    /// masked on a hardware routing failure rather than risking delivery to
    /// the departing processor.
    pub fn detach_cpu_lines(cpu: usize) -> Result<usize, IrqError> {
        let mut online_set = sched::online_cpus();
        if !online_set.contains(cpu) {
            return Err(IrqError::Offline);
        }
        online_set.remove(cpu);
        if online_set.is_empty() {
            return Err(IrqError::Offline);
        }
        let online = CpuBitmap::from_cpu_set(online_set)
            .map_err(|_| IrqError::NoMemory)?;
        let cpu_bits = ROUTING_CPU_BITS
            .load(Ordering::Relaxed)
            .max(online.capacity_bits().map_err(|_| IrqError::NoLine)?);
        let n = line_count();
        let mut lines = Vec::new();
        let mut indices = Vec::new();
        lines.try_reserve_exact(n).map_err(|_| IrqError::NoLine)?;
        indices
            .try_reserve_exact(n)
            .map_err(|_| IrqError::NoLine)?;
        for _ in 0..n {
            let allowed = CpuBitmap::with_capacity(cpu_bits)
                .map_err(|_| IrqError::NoMemory)?;
            lines.push(LineLoad {
                allowed,
                current: None,
                load: 0,
            });
        }
        {
            let routing = ROUTING.lock();
            let mut used = 0;
            for line in 0..n {
                if routing.enabled[line] {
                    lines[used]
                        .allowed
                        .copy_from(&routing.allowed[line])
                        .map_err(|_| IrqError::NoMemory)?;
                    lines[used].current = routing.target[line];
                    indices.push(line);
                    used += 1;
                }
            }
            lines.truncate(used);
        }
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(lines.len())
            .map_err(|_| IrqError::NoLine)?;
        targets.resize(lines.len(), 0);
        let mut base = Vec::new();
        base.try_reserve_exact(cpu_bits)
            .map_err(|_| IrqError::NoMemory)?;
        base.resize(cpu_bits, 0);
        Keep.assign(&lines, &online, &base, &mut targets)?;

        let mut rerouted = 0;
        let mut affected = Vec::new();
        affected
            .try_reserve_exact(indices.len())
            .map_err(|_| IrqError::NoLine)?;
        for (index, line) in indices.iter().copied().enumerate() {
            if lines[index].current != Some(targets[index]) {
                affected.push((line, targets[index]));
            }
        }
        for &(line, _) in affected.iter() {
            arch::device_irq_set_masked(line, true);
        }
        for &(line, target) in affected.iter() {
            arch::device_irq_route(line, target)?;
            ROUTING.lock().target[line] = Some(target);
            arch::device_irq_set_masked(line, false);
            rerouted += 1;
        }
        Ok(rerouted)
    }

    /// Demote the line-IRQ quota of a processor after route handoff and
    /// quiescence. MSI ownership and in-flight device work remain the caller's
    /// responsibility and must be drained before this call.
    pub fn demote_cpu_quota(cpu: usize) -> Result<(), IrqError> {
        let still_routed = {
            let routing = ROUTING.lock();
            routing
                .enabled
                .iter()
                .enumerate()
                .any(|(line, enabled)| *enabled && routing.target[line] == Some(cpu))
        };
        if still_routed {
            return Err(IrqError::Offline);
        }
        quota_slot(cpu)
            .ok_or(IrqError::Offline)?
            .lock()
            .demote();
        Ok(())
    }

    /// 当前路由到的处理器（尚未路由时为 `None`）。
    /// Processor the line is routed to.
    pub fn routed_to(line: usize) -> Option<usize> {
        if line >= line_count() {
            return None;
        }
        ROUTING.lock().target[line]
    }

    /// 启用 / 停用一条线（启用前必须已路由）。停用时同时关闭设备的持续自触发。
    /// Enable or disable a routed line.
    pub fn set_enabled(line: usize, on: bool) -> Result<(), IrqError> {
        check_line(line)?;
        {
            let mut r = ROUTING.lock();
            if on && r.target[line].is_none() {
                return Err(IrqError::Offline);
            }
            r.enabled[line] = on;
        }
        if !on {
            let _ = arch::device_irq_self_trigger(line, false);
        }
        arch::device_irq_set_masked(line, !on);
        Ok(())
    }

    /// 已启用的线集合（位图）。
    /// Enabled lines, as a bit map.
    pub fn enabled_lines() -> Vec<usize> {
        let n = line_count();
        let mut out = Vec::new();
        if out.try_reserve_exact(n).is_err() {
            return out;
        }
        let routing = ROUTING.lock();
        for (line, enabled) in routing.enabled.iter().enumerate() {
            if *enabled {
                out.push(line);
            }
        }
        out
    }

    /// 打开 / 关闭设备的持续自触发（中断风暴演练用）；线必须已启用。
    /// Turn the device's continuous self-trigger on or off.
    pub fn set_self_trigger(line: usize, on: bool) -> Result<(), IrqError> {
        check_line(line)?;
        if on {
            let enabled = ROUTING.lock().enabled[line];
            if !enabled {
                return Err(IrqError::Offline);
            }
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
        if let Some(quotas) = EXTRA_QUOTAS.get().and_then(|quotas| quotas.as_ref().ok()) {
            for quota in quotas {
                quota.lock().set_params(params)?;
            }
        }
        Ok(())
    }

    /// 处理器 `cpu` 的预算参数（越界为 `None`）。
    /// Quota parameters of processor `cpu`.
    pub fn quota_on(cpu: usize) -> Option<QuotaParams> {
        quota_slot(cpu).map(|b| b.lock().params())
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
        /// 节流次数（中断线）。
        pub throttles: u32,
        /// 节流次数（MSI 槽位）。
        pub msi_throttles: u32,
        /// 测得的 tick 长度（周期计数）。
        pub tick_cycles: u64,
    }

    /// 处理器 `cpu` 的统计。
    /// Statistics of processor `cpu`.
    pub fn cpu_stats(cpu: usize) -> CpuIrqStats {
        match quota_slot(cpu) {
            Some(b) => {
                let b = b.lock();
                let (handled, cycles, throttles) = b.stats();
                CpuIrqStats {
                    handled,
                    cycles,
                    throttles,
                    msi_throttles: b.msi_throttles(),
                    tick_cycles: b.tick_cycles(),
                }
            }
            None => CpuIrqStats::default(),
        }
    }

    /// 线 `line` 在处理器 `cpu` 上被处理的次数。
    /// Times `line` was handled on `cpu`.
    pub fn count_on(line: usize, cpu: usize) -> u32 {
        LINES
            .get()
            .and_then(Option::as_ref)
            .and_then(|storage| line_count_slot(storage, line, cpu))
            .map_or(0, |count| count.load(Ordering::Relaxed))
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
        if let Some(quotas) = EXTRA_QUOTAS.get().and_then(|quotas| quotas.as_ref().ok()) {
            for quota in quotas {
                quota.lock().reset_stats();
            }
        }
        if let Some(storage) = LINES.get().and_then(Option::as_ref) {
            for row in storage.counts.iter() {
                for count in row.iter() {
                    count.store(0, Ordering::Relaxed);
                }
            }
            for window in storage.window.iter() {
                window.store(0, Ordering::Relaxed);
            }
            if let Some(rows) = EXTRA_LINE_COUNTS
                .get()
                .and_then(|rows| rows.as_ref().ok())
            {
                for row in rows {
                    for count in row {
                        count.store(0, Ordering::Relaxed);
                    }
                }
            }
        }
        ROUTING.lock().moves = 0;
    }

    /// 中断上下文：设备侧确认 → 计数 → 处理函数 → 记账；预算用完就屏蔽这条线。
    pub(super) fn dispatch(line: usize) {
        let Some(storage) = LINES.get().and_then(Option::as_ref) else {
            STRAY.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if line >= storage.handlers.len() || line >= line_count() {
            STRAY.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let t0 = arch::cycles();
        arch::device_irq_ack(line);
        let cpu = arch::cpu_index();
        let Some(count) = line_count_slot(storage, line, cpu) else {
            crate::kprintln!(
                "[JSR-IRQ] reject=cpu_index_storage_missing line={} index={} prepared={}",
                line,
                cpu,
                {
                    let layout = CpuTailLayout::new(MAX_CPUS, crate::smp::cpu_count());
                    layout.bootstrap_len()
                        + EXTRA_LINE_COUNTS
                            .get()
                            .and_then(|rows| rows.as_ref().ok())
                            .map_or(0, |rows| rows.len().min(layout.tail_len()))
                }
            );
            arch::halt_forever();
        };
        count.fetch_add(1, Ordering::Relaxed);
        storage.window[line].fetch_add(1, Ordering::Relaxed);
        let h = storage.handlers[line].load(Ordering::Acquire);
        if h != 0 {
            // SAFETY：非零值只来自 `set_handler` 写入的 `DeviceHandler` 函数指针。
            let f: DeviceHandler = unsafe { core::mem::transmute::<usize, DeviceHandler>(h) };
            f(line);
        }
        let cost = arch::cycles().wrapping_sub(t0);
        let Some(quota) = quota_slot(cpu) else {
            arch::halt_forever();
        };
        let verdict = quota.lock().charge(line, cost);
        if verdict == Charge::Exhausted {
            arch::device_irq_set_masked(line, true);
        }
    }

    /// MSI 记账（中断上下文，处理函数之后）：超出预算 ⇒ 调用该槽位登记的屏蔽动作（未登记则只记账）。
    /// 预算锁在调用屏蔽动作之前释放：动作可以取级别更低的锁。
    pub(super) fn charge_msi(cpu: usize, vector: u8, cycles: u64) {
        let Some(quota) = quota_slot(cpu) else {
            arch::halt_forever();
        };
        let verdict = quota.lock().charge_msi(vector as usize, cycles);
        if verdict == Ok(Charge::Exhausted) {
            if let Some((ops, ctx)) = msi_mask_ops(cpu, vector as usize) {
                (ops.mask)(cpu, vector, ctx);
            }
        }
    }

    /// 每个处理器的 tick（中断上下文）：补充本处理器的预算，解除被节流且仍启用的线的屏蔽，
    /// 并对被节流的 MSI 槽位调用其解除屏蔽动作（槽位已解除登记的跳过）。
    pub(super) fn on_cpu_tick() {
        let cpu = arch::cpu_index();
        let Some(quota) = quota_slot(cpu) else {
            arch::halt_forever();
        };
        let (released, released_count) = {
            let mut quota = quota.lock();
            let released = quota.on_tick(arch::cycles());
            (released, quota.released_lines().len())
        };
        if released.line_overflow {
            crate::kprintln!(
                "[JSR-IRQ] reject=released_line_capacity cpu={} capacity={}",
                cpu,
                line_count()
            );
            arch::halt_forever();
        }
        for slot in released.msi.iter() {
            if let Some((ops, ctx)) = msi_mask_ops(cpu, slot) {
                (ops.unmask)(cpu, slot as u8, ctx);
            }
        }
        for index in 0..released_count {
            let Some(line) = quota
                .lock()
                .released_lines()
                .get(index)
                .copied()
            else {
                arch::halt_forever();
            };
            // JASPER-HARDCODE-REVIEW: issue=33 source=released-request-runtime-state reason=line-missing-from-current-table-is-not-enabled
            let enabled = ROUTING.lock().enabled.get(line).copied() == Some(true);
            if enabled {
                arch::device_irq_set_masked(line, false);
            }
        }
        quota.lock().clear_released_lines();
    }

    /// 本处理器是否还需要周期 tick 来补充设备中断预算（本 tick 处理过设备中断或有被节流的线）。
    /// 空闲停表前查询：是 ⇒ 保持周期 tick，否则风暴下的补充与解除屏蔽会被推迟到停表结束。
    /// Whether this CPU's device quota still needs the periodic tick.
    pub fn cpu_needs_tick() -> bool {
        let cpu = arch::cpu_index();
        quota_slot(cpu)
            .is_some_and(|quota| quota.lock().needs_tick())
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
        let online = CpuBitmap::from_cpu_set(sched::online_cpus())
            .map_err(|_| IrqError::NoMemory)?;
        let cpu_bits = ROUTING_CPU_BITS
            .load(Ordering::Relaxed)
            .max(online.capacity_bits().map_err(|_| IrqError::NoLine)?);
        let policy = ROUTING.lock().policy;
        let Some(policy) = policy else {
            return Ok(0);
        };
        // Allocate before taking the routing lock: heap allocation is a lower
        // rank and must not occur while IRQ routing is held.
        let mut lines = Vec::new();
        let mut idx = Vec::new();
        lines.try_reserve_exact(n).map_err(|_| IrqError::NoLine)?;
        idx.try_reserve_exact(n).map_err(|_| IrqError::NoLine)?;
        for _ in 0..n {
            lines.push(LineLoad {
                allowed: CpuBitmap::with_capacity(cpu_bits)
                    .map_err(|_| IrqError::NoMemory)?,
                current: None,
                load: 0,
            });
        }
        let mut out = Vec::new();
        out.try_reserve_exact(n).map_err(|_| IrqError::NoLine)?;
        out.resize(n, 0);
        let mut base = Vec::new();
        base.try_reserve_exact(cpu_bits)
            .map_err(|_| IrqError::NoMemory)?;
        base.resize(cpu_bits, 0);
        {
            let r = ROUTING.lock();
            let mut used = 0;
            for line in 0..n {
                if r.enabled[line] {
                    let storage = LINES
                        .get()
                        .and_then(Option::as_ref)
                        .ok_or(IrqError::NoLine)?;
                    lines[used]
                        .allowed
                        .copy_from(&r.allowed[line])
                        .map_err(|_| IrqError::NoMemory)?;
                    lines[used].current = r.target[line];
                    lines[used].load =
                        storage.window[line].swap(0, Ordering::Relaxed);
                    idx.push(line);
                    used += 1;
                }
            }
            lines.truncate(used);
        }
        out.truncate(lines.len());
        policy.assign(&lines, &online, &base, &mut out)?;
        let mut r = ROUTING.lock();
        let mut moved = 0;
        for i in 0..lines.len() {
            let line = idx[i];
            if r.enabled[line]
                && r.allowed[line].contains(out[i])
                && r.target[line] != Some(out[i])
                && arch::device_irq_route(line, out[i]).is_ok()
            {
                r.target[line] = Some(out[i]);
                moved += 1;
            }
        }
        r.moves += moved;
        Ok(moved)
    }
}

/// Legacy device/smp credit follows elapsed accounting, not sub-tick IRQ count.
pub(crate) fn on_elapsed_cpu_ticks(credits: u64) {
    for _ in 0..credits {
        crate::smp::on_local_tick();
        device::on_cpu_tick();
    }
}
