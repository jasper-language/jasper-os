//! 多处理器子系统门面（Facade）：启动其他处理器、每核数据、核间中断、跨核调用与 TLB 击落。
//! Multiprocessor facade: start-up, per-CPU data, IPIs, cross-CPU calls and TLB shootdown.
//!
//! # 结构
//! * `percpu` —— 每核数据（状态、当前任务、本地时钟、核间中断计数、跨核调用格）
//! * `demo` / `shared_demo` —— 里程碑演练（与机制分离，可整体删除）
//! * 本文件   —— 启动流程、核间中断的 Core 侧处理、跨核调用与 TLB 击落的发起方逻辑
//!
//! 协议本体（状态机、击落公告板、调用格）在 `kernel_core::smp`，宿主已测；硬件动作全部经 `arch::*`。
//!
//! # 锁顺序登记
//! 子系统级全局锁登记在 `crate::lockorder` 的一条链上，加锁时按每核持有集合检查顺序。
//! 本子系统的锁全部是叶子锁，持有期间不获取任何其他锁，也不触发调度：
//! * 击落公告板锁 —— 持锁期间只执行本地 TLB 作废（无锁）；
//! * 每核跨核调用格锁 —— 被调函数在锁外执行；
//! * 每核数据只有原子量（32 位目标上的 64 位计数是关中断 + 叶子自旋锁）。
//! 发起方等待应答期间不持有任何锁，并持续服务发给自己的击落请求——两个处理器同时发起时不会互相等死。
//!
//! # 调度
//! 其他处理器报到后进入调度子系统的空闲执行流：从自己的运行队列取任务、空闲时窃取；
//! 「重新调度」核间中断只置每核标志并唤醒处理器，切换由调度子系统在中断之外或下一个本地 tick 完成。

pub mod demo;
pub mod percpu;
pub mod shared_demo;

use alloc::vec;
use kernel_core::frame::PhysFrame;
use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::smp::{CallFn, CpuSet, CpuState, IpiKind, ShootdownBoard, SmpError, Topology};
use spin::Once;

use crate::arch;
use crate::mm;

/// 等待其他处理器应答的自旋上限（超过即判超时并撤销请求，不无限等待）。
const WAIT_SPINS: u64 = 200_000_000;
/// 每个其他处理器空闲执行流的栈大小。
const IDLE_STACK_SIZE: usize = 16 * 1024;

/// 发现得到的拓扑（启动其他处理器时写入一次）。
static TOPOLOGY: Once<Topology> = Once::new();
/// 平台要求的低端启动帧（只预留一次，永久保留供以后再次启动处理器）。
static START_FRAME: Once<Option<PhysFrame>> = Once::new();
/// 全系统唯一的 TLB 击落公告板。
static SHOOTDOWN: ShootdownBoard = ShootdownBoard::new();

/// 启动结果汇总。
/// Start-up summary.
#[derive(Debug, Clone, Copy)]
pub struct StartReport {
    /// 拓扑中的处理器数（含引导处理器）。
    pub present: usize,
    /// 已在线的处理器数（含引导处理器）。
    pub online: usize,
    /// 启动失败或超时的处理器数。
    pub failed: usize,
    /// 拓扑来源或失败原因。
    pub source: &'static str,
    /// 超出容量未纳入的处理器数。
    pub dropped: usize,
    /// 固件报告存在但未启用的处理器数。
    pub disabled: usize,
}

/// 预留平台需要的低端启动帧（在页帧分配器初始化之后、低端内存被其他用途占满之前调用）。
/// 平台不需要时什么也不做。返回是否满足了平台要求。
/// Reserve the platform's low start-up frame, if it needs one.
pub fn reserve_start_frame() -> bool {
    START_FRAME
        .call_once(|| arch::CPU_START_FRAME_LIMIT.and_then(|limit| mm::frame::allocate_below(limit).ok()))
        .is_some()
        || arch::CPU_START_FRAME_LIMIT.is_none()
}

/// 发现并启动其他处理器（只调用一次，在内核地址空间中、开启任何用户空间之前之后均可）。
/// 每个处理器依次启动：发出启动命令后等它报到，超时则判失败、不再给它任何工作。
/// Discover and start the other processors one by one.
pub fn start_secondaries(timer_hz: u32) -> StartReport {
    let Some(boot) = crate::boot::get() else {
        return StartReport { present: 1, online: 1, failed: 0, source: "boot_only", dropped: 0, disabled: 0 };
    };
    let discovery = arch::cpu_init_boot(boot);
    let topo = *TOPOLOGY.call_once(|| discovery.topology);
    let me = percpu::get(0).expect("引导处理器的每核数据");
    me.set_hw_id(topo.hw_id(0).unwrap_or(0));
    if me.state.get() == CpuState::Absent {
        let _ = me.state.begin_start().and_then(|_| me.state.mark_online());
    }

    let mut failed = 0;
    let frame = START_FRAME.get().copied().flatten();
    let identity = topo.count() > 1 && arch::CPU_START_FRAME_LIMIT.is_some();
    // 平台要求：启动期间启动帧在内核空间中「虚拟地址 = 物理地址」可写可执行
    let mapped = match frame {
        Some(f) if identity => VirtPage::from_start(f.start())
            .map(|p| mm::map::map(p, f, MapFlags::WRITE.union(MapFlags::EXECUTE)).is_ok())
            .unwrap_or(false),
        _ => !identity,
    };
    let space = arch::current_space();
    for cpu in 1..topo.count() {
        let Some(pc) = percpu::get(cpu) else { break };
        let hw_id = topo.hw_id(cpu).unwrap_or(u32::MAX);
        pc.set_hw_id(hw_id);
        if !mapped || pc.state.begin_start().is_err() {
            failed += 1;
            continue;
        }
        // 栈永久属于该处理器（处理器不下线），泄漏为 'static。
        let stack: &'static mut [u8] = vec![0u8; IDLE_STACK_SIZE].leak();
        let stack_top = (stack.as_ptr() as u64 + IDLE_STACK_SIZE as u64) & !0xF;
        let req = arch::CpuStart { index: cpu, hw_id, stack_top, space, timer_hz };
        // SAFETY：栈专属于该处理器；启动帧满足平台要求并已映射；处理器依次启动。
        let started = unsafe { arch::cpu_start(&req, frame) };
        let online = started.is_ok() && wait_until(|| pc.state.get() != CpuState::Starting);
        if !online || pc.state.get() != CpuState::Online {
            // 超时：判失败。迟到的报到会被状态机拒绝，该处理器随即停机。
            let _ = pc.state.mark_failed();
            failed += 1;
        }
    }
    // 全部报到后撤掉恒等映射；有失败者时保留（迟到的处理器可能仍在执行启动代码）。
    if let (Some(f), true, 0) = (frame, identity && mapped, failed) {
        if let Some(p) = VirtPage::from_start(f.start()) {
            let _ = mm::map::unmap(p);
        }
    }
    StartReport {
        present: topo.count(),
        online: online_set().len(),
        failed,
        source: discovery.source,
        dropped: topo.dropped,
        disabled: topo.disabled,
    }
}

/// 有界等待条件成立（返回是否成立）。
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..WAIT_SPINS {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    cond()
}

/// 其他处理器完成平台初始化后的入口（由 arch 调用，永不返回）：报到，然后运行空闲执行流。
/// Entry of a secondary processor after platform initialisation.
pub fn secondary_main(index: usize) -> ! {
    let Some(me) = percpu::get(index) else { arch::halt_forever() };
    me.set_current(percpu::IDLE_SLOT);
    me.set_space(None);
    if me.state.mark_online().is_err() {
        // 发起方已判超时：不再参与任何工作
        arch::halt_forever();
    }
    // 加入调度：此后本处理器从自己的运行队列取任务，队列空时窃取，仍没有则休眠
    crate::sched::idle_loop(index)
}

/// 本地定时器中断的 Core 侧处理（中断上下文）。
/// Local timer tick (interrupt context).
pub fn on_local_tick() {
    percpu::this().tick();
}

/// 核间中断的 Core 侧处理（中断上下文）。
/// Inter-processor interrupt handling (interrupt context).
pub fn on_ipi(kind: IpiKind) {
    let me = percpu::this();
    me.count_ipi(kind);
    match kind {
        IpiKind::Reschedule => me.request_resched(),
        IpiKind::TlbShootdown => {
            service_shootdown(arch::cpu_index());
        }
        IpiKind::Call => {
            me.call.run();
        }
    }
}

/// 拓扑中的处理器数（未启动多处理器时为 1）。
/// Number of processors in the topology.
pub fn cpu_count() -> usize {
    TOPOLOGY.get().map(|t| t.count()).unwrap_or(1)
}

/// 当前在线的处理器集合。
/// Set of online processors.
pub fn online_set() -> CpuSet {
    let mut s = CpuSet::EMPTY;
    for cpu in 0..cpu_count() {
        if percpu::get(cpu).map(|p| p.state.get()) == Some(CpuState::Online) {
            s.insert(cpu);
        }
    }
    s
}

/// 目标是否可接收核间中断：存在、不是自己、在线。
fn check_target(cpu: usize) -> Result<&'static percpu::PerCpu, SmpError> {
    let pc = percpu::get(cpu).filter(|_| cpu < cpu_count()).ok_or(SmpError::NoSuchCpu)?;
    if cpu == arch::cpu_index() {
        return Err(SmpError::SelfTarget);
    }
    if pc.state.get() != CpuState::Online {
        return Err(SmpError::NotOnline);
    }
    Ok(pc)
}

/// 请处理器 `cpu` 重新调度。
/// Ask processor `cpu` to reschedule.
pub fn reschedule(cpu: usize) -> Result<(), SmpError> {
    check_target(cpu)?;
    arch::send_ipi(cpu, IpiKind::Reschedule)
}

/// 在处理器 `cpu` 上（核间中断上下文中）执行 `f(arg)` 并取回结果；超时则撤销投递。
/// `f` 必须短小、不阻塞、不获取可能被调用者持有的锁。
/// Run `f(arg)` on processor `cpu` and return its result.
pub fn call_on(cpu: usize, f: CallFn, arg: u64) -> Result<u64, SmpError> {
    post_call(cpu, f, arg)?;
    collect_call(cpu)
}

/// 向处理器 `cpu` 投递 `f(arg)` 并发出核间中断后立即返回（不等结果）；之后必须以 [`collect_call`] 取回。
/// 用于让多个处理器**同时**执行；约束同 [`call_on`]。失败时不留投递。
/// Post `f(arg)` to processor `cpu` without waiting.
pub fn post_call(cpu: usize, f: CallFn, arg: u64) -> Result<(), SmpError> {
    let pc = check_target(cpu)?;
    pc.call.post(f, arg)?;
    if let Err(e) = arch::send_ipi(cpu, IpiKind::Call) {
        pc.call.abandon();
        return Err(e);
    }
    Ok(())
}

/// 等待并取回此前经 [`post_call`] 投递给 `cpu` 的结果；超时则撤销投递。
/// Wait for and collect the result of a posted call.
pub fn collect_call(cpu: usize) -> Result<u64, SmpError> {
    let pc = check_target(cpu)?;
    let mut result = None;
    if wait_until(|| {
        result = pc.call.collect();
        result.is_some()
    }) {
        if let Some(v) = result {
            return Ok(v);
        }
    }
    pc.call.abandon();
    Err(SmpError::Timeout)
}

/// 在所有在线处理器上作废 `[va, va + pages × 4 KiB)` 的 TLB 项。
/// Invalidate a page range on every online processor.
pub fn tlb_shootdown(va: u64, pages: u64) -> Result<(), SmpError> {
    tlb_shootdown_on(online_set(), va, pages)
}

/// 在 `active` 中仍在线的处理器上作废一段映射；本处理器总在本地作废，不为它发送中断。
///
/// 范围超过公告板单请求上限时改为整表刷新，仍然只登记一个请求、每个目标只接收一次核间中断。
/// 本处理器直接作废，其他目标经核间中断作废并应答；发出请求后不持锁等待，超时则撤销请求。
/// Invalidate a mapping on the online subset of `active` and wait for every acknowledgement.
pub fn tlb_shootdown_on(active: CpuSet, va: u64, pages: u64) -> Result<(), SmpError> {
    if pages == 0 || va % 4096 != 0 {
        return Err(SmpError::BadRange);
    }
    if pages.checked_mul(4096).and_then(|len| va.checked_add(len)).is_none() {
        return Err(SmpError::BadRange);
    }
    let me = arch::cpu_index();
    let targets = active.intersect(online_set()).without(me);
    let whole = pages > kernel_core::smp::MAX_SHOOTDOWN_PAGES;
    let mut generation = None;
    // 别的处理器正在发起时：服务它发给我们的请求，直到公告板空出来
    let posted = wait_until(|| match if whole {
        SHOOTDOWN.begin_all(targets)
    } else {
        SHOOTDOWN.begin(targets, va, pages)
    } {
        Ok(g) => {
            generation = Some(Ok(g));
            true
        }
        Err(SmpError::Busy) => {
            service_shootdown(me);
            false
        }
        Err(e) => {
            generation = Some(Err(e));
            true
        }
    });
    let generation = match (posted, generation) {
        (true, Some(r)) => r?,
        _ => return Err(SmpError::Timeout),
    };
    if whole {
        arch::tlb_flush_all_local();
    } else {
        arch::tlb_flush_local(va, pages);
    }
    for cpu in targets.iter() {
        if let Err(e) = arch::send_ipi(cpu, IpiKind::TlbShootdown) {
            SHOOTDOWN.abandon(generation);
            return Err(e);
        }
    }
    #[cfg(feature = "fault-inject")]
    if crate::fault_inject::IPI_TIMEOUT.hit() {
        SHOOTDOWN.abandon(generation);
        return Err(SmpError::Timeout);
    }
    if wait_until(|| {
        service_shootdown(me);
        SHOOTDOWN.is_complete(generation)
    }) {
        Ok(())
    } else {
        SHOOTDOWN.abandon(generation);
        Err(SmpError::Timeout)
    }
}

fn service_shootdown(cpu: usize) {
    SHOOTDOWN.service(cpu, |start, pages| {
        if pages == 0 {
            arch::tlb_flush_all_local();
        } else {
            arch::tlb_flush_local(start, pages);
        }
    });
}

/// 击落公告板是否空闲（演练检查「拒绝后无残留」用）。
/// Whether the shootdown board is idle.
pub fn shootdown_idle() -> bool {
    SHOOTDOWN.is_idle()
}
