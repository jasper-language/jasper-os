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

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use kernel_core::cpu_runtime::{CpuInventoryEntry, CpuRuntimeRegistry};
use kernel_core::frame::PhysFrame;
use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::smp::{
    CallFn, CpuSet, CpuState, IpiKind, ShootdownBoard, ShootdownBoards, SmpError, Topology,
};
use spin::Once;

use crate::arch;
use crate::mm;
use crate::sync::IrqSpinLock;

/// 等待其他处理器应答的自旋上限（超过即判超时并撤销请求，不无限等待）。
const WAIT_SPINS: u64 = 200_000_000;
/// 每个其他处理器空闲执行流的栈大小。
const IDLE_STACK_SIZE: usize = 16 * 1024;

/// 堆后唯一 CPU 身份与生命周期事实源（启动其他处理器时写入一次）。
static CPU_RUNTIME: Once<IrqSpinLock<CpuRuntimeRegistry>> = Once::new();
/// Lock-free admitted logical-index bound for the CPU-identity fast path.
static CPU_ADMITTED_COUNT: AtomicUsize = AtomicUsize::new(0);
static CPU_DISCOVERED_COUNT: AtomicUsize = AtomicUsize::new(0);
static CPU_DISABLED_COUNT: AtomicUsize = AtomicUsize::new(0);
static CPU_FIRMWARE_ENABLED_RECORDS: AtomicUsize = AtomicUsize::new(0);
static CPU_FIRMWARE_DISABLED_RECORDS: AtomicUsize = AtomicUsize::new(0);
static CPU_FIRMWARE_DUPLICATE_RECORDS: AtomicUsize = AtomicUsize::new(0);
static CPU_FIRMWARE_CONFLICTING_RECORDS: AtomicUsize = AtomicUsize::new(0);
static CPU_FIRMWARE_UNIQUE_ENABLED: AtomicUsize = AtomicUsize::new(0);
/// 平台要求的低端启动帧（只预留一次，永久保留供以后再次启动处理器）。
static START_FRAME: Once<Option<PhysFrame>> = Once::new();
/// One board per initiating logical CPU. The vector is allocated after the
/// platform CPU inventory is admitted and before any secondary CPU starts.
static SHOOTDOWN_BOARDS: Once<Vec<ShootdownBoard>> = Once::new();
/// Bootstrap-only board used by single-CPU boot code before firmware CPU
/// discovery admits the runtime board set.
static BOOT_SHOOTDOWN: ShootdownBoard = ShootdownBoard::new();
static SHOOTDOWN_ACTIVE: AtomicU32 = AtomicU32::new(0);
static SHOOTDOWN_PEAK: AtomicU32 = AtomicU32::new(0);
static SHOOTDOWN_REQUESTS: AtomicU32 = AtomicU32::new(0);

/// Observable concurrency of admitted TLB shootdown requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShootdownStats {
    /// Requests posted since the last reset.
    pub requests: u32,
    /// Highest number of simultaneously in-flight requests.
    pub peak: u32,
}

/// Reset the concurrency observation window.
pub fn reset_shootdown_stats() {
    SHOOTDOWN_ACTIVE.store(0, Ordering::Release);
    SHOOTDOWN_PEAK.store(0, Ordering::Release);
    SHOOTDOWN_REQUESTS.store(0, Ordering::Release);
}

/// Read the current concurrency observation window.
pub fn shootdown_stats() -> ShootdownStats {
    ShootdownStats {
        requests: SHOOTDOWN_REQUESTS.load(Ordering::Acquire),
        peak: SHOOTDOWN_PEAK.load(Ordering::Acquire),
    }
}

/// Account for one admitted request until it completes or is abandoned.
struct ShootdownActivity;

impl ShootdownActivity {
    fn begin() -> Self {
        SHOOTDOWN_REQUESTS.fetch_add(1, Ordering::AcqRel);
        let active = SHOOTDOWN_ACTIVE.fetch_add(1, Ordering::AcqRel) + 1;
        SHOOTDOWN_PEAK.fetch_max(active, Ordering::AcqRel);
        Self
    }
}

impl Drop for ShootdownActivity {
    fn drop(&mut self) {
        SHOOTDOWN_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Admit the shootdown-board storage for the actual logical CPU count.
fn initialize_shootdown_boards(count: usize) -> ShootdownBoards<'static> {
    let boards = SHOOTDOWN_BOARDS.call_once(|| {
        let mut boards = Vec::new();
        if boards.try_reserve_exact(count.max(1)).is_err() {
            crate::kprintln!("[JSR-SMP] reject=shootdown_board_capacity cpus={}", count);
            arch::halt_forever();
        }
        for _ in 0..count.max(1) {
            boards.push(ShootdownBoard::new());
        }
        boards
    });
    ShootdownBoards::new(boards.as_slice())
}

fn admitted_shootdown_boards() -> Option<ShootdownBoards<'static>> {
    SHOOTDOWN_BOARDS
        .get()
        .map(|boards| ShootdownBoards::new(boards.as_slice()))
}

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

/// Result of removing one idle secondary CPU from software execution.
/// 一个空闲次级 CPU 退出软件执行域后的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMembershipReport {
    pub routes_rerouted: usize,
    /// Tasks moved away from the departing CPU.
    /// 从离场 CPU 迁移走的任务数。
    pub tasks_migrated: usize,
    pub interrupt_objects_closed: usize,
    pub interrupt_bindings_removed: usize,
    pub interrupt_vectors_returned: usize,
    pub interrupt_residual_bindings: usize,
    pub generation: u64,
}

/// Failure phase for a CPU membership transition.
/// CPU 成员关系迁移失败的阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuMembershipError {
    BadCpu,
    Runtime(&'static str),
    Routes(kernel_core::irq::IrqError),
    Quiesce(kernel_core::msi::MsiError),
    Scheduler(&'static str),
    State(SmpError),
}

impl CpuMembershipError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::BadCpu => "system.cpu.error.no_such_cpu",
            Self::Runtime(error) => error,
            Self::Routes(error) => error.name(),
            Self::Quiesce(error) => error.name(),
            Self::Scheduler(_) => "system.cpu.error.scheduler_departure",
            Self::State(error) => error.name(),
        }
    }
}

/// 预留平台需要的低端启动帧（在页帧分配器初始化之后、低端内存被其他用途占满之前调用）。
/// 平台不需要时什么也不做。返回是否满足了平台要求。
/// Reserve the platform's low start-up frame, if it needs one.
pub fn reserve_start_frame() -> bool {
    START_FRAME
        .call_once(|| {
            arch::CPU_START_FRAME_LIMIT.and_then(|limit| mm::frame::allocate_below(limit).ok())
        })
        .is_some()
        || arch::CPU_START_FRAME_LIMIT.is_none()
}

fn runtime_cpu_inventory(
    topology: &Topology,
    per_cpu_bytes: u64,
    available_bytes: u64,
) -> Result<CpuRuntimeRegistry, &'static str> {
    if topology.disabled_ids().len() != topology.disabled {
        return Err("disabled_cpu_identity_missing");
    }
    let total = topology
        .count()
        .checked_add(topology.disabled)
        .ok_or("cpu_inventory_overflow")?;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(total)
        .map_err(|_| "cpu_inventory_allocation")?;
    for hardware_id in topology.iter() {
        entries.push(CpuInventoryEntry {
            hardware_id,
            enabled: true,
            supported: true,
        });
    }
    for &hardware_id in topology.disabled_ids() {
        entries.push(CpuInventoryEntry {
            hardware_id,
            enabled: false,
            supported: false,
        });
    }
    CpuRuntimeRegistry::admit_complete(&entries, per_cpu_bytes, available_bytes, 0)
        .map_err(|error| error.name())
}

/// 发现并启动其他处理器（只调用一次，在内核地址空间中、开启任何用户空间之前之后均可）。
/// 每个处理器依次启动：发出启动命令后等它报到，超时则判失败、不再给它任何工作。
/// Discover and start the other processors one by one.
pub fn start_secondaries(timer_hz: u32) -> StartReport {
    crate::early::mark("SMP DISCOVER");
    let Some(boot) = crate::boot::get() else {
        let _ = initialize_shootdown_boards(1);
        return StartReport {
            present: 1,
            online: 1,
            failed: 0,
            source: "boot_only",
            dropped: 0,
            disabled: 0,
        };
    };
    let discovery = arch::cpu_init_boot(boot);
    CPU_DISCOVERED_COUNT.store(discovery.inventory.raw_records(), Ordering::Release);
    CPU_DISABLED_COUNT.store(discovery.inventory.unique_disabled, Ordering::Release);
    CPU_FIRMWARE_ENABLED_RECORDS.store(discovery.inventory.enabled_records, Ordering::Release);
    CPU_FIRMWARE_DISABLED_RECORDS.store(discovery.inventory.disabled_records, Ordering::Release);
    CPU_FIRMWARE_DUPLICATE_RECORDS.store(discovery.inventory.duplicate_records, Ordering::Release);
    CPU_FIRMWARE_CONFLICTING_RECORDS.store(
        discovery.inventory.conflicting_duplicates,
        Ordering::Release,
    );
    CPU_FIRMWARE_UNIQUE_ENABLED.store(
        discovery.inventory.unique_enabled,
        Ordering::Release,
    );
    crate::kprintln!(
        "[JSR-SMP] firmware raw={} enabled_records={} disabled_records={} duplicate_records={} conflicting_duplicates={} unique_enabled={} unique_disabled={} source={}",
        discovery.inventory.raw_records(),
        discovery.inventory.enabled_records,
        discovery.inventory.disabled_records,
        discovery.inventory.duplicate_records,
        discovery.inventory.conflicting_duplicates,
        discovery.inventory.unique_enabled,
        discovery.inventory.unique_disabled,
        discovery.source
    );
    #[cfg(feature = "smp-bsp-only")]
    let discovery = {
        let present = discovery.topology.count().saturating_add(discovery.topology.disabled);
        let boot_hw_id = discovery.topology.iter().next().unwrap_or(0);
        crate::early::mark("SMP BSP ONLY");
        crate::kprintln!(
            "[JSR-SMP] forced=bsp_only present={} online=1 source={}",
            present,
            discovery.source
        );
        arch::CpuDiscovery {
            topology: Topology::boot_only(boot_hw_id),
            source: "bsp_only",
            inventory: discovery.inventory,
            inventory_complete: true,
        }
    };
    if !discovery.inventory_complete {
        crate::kprintln!(
            "[JSR-SMP] reject=topology_incomplete source={}",
            discovery.source
        );
        arch::halt_forever();
    }
    let topo = discovery.topology;
    crate::early::mark("SMP PREP");
    if topo.dropped > 0 {
        crate::kprintln!(
            "[JSR-SMP] reject=topology_inventory_incomplete discovered={} retained={} dropped={}",
            topo.count().saturating_add(topo.dropped),
            topo.count(),
            topo.dropped
        );
        arch::halt_forever();
    }
    if let Err(error) = crate::irq::prepare_msi_storage(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=msi_dispatch_storage cpus={} reason={}",
            topo.count(),
            error.name()
        );
        arch::halt_forever();
    }
    if let Err(error) = crate::irq::device::prepare_cpu_storage(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=irq_device_cpu_storage cpus={} reason={}",
            topo.count(),
            error.name()
        );
        arch::halt_forever();
    }
    if let Err(error) = percpu::reserve(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=percpu_storage cpus={} reason={}",
            topo.count(),
            error.name()
        );
        arch::halt_forever();
    }
    if let Err(error) = crate::wcet::prepare_cpu_storage(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=wcet_cpu_storage cpus={} reason={}",
            topo.count(),
            error.name()
        );
        arch::halt_forever();
    }
    if let Err(error) = crate::sched::prepare_cpu_slots(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=scheduler_cpu_slots cpus={} reason={}",
            topo.count(),
            error.name()
        );
        arch::halt_forever();
    }
    if let Err(error) = crate::sched::prepare_cpu_leaves(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=scheduler_leaf_storage cpus={} reason={}",
            topo.count(),
            error.name()
        );
        arch::halt_forever();
    }
    if let Err(reason) = arch::prepare_cpu_runtime(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=arch_cpu_runtime cpus={} reason={}",
            topo.count(),
            reason
        );
        arch::halt_forever();
    }
    let per_cpu_bytes = IDLE_STACK_SIZE as u64;
    let available_bytes =
        mm::frame::free_frames() as u64 * kernel_core::frame::FRAME_SIZE as u64;
    let runtime = match runtime_cpu_inventory(&topo, per_cpu_bytes, available_bytes) {
        Ok(runtime) => runtime,
        Err(reason) => {
            crate::kprintln!(
                "[JSR-SMP] reject=cpu_runtime_registry present={} disabled={} reason={}",
                topo.count().saturating_add(topo.disabled),
                topo.disabled,
                reason
            );
            arch::halt_forever();
        }
    };
    let admission = runtime.admission();
    crate::kprintln!(
        "[JSR-SMP] admit present={} enabled={} disabled={} per_cpu_bytes={} required_bytes={} available_bytes={} source=resource-budget",
        admission.present,
        admission.enabled,
        admission.disabled,
        per_cpu_bytes,
        admission.required_bytes,
        admission.available_bytes
    );
    CPU_ADMITTED_COUNT.store(admission.enabled, Ordering::Release);
    CPU_RUNTIME.call_once(|| {
        IrqSpinLock::ranked(crate::lockorder::CPU_RUNTIME, runtime)
    });
    if let Err(error) = crate::sched::prepare_nohz_cpus(topo.count()) {
        crate::kprintln!(
            "[JSR-SMP] reject=tickless_cpu_storage cpus={} reason={}",
            topo.count(),
            error.name()
        );
        arch::halt_forever();
    }
    let boards = initialize_shootdown_boards(topo.count());
    if boards.len() != topo.count() {
        crate::kprintln!(
            "[JSR-SMP] reject=shootdown_board_capacity present={} boards={}",
            topo.count(),
            boards.len()
        );
        arch::halt_forever();
    }
    let me = percpu::get(0).expect("引导处理器的每核数据");
    let Some(boot_hw_id) = runtime_hw_id(0) else {
        crate::kprintln!("[JSR-SMP] reject=boot_cpu_identity_missing");
        arch::halt_forever();
    };
    me.set_hw_id(boot_hw_id);
    if me.state.get() == CpuState::Absent {
        let _ = me.state.begin_start().and_then(|_| me.state.mark_online());
    }

    let mut failed = 0;
    let frame = START_FRAME.get().copied().flatten();
    let identity = topo.count() > 1 && arch::CPU_START_FRAME_LIMIT.is_some();
    // 平台要求：启动期间启动帧在内核空间中「虚拟地址 = 物理地址」可写可执行
    let mapped = match frame {
        Some(f) if identity => match VirtPage::from_start(f.start()) {
            Some(page) => {
                mm::map::map(page, f, MapFlags::WRITE.union(MapFlags::EXECUTE)).is_ok()
            }
            None => {
                crate::kprintln!("[JSR-SMP] reject=start_frame_page invalid=true");
                false
            }
        },
        _ => !identity,
    };
    let space = arch::current_space();
    crate::early::append_progress(&alloc::format!(
        "SMP starting processors present={}",
        topo.count().saturating_sub(1)
    ));
    for cpu in 1..topo.count() {
        let Some(pc) = percpu::get(cpu) else {
            crate::kprintln!("[JSR-SMP] reject=percpu_missing cpu={}", cpu);
            arch::halt_forever();
        };
        let Some(hw_id) = runtime_hw_id(cpu) else {
            crate::kprintln!("[JSR-SMP] reject=cpu_identity_missing cpu={}", cpu);
            arch::halt_forever();
        };
        pc.set_hw_id(hw_id);
        if !mapped || pc.state.begin_start().is_err() {
            failed += 1;
            continue;
        }
        // 栈永久属于该处理器（处理器不下线），泄漏为 'static。
        let stack: &'static mut [u8] = vec![0u8; IDLE_STACK_SIZE].leak();
        let stack_top = (stack.as_ptr() as u64 + IDLE_STACK_SIZE as u64) & !0xF;
        let req = arch::CpuStart {
            index: cpu,
            hw_id,
            stack_top,
            space,
            timer_hz,
        };
        let marker = alloc::format!("SMP START {cpu}");
        crate::early::mark_serial(&marker);
        // SAFETY：栈专属于该处理器；启动帧满足平台要求并已映射；处理器依次启动。
        let started = unsafe { arch::cpu_start(&req, frame) };
        let marker = alloc::format!("SMP WAIT {cpu}");
        crate::early::mark_serial(&marker);
        let online = started.is_ok() && wait_until(|| pc.state.get() != CpuState::Starting);
        if !online || pc.state.get() != CpuState::Online {
            // 超时：判失败。迟到的报到会被状态机拒绝，该处理器随即停机。
            let _ = pc.state.mark_failed();
            failed += 1;
        }
    }
    crate::early::append_progress(&alloc::format!(
        "SMP online {}/{} failed={}",
        online_set().len(),
        topo.count(),
        failed
    ));
    // 全部报到后撤掉恒等映射；有失败者时保留（迟到的处理器可能仍在执行启动代码）。
    if let (Some(f), true, 0) = (frame, identity && mapped, failed) {
        if let Some(p) = VirtPage::from_start(f.start()) {
            let _ = mm::map::unmap(p);
        }
    }
    crate::early::mark("SMP DONE");
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
    let Some(me) = percpu::get(index) else {
        arch::halt_forever()
    };
    me.set_current(percpu::IDLE_SLOT);
    me.set_space(None);
    let Some(runtime) = CPU_RUNTIME.get() else {
        crate::kprintln!("[JSR-SMP] reject=cpu_runtime_missing cpu={}", index);
        arch::halt_forever();
    };
    if let Err(error) = runtime.lock().mark_online(index) {
        crate::kprintln!(
            "[JSR-SMP] reject=cpu_online_registry cpu={} reason={}",
            index,
            error.name()
        );
        arch::halt_forever();
    }
    if me.state.mark_online().is_err() {
        // Do not leave the runtime registry claiming a timed-out AP is online.
        let _ = runtime.lock().mark_offline(index);
        arch::halt_forever();
    }
    // 加入调度：此后本处理器从自己的运行队列取任务，队列空时窃取，仍没有则休眠
    // `idle_loop` publishes scheduler membership last, after registry and
    // per-CPU state are visible.
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
        IpiKind::Reschedule => {
            me.request_resched();
            if crate::hrtime::enabled() {
                let _ = unsafe { arch::timer_arm_after_ns(1) };
            }
        }
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
    match CPU_RUNTIME.get() {
        Some(runtime) => runtime.lock().identities().len(),
        None => 1,
    }
}

/// Timer ticks observed by the current processor.
pub fn local_ticks() -> u64 {
    percpu::this().ticks()
}

pub fn discovered_cpu_count() -> usize {
    CPU_DISCOVERED_COUNT.load(Ordering::Acquire).max(1)
}

pub fn admitted_cpu_count() -> usize {
    CPU_ADMITTED_COUNT.load(Ordering::Acquire).max(1)
}

pub fn disabled_cpu_count() -> usize {
    CPU_DISABLED_COUNT.load(Ordering::Acquire)
}

pub fn firmware_enabled_cpu_record_count() -> usize {
    CPU_FIRMWARE_ENABLED_RECORDS.load(Ordering::Acquire)
}

pub fn firmware_disabled_cpu_record_count() -> usize {
    CPU_FIRMWARE_DISABLED_RECORDS.load(Ordering::Acquire)
}

pub fn duplicate_cpu_record_count() -> usize {
    CPU_FIRMWARE_DUPLICATE_RECORDS.load(Ordering::Acquire)
}

pub fn conflicting_cpu_record_count() -> usize {
    CPU_FIRMWARE_CONFLICTING_RECORDS.load(Ordering::Acquire)
}

pub fn unique_enabled_cpu_count() -> usize {
    CPU_FIRMWARE_UNIQUE_ENABLED.load(Ordering::Acquire)
}

fn runtime_hw_id(cpu: usize) -> Option<u32> {
    CPU_RUNTIME
        .get()
        .and_then(|runtime| runtime.lock().identity(cpu).map(|identity| identity.hardware_id))
}

/// Validate a logical CPU without taking the runtime registry lock.
///
/// CPU identity is required by the IRQ-safe lock implementation itself, so
/// this fast path must be lock-free to avoid a lock -> per-CPU -> identity
/// cycle. Logical IDs are contiguous and the admitted count is published
/// before secondaries can execute.
pub fn cpu_index_admitted(index: usize) -> bool {
    if CPU_RUNTIME.get().is_some() {
        index < CPU_ADMITTED_COUNT.load(Ordering::Acquire)
    } else {
        index < kernel_core::smp::MAX_CPUS
    }
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

/// Remove an idle secondary CPU from scheduler, IRQ, MSI and runtime-registry
/// membership in one ordered software departure.
///
/// Runtime and scheduler preflight complete before route mutation or interrupt
/// teardown. Device routes move while the CPU still participates in scheduling;
/// scheduler membership is then withdrawn, MSI objects quiesced, and finally the
/// runtime generation advances. Physical halt/start remains a hardware gate.
///
/// 在移动路由或拆除中断前完成 runtime 与调度器预检。设备路由先迁走，再退出调度、
/// 关闭 MSI 对象并推进 runtime 代际；平台侧真实停核/重启仍属于独立硬件门。
pub fn detach_cpu_membership(
    cpu: usize,
) -> Result<CpuMembershipReport, CpuMembershipError> {
    if cpu == 0 || cpu == arch::cpu_index() || cpu >= cpu_count() {
        return Err(CpuMembershipError::BadCpu);
    }
    let runtime = CPU_RUNTIME.get().ok_or(CpuMembershipError::BadCpu)?;
    runtime
        .lock()
        .ensure_can_mark_offline(cpu)
        .map_err(|error| CpuMembershipError::Runtime(error.name()))?;
    crate::sched::ensure_can_evacuate_cpu(cpu)
        .map_err(CpuMembershipError::Scheduler)?;

    crate::kprintln!("[JSR-CPU-DEPART] stage=routes cpu={}", cpu);
    let routes_rerouted = crate::irq::device::detach_cpu_lines(cpu)
        .map_err(CpuMembershipError::Routes)?;
    let tasks_migrated =
        crate::sched::evacuate_cpu(cpu).map_err(CpuMembershipError::Scheduler)?;
    crate::kprintln!(
        "[JSR-CPU-DEPART] stage=scheduler cpu={} routes={} tasks={}",
        cpu,
        routes_rerouted,
        tasks_migrated
    );
    crate::sched::offline_idle_cpu(cpu).map_err(CpuMembershipError::Scheduler)?;
    crate::kprintln!("[JSR-CPU-DEPART] stage=msi cpu={}", cpu);
    let quiesced = match crate::interrupt::quiesce_cpu(cpu) {
        Ok(report) => report,
        Err(error) => {
            let _ = crate::sched::online_idle_cpu(cpu);
            return Err(CpuMembershipError::Quiesce(error));
        }
    };
    crate::kprintln!("[JSR-CPU-DEPART] stage=runtime cpu={}", cpu);
    let generation = runtime
        .lock()
        .mark_offline(cpu)
        .map_err(|error| CpuMembershipError::Runtime(error.name()))?;
    let Some(percpu) = percpu::get(cpu) else {
        return Err(CpuMembershipError::BadCpu);
    };
    percpu
        .state
        .mark_offline()
        .map_err(CpuMembershipError::State)?;
    crate::kprintln!("[JSR-CPU-DEPART] stage=quota cpu={}", cpu);
    crate::irq::device::demote_cpu_quota(cpu)
        .map_err(CpuMembershipError::Routes)?;
    crate::kprintln!("[JSR-CPU-DEPART] stage=commit cpu={}", cpu);

    Ok(CpuMembershipReport {
        routes_rerouted,
        tasks_migrated,
        interrupt_objects_closed: quiesced.objects_closed,
        interrupt_bindings_removed: quiesced.bindings_removed,
        interrupt_vectors_returned: quiesced.vectors_returned,
        interrupt_residual_bindings: quiesced.residual_bindings,
        generation,
    })
}

/// Reattach a CPU that completed [`detach_cpu_membership`].
///
/// Any required platform restart must complete first. Dispatch resumes before
/// the runtime generation, CPU state cell and scheduler membership are restored.
///
/// 平台侧若需要重启，必须先完成。随后依次恢复 MSI 分发、runtime 代际、每核状态
/// 与调度成员。
pub fn attach_cpu_membership(cpu: usize) -> Result<u64, CpuMembershipError> {
    if cpu == 0 || cpu == arch::cpu_index() || cpu >= cpu_count() {
        return Err(CpuMembershipError::BadCpu);
    }
    let runtime = CPU_RUNTIME.get().ok_or(CpuMembershipError::BadCpu)?;
    runtime
        .lock()
        .ensure_can_mark_online(cpu)
        .map_err(|error| CpuMembershipError::Runtime(error.name()))?;
    crate::sched::ensure_can_online_idle_cpu(cpu)
        .map_err(CpuMembershipError::Scheduler)?;
    crate::irq::msi_resume_cpu(cpu).map_err(CpuMembershipError::Quiesce)?;
    let generation = runtime
        .lock()
        .mark_online(cpu)
        .map_err(|error| CpuMembershipError::Runtime(error.name()))?;
    let Some(percpu) = percpu::get(cpu) else {
        return Err(CpuMembershipError::BadCpu);
    };
    if let Err(error) = percpu
        .state
        .begin_start()
        .and_then(|_| percpu.state.mark_online())
    {
        let _ = runtime.lock().mark_offline(cpu);
        return Err(CpuMembershipError::State(error));
    }
    if let Err(error) = crate::sched::online_idle_cpu(cpu) {
        let _ = percpu.state.mark_offline();
        let _ = runtime.lock().mark_offline(cpu);
        return Err(CpuMembershipError::Scheduler(error));
    }
    Ok(generation)
}

/// 目标是否可接收核间中断：存在、不是自己、在线。
fn check_target(cpu: usize) -> Result<&'static percpu::PerCpu, SmpError> {
    let pc = percpu::get(cpu)
        .filter(|_| cpu < cpu_count())
        .ok_or(SmpError::NoSuchCpu)?;
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
        // A target may itself be waiting for a shootdown response while its
        // cross-CPU call is being collected. Continue servicing this CPU's
        // shootdown boards so the call and the shootdown cannot wait on each
        // other.
        service_shootdown(arch::cpu_index());
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
    if pages
        .checked_mul(4096)
        .and_then(|len| va.checked_add(len))
        .is_none()
    {
        return Err(SmpError::BadRange);
    }
    let me = arch::cpu_index();
    let targets = active.intersect(online_set()).without(me);
    let whole = pages > kernel_core::smp::MAX_SHOOTDOWN_PAGES;
    let mut generation = None;
    // 别的处理器正在发起时：服务它发给我们的请求，直到公告板空出来
    let posted = wait_until(|| {
        let admitted = match admitted_shootdown_boards() {
            Some(boards) if whole => boards.begin_all(me, targets.clone()),
            Some(boards) => boards.begin(me, targets.clone(), va, pages),
            None if me == 0 && whole => BOOT_SHOOTDOWN.begin_all(targets.clone()),
            None if me == 0 => BOOT_SHOOTDOWN.begin(targets.clone(), va, pages),
            None => Err(SmpError::NoSuchCpu),
        };
        match admitted {
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
        }
    });
    let generation = match (posted, generation) {
        (true, Some(r)) => r?,
        _ => return Err(SmpError::Timeout),
    };
    let _activity = ShootdownActivity::begin();
    if whole {
        arch::tlb_flush_all_local();
    } else {
        arch::tlb_flush_local(va, pages);
    }
    for cpu in targets.iter() {
        if let Err(e) = arch::send_ipi(cpu, IpiKind::TlbShootdown) {
            abandon_shootdown(me, generation);
            return Err(e);
        }
    }
    #[cfg(feature = "fault-inject")]
    if crate::fault_inject::IPI_TIMEOUT.hit() {
        abandon_shootdown(me, generation);
        return Err(SmpError::Timeout);
    }
    if wait_until(|| {
        service_shootdown(me);
        admitted_shootdown_boards().map_or_else(
            || BOOT_SHOOTDOWN.is_complete(generation),
            |boards| boards.is_complete(me, generation),
        )
    }) {
        Ok(())
    } else {
        abandon_shootdown(me, generation);
        Err(SmpError::Timeout)
    }
}

fn abandon_shootdown(cpu: usize, generation: u32) {
    if let Some(boards) = admitted_shootdown_boards() {
        boards.abandon(cpu, generation);
    } else {
        BOOT_SHOOTDOWN.abandon(generation);
    }
}

fn service_shootdown(cpu: usize) {
    let mut flush = |start, pages| {
        if pages == 0 {
            arch::tlb_flush_all_local();
        } else {
            arch::tlb_flush_local(start, pages);
        }
    };
    if let Some(boards) = admitted_shootdown_boards() {
        boards.service(cpu, &mut flush);
    } else if cpu == 0 {
        BOOT_SHOOTDOWN.service(cpu, &mut flush);
    }
}

/// 击落公告板是否空闲（演练检查「拒绝后无残留」用）。
/// Whether the shootdown board is idle.
pub fn shootdown_idle() -> bool {
    BOOT_SHOOTDOWN.is_idle() && admitted_shootdown_boards().is_none_or(|boards| boards.is_idle())
}
