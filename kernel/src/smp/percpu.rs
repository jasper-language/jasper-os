//! 每核数据：每个逻辑处理器一份，只由下标访问，没有跨核共享的可变全局结构。
//! Per-CPU data: one record per logical processor, indexed by logical index.
//!
//! # 职责
//! 记录每个处理器的启动状态、硬件标识、当前任务槽位、本地时钟 tick、各类核间中断的接收计数、
//! 「需要重新调度」标志、空闲循环醒来次数、发给它的跨核调用格，以及它当前持有的全局锁级别（锁顺序检查）。
//!
//! # 边界与原因
//! 字段全部是原子量或叶子锁，跨核读取无需额外加锁；写入方各有约定（状态机由发起方与本处理器
//! 按迁移规则推进，计数只由本处理器递增）。处理器下标由平台的 `cpu_index` 给出，本文件不含指令集代码。

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use kernel_core::lockorder::HeldRanks;
use kernel_core::smp::{
    CallSlot, CpuStateCell, IpiKind, BOOTSTRAP_CPUS,
};
use spin::Once;

use crate::arch;
use crate::sync::{IrqSpinLock, IrqU64};

/// 「当前任务」为空闲执行流时的槽位取值。
/// Slot value meaning "running the idle flow".
pub const IDLE_SLOT: usize = usize::MAX;

/// 一个逻辑处理器的每核数据。
/// Per-CPU record of one logical processor.
pub struct PerCpu {
    /// 启动状态机。
    pub state: CpuStateCell,
    hw_id: AtomicU32,
    current: AtomicUsize,
    space: IrqSpinLock<Option<arch::SpaceRoot>>,
    ticks: IrqU64,
    ipis: [AtomicU32; IpiKind::ALL.len()],
    resched_pending: AtomicBool,
    idle_wakeups: AtomicU32,
    /// 发给本处理器的跨核调用。
    pub call: CallSlot,
    /// 本处理器当前持有的全局锁级别（加锁顺序检查用；只由本处理器在关中断时修改）。
    held: HeldRanks,
}

impl PerCpu {
    const fn new() -> Self {
        PerCpu {
            state: CpuStateCell::new(),
            hw_id: AtomicU32::new(0),
            current: AtomicUsize::new(IDLE_SLOT),
            space: IrqSpinLock::new(None),
            ticks: IrqU64::new(0),
            ipis: [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)],
            resched_pending: AtomicBool::new(false),
            idle_wakeups: AtomicU32::new(0),
            call: CallSlot::new(),
            held: HeldRanks::new(),
        }
    }

    /// 硬件标识。
    /// Hardware identifier.
    pub fn hw_id(&self) -> u32 {
        self.hw_id.load(Ordering::Relaxed)
    }

    /// 记录硬件标识（启动前由发起方写入）。
    /// Record the hardware identifier.
    pub fn set_hw_id(&self, id: u32) {
        self.hw_id.store(id, Ordering::Relaxed);
    }

    /// 当前任务槽位（[`IDLE_SLOT`] = 空闲执行流）。
    /// Current task slot.
    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    /// 记录当前任务槽位（调度切换时由本处理器写入）。
    /// Record the current task slot.
    pub fn set_current(&self, slot: usize) {
        self.current.store(slot, Ordering::Relaxed);
    }

    /// 本处理器当前装入的用户地址空间；`None` 表示内核空间。
    /// User address space currently installed on this processor.
    pub fn space(&self) -> Option<arch::SpaceRoot> {
        *self.space.lock()
    }

    /// 记录地址空间切换结果（由调度器在切换前后调用）。
    /// Record the installed user address space after a switch.
    pub fn set_space(&self, space: Option<arch::SpaceRoot>) {
        *self.space.lock() = space;
    }

    /// 本处理器本地时钟的 tick 数。
    /// Local clock ticks of this processor.
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    /// 本地时钟走一格（只在本处理器的时钟中断里调用）。
    /// Advance the local clock by one tick.
    pub fn tick(&self) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }

    /// 收到某类核间中断的次数。
    /// Number of IPIs of `kind` received.
    pub fn ipis(&self, kind: IpiKind) -> u32 {
        self.ipis[kind.index()].load(Ordering::Relaxed)
    }

    /// 记一次收到的核间中断。
    /// Count one received IPI.
    pub fn count_ipi(&self, kind: IpiKind) {
        self.ipis[kind.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// 置「需要重新调度」。
    /// Mark that a reschedule is needed.
    pub fn request_resched(&self) {
        self.resched_pending.store(true, Ordering::Release);
    }

    /// 取走「需要重新调度」标志（返回取走前的值）。
    /// Take the reschedule flag.
    pub fn take_resched(&self) -> bool {
        self.resched_pending.swap(false, Ordering::AcqRel)
    }

    /// 「需要重新调度」标志是否置位（只读，不取走）。
    /// Whether a reschedule is pending (without taking it).
    pub fn resched_pending(&self) -> bool {
        self.resched_pending.load(Ordering::Acquire)
    }

    /// 空闲循环醒来的次数。
    /// Times the idle loop woke up.
    pub fn idle_wakeups(&self) -> u32 {
        self.idle_wakeups.load(Ordering::Relaxed)
    }

    /// 本处理器当前持有的全局锁级别集合。
    /// Lock ranks currently held on this processor.
    pub fn held_locks(&self) -> &HeldRanks {
        &self.held
    }

    /// 记一次空闲循环醒来。
    /// Count one idle wake-up.
    pub fn count_idle_wakeup(&self) {
        self.idle_wakeups.fetch_add(1, Ordering::Relaxed);
    }
}

/// 堆前可用的每核数据（下标 = 逻辑下标；引导处理器为 0）。
static BOOTSTRAP_CPUS_DATA: [PerCpu; BOOTSTRAP_CPUS] =
    [const { PerCpu::new() }; BOOTSTRAP_CPUS];

/// Heap-backed records beyond the pre-heap bootstrap area.
static EXTRA_CPUS: Once<Result<alloc::vec::Vec<PerCpu>, ReserveError>> =
    Once::new();

/// Why the runtime per-CPU record table could not be reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    Allocation,
    AlreadyReservedTooSmall,
}

impl ReserveError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allocation => "system.cpu.error.percpu_allocation",
            Self::AlreadyReservedTooSmall => "system.cpu.error.percpu_capacity",
        }
    }
}

/// Reserve heap-backed per-CPU records for every admitted logical CPU.
///
/// The bootstrap area remains valid before the heap exists. `reserve` is a
/// boot-time transaction called before any secondary CPU starts; after it
/// succeeds, `get` and `this` can use the same logical indices without a final
/// 128-CPU ceiling.
pub fn reserve(cpus: usize) -> Result<(), ReserveError> {
    let extra = cpus.saturating_sub(BOOTSTRAP_CPUS);
    let reserved = EXTRA_CPUS.call_once(|| {
        let mut records = alloc::vec::Vec::new();
        records
            .try_reserve_exact(extra)
            .map_err(|_| ReserveError::Allocation)?;
        for _ in 0..extra {
            records.push(PerCpu::new());
        }
        Ok(records)
    });
    match reserved {
        Ok(records) if records.len() >= extra => Ok(()),
        Ok(_) => Err(ReserveError::AlreadyReservedTooSmall),
        Err(error) => Err(*error),
    }
}

/// 逻辑下标为 `cpu` 的每核数据（越界返回 `None`）。
/// Per-CPU record of logical index `cpu`.
pub fn get(cpu: usize) -> Option<&'static PerCpu> {
    if let Some(record) = BOOTSTRAP_CPUS_DATA.get(cpu) {
        return Some(record);
    }
    let extra = cpu.checked_sub(BOOTSTRAP_CPUS)?;
    EXTRA_CPUS.get()?.as_ref().ok()?.get(extra)
}

/// 本处理器的每核数据。
/// Per-CPU record of the executing processor.
pub fn this() -> &'static PerCpu {
    let index = arch::cpu_index();
    get(index).unwrap_or_else(|| {
        crate::kprintln!(
            "[JSR-SMP] reject=cpu_index_out_of_range index={} max={}",
            index,
            BOOTSTRAP_CPUS
                + EXTRA_CPUS
                    .get()
                    .and_then(|records| records.as_ref().ok())
                    .map_or(0, |records| records.len())
        );
        arch::halt_forever()
    })
}
