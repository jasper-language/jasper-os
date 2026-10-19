//! 内核全局锁顺序登记表：所有子系统级全局锁在此登记级别，加锁时按级别检查顺序。
//! Kernel lock-order registry: every subsystem-wide global lock is ranked here.
//!
//! # 规则
//! * 持有级别 r 的锁时，只能再获取级别 **大于** r 的锁；同级锁不可重入。
//! * 级别越小越外层：进程登记表 → 对象表 → 固定帧 → 调度器 → 诊断记录 → 内存压力 → 内核堆 → 页帧 →
//!   中断路由 → 中断预算 → 跟踪 → 服务分片 → 控制台。
//! * 新增全局锁必须在此登记并放在它实际嵌套位置上；登记表在编译期校验（严格递增、名称唯一）。
//!
//! # 边界
//! 检查机制在 `kernel_core::lockorder`（宿主已测），每核的持有集合在每核数据里，
//! 加锁 / 解锁处的调用在 `sync::IrqSpinLock`。本文件只有登记数据与按级别查名称。
//! 演练专用的局部锁不登记（不参与全局顺序，且持有期间不获取其他锁）。
//!
//! # 原因
//! 多处理器下没有大内核锁，各子系统各自一把锁；只要所有处理器都按同一条链加锁就不会互相等待成环。

use kernel_core::lockorder::{validate_registry, LockClass};

/// 进程登记表（进程与成员线程）。
/// Process registry.
pub const PROC_REGISTRY: LockClass = LockClass::new(2, "system.process.registry");
/// 内核对象表。
/// Kernel object table.
pub const OBJECT_TABLE: LockClass = LockClass::new(4, "system.object.table");
/// 固定（pin）页帧记录。
/// Pinned frame records.
pub const MEMORY_PINS: LockClass = LockClass::new(6, "system.memory.pins");
/// 调度器（任务表、运行队列、时钟记账）。
/// Scheduler state.
pub const SCHED: LockClass = LockClass::new(8, "system.sched");
/// 最近一次用户态故障记录。
/// Last user fault record.
pub const FAULT_LAST: LockClass = LockClass::new(10, "system.fault.last");
/// 最近一次线程退出记录。
/// Last thread exit record.
pub const SYSCALL_LAST_EXIT: LockClass = LockClass::new(11, "system.syscall.last_exit");
/// 内存压力参数与统计。
/// Memory-pressure state.
pub const MEMORY_PRESSURE: LockClass = LockClass::new(13, "system.memory.pressure");
/// 内核堆。
/// Kernel heap.
pub const MEMORY_HEAP: LockClass = LockClass::new(15, "system.memory.heap");
/// 物理页帧分配器。
/// Physical frame allocator.
pub const MEMORY_FRAME: LockClass = LockClass::new(17, "system.memory.frame");
/// 设备中断路由表（亲和、目标处理器、均衡策略）。
/// Device-interrupt routing table.
pub const IRQ_ROUTING: LockClass = LockClass::new(18, "system.irq.routing");
/// 每核设备中断预算。
/// Per-processor device-interrupt quota.
pub const IRQ_QUOTA: LockClass = LockClass::new(19, "system.irq.quota");
/// 内核跟踪缓冲。
/// Kernel trace buffer.
pub const TRACE: LockClass = LockClass::new(20, "system.trace");
/// 系统服务的分片队列（每个分片一把，同级，彼此从不嵌套）。
/// Shard queues of sharded system services.
pub const SERVICE_SHARD: LockClass = LockClass::new(22, "system.service.shard");
/// 控制台输出（最内层：持有它时不再获取任何锁）。
/// Console output (innermost).
pub const CONSOLE: LockClass = LockClass::new(24, "system.console");

/// 登记表（按级别递增）。
/// The registry, in ascending rank order.
pub const REGISTRY: &[LockClass] = &[
    PROC_REGISTRY,
    OBJECT_TABLE,
    MEMORY_PINS,
    SCHED,
    FAULT_LAST,
    SYSCALL_LAST_EXIT,
    MEMORY_PRESSURE,
    MEMORY_HEAP,
    MEMORY_FRAME,
    IRQ_ROUTING,
    IRQ_QUOTA,
    TRACE,
    SERVICE_SHARD,
    CONSOLE,
];

// 编译期校验：登记表不合法时内核无法构建。
const _: () = assert!(validate_registry(REGISTRY).is_ok(), "锁顺序登记表不合法");

/// 级别 `rank` 对应的登记名称（未登记时 `"unregistered"`）。
/// Registered name of `rank`.
pub fn name_of(rank: u8) -> &'static str {
    REGISTRY.iter().find(|c| c.rank == rank).map(|c| c.name).unwrap_or("unregistered")
}
