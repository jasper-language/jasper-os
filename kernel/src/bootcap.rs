//! 启动期容量的内核侧：读镜像里的启动容量记录，合成并校验对象表 / 任务表 / 实时表的容量。
//! Kernel side of boot-time capacities: read the capacity record and validate the table sizes.
//!
//! # 流程（堆就绪后、其他处理器上线前，由 `capacity` 阶段调用 [`validate`] 一次）
//! 1. 读取 [`RECORD`]（宿主工具可在不重新编译的情况下改写它，见 `xtask bootcap`）；记录损坏 ⇒ 拒绝启动；
//! 2. 以生效配置档的容量为默认值、叠加记录里的覆盖值，经 `kernel_core::capacity::resolve` 检查
//!    范围、一致性与内存预算；不通过 ⇒ 打印结构化原因并拒绝启动；
//! 3. 保存已批准的容量，由 `core`、`sched`、`realtime` 模块的激活函数分别安装对象表、任务表和实时表。
//!
//! # 为什么拒绝启动而不是「降级到默认值」
//! 容量是部署者声明的约束。悄悄换成别的值会让后面所有配额、调度与验收判定建立在错误前提上；
//! 明确失败、说清哪一项为什么不行，才能让部署者改对配置。
//!
//! # 结构化事件
//! * `[JSR-CAP] boot source=<default|override> objects=<n> tasks=<n> rt=<n> task_stacks=<n> mem_limit=<字节>`
//! * `[JSR-CAP] reject field=<名> value=<值> min=<下限> max=<上限> reason=<原因>`（随后 `[JSR-EXIT] failure boot_capacity`）

use alloc::boxed::Box;
use alloc::vec::Vec;

use kernel_core::capacity::{self, BootCapacity, CapError, MemoryCost, Overrides, RECORD_LEN};
use spin::Once;

use crate::arch::ExitStatus;
use crate::config::ACTIVE;
use crate::kprintln;

/// 已校验的容量与来源。Validated capacity and its source.
#[derive(Clone, Copy)]
struct Plan {
    capacity: BootCapacity,
    source: capacity::Source,
}

static PLAN: Once<Plan> = Once::new();
static HEAP_SLACK: Once<usize> = Once::new();

/// 镜像里的启动容量记录。默认「不覆盖」（全部取配置档默认值）；宿主工具按记录标记定位并改写。
/// `#[used]` 保证即使内核代码只经易失读取访问它，链接器也不会丢弃。
#[used]
static RECORD: [u8; RECORD_LEN] = capacity::encode(Overrides { objects: None, tasks: None, rt: None });

/// 以易失方式读取记录：编译器不能把它当作常量折叠掉（镜像里的字节可能已被宿主工具改写）。
fn read_record() -> [u8; RECORD_LEN] {
    // SAFETY：RECORD 是有效、对齐的静态数组，读取不产生别名问题。
    unsafe { core::ptr::read_volatile(&RECORD) }
}

/// 分配 `n` 项并逐项用 `fill` 初始化。内核堆不足返回 `None`。
/// Allocate and initialise `n` items, returning ownership to the caller.
pub fn try_boxed<T>(n: usize, mut fill: impl FnMut() -> T) -> Option<Box<[T]>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).ok()?;
    for _ in 0..n {
        v.push(fill());
    }
    Some(v.into_boxed_slice())
}

/// 分配 `n` 项并逐项用 `fill` 初始化，之后常驻（启动期表存储，永不释放）。内核堆不足返回 `None`。
/// Allocate and leak boot-time table storage.
pub fn try_leak<T>(n: usize, fill: impl FnMut() -> T) -> Option<&'static mut [T]> {
    try_boxed(n, fill).map(Box::leak)
}

/// 三张表合计可用的内存预算：堆上限减去 IPC 全系统配额的两倍。
/// 配置档已要求「IPC 全系统字节配额 × 2 ≤ 堆上限」，这里把同样的余量留给运行期的消息体与其他分配。
fn mem_limit() -> usize {
    (ACTIVE.memory.heap_max as usize).saturating_sub(2 * ACTIVE.ipc.max_total_bytes)
}

fn cost() -> MemoryCost {
    MemoryCost {
        per_object: crate::kobj::BYTES_PER_OBJECT,
        per_task: crate::sched::BYTES_PER_TASK,
        per_rt: crate::rt::BYTES_PER_RT,
        mem_limit: mem_limit(),
    }
}

fn reject(e: CapError) -> ! {
    kprintln!(
        "[JSR-CAP] reject field={} value={} min={} max={} reason={}",
        e.field,
        e.value,
        e.min,
        e.max,
        e.reason.as_str()
    );
    kprintln!("[JSR-EXIT] failure boot_capacity");
    crate::kmain::stop_boot(ExitStatus::Failure)
}

/// 读取并校验启动期容量，保存批准结果而不安装任何表；任何失败都拒绝启动（不返回）。
/// Resolve and validate boot capacities; table installation belongs to module activation.
pub fn validate() -> BootCapacity {
    let overrides = match capacity::parse(&read_record()) {
        Ok(ov) => ov,
        Err(e) => {
            kprintln!("[JSR-CAP] reject field=record value=0 min=0 max=0 reason={}", e.as_str());
            kprintln!("[JSR-EXIT] failure boot_capacity");
            crate::kmain::stop_boot(ExitStatus::Failure)
        }
    };
    let (cap, source) = match capacity::resolve(ACTIVE.boot_capacity(), overrides, cost()) {
        Ok(r) => r,
        Err(e) => reject(e),
    };
    let (_, heap_slack, _, _) = crate::mm::heap::stats();
    HEAP_SLACK.call_once(|| heap_slack);
    PLAN.call_once(|| Plan { capacity: cap, source });
    cap
}

/// `capacity` 阶段批准、等待模块激活安装的容量。
/// Capacity approved by the stage and awaiting module activation.
pub fn requested() -> Result<BootCapacity, &'static str> {
    PLAN.get().map(|p| p.capacity).ok_or("boot capacity not validated")
}

/// 模块安装完成后恢复堆余量；失败只报告，不改变已经安装的表。
/// Restore heap headroom after module activation; a failure is reported without changing tables.
pub fn restore_heap() {
    let Some(heap_slack) = HEAP_SLACK.get().copied() else { return };
    if crate::mm::heap::ensure_free(heap_slack).is_err() {
        kprintln!("[JSR-SCHED] capacity heap_slack_restore_failed want={}", heap_slack);
    }
}

/// 所有服务激活完成后报告生效容量与真实表大小。
/// Report effective capacities and actual installed sizes after all activations.
pub fn report_boot() {
    let Some(plan) = PLAN.get() else { return };
    kprintln!(
        "[JSR-CAP] boot source={} objects={} tasks={} rt={} task_stacks={} mem_limit={}",
        plan.source.as_str(),
        crate::kobj::capacity(),
        crate::sched::slots(),
        crate::rt::capacity(),
        crate::sched::capacity(),
        mem_limit()
    );
}
