//! 启动期容量的内核侧：读镜像里的启动容量记录，合成并校验对象表 / 任务表 / 实时表的容量，然后安装。
//! Kernel side of boot-time capacities: read the image's capacity record, validate, install the tables.
//!
//! # 流程（堆就绪后、其他处理器上线前，由 `kmain` 调用 [`apply`] 一次）
//! 1. 读取 [`RECORD`]（宿主工具可在不重新编译的情况下改写它，见 `xtask bootcap`）；记录损坏 ⇒ 拒绝启动；
//! 2. 以生效配置档的容量为默认值、叠加记录里的覆盖值，经 `kernel_core::capacity::resolve` 检查
//!    范围、一致性与内存预算；不通过 ⇒ 打印结构化原因并拒绝启动；
//! 3. 依次安装对象表、实时表存储，并把调度器任务表扩到启动期容量（含内核栈）；任一步失败 ⇒ 拒绝启动。
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

use kernel_core::capacity::{self, BootCapacity, CapError, CapReason, MemoryCost, Overrides, RECORD_LEN};

use crate::arch::{self, ExitStatus};
use crate::config::ACTIVE;
use crate::kprintln;

/// 镜像里的启动容量记录。默认「不覆盖」（全部取配置档默认值）；宿主工具按记录标记定位并改写。
/// `#[used]` 保证即使内核代码只经易失读取访问它，链接器也不会丢弃。
#[used]
static RECORD: [u8; RECORD_LEN] = capacity::encode(Overrides { objects: None, tasks: None, rt: None });

/// 以易失方式读取记录：编译器不能把它当作常量折叠掉（镜像里的字节可能已被宿主工具改写）。
fn read_record() -> [u8; RECORD_LEN] {
    // SAFETY：RECORD 是有效、对齐的静态数组，读取不产生别名问题。
    unsafe { core::ptr::read_volatile(&RECORD) }
}

/// 分配 `n` 项并逐项用 `fill` 初始化，之后常驻（启动期表存储，永不释放）。内核堆不足返回 `None`。
pub fn try_leak<T>(n: usize, mut fill: impl FnMut() -> T) -> Option<&'static mut [T]> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).ok()?;
    for _ in 0..n {
        v.push(fill());
    }
    Some(Box::leak(v.into_boxed_slice()))
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
    arch::exit_emulator(ExitStatus::Failure)
}

fn reject_install(table: &'static str, value: usize, why: &'static str) -> ! {
    kprintln!("[JSR-CAP] reject field={} value={} min=0 max=0 reason={}", table, value, why);
    kprintln!("[JSR-EXIT] failure boot_capacity");
    arch::exit_emulator(ExitStatus::Failure)
}

/// 读取、校验并安装启动期容量；成功返回生效容量，任何失败都拒绝启动（不返回）。
pub fn apply() -> BootCapacity {
    let overrides = match capacity::parse(&read_record()) {
        Ok(ov) => ov,
        Err(e) => {
            kprintln!("[JSR-CAP] reject field=record value=0 min=0 max=0 reason={}", e.as_str());
            kprintln!("[JSR-EXIT] failure boot_capacity");
            arch::exit_emulator(ExitStatus::Failure)
        }
    };
    let (cap, source) = match capacity::resolve(ACTIVE.boot_capacity(), overrides, cost()) {
        Ok(r) => r,
        Err(e) => reject(e),
    };
    match crate::kobj::install(cap.objects) {
        Ok(_) => {}
        Err(None) => reject_install("objects", cap.objects, CapReason::ExceedsMemory.as_str()),
        Err(Some(e)) => reject_install("objects", cap.objects, e.as_str()),
    }
    match crate::rt::install(cap.rt) {
        Ok(_) => {}
        Err(None) => reject_install("rt", cap.rt, CapReason::ExceedsMemory.as_str()),
        Err(Some(e)) => reject_install("rt", cap.rt, e.as_str()),
    }
    let stacks = match crate::sched::grow(cap.tasks) {
        Ok(n) if n == cap.tasks => n,
        Ok(n) => reject_install("tasks", n, CapReason::ExceedsMemory.as_str()),
        Err(crate::sched::GrowError::OutOfMemory { available }) => reject_install("tasks", available, CapReason::ExceedsMemory.as_str()),
        Err(crate::sched::GrowError::Shrink) => reject_install("tasks", cap.tasks, "shrink"),
        Err(crate::sched::GrowError::NotQuiescent) => reject_install("tasks", cap.tasks, "not_quiescent"),
    };
    kprintln!(
        "[JSR-CAP] boot source={} objects={} tasks={} rt={} task_stacks={} mem_limit={}",
        source.as_str(),
        crate::kobj::capacity(),
        crate::sched::slots(),
        crate::rt::capacity(),
        stacks,
        mem_limit()
    );
    cap
}
