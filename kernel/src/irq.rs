//! 中断分发（架构无关）：逻辑中断线、延迟处理队列、立即处理钩子。
//!
//! 两条路径，对应 Java 原型 `InterruptController` 的语义并加上抢占：
//! 1. **立即路径**（中断上下文）：`on_hardware_irq` 由 arch 的中断入口在 EOI 之后调用；
//!    只做必须立刻做的事——入队、驱动调度器时间片（可能就地抢占）。
//! 2. **延迟路径**（任务/主循环上下文）：`poll_and_handle` 排空队列，执行可以慢的工作（如打印 tick）。
//!
//! Core 只认 [`IrqLine`]（逻辑中断线），不认向量号；向量号 ↔ 中断线的映射在 `arch/<isa>/` 内。

use spin::Mutex;

use crate::{arch, clock, sched};

/// 逻辑中断线。新增设备中断时在这里加一项，并在各 ISA 的中断入口里映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqLine {
    /// 周期定时器（驱动时钟与时间片）。
    Timer,
}

/// 延迟处理队列容量。
const QUEUE_LEN: usize = 64;

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
    enqueue(line);
    if line == IrqLine::Timer {
        sched::on_timer_interrupt();
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
    }
}
