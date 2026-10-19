//! 用户态故障隔离（M3.1，架构无关）。
//!
//! 规则：**用户态触发的异常只终止该任务，内核继续运行。** 内核态异常仍然是致命的（停机）。
//! arch 的异常入口判断「来自用户态」后调用 [`on_user_fault`]；这里记录事件、打印结构化标记，
//! 然后经调度器结束当前任务并切走——被打断的用户上下文与该任务的内核栈一起被丢弃。
//!
//! 事件名：`system.task.faulted`（命名约定：事件名末段为过去分词）。

use crate::sync::IrqSpinLock;
use crate::{kprintln, sched};

/// 用户态故障种类（中立；arch 负责把具体异常向量翻译过来）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserFaultKind {
    /// 访问了未映射或无权限的内存。
    PageFault,
    /// 执行了特权指令或违反了段/保护规则。
    ProtectionFault,
    /// 执行了无效指令。
    InvalidInstruction,
}

impl UserFaultKind {
    /// 规范小写名。
    pub const fn name(self) -> &'static str {
        match self {
            UserFaultKind::PageFault => "page_fault",
            UserFaultKind::ProtectionFault => "protection_fault",
            UserFaultKind::InvalidInstruction => "invalid_instruction",
        }
    }
}

/// 一次用户态故障的记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserFault {
    /// 种类。
    pub kind: UserFaultKind,
    /// 出错指令地址。
    pub ip: u64,
    /// 相关数据地址（缺页时为访问地址，否则为 0）。
    pub addr: u64,
}

/// 最近一次用户态故障与累计次数。
static LAST: IrqSpinLock<(Option<UserFault>, u32)> = IrqSpinLock::ranked(crate::lockorder::FAULT_LAST, (None, 0));

/// 用户态异常入口（arch 调用；永不返回）。
pub fn on_user_fault(fault: UserFault) -> ! {
    {
        let mut g = LAST.lock();
        g.0 = Some(fault);
        g.1 += 1;
    }
    let (id, name) = sched::current();
    kprintln!(
        "[JSR-USER] event=system.task.faulted task={} id={} kind={} ip={:#x} addr={:#x} action=terminated",
        name,
        id.0,
        fault.kind.name(),
        fault.ip,
        fault.addr
    );
    // 用户态故障终止**整个进程**（只杀该进程，内核与其他进程不受影响）：先发起进程终止（退出码 -1，
    // 其余线程在下一个调度点停止），再经线程退出路径结束本线程。不属于任何进程的探针任务只结束自己。
    if let Some(pid) = crate::proc::current_process() {
        crate::proc::begin_exit(pid, -1);
    }
    crate::proc::thread_exit(-1, "fault")
}

/// 最近一次用户态故障。
pub fn last() -> Option<UserFault> {
    LAST.lock().0
}

/// 用户态故障累计次数。
pub fn count() -> u32 {
    LAST.lock().1
}
