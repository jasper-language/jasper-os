//! 陷入与系统调用分发（机制部分，架构无关）。
//!
//! # 职责
//! * [`TrapFrame`]：一次系统调用的架构无关描述——谁（任务）、调什么（名字）、参数
//! * [`SyscallEntry`]：分发表的一项 = 接口元数据（名字/版本/Rights/副作用/中文名）+ 处理函数
//! * [`Dispatcher`]：按名字查静态表并调用；未知名字返回**稳定**错误 `system.error.unsupported`；
//!   进入与退出各通知一次观察者（Observer 模式，内核把它接到串口/trace）
//!
//! # 边界
//! * 陷入指令、寄存器到参数的搬运都在 `arch/<isa>/`（M3.2）；这里只看到已经解码好的 [`TrapFrame`]。
//! * Phase 1 当前阶段按名字查表；M3.2 会在构建期把名字映射为稳定数字 ID（陷入时只传 ID），
//!   届时本模块的表结构与元数据保持不变，只增加 ID 列。
//! * 不使用整数 errno：错误是带规范名的枚举。

use crate::meta::InterfaceMeta;
use crate::object::HandleError;

/// 最多携带的参数个数。
pub const MAX_ARGS: usize = 4;

/// 架构无关的系统调用帧。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapFrame<'a> {
    /// 发起调用的任务。
    pub task_id: u64,
    /// 规范名，如 `system.handle.close`。
    pub syscall_name: &'a str,
    /// 参数（句柄值、长度等，含义由各调用的元数据定义）。
    pub args: [u64; MAX_ARGS],
}

impl<'a> TrapFrame<'a> {
    /// 构造帧。
    pub const fn new(task_id: u64, syscall_name: &'a str, args: [u64; MAX_ARGS]) -> Self {
        TrapFrame { task_id, syscall_name, args }
    }
}

/// 系统调用错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    /// 没有这个调用（或已退役）。
    Unsupported,
    /// 参数非法。
    InvalidArgument,
    /// 句柄错误（无效 / 权限不足 / 表满）。
    Handle(HandleError),
}

impl SysError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            SysError::Unsupported => "system.error.unsupported",
            SysError::InvalidArgument => "system.error.invalid_argument",
            SysError::Handle(e) => e.name(),
        }
    }
}

impl From<HandleError> for SysError {
    fn from(e: HandleError) -> Self {
        SysError::Handle(e)
    }
}

/// 系统调用结果：成功时返回一个 64 位值。
pub type SysResult = Result<u64, SysError>;

/// 处理函数。
pub type SyscallHandler = fn(&TrapFrame<'_>) -> SysResult;

/// 分发表的一项。
#[derive(Clone, Copy)]
pub struct SyscallEntry {
    /// 接口元数据（名字即查表键）。
    pub meta: InterfaceMeta,
    /// 处理函数。
    pub handler: SyscallHandler,
}

/// 分发过程中的事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrapEvent<'a> {
    /// 进入：任务与调用名。
    Enter { task_id: u64, name: &'a str },
    /// 退出：调用名与结果。
    Exit { task_id: u64, name: &'a str, result: SysResult },
}

/// 分发观察者。
pub type TrapObserver = fn(&TrapEvent<'_>);

/// 分发表校验错误（构建期 `name-lint` 的最小子集，完整版见 M3.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    /// 同一名字出现两次。
    Duplicate(&'static str),
    /// 缺少中文显示名。
    MissingDisplay(&'static str),
}

/// 系统调用分发器（持有静态表的引用）。
pub struct Dispatcher {
    table: &'static [SyscallEntry],
    observer: Option<TrapObserver>,
}

impl Dispatcher {
    /// 以静态表创建。
    pub const fn new(table: &'static [SyscallEntry]) -> Self {
        Dispatcher { table, observer: None }
    }

    /// 安装观察者。
    pub fn set_observer(&mut self, o: TrapObserver) {
        self.observer = Some(o);
    }

    /// 校验表：名字唯一、`display_zh` 非空。
    pub fn validate(&self) -> Result<usize, TableError> {
        for (i, e) in self.table.iter().enumerate() {
            if e.meta.display_zh.is_empty() {
                return Err(TableError::MissingDisplay(e.meta.name));
            }
            if self.table[..i].iter().any(|p| p.meta.name == e.meta.name) {
                return Err(TableError::Duplicate(e.meta.name));
            }
        }
        Ok(self.table.len())
    }

    /// 按名字查元数据。
    pub fn lookup(&self, name: &str) -> Option<&'static SyscallEntry> {
        self.table.iter().find(|e| e.meta.name == name)
    }

    /// 全部表项（供能力发现 / Schema 导出）。
    pub fn entries(&self) -> &'static [SyscallEntry] {
        self.table
    }

    /// 分发一次系统调用。未知名字返回 [`SysError::Unsupported`]，且同样产生 enter/exit 事件。
    pub fn dispatch(&self, frame: &TrapFrame<'_>) -> SysResult {
        let notify = |e: TrapEvent<'_>| {
            if let Some(o) = self.observer {
                o(&e);
            }
        };
        notify(TrapEvent::Enter { task_id: frame.task_id, name: frame.syscall_name });
        let result = match self.lookup(frame.syscall_name) {
            Some(e) => (e.handler)(frame),
            None => Err(SysError::Unsupported),
        };
        notify(TrapEvent::Exit { task_id: frame.task_id, name: frame.syscall_name, result });
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::Effects;
    use crate::object::Rights;
    use std::sync::Mutex;

    fn ping(f: &TrapFrame<'_>) -> SysResult {
        Ok(f.args[0] + 1)
    }
    fn deny(_: &TrapFrame<'_>) -> SysResult {
        Err(HandleError::RightsDenied.into())
    }

    static TABLE: [SyscallEntry; 2] = [
        SyscallEntry { meta: InterfaceMeta::op("x.demo.ping", Rights::NONE, Effects::None, "演示·回声"), handler: ping },
        SyscallEntry {
            meta: InterfaceMeta::op("system.handle.close", Rights::NONE, Effects::Write, "句柄·关闭"),
            handler: deny,
        },
    ];

    #[test]
    fn dispatch_by_name() {
        let d = Dispatcher::new(&TABLE);
        assert_eq!(d.validate(), Ok(2));
        assert_eq!(d.dispatch(&TrapFrame::new(1, "x.demo.ping", [41, 0, 0, 0])), Ok(42));
        let e = d.dispatch(&TrapFrame::new(1, "system.handle.close", [0; 4])).unwrap_err();
        assert_eq!(e.name(), "system.handle.error.rights_denied");
    }

    #[test]
    fn unknown_syscall_returns_stable_error() {
        let d = Dispatcher::new(&TABLE);
        let r = d.dispatch(&TrapFrame::new(7, "system.nope.get", [0; 4]));
        assert_eq!(r, Err(SysError::Unsupported));
        assert_eq!(SysError::Unsupported.name(), "system.error.unsupported");
    }

    #[test]
    fn observer_sees_enter_then_exit() {
        static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
        fn obs(e: &TrapEvent<'_>) {
            SEEN.lock().unwrap().push(format!("{:?}", e));
        }
        let mut d = Dispatcher::new(&TABLE);
        d.set_observer(obs);
        d.dispatch(&TrapFrame::new(3, "x.demo.ping", [0; 4])).unwrap();
        let seen = SEEN.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].starts_with("Enter") && seen[1].contains("Ok(1)"));
    }

    #[test]
    fn validate_rejects_duplicates_and_missing_display() {
        static DUP: [SyscallEntry; 2] = [
            SyscallEntry { meta: InterfaceMeta::op("x.demo.ping", Rights::NONE, Effects::None, "甲"), handler: ping },
            SyscallEntry { meta: InterfaceMeta::op("x.demo.ping", Rights::NONE, Effects::None, "乙"), handler: ping },
        ];
        static NODISP: [SyscallEntry; 1] =
            [SyscallEntry { meta: InterfaceMeta::op("x.demo.ping", Rights::NONE, Effects::None, ""), handler: ping }];
        assert_eq!(Dispatcher::new(&DUP).validate(), Err(TableError::Duplicate("x.demo.ping")));
        assert_eq!(Dispatcher::new(&NODISP).validate(), Err(TableError::MissingDisplay("x.demo.ping")));
    }
}
