//! L1 模块表（SPEC §12.2）：依赖判定所依据的「已装入且运行中」模块、`stop` 的前提、beta 对卸载请求的固定答复。
//! The L1 module table: dependency satisfaction, stop preconditions and the beta reply to unload requests.
//!
//! 只管决策、不碰内存；映射与调用由装载器做。不变量：**运行中模块的每项依赖都由运行中的模块满足**——
//! 依赖只在装入时按运行中的模块判定，运行中的依赖者存在时拒绝 `stop`，模块表项从不移除（beta 没有卸载）。

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::manifest::{Dependency, Lifecycle, Manifest};

/// 模块在表中的编号（按装入顺序）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleId(pub usize);

/// 模块的阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// `init` 与 `start` 都已成功，模块在服务。
    Running,
    /// 已 `stop`，不再服务；beta 中映像仍保留。
    Stopped,
}

/// beta 对卸载请求的答复（SPEC §12.2）：两种都不卸载，也不得报告为已卸载。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnloadReply {
    /// `plugin`：推迟，模块保持映射。
    Deferred,
    /// `system`：拒绝。
    Refused,
}

/// `stop` 失败的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopError {
    /// 没有这个模块。
    UnknownModule,
    /// 已经停止过（`jaso_stop` 不会再被调用）。
    AlreadyStopped,
    /// 仍有运行中的模块依赖它（附依赖者的名字）；未调用 `jaso_stop`，模块继续服务。
    Dependent(String),
    /// `jaso_stop` 返回了非 0；模块同样已经停止服务。
    Hook(i32),
}

#[derive(Debug)]
struct Entry {
    name: String,
    version: (u32, u32, u32),
    lifecycle: Lifecycle,
    depends: Vec<String>,
    phase: Phase,
}

/// L1 模块表。
#[derive(Debug, Default)]
pub struct Registry {
    entries: Vec<Entry>,
}

impl Registry {
    /// 空表。
    pub const fn new() -> Registry {
        Registry { entries: Vec::new() }
    }

    /// 表中模块数（含已停止的）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 表是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 是否有运行中的模块满足这项依赖（已停止的模块不算）。
    pub fn satisfies(&self, d: &Dependency<'_>) -> bool {
        self.entries.iter().any(|e| e.phase == Phase::Running && e.name == d.name && d.range.is_none_or(|r| r.contains(e.version)))
    }

    /// 表中是否已有这个名字（含已停止的：beta 没有卸载，名字不复用）。
    pub fn contains(&self, name: &str) -> bool {
        self.entries.iter().any(|e| e.name == name)
    }

    /// 登记一个 `init` 与 `start` 都成功的模块。调用者须已确认依赖满足、名字未被占用。
    pub fn insert(&mut self, m: &Manifest<'_>) -> ModuleId {
        self.entries.push(Entry {
            name: m.name.to_string(),
            version: m.version,
            lifecycle: m.lifecycle,
            depends: m.depends().map(|d| d.name.to_string()).collect(),
            phase: Phase::Running,
        });
        ModuleId(self.entries.len() - 1)
    }

    /// 阶段（没有这个模块为 `None`）。
    pub fn phase(&self, id: ModuleId) -> Option<Phase> {
        self.entries.get(id.0).map(|e| e.phase)
    }

    /// 判定并记录一次 `stop`：成功返回后模块已是 [`Phase::Stopped`]，调用者随即调用 `jaso_stop`。
    pub fn begin_stop(&mut self, id: ModuleId) -> Result<(), StopError> {
        let e = self.entries.get(id.0).ok_or(StopError::UnknownModule)?;
        if e.phase == Phase::Stopped {
            return Err(StopError::AlreadyStopped);
        }
        if let Some(dep) = self.entries.iter().find(|o| o.phase == Phase::Running && o.depends.contains(&e.name)) {
            return Err(StopError::Dependent(dep.name.clone()));
        }
        self.entries[id.0].phase = Phase::Stopped;
        Ok(())
    }

    /// 卸载请求的答复；不改变任何状态（没有这个模块为 `None`）。
    pub fn unload_request(&self, id: ModuleId) -> Option<UnloadReply> {
        self.entries.get(id.0).map(|e| match e.lifecycle {
            Lifecycle::Plugin => UnloadReply::Deferred,
            Lifecycle::System => UnloadReply::Refused,
        })
    }

    /// 运行中模块的不变量：每项依赖都有同名的运行中模块。
    pub fn dependencies_hold(&self) -> bool {
        self.entries
            .iter()
            .filter(|e| e.phase == Phase::Running)
            .all(|e| e.depends.iter().all(|d| self.entries.iter().any(|o| o.phase == Phase::Running && o.name == *d)))
    }
}
