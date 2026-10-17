//! 接口元数据：每个对外名字（操作、事件、错误、类型）携带的结构化描述。
//!
//! # 为什么需要
//! 设计约束「原生 AI：系统接口带结构化元数据」与命名约定：系统调用、IPC、对象都必须能被
//! 机器读懂——它是谁（名字/版本）、要什么权限、有什么副作用、稳定到什么程度、中文怎么显示。
//! 本模块只定义**形状**；M3.2 会在构建期从同一份数据生成稳定数字 ID 表与 `name-lint`。
//!
//! # 边界
//! 纯数据，`const` 可构造，零运行时开销；不做字符串解析、不分配内存。

use crate::object::Rights;

/// 名字的角色（命名约定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 可调用的操作，末段是受控动词（`system.handle.close`）。
    Op,
    /// 可订阅的事件，末段是过去分词（`system.module.loaded`）。
    Event,
    /// 错误，形如 `<领域>.error.<代码>`。
    Error,
    /// 类型，末段 PascalCase（`system.async.Completion`）。
    Type,
}

/// 副作用分级（命名约定 `effects`）。AI/工具据此判断能否安全重试或自动执行。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effects {
    /// 无副作用（纯查询以外也不改变任何状态）。
    None,
    /// 只读取状态。
    Read,
    /// 修改状态，可撤销或可重复。
    Write,
    /// 不可逆（销毁、退出等）。
    Irreversible,
}

impl Effects {
    /// 元数据中的规范小写写法。
    pub const fn as_str(self) -> &'static str {
        match self {
            Effects::None => "none",
            Effects::Read => "read",
            Effects::Write => "write",
            Effects::Irreversible => "irreversible",
        }
    }
}

/// 稳定性（命名约定）。稳定性只写在元数据里，从不写进名字。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    /// 刚引入，可能变化。
    Experimental,
    /// 稳定：只增不改。
    Stable,
    /// 已弃用：名字与 ID 保留，调用产生弃用事件。
    Deprecated,
    /// 已退役：调用返回 `system.error.unsupported`，名字与 ID 永不复用。
    Retired,
}

/// 一个对外名字的完整元数据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceMeta {
    /// 规范名，如 `system.handle.close`（仅 ASCII，见命名约定）。
    pub name: &'static str,
    /// 主版本（不兼容变更 = 新版本）。
    pub version: u16,
    /// 角色。
    pub kind: Kind,
    /// 调用所需的句柄权限（无句柄参数时为 [`Rights::NONE`]）。
    pub rights: Rights,
    /// 副作用分级。
    pub effects: Effects,
    /// 稳定性。
    pub stability: Stability,
    /// 中文显示名（命名约定：中文是一等显示语言，`display.zh-CN` 必填）。
    pub display_zh: &'static str,
}

impl InterfaceMeta {
    /// 构造一个 `stable`、版本 1 的操作元数据（最常见的情形）。
    pub const fn op(name: &'static str, rights: Rights, effects: Effects, display_zh: &'static str) -> Self {
        InterfaceMeta {
            name,
            version: 1,
            kind: Kind::Op,
            rights,
            effects,
            stability: Stability::Stable,
            display_zh,
        }
    }

    /// 改为 `experimental`（链式构造用）。
    pub const fn experimental(mut self) -> Self {
        self.stability = Stability::Experimental;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_defaults_are_stable_v1() {
        let m = InterfaceMeta::op("system.handle.close", Rights::NONE, Effects::Write, "句柄·关闭");
        assert_eq!(m.kind, Kind::Op);
        assert_eq!(m.version, 1);
        assert_eq!(m.stability, Stability::Stable);
        assert_eq!(m.experimental().stability, Stability::Experimental);
        assert_eq!(Effects::Irreversible.as_str(), "irreversible");
        assert!(Effects::Write < Effects::Irreversible);
    }
}
