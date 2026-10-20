//! 系统接口查表：由 `build.rs` 依据 `abi/system-ids.txt` 生成的常量与条目表。
//! System-interface table generated from `abi/system-ids.txt`.
//!
//! 本文件只定义条目类型并 `include!` 生成代码；编号从不在这里手写，也从不由生成器分配。

use kernel_core::meta::Effects;

/// 条目种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiKind {
    /// 可调用的操作。
    Op,
    /// 错误码（系统调用以 `-(ID)` 返回）。
    Error,
}

/// 一条登记记录（编译期常量）。
#[derive(Debug, Clone, Copy)]
pub struct AbiEntry {
    /// 稳定 ID。
    pub id: u32,
    /// 种类。
    pub kind: AbiKind,
    /// 规范名。
    pub name: &'static str,
    /// 主版本。
    pub version: u16,
    /// 副作用分级。
    pub effects: Effects,
    /// 中文显示名。
    pub display_zh: &'static str,
    /// 英文显示名（登记表必填；构建期生成的错误渲染表也取这一列）。English display name.
    pub display_en: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/abi_generated.rs"));

/// 按 ID 查找操作条目（错误码不可调用）。
pub fn op(id: u64) -> Option<&'static AbiEntry> {
    ENTRIES.iter().find(|e| e.kind == AbiKind::Op && e.id as u64 == id)
}

/// 按 ID 查找任意条目（诊断与错误名显示用）。
pub fn entry(id: u32) -> Option<&'static AbiEntry> {
    ENTRIES.iter().find(|e| e.id == id)
}
