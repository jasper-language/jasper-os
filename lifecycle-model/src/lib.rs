//! Issue #21 LC-0 生命周期协议的可执行模型。
//! Executable model of the Issue #21 LC-0 lifecycle protocol.
//!
//! 本 crate 属于系统服务层的纯模型，不是内核机制，也不声明新的原生 ABI。
//! 它只冻结更新事务阶段、双槽启动控制和恢复判定，供 LC-2/LC-3 的正式服务复用。
//! This pure system-service model is neither a kernel mechanism nor a new native ABI.
//! It freezes only the update phases, dual-slot boot control, and recovery decisions for LC-2/LC-3.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod boot;
pub mod diagnostics;
pub mod manifest;
pub mod update;

/// 一份启动控制记录的固定线上长度（字节）。
/// Fixed on-wire size of one boot-control record in bytes.
pub const CONTROL_RECORD_BYTES: usize = 180;
