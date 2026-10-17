//! jasper-os 内核纯机制库（`kernel-core`）。
//!
//! # 职责
//! 提供与硬件、ISA、引导方式全部无关的内核机制：
//! * [`meta`]   —— 接口元数据（名字、版本、所需 Rights、副作用、稳定性、中文显示名）
//! * [`object`] —— 对象标识、[`object::Rights`] 位掩码、带世代计数的句柄表、对象管理器
//! * [`wait`]   —— 可等待对象（事件、定时器）与等待集合；时间源抽象为 trait
//! * [`frame`]  —— 物理页帧分配（与引导协议无关的内存图 + 位图分配器，M2.1）
//! * [`paging`] —— 架构无关的页映射契约（虚拟页、中立权限位、PageMapper，M2.2）
//! * [`heap`]   —— 堆分配算法（按地址排序空闲链表 + 首次适配 + 合并，M2.3）
//! * [`io`]     —— 异步 I/O 的**唯一**形态：提交 → 完成（ring）；后端可替换
//! * [`memory`] —— 虚拟内存区域与地址空间记账（真实页表在内核的 `arch/` 与后续 M2.x）
//! * [`module`] —— 编译期模块描述符 + 依赖检查 + 顺序装载/逆序卸载
//! * [`trap`]   —— 陷入帧与「名字 → 处理函数」的系统调用分发表
//! * [`trace`]  —— 无堆环形缓冲、ID 分配器、结构化事件追踪器
//! * [`sync`]   —— 自旋锁
//!
//! # 边界（为什么这样分）
//! * 只依赖 `core`：`#![no_std]`，测试时才链接 `std`（`cfg_attr(not(test), no_std)`），
//!   因此 `cargo test -p kernel-core` 能在宿主上直接运行全部单元测试。
//! * 不定义 `#[panic_handler]`：它是**二进制**的职责（内核在 `kernel/src/panic.rs` 里定义），
//!   库若定义会与内核冲突。
//! * 不出现 POSIX 概念（fd / errno / fork / VFS）：资源一律经 Handle + Rights；
//!   错误一律是带 `system.<领域>.error.<代码>` 名字的枚举，不用整数 errno。
//! * 不出现任何 ISA 代码：中断开关、时钟读取等经 trait 由调用者注入。
//!
//! 命名遵守系统接口的「.」分层命名约定：对外标识符为 `system.<领域>.<对象>.<动作>`，
//! 本 crate 内的 Rust 模块名只是代码组织，不是接口。
#![cfg_attr(not(test), no_std)]

pub mod frame;
pub mod heap;
pub mod io;
pub mod memory;
pub mod meta;
pub mod paging;
pub mod module;
pub mod object;
pub mod sync;
pub mod trace;
pub mod trap;
pub mod wait;
