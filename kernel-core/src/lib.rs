//! jasper-os 内核纯机制库（`kernel-core`）。
//!
//! # 职责
//! 提供与硬件、ISA、引导方式全部无关的内核机制：
//! * [`bench`]  —— 基准测量的统计（最近秩百分位）、周期计数器校准与按预算的参数取值规则
//! * [`config`] —— 内核可调参数与构建期配置档（校验 + 逐项列出）
//! * [`capacity`] —— 启动期容量：对象表 / 任务表 / 实时表的容量记录、解析与启动期校验（越界即拒绝启动）
//! * [`meta`]   —— 接口元数据（名字、版本、所需 Rights、副作用、稳定性、中文显示名）
//! * [`objtable`] —— 内核对象表：外部所有权与内部引用分开计数、带世代标识、迭代式清理队列（M4.1）
//! * [`object`] —— 对象标识、[`object::Rights`] 位掩码、带世代计数的句柄表、对象管理器
//! * [`fs`]     —— 与 ext4/JaFS 无关的 FS-0 文件系统契约、命名空间、句柄、持久化与 mmap 世代
//! * [`wait`]   —— 可等待对象（事件、定时器）与等待集合；时间源抽象为 trait
//! * [`abi`]    —— 系统接口登记表：显式稳定 ID 的解析、命名校验与冻结检查（M3.2，构建期使用）
//! * [`abi_version`] —— 原生 ABI 世代：版本真源、用户程序 ABI 章与同主版本兼容判定（issue #8）
//! * [`abi_contract`] —— 按 ABI 主版本发布的契约快照与同主版本只增不改门槛（issue #8）
//! * [`l10n`]   —— 错误文本的本地化渲染：按错误码 ID 二分查找中文 / 英文文本，无状态、无分配
//! * [`elf`]    —— ELF64 静态可执行文件解析与校验（M5.1-pre，机器类型由调用者给出）
//! * [`frame`]  —— 物理页帧分配（与引导协议无关的内存图 + 位图分配器，M2.1）
//! * [`paging`] —— 架构无关的页映射契约（虚拟页、中立权限位、PageMapper，M2.2）
//! * [`pagetable`] —— 多级基数页表的通用遍历（表项位格式与表内存访问由各 ISA 注入）
//! * [`fdt`]    —— 扁平设备树的只读解析（内存图、设备寄存器地址；固件输入按不可信处理）
//! * [`image_header`] —— AArch64 Linux `Image` 头的只读解析与校验（PDA-1；不可信输入）
//! * [`heap`]   —— 堆分配算法（按地址排序空闲链表 + 首次适配 + 合并，M2.3）
//! * [`io`]     —— 异步 I/O 的**唯一**形态：提交 → 完成（ring）；后端可替换
//! * [`dma_quiesce`] —— virtio 拆除裁决：复位结果 + 总线主控读回 ⇒ 释放 / 关总线主控后释放 / 隔离
//! * [`msi`]    —— 每核 MSI 向量池：独立位图、分配 / 释放与拒绝路径
//! * [`async_ring`] —— 异步环的请求状态机：请求 ID、完成信用、终态裁决与事件依赖、取消、历史窗口、closing
//! * [`ring_abi`] —— 异步环的用户态二进制布局（提交记录、完成记录、enter 参数块）
//! * [`memory`] —— 虚拟内存区域与地址空间记账（真实页表在内核的 `arch/` 与后续 M2.x）
//! * [`spawn_abi`] —— `system.process.spawn` 参数块 v2 与无状态准入规则
//! * [`syscall_set`] —— 有界系统调用能力集合（256 位位图，ID 越界显式拒绝）
//! * [`trap`]   —— 陷入帧与「名字 → 处理函数」的系统调用分发表
//! * [`sched`]  —— 调度策略：QoS 四档 + 用量衰减 + 各档最低份额 + 唤醒延迟直方图（宿主可模拟测试）
//! * [`argcase`] —— 系统调用参数用例生成：确定性伪随机数、边界值、避开受保护区间的地址规划（健壮性测试共用）
//! * [`trace`]  —— 无堆环形缓冲、ID 分配器、结构化事件追踪器
//! * [`sync`]   —— 自旋锁
//! * [`smp`]    —— 多处理器：处理器集合与拓扑、启动状态机、核间中断种类、TLB 击落与跨核调用协议
//! * [`acpi`]   —— ACPI 表只读解析（处理器枚举：RSDP → RSDT/XSDT → MADT；固件输入按不可信处理）
//! * [`user_layout`] —— 各指令集的用户私有窗口起点与用户程序装载地址（内核、运行时与构建脚本共用）
//! * [`workload`] —— 原生 Workload 身份、父子资源域、生命周期和成员归属契约（issue #23）
//! * [`sandbox_image`] —— Sandbox 镜像、不可变层、CoW 卷与存储所有权契约
//! * [`sandbox_launch`] —— Sandbox 启动计划、能力衰减与展示专用逻辑视图
//! * [`native_install`] —— 原生包、安装登记、授权、运行主体、数据与更新权分离契约
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

#[cfg(any(test, feature = "ext4-view", feature = "persistent-install"))]
extern crate alloc;

pub mod abi;
pub mod abi_contract;
pub mod arch2;
pub mod abi_version;
pub mod acpi;
pub mod argcase;
pub mod arbiter;
pub mod bench;
pub mod block;
pub mod boot_stage;
pub mod async_ring;
pub mod capacity;
pub mod capability;
pub mod config;
pub mod device;
pub mod display_input;
pub mod deadline;
pub mod drill;
pub mod deadline_forest;
pub mod yield_gate;
pub mod dma_quiesce;
pub mod dma_abi;
pub mod elf;
#[cfg(feature = "ext4-view")]
pub mod ext4_view;
#[cfg(feature = "ext4-write")]
pub mod ext4_write;
pub mod environment;
pub mod ticket;
pub mod task_index;
pub mod task_hot;
pub mod task_lifecycle;
/// Bounded native terminal session queues and close semantics.
pub mod terminal_session;
/// Bounded terminal line editing and command history.
pub mod terminal_editor;
pub mod tick_lease;
pub mod wake_mailbox;
pub mod fdt;
pub mod frame;
pub mod fs;
pub mod fs_prod;
pub mod fault;
pub mod heap;
pub mod image_header;
pub mod interrupt;
pub mod iommu;
pub mod inherited_mutex;
pub mod io;
pub mod irq;
pub mod job;
pub mod l10n;
pub mod lockorder;
pub mod mac;
pub mod memory;
pub mod memory_object;
pub mod memory_abi;
pub mod memory_capability;
pub mod meta;
pub mod msi;
pub mod net;
pub mod net1a;
pub mod net3;
pub mod net4_runtime;
pub mod net4_service;
pub mod numa;
pub mod profile;
pub mod program_caps;
/// 服务装配契约：模块运行时状态、依赖顺序、能力发布与审计（issue #6）。
pub mod assembly;
/// 可撤回能力发布门：读者租约、撤位与排空（issue #6）。
pub mod service_gate;
pub mod paging;
pub mod pagetable;
pub mod pci;
pub mod pio;
pub mod pressure;
pub mod psci;
pub mod ring_abi;
pub mod ring_backend;
pub mod quota;
pub mod rt;
pub mod sbi;
pub mod sched;
pub mod shard;
pub mod smp;
pub mod spawn_abi;
pub mod syscall_set;
pub mod object;
pub mod kobj_type;
pub mod objtable;
pub mod sync;
pub mod tickless;
pub mod trace;
pub mod trap;
pub mod usi;
pub mod usi_request;
pub mod user_layout;
pub mod vmm_device;
pub mod virtio_fs;
pub mod virtio_gpu;
pub mod virtio_net;
pub mod wait;
pub mod workload;
pub mod workload_recovery;
pub mod workload_abi;
pub mod wireguard;

#[cfg(test)]
mod robustness;

#[cfg(kani)]
mod fv1;

// Author: chatgpt. Diagnostic raw sample storage, not a clock or proof of timing.
pub mod raw_timing;

pub mod publication_credit;

pub mod pi_work;
pub mod percpu_migration;
pub mod sync_origin;
pub mod event_wait;

pub mod extension_abi;

pub mod cpu_time;

pub mod subscription;

pub mod subscription_abi;

pub mod rt_partition;

pub mod rt_abi;

pub mod timer_units;
pub mod sandbox;
pub mod sandbox_image;
pub mod sandbox_abi;
pub mod sandbox_storage_abi;
pub mod sandbox_launch;
pub mod sandbox_launch_abi;
pub mod sandbox_store;

pub mod native_install;
#[cfg(any(test, feature = "persistent-install"))]
pub mod persistent_install;
#[cfg(any(test, feature = "persistent-install"))]
pub mod native_install_service;
pub mod native_module_lifecycle;

// issue #3：统一定时事件契约。 / Unified timer-event contract.
pub mod timer_event;
pub mod timer_progress;
pub mod dirty_slots;
pub mod hwvirt;
pub mod hwv5_pep;
pub mod hwv7;
pub mod hwvirt_vcpu;
pub mod hwvirt_vmm;

pub mod ns_budget;
pub mod security;
pub mod security_domain;
pub mod net1b;
pub mod net1c;
pub mod net2;
pub mod ifc;
