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
//! * [`wait`]   —— 可等待对象（事件、定时器）与等待集合；时间源抽象为 trait
//! * [`abi`]    —— 系统接口登记表：显式稳定 ID 的解析、命名校验与冻结检查（M3.2，构建期使用）
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
//! * [`module`] —— 编译期模块描述符 + 依赖检查 + 顺序装载/逆序卸载
//! * [`trap`]   —— 陷入帧与「名字 → 处理函数」的系统调用分发表
//! * [`sched`]  —— 调度策略：QoS 四档 + 用量衰减 + 各档最低份额 + 唤醒延迟直方图（宿主可模拟测试）
//! * [`argcase`] —— 系统调用参数用例生成：确定性伪随机数、边界值、避开受保护区间的地址规划（健壮性测试共用）
//! * [`trace`]  —— 无堆环形缓冲、ID 分配器、结构化事件追踪器
//! * [`sync`]   —— 自旋锁
//! * [`smp`]    —— 多处理器：处理器集合与拓扑、启动状态机、核间中断种类、TLB 击落与跨核调用协议
//! * [`acpi`]   —— ACPI 表只读解析（处理器枚举：RSDP → RSDT/XSDT → MADT；固件输入按不可信处理）
//! * [`user_layout`] —— 各指令集的用户私有窗口起点与用户程序装载地址（内核、运行时与构建脚本共用）
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

pub mod abi;
pub mod acpi;
pub mod argcase;
pub mod arbiter;
pub mod bench;
pub mod async_ring;
pub mod capacity;
pub mod config;
pub mod device;
pub mod dma_quiesce;
pub mod elf;
pub mod fdt;
pub mod frame;
pub mod fault;
pub mod heap;
pub mod image_header;
pub mod interrupt;
pub mod io;
pub mod irq;
pub mod job;
pub mod l10n;
pub mod lockorder;
pub mod memory;
pub mod meta;
pub mod msi;
pub mod profile;
pub mod paging;
pub mod pagetable;
pub mod pci;
pub mod pressure;
pub mod psci;
pub mod ring_abi;
pub mod rt;
pub mod sbi;
pub mod sched;
pub mod shard;
pub mod smp;
pub mod spawn_abi;
pub mod module;
pub mod object;
pub mod objtable;
pub mod sync;
pub mod tickless;
pub mod trace;
pub mod trap;
pub mod user_layout;
pub mod wait;

#[cfg(test)]
mod robustness;
