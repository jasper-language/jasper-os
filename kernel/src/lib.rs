//! jasper-os 内核库：模块树与分层。
//!
//! 分层（自下而上，只允许向下依赖）：
//! * `arch`     —— 唯一的 ISA 接缝（`Platform` 契约 + `arch/<isa>/` 实现）
//! * `console` `irq` `clock` —— 架构无关的基础设施（输出、中断分发、时钟）
//! * `task` `sched` —— 任务与调度（机制 + 可替换策略）
//! * `smp`      —— 多处理器：启动其他处理器、每核数据、核间中断、跨核调用、TLB 击落
//! * `sync`     —— 关中断自旋锁（`kernel-core` 自旋锁 + arch 中断开关）
//! * `ktrace`   —— 全局结构化事件追踪器（`kernel-core::trace` 的内核实例）
//! * `mech_demo`—— M1.5：在真机上逐一演练 `kernel-core` 的机制（与机制分离，可整体删除）
//!
//! 纯机制（对象/句柄/权限、等待、异步 ring、地址空间记账、模块、陷入分发、追踪）在
//! 独立的 `kernel-core` crate 中，宿主可测；本 crate 只负责把它们接到硬件上。
//! * `boot`     —— 与引导协议无关的交接信息（内存图、物理内存映射偏移）
//! * `mm`       —— 内存管理：物理页帧分配（M2.1），后续页表与内核堆
//! * `pci`      —— PCI 设备发现的启动期部分：配置空间访问者、穷举枚举与只读设备表（DRV-1B）
//! * `kmain`    —— 架构无关的内核主流程；`main.rs` 只是引导适配层
//! * `panic`    —— 全二进制唯一的 `#[panic_handler]`
//! * `*_demo`   —— 验收演练；运行内嵌用户程序的演练只在特性 `user-programs` 开启时编译
//!
//! Core（除 `arch/` 外的一切）不得出现 ISA 专有代码，由 `verify-m1.4b.sh` 机械检查。
#![no_std]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]

extern crate alloc;

pub mod appid_demo;
pub mod arbiter_demo;
pub mod arch;
pub mod baseline;
pub mod boot;
pub mod bootcap;
pub mod clock;
pub mod config;
pub mod fix_demo;
pub mod console;
pub mod counter_demo;
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
pub mod device_demo;
pub mod interrupt;
pub mod exit_state;
pub mod fault;
pub mod ipc;
#[cfg(feature = "user-programs")]
pub mod ipc_demo;
pub mod irq;
pub mod job;
pub mod job_demo;
pub mod irq_demo;
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
pub mod irqring_demo;
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
pub mod irqstorm_demo;
pub mod kmain;
pub mod krn0_demo;
pub mod kobj;
pub mod l10n_demo;
pub mod mm;
pub mod mmio;
pub mod ktrace;
pub mod msi_demo;
pub mod msix;
pub mod lockorder;
pub mod mech_demo;
pub mod panic;
pub mod pci;
pub mod pci_demo;
pub mod proc;
pub mod profile;
pub mod profile_demo;
#[cfg(feature = "user-programs")]
pub mod prog_demo;
pub mod ring;
pub mod rt;
pub mod rtclass_demo;
#[cfg(feature = "user-programs")]
pub mod robust_demo;
#[cfg(feature = "user-programs")]
pub mod ring_demo;
#[cfg(feature = "user-programs")]
pub mod rt_demo;
#[cfg(feature = "user-programs")]
pub mod uptr_demo;
#[cfg(feature = "user-programs")]
pub mod longrun_demo;
pub mod scale_demo;
pub mod nohz_demo;
#[cfg(feature = "user-programs")]
pub mod qos_demo;
#[cfg(feature = "user-programs")]
pub mod overload_demo;
#[cfg(feature = "user-programs")]
pub mod bench_demo;
pub mod balance_demo;
pub mod pi_demo;
pub mod sched;
pub mod shard;
pub mod smp;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod user_demo;
pub mod virtio;
pub mod virtio_rng_demo;
pub mod wcet;
