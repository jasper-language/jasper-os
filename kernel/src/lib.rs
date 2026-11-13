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
#![feature(allocator_ext)]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]

extern crate alloc;

/// 构建期选择启动计划：`production` 只有阶段和等待，其余构建走验收清单（issue #7）。
#[cfg(not(feature = "production"))]
pub mod acceptance;
#[cfg(not(feature = "production"))]
pub use acceptance as plan;
#[cfg(feature = "production")]
pub mod production;
#[cfg(feature = "production")]
pub use production as plan;

pub mod appid_demo;
#[cfg(all(feature = "arch2-verify", target_arch = "x86_64"))]
pub mod arch2_demo;
pub mod abi_demo;
pub mod arbiter_demo;
pub mod arch;
pub mod baseline;
pub mod boot;
pub mod bootcap;
pub mod clock;
pub mod config;
#[cfg(feature = "lifecycle-ab-health")]
pub mod lifecycle_health;
#[cfg(feature = "fault-inject")]
pub mod fault_inject;
pub mod fix_demo;
pub mod console;
pub mod counter_demo;
pub mod dma;
pub mod drv3_demo;
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
pub mod device_demo;
pub mod display;
pub mod interrupt;
pub mod exit_state;
pub mod fault;
#[cfg(feature = "user-programs")]
pub(crate) mod first_program;
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub(crate) mod binder;
#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]
pub mod linux_abi;
#[cfg(all(
    any(
        feature = "compat-dynamic-libc-verify",
        feature = "lifecycle-root-exec-verify",
        feature = "workload-io-verify"
    ),
    target_arch = "x86_64"
))]
pub mod linux_vfs;
#[cfg(all(feature = "lifecycle-root-exec-verify", target_arch = "x86_64"))]
pub mod compat_rng;
#[cfg(all(feature = "compat-syscall-verify", target_arch = "x86_64"))]
pub mod linux_abi_demo;
#[cfg(all(
    any(
        feature = "compat-dynamic-libc-verify",
        feature = "lifecycle-root-exec-verify"
    ),
    target_arch = "x86_64"
))]
pub mod compat_dynamic_demo;
pub mod ipc;
pub mod ifc;
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
pub mod krn0_tlb;
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
pub mod assembly;
pub mod profile_demo;
#[cfg(feature = "user-programs")]
pub mod prog_demo;
pub mod ring;
pub mod rt;
pub mod rtclass_demo;
pub mod sandbox;
pub mod sandbox_launch;
pub mod sandbox_storage;
pub mod terminal;
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
#[cfg(target_arch = "x86_64")]
pub mod blk;
#[cfg(all(feature = "compat-elf", target_arch = "x86_64"))]
pub mod compat_elf;
#[cfg(all(target_arch = "x86_64", feature = "compat-elf-backend-verify"))]
pub mod compat_elf_demo;
#[cfg(target_arch = "x86_64")]
pub mod blk1_demo;
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "hwv5-verify", feature = "hwv5-prod-verify")
))]
pub mod hwv5_vmm_demo;
#[cfg(target_arch = "x86_64")]
pub mod hwv5_policy;
#[cfg(all(target_arch = "x86_64", feature = "fs0-journal-verify"))]
pub mod fs0_demo;
#[cfg(all(target_arch = "x86_64", feature = "native-install-block-verify"))]
pub mod native_install_block;
#[cfg(all(target_arch = "x86_64", feature = "native-install-abi-verify"))]
pub mod native_install_abi;
#[cfg(any(feature = "linux-abi", feature = "sec3-verify"))]
pub mod native_module_authority;
pub mod native_module_catalog;
#[cfg(all(
    target_arch = "x86_64",
    feature = "lifecycle-diagnostic-block-verify"
))]
pub mod lifecycle_diagnostic_block;
#[cfg(feature = "lifecycle-diagnostic-sources")]
pub mod diagnostic_sources;
#[cfg(all(target_arch = "x86_64", feature = "fs1-ext4-verify"))]
pub mod fs1_demo;
#[cfg(any(feature = "pex0-verify", feature = "pex2-verify"))]
pub mod pex0_demo;
#[cfg(feature = "pex3-verify")]
pub mod pex3_demo;
#[cfg(feature = "pex4-verify")]
pub mod pex4_demo;
#[cfg(feature = "pex5-verify")]
pub mod pex5_demo;
#[cfg(feature = "pex7-verify")]
pub mod pex7_demo;
pub mod balance_demo;
pub mod pi_demo;
pub mod sched;
pub mod security;
#[cfg(feature = "sec1-verify")]
pub mod sec1_demo;
#[cfg(feature = "sec2-verify")]
pub mod sec2_notices;
#[cfg(feature = "sec2-verify")]
pub mod sec2_demo;
#[cfg(feature = "sec3-verify")]
pub mod sec3_demo;
#[cfg(feature = "sec4-verify")]
pub mod sec4_demo;
#[cfg(feature = "sec5-verify")]
pub mod sec5_demo;
#[cfg(feature = "net2-verify")]
pub mod net2_demo;
#[cfg(feature = "net3-verify")]
pub mod net3_demo;
#[cfg(feature = "net4-runtime-verify")]
pub mod net4_runtime_demo;
#[cfg(feature = "sec6-verify")]
pub mod sec6_demo;
pub mod shard;
pub mod smp;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod usi;
pub mod workload;
#[cfg(all(feature = "workload-verify", target_arch = "x86_64"))]
pub mod workload_verify;
#[cfg(all(feature = "workload-io-verify", target_arch = "x86_64"))]
pub mod workload_io_verify;
#[cfg(feature = "user-programs")]
pub mod usi1_demo;
#[cfg(feature = "usi2-verify")]
pub mod usi2_demo;
pub mod user_demo;
#[cfg(target_arch = "x86_64")]
pub use arch::hwvirt_demo;
#[cfg(target_arch = "x86_64")]
pub mod hwv1_demo;
#[cfg(target_arch = "x86_64")]
pub use arch::hwv2_demo;
#[cfg(target_arch = "x86_64")]
pub use arch::hwv3_demo;
#[cfg(target_arch = "x86_64")]
pub use arch::hwv4_demo;
#[cfg(all(
    target_arch = "x86_64",
    any(feature = "hwv5-verify", feature = "hwv5-prod-verify")
))]
pub use arch::hwv5_demo;
#[cfg(feature = "rt3-verify")]
pub mod rt3_demo;
pub mod virtio;
pub mod virtio_rng_demo;
pub mod wcet;

#[cfg(all(feature = "s2-fuzz", target_arch = "x86_64"))]
pub mod s2;

#[cfg(all(feature = "krn1-soak", target_arch = "x86_64"))]
pub mod soak;

#[cfg(all(feature = "s4-soak", target_arch = "x86_64"))]
pub mod s4_soak;

#[cfg(feature = "evt1-verify")]
pub mod evt1_demo;

#[cfg(feature = "shm1-verify")]
pub mod shm_demo;

pub mod subscription;
pub mod service_catalog;

#[cfg(feature="evt2-verify")]
pub mod subscription_demo;

#[cfg(feature="evt2-broadcast-verify")]
pub mod subscription_broadcast_demo;

#[cfg(feature="rt1-verify")]
pub mod rt1_demo;

pub mod task_control;
pub mod user_mutex;
pub mod user_timer;
pub mod vcpu;

#[cfg(feature="rt2-verify")]
pub mod rt2_demo;

pub mod hrtime;
