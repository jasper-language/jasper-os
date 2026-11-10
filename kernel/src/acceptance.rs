//! 验收清单（issue #7 第二片）：验收用例的静态登记与构建期选择。
//! Acceptance manifest: static registration of cases and their build-time selection.
//!
//! 每份计划由若干段组成，按顺序执行。全量验收是 `FULL`；每个专项特性选一份专项计划，
//! 两者共用同一套阶段实现（`kmain::run_stage`）。计划在编译期检查（`kernel_core::boot_stage::plan_check`）。
//!
//! **加一个用例**：写一个 `fn(&mut BootCtx)`，在 `FULL` 或专项计划的合适位置登记一行，声明依赖的阶段；
//! 有断言的话在 [`SUMMARIES`] 加一行并在用例上写行名。不需要改 `kmain`。
//!
//! A plan is a sequence of parts run in order. `FULL` is the complete acceptance; each dedicated
//! feature selects its own plan. To add a case: write a function, register it here with the stages
//! it needs and, if it asserts anything, add a row to [`SUMMARIES`]. `kmain` does not change.

// 选中专项计划时，全量计划的用例执行体不被引用。
// With a dedicated plan selected, the bodies of the full plan are unreferenced.
#![allow(dead_code, unused_imports)]

use kernel_core::boot_stage::{str_eq, CaseSpec, PlanItem, Stage};

use crate::arch::{self, ExitStatus};
use crate::kmain::{BootCtx, Step};
use crate::{
    appid_demo, arbiter_demo, balance_demo, counter_demo, fix_demo, irq_demo, job_demo, kprint, kprintln, l10n_demo,
    mech_demo, mm, msi_demo, nohz_demo, pci_demo, pi_demo, profile_demo, rtclass_demo, scale_demo, sched, smp,
    user_demo, virtio_rng_demo, wcet,
};
#[cfg(feature = "user-programs")]
use crate::{abi_demo, bench_demo, ipc_demo, longrun_demo, overload_demo, prog_demo, qos_demo, ring_demo, robust_demo, rt_demo, uptr_demo};
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
use crate::device_demo;

/// 验收构建的启动失败：退出模拟器，由退出码和标记报告原因。
/// An acceptance boot failure exits the emulator; the code and markers report why.
pub fn stop(status: ExitStatus) -> ! {
    arch::exit_emulator(status)
}

// ---- 失败汇总 ----

/// 失败汇总表的一行。One row of the failure summary.
pub struct Summary {
    /// 行名，输出为 `<name>_failed=` 和 `<name>_timing_failed=`。Row name in the exit markers.
    pub name: &'static str,
    /// 功能断言失败数。Functional assertion failures.
    pub failed: fn() -> u32,
    /// 计时类断言超界数（只记录，不判失败）。Timing-class overruns: reported, not failed.
    pub timing: Option<fn() -> u32>,
}

/// 高精度期限事件增量同步：计数必须守恒，校验内核下不得有不一致。
fn nssync_failed() -> u32 {
    let (mismatch, _) = sched::ns_audit();
    u32::from(!sched::ns_sync_stats().balanced()) + mismatch
}

const fn row(name: &'static str, failed: fn() -> u32) -> Summary {
    Summary { name, failed, timing: None }
}

const fn both(name: &'static str, failed: fn() -> u32, timing: fn() -> u32) -> Summary {
    Summary { name, failed, timing: Some(timing) }
}

/// 全部汇总行（顺序即 `[JSR-EXIT]` 的输出顺序）；未编译的演练不出现。
/// All summary rows, in `[JSR-EXIT]` output order; exercises that are not compiled do not appear.
pub const SUMMARIES: &[Summary] = &[
    row("nssync", nssync_failed),
    row("mm", mm::demo::failed),
    row("smp", smp::demo::failed),
    both("balance", balance_demo::failed, balance_demo::timing_failed),
    both("irq", irq_demo::failed, irq_demo::timing_failed),
    both("scale", scale_demo::failed, scale_demo::timing_failed),
    row("nohz", nohz_demo::failed),
    row("user", user_demo::failed),
    #[cfg(feature = "user-programs")]
    row("abi", abi_demo::failed),
    row("fix", fix_demo::failed),
    row("profile", profile_demo::failed),
    #[cfg(target_arch = "x86_64")]
    row("hwv0", crate::hwvirt_demo::failed),
    #[cfg(target_arch = "x86_64")]
    row("hwv1", crate::hwv1_demo::failed),
    #[cfg(target_arch = "x86_64")]
    row("hwv2", crate::hwv2_demo::failed),
    #[cfg(target_arch = "x86_64")]
    row("hwv3", crate::hwv3_demo::failed),
    #[cfg(target_arch = "x86_64")]
    row("hwv4", crate::hwv4_demo::failed),
    row("job", job_demo::failed),
    row("rtclass", rtclass_demo::failed),
    both("arbiter", arbiter_demo::failed, arbiter_demo::timing_failed),
    row("appid", appid_demo::failed),
    row("pci", pci_demo::failed),
    row("msi", msi_demo::failed),
    row("msix", virtio_rng_demo::failed),
    #[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
    row("drv1c", device_demo::failed),
    #[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
    row("drv2c1", crate::irqring_demo::failed),
    #[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
    both("drv2c2", crate::irqstorm_demo::failed, crate::irqstorm_demo::timing_failed),
    #[cfg(target_arch = "x86_64")]
    row("drv3", crate::drv3_demo::failed),
    #[cfg(all(feature = "arch2-verify", target_arch = "x86_64"))]
    row("arch2", crate::arch2_demo::failed),
    #[cfg(all(feature = "fs1-ext4-verify", target_arch = "x86_64"))]
    row("fs1", crate::fs1_demo::failed),
    #[cfg(feature = "sec4-verify")]
    row("sec4", crate::sec4_demo::failed),
    #[cfg(feature = "sec5-verify")]
    row("sec5", crate::sec5_demo::failed),
    #[cfg(feature = "net2-verify")]
    row("net2", crate::net2_demo::failed),
    #[cfg(feature = "net3-verify")]
    row("net3", crate::net3_demo::failed),
    #[cfg(feature = "net4-runtime-verify")]
    row("net4-runtime", crate::net4_runtime_demo::failed),
    #[cfg(feature = "compat-elf-backend-verify")]
    row("compat-elf-backend", crate::compat_elf_demo::failed),
    #[cfg(all(feature = "compat-syscall-verify", target_arch = "x86_64"))]
    row("compat-syscall", crate::linux_abi_demo::failed),
    #[cfg(all(feature = "compat-dynamic-libc-verify", target_arch = "x86_64"))]
    row("compat-dynamic-libc", crate::compat_dynamic_demo::failed),
    #[cfg(target_arch = "x86_64")]
    row("blk1", crate::blk1_demo::failed),
    row("krn0", crate::krn0_demo::failed),
    row("l10n", l10n_demo::failed),
    #[cfg(feature = "user-programs")]
    row("ring", ring_demo::failed),
    #[cfg(feature = "user-programs")]
    row("ipc", ipc_demo::failed),
    #[cfg(feature = "user-programs")]
    row("prog", prog_demo::failed),
    #[cfg(feature = "user-programs")]
    row("robust", robust_demo::failed),
    #[cfg(feature = "user-programs")]
    both("rt", rt_demo::failed, rt_demo::timing_failed),
    #[cfg(feature = "user-programs")]
    row("uptr", uptr_demo::failed),
    #[cfg(feature = "user-programs")]
    row("longrun", longrun_demo::failed),
    #[cfg(feature = "user-programs")]
    both("qos", qos_demo::failed, qos_demo::timing_failed),
    both("pi", pi_demo::failed, pi_demo::timing_failed),
    #[cfg(feature = "user-programs")]
    row("overload", overload_demo::failed),
    #[cfg(feature = "user-programs")]
    both("bench", bench_demo::failed, bench_demo::timing_failed),
    #[cfg(feature = "pex0-verify")]
    row("pex0", crate::pex0_demo::failed),
    #[cfg(feature = "pex2-verify")]
    row("pex2", crate::pex0_demo::failed),
    #[cfg(feature = "sec1-verify")]
    row("sec1", crate::sec1_demo::failed),
    #[cfg(feature = "sec3-verify")]
    row("sec3", crate::sec3_demo::failed),
];

/// 查一行汇总。Whether a summary row exists, and whether it reports timing.
const fn summary_ok(name: &str, timing: bool) -> bool {
    let mut i = 0;
    while i < SUMMARIES.len() {
        if str_eq(SUMMARIES[i].name, name) {
            return !timing || SUMMARIES[i].timing.is_some();
        }
        i += 1;
    }
    false
}

/// 登记的行名都存在，计时类用例的行报告计时。Registered rows exist; timing cases report timing.
const fn summaries_consistent(parts: &[&[Step]]) -> bool {
    let mut p = 0;
    while p < parts.len() {
        let mut i = 0;
        while i < parts[p].len() {
            if let PlanItem::Case(spec, _) = &parts[p][i] {
                if !spec.summary.is_empty() && !summary_ok(spec.summary, spec.timing) {
                    return false;
                }
                if spec.summary.is_empty() && spec.timing {
                    return false;
                }
            }
            i += 1;
        }
        p += 1;
    }
    true
}

const _: () = assert!(summaries_consistent(PLAN));

// ---- 登记的简写 ----

/// 登记一个用例：名称、依赖阶段、汇总行、执行体。
const fn case(name: &'static str, requires: Stage, summary: &'static str, run: fn(&mut BootCtx)) -> Step {
    PlanItem::Case(CaseSpec { name, requires: requires.bit(), summary, timing: false }, run)
}

/// 登记一个报告计时结果的用例。Register a case that reports timing results.
const fn timed(name: &'static str, requires: Stage, summary: &'static str, run: fn(&mut BootCtx)) -> Step {
    PlanItem::Case(CaseSpec { name, requires: requires.bit(), summary, timing: true }, run)
}

const fn st(s: Stage) -> Step {
    PlanItem::Stage(s)
}

// ---- 用例执行体 ----

fn sched_cooperative(_: &mut BootCtx) {
    sched::demo::run();
}

/// M1.4：定时器抢占（需要开中断才能收到定时器中断）。
fn sched_preemptive(_: &mut BootCtx) {
    arch::irq_enable();
    sched::demo::run_preemptive();
    arch::irq_disable();
}

/// 64 位计数单元：宽值与「与定时器中断共享」（32 位目标上没有 64 位原子指令，这里证明实现不会在中断中自锁）。
fn counter64(_: &mut BootCtx) {
    counter_demo::run();
    if counter_demo::failed() > 0 {
        kprintln!("[JSR-EXIT] failure counter64_failed={}", counter_demo::failed());
        arch::exit_emulator(ExitStatus::Failure);
    }
}

/// M1.5：以内核任务演练 kernel-core 的全部机制（任务内自行开关中断）。
fn mechanisms(_: &mut BootCtx) {
    mech_demo::run();
    if mech_demo::failed() > 0 {
        kprintln!("[JSR-EXIT] failure mech_failed={}", mech_demo::failed());
        arch::exit_emulator(ExitStatus::Failure);
    }
}

fn mm_frames(ctx: &mut BootCtx) {
    if let Some(frames) = ctx.frames {
        mm::demo::run(ctx.boot, frames);
    }
}

fn mm_map(_: &mut BootCtx) {
    mm::demo::run_map();
}

fn mm_heap(_: &mut BootCtx) {
    mm::demo::run_heap();
}

fn pci_table(_: &mut BootCtx) {
    pci_demo::run();
}

fn capacity_report(ctx: &mut BootCtx) {
    let max = ctx.capacity.map_or(0, |c| c.tasks);
    kprintln!(
        "[JSR-SCHED] capacity slots={} static_stacks={} max={} policy={} preemption=default_on",
        sched::capacity(),
        sched::stack::STATIC_STACKS,
        max,
        sched::policy_name()
    );
}

fn profile_checks(_: &mut BootCtx) {
    profile_demo::run();
}

#[cfg(target_arch = "x86_64")]
fn hardware_virt(_: &mut BootCtx) {
    crate::hwvirt_demo::run();
    if crate::hwvirt_demo::failed() != 0 {
        kprintln!("[JSR-HWV0-FAIL] failed={}", crate::hwvirt_demo::failed());
    }
}

#[cfg(target_arch = "x86_64")]
fn hardware_virt_vcpu(_: &mut BootCtx) {
    crate::hwv1_demo::run();
}

#[cfg(target_arch = "x86_64")]
fn hardware_virt_vmx(_: &mut BootCtx) {
    crate::hwv2_demo::run();
}

#[cfg(target_arch = "x86_64")]
fn hardware_virt_svm(_: &mut BootCtx) {
    crate::hwv3_demo::run();
}

#[cfg(target_arch = "x86_64")]
fn hardware_virt_vmm(_: &mut BootCtx) {
    crate::hwv4_demo::run();
}

#[cfg(target_arch = "x86_64")]
fn drv3_dma(_: &mut BootCtx) {
    crate::drv3_demo::run();
}

#[cfg(target_arch = "x86_64")]
fn blk1(_: &mut BootCtx) {
    crate::blk1_demo::run();
}

/// POL-3：批处理作业（依赖 / 优先级 / 取消 / 终态 / 满载下交互性）。
fn jobs(_: &mut BootCtx) {
    job_demo::run();
}

/// POL-4：实时准入与预算（协作式节流；抢占式执行待接入）。
fn rt_class(_: &mut BootCtx) {
    rtclass_demo::run();
}

/// M2.4：独立地址空间（同一虚拟地址、不同物理帧，真实切换）。
fn mm_space(_: &mut BootCtx) {
    mm::demo::run_space();
}

/// SMP-1：每核数据、各自计时、核间中断、跨核调用、TLB 击落。
fn smp_checks(ctx: &mut BootCtx) {
    if let Some(report) = ctx.smp {
        smp::demo::run(report);
    }
}

#[cfg(feature = "fault-inject")]
fn fault_selftest(_: &mut BootCtx) {
    if crate::fault_inject::selftest() != 0 {
        kprintln!("[JSR-EXIT] failure fault_inject_failed=1");
        arch::exit_emulator(ExitStatus::Failure);
    }
}

/// KRN-0①：两个钉在不同处理器的任务批量映射、读取、击落与回收。
fn krn0_tlb(_: &mut BootCtx) {
    crate::krn0_tlb::run(smp::online_set().len());
}

/// DRV-2A：每核 MSI 向量池、绑定、投递与拒绝路径（放在其他处理器已报到之后）。
fn msi(_: &mut BootCtx) {
    msi_demo::run();
}

/// DRV-2B：真实 virtio-rng 设备的 MSI-X 送达、改核、屏蔽与待决释放。
fn msix(_: &mut BootCtx) {
    virtio_rng_demo::run();
}

/// 此后全部演练都在停表开启下运行。
fn nohz(_: &mut BootCtx) {
    nohz_demo::run();
}

/// POL-5：三类线程同核争用 + 多核下各类各占一个核（放在 SMP 启动之后）。
fn arbiter(_: &mut BootCtx) {
    arbiter_demo::run();
}

/// M3.1：真实进入 Ring 3；用户态异常只终止该任务。
fn user_ring3(_: &mut BootCtx) {
    user_demo::run();
}

/// M3.2：系统调用入口 + 稳定 ID 登记表 + 统一权限检查。
fn user_syscall(_: &mut BootCtx) {
    user_demo::run_syscall();
}

/// M3.3：用户指针安全（校验 + 经物理映射复制）。
fn user_pointers(_: &mut BootCtx) {
    user_demo::run_user_pointers();
}

/// M3.4：进程 / 线程对象（同一进程两个线程、句柄、退出与回收）。
fn user_process(_: &mut BootCtx) {
    user_demo::run_process();
}

/// M5.1-pre：从 ELF 文件装载并运行用户程序。
#[cfg(feature = "user-programs")]
fn user_elf(_: &mut BootCtx) {
    user_demo::run_elf();
}

/// ABI 世代：单一真源、真实章、装载前拒绝（issue #8 第一片）。
#[cfg(feature = "user-programs")]
fn abi_generation(_: &mut BootCtx) {
    abi_demo::run();
}

/// M4.1：对象生命周期（外部所有权 / 内部引用 / 清理过程级联）。
#[cfg(feature = "user-programs")]
fn user_lifecycle(_: &mut BootCtx) {
    user_demo::run_lifecycle();
}

/// M4.2：Handle/Rights（duplicate/restrict 只降权；跨进程原子转移）。
fn user_handles(_: &mut BootCtx) {
    user_demo::run_handles();
}

/// DRV-1C：设备内核对象与 list / open / get 系统调用（设备表由 DRV-1B 在启动期建立）。
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
fn device_objects(_: &mut BootCtx) {
    device_demo::run();
}

/// DRV-2C-1：真实 virtio-rng 的 MSI-X 中断经中断对象成为用户 Ring 上的一条完成。
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
fn irq_ring(_: &mut BootCtx) {
    crate::irqring_demo::run();
}

/// DRV-2C-2：真实 virtio-rng 的 MSI-X 中断风暴受每核预算约束（屏蔽 / 下一 tick 解除、到达不丢）。
#[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
fn irq_storm(_: &mut BootCtx) {
    crate::irqstorm_demo::run();
}

/// KRN-0：中断到达计数跨 u32 回绕仍按模差正确计数。
fn krn0_counter(_: &mut BootCtx) {
    crate::krn0_demo::run();
}

/// KRN-0②：virtio 复位失败时关总线主控并读回确认，仍不可信则隔离队列页（真实设备演练）。
fn krn0_dma(_: &mut BootCtx) {
    crate::krn0_demo::run_dma();
}

/// KRN-0④：MMIO 槽位 CAS 分配、耗尽拒绝与位图回收。
fn krn0_mmio(_: &mut BootCtx) {
    crate::krn0_demo::run_mmio();
}

/// 基础设施修复的回归演练：失败路径与回滚。
fn fixes(_: &mut BootCtx) {
    fix_demo::run();
}

/// M4.3：用户态异步环（提交 → 完成；完成信用；取消；closing；配额）。
#[cfg(feature = "user-programs")]
fn async_ring(_: &mut BootCtx) {
    ring_demo::run();
}

/// M4.4：IPC Channel（send/recv 经 ring；两阶段 send；原子交付；取消竞争；页帧固定）。
#[cfg(feature = "user-programs")]
fn ipc_channel(_: &mut BootCtx) {
    ipc_demo::run();
}

/// M5.1：最小非特权程序（特权级 3、隔离、用户异常、坏指针、进程终止与等待、完全回收）。
#[cfg(feature = "user-programs")]
fn programs(_: &mut BootCtx) {
    prog_demo::run();
}

/// S-1：系统调用健壮性回归（真实用户态、固定种子、有界调用、资源回到基线）。
#[cfg(feature = "user-programs")]
fn robustness(_: &mut BootCtx) {
    robust_demo::run();
}

/// J-1：用户态运行时（匿名内存系统调用；用运行时写成的普通 Rust 程序：堆、线程、Channel、异步环）。
#[cfg(feature = "user-programs")]
fn user_rt(_: &mut BootCtx) {
    rt_demo::run();
}

/// HARDEN-1C：用户指针复制与并发取消映射（多核下不得读写已回收、已分给别的进程的帧）。
#[cfg(feature = "user-programs")]
fn uptr_races(_: &mut BootCtx) {
    uptr_demo::run();
}

/// HARDEN-1C ③：长期运行（同一组资源反复创建 / 使用 / 关闭 1500 轮后回到基线、容量不塌陷）。
#[cfg(feature = "user-programs")]
fn long_run(_: &mut BootCtx) {
    longrun_demo::run();
}

/// SCHED-1：服务质量分级调度。纯轮转策略不提供分级语义，其构建不登记依赖 QoS 保证的演练。
#[cfg(all(feature = "user-programs", not(feature = "sched-rr")))]
fn qos(_: &mut BootCtx) {
    qos_demo::run();
}

/// SCHED-2：优先级继承（三任务反转有界、传递继承、拒绝路径、持有者退出、压力撤销后恢复）。
#[cfg(not(feature = "sched-rr"))]
fn priority_inheritance(_: &mut BootCtx) {
    pi_demo::run();
}

/// SMP-2：每核运行队列与负载均衡。
#[cfg(not(feature = "sched-rr"))]
fn balance(_: &mut BootCtx) {
    balance_demo::run();
}

/// SMP-3：中断与服务的多核化（送达、均衡、风暴预算下交互延迟有上界、恢复、分片服务各核均衡）。
#[cfg(not(feature = "sched-rr"))]
fn irq_scaling(_: &mut BootCtx) {
    irq_demo::run();
}

/// HARDEN-1D：调度规模化（选择只遍历本核运行列表、到期唤醒按最早时刻跳过、锁争用测量、同规模下的响应性底线）。
#[cfg(not(feature = "sched-rr"))]
fn scale(_: &mut BootCtx) {
    scale_demo::run();
}

/// SCHED-3：过载防护（每进程 CPU 上限、看门狗、内存压力分级准入、压力撤销后回到基线）。
#[cfg(all(feature = "user-programs", not(feature = "sched-rr")))]
fn overload(_: &mut BootCtx) {
    overload_demo::run();
}

/// T-2：基准（时钟中断、上下文切换、页帧、堆、系统调用、异步环、IPC 往返）与按预算评估参数取值。
#[cfg(feature = "user-programs")]
fn bench(_: &mut BootCtx) {
    bench_demo::run();
}

/// DRV-0：应用身份的写入与不可变性（放在最后，避免占用早期演练依赖的对象编号）。
fn appid(_: &mut BootCtx) {
    appid_demo::run();
}

/// L10N-1：登记表中英显示名齐全，且据此生成的错误渲染表可用（中英渲染、非错误与未知码被拒）。
fn l10n(_: &mut BootCtx) {
    l10n_demo::run();
}

/// WCET 证据：关键路径的最大实测值（系统调用周期、交互唤醒 tick）。
fn wcet_report(_: &mut BootCtx) {
    wcet::report();
}

/// issue #2：高精度期限事件增量同步计数；定时器前进保证计数。
fn sync_counters(_: &mut BootCtx) {
    let ns_sync = sched::ns_sync_stats();
    let ns_budget = sched::ns_budget_stats();
    let (ns_mismatch, ns_audits) = sched::ns_audit();
    let (timer_full, timer_bsp, timer_local, timer_highres, timer_cost) = sched::timer_progress_stats();
    kprintln!("[JSR-TIMER-PROGRESS] full={} deferred_tick={} deferred_local={} deferred_highres={} max_cost={}", timer_full, timer_bsp, timer_local, timer_highres, timer_cost);
    kprintln!(
        "[JSR-NS-SYNC] passes={} synced={} unchanged={} writes={} inserted={} rescheduled={} moved={} removed={} balanced={} audit_mismatch={} audits={}",
        ns_sync.passes, ns_sync.synced, ns_sync.unchanged, ns_sync.writes(),
        ns_sync.inserted, ns_sync.rescheduled, ns_sync.moved, ns_sync.removed, ns_sync.balanced(), ns_mismatch, ns_audits
    );
    kprintln!(
        "[JSR-NS-BUDGET] passes={} budget_cpu_checks={} due_cpu_checks={} due_cpus={} table_slots={} due_events={} running_settlements={} inactive_settlements={} heap_ops={} max_settle_cycles={}",
        ns_budget.passes, ns_budget.budget_cpu_checks, ns_budget.due_cpu_checks, ns_budget.due_cpus,
        ns_budget.table_slots, ns_budget.due_events, ns_budget.running_settlements,
        ns_budget.inactive_settlements, ns_sync.writes().saturating_add(ns_budget.due_events),
        ns_budget.max_settle_cycles
    );
}

/// 功能失败表：任何一行非零都判失败。Any non-zero row in the failure table fails the run.
fn failure_gate(_: &mut BootCtx) {
    if SUMMARIES.iter().any(|s| (s.failed)() > 0) {
        kprint!("[JSR-EXIT] failure");
        for s in SUMMARIES {
            kprint!(" {}_failed={}", s.name, (s.failed)());
        }
        kprintln!();
        arch::exit_emulator(ExitStatus::Failure);
    }
}

#[cfg(all(feature = "s2-fuzz", target_arch = "x86_64", not(feature = "s2-only")))]
fn s2_campaign(_: &mut BootCtx) {
    if !crate::s2::run() {
        kprintln!("[JSR-EXIT] failure s2_failed=1");
        arch::exit_emulator(ExitStatus::Failure);
    }
}

#[cfg(all(feature = "krn1-soak", target_arch = "x86_64"))]
fn soak(_: &mut BootCtx) {
    if !crate::soak::run() {
        kprintln!("[JSR-EXIT] failure soak_failed=1");
        arch::exit_emulator(ExitStatus::Failure);
    }
}

/// 全量收尾：功能失败表已判过；只区分「全过」与「功能全过但只有计时超界」。
/// 计时类断言超界只记录、不阻塞：指令翻译型仿真器的时间基准跟随宿主，性能只在裸机上判定。
/// Timing-class overruns are reported, not failed; performance is judged on bare metal only.
fn finish_full(_: &mut BootCtx) {
    // 未内嵌用户程序时如实说明：依赖用户程序的演练没有运行。
    if !cfg!(feature = "user-programs") {
        kprintln!("[JSR-STAGE] user_programs=absent skipped=elf,lifecycle,ring,ipc,prog,rt,qos,overload,bench");
    }
    let count = |s: &Summary| s.timing.map_or(0, |t| t());
    if SUMMARIES.iter().map(count).sum::<u32>() > 0 {
        kprint!("[JSR-EXIT] timing-only");
        for s in SUMMARIES.iter().filter(|s| count(s) > 0) {
            kprint!(" {}_timing_failed={}", s.name, count(s));
        }
        kprintln!();
        arch::exit_emulator(ExitStatus::TimingOnly);
    }
    kprintln!("[JSR-EXIT] success");
    arch::exit_emulator(ExitStatus::Success)
}

// ---- 计划的公共段 ----

/// 所有验收计划共用的前半段：从控制台到调度模式，穿插启动早期的演练。
/// The part every acceptance plan shares: console through scheduling mode, with early exercises.
const PREFIX: &[Step] = &[
    st(Stage::Console),
    st(Stage::Platform),
    st(Stage::Timer),
    case("sched-cooperative", Stage::Timer, "", sched_cooperative),
    case("sched-preemptive", Stage::Timer, "", sched_preemptive),
    case("counter64", Stage::Timer, "", counter64),
    case("mechanisms", Stage::Timer, "", mechanisms),
    st(Stage::Frames),
    case("mm-frames", Stage::Frames, "mm", mm_frames),
    st(Stage::KernelMap),
    case("mm-map", Stage::KernelMap, "mm", mm_map),
    st(Stage::Heap),
    case("mm-heap", Stage::Heap, "mm", mm_heap),
    st(Stage::Capacity),
    st(Stage::Devices),
    st(Stage::Profile),
    st(Stage::Assembly),
    case("pci-table", Stage::Assembly, "pci", pci_table),
    case("capacity-report", Stage::Assembly, "", capacity_report),
    case("profile-checks", Stage::Assembly, "profile", profile_checks),
    st(Stage::SchedMode),
    #[cfg(target_arch = "x86_64")]
    case("hardware-virt", Stage::Assembly, "hwv0", hardware_virt),
];

/// 地址空间与其他处理器上线，专项计划在这之后运行各自的用例。
const SMP_UP: &[Step] = &[
    st(Stage::Space),
    case("mm-space", Stage::Space, "mm", mm_space),
    st(Stage::Smp),
    case("smp-checks", Stage::Smp, "smp", smp_checks),
    #[cfg(target_arch = "x86_64")]
    case("drv3-dma", Stage::Smp, "drv3", drv3_dma),
    #[cfg(target_arch = "x86_64")]
    case("blk1", Stage::Smp, "blk1", blk1),
    #[cfg(feature = "fault-inject")]
    case("fault-selftest", Stage::Smp, "", fault_selftest),
];

/// 批处理与实时类别（全量和 S-2 专项在地址空间之前运行）。
const CLASSES: &[Step] = &[
    case("jobs", Stage::SchedMode, "job", jobs),
    case("rt-class", Stage::SchedMode, "rtclass", rt_class),
];

/// 全量计划的高精度阶段。
const HIGHRES: &[Step] = &[st(Stage::HighRes)];

// ---- 全量计划 ----

/// 全量验收在 `smp` 之后的用例。
#[cfg(not(any(
    feature = "rt1-verify", feature = "rt2-verify", feature = "rt3-verify", feature = "budget-window-verify",
    feature = "krn3-fast-tick-verify", feature = "krn3-postsplit-verify", feature = "krn3-p999-verify",
    feature = "evt1-verify", feature = "evt2-verify", feature = "evt2-broadcast-verify",
    feature = "s3-nohz-verify", feature = "shm1-verify", feature = "hwv1-verify", feature = "hwv2-verify", feature = "hwv3-verify", feature = "hwv4-verify", feature = "hwv5-prod-verify", feature = "jaso1-verify", feature = "drv3-verify", feature = "arch2-verify", feature = "fs1-ext4-verify", feature = "blk1-verify", feature = "fs0-journal-verify", feature = "mod1-verify", feature = "boot-stage-rollback-verify", feature = "pex0-verify", feature = "usi1-verify", feature = "usi2-verify", feature = "sec1-verify", feature = "sec2-verify", feature = "sec3-verify", feature = "sec4-verify", feature = "sec5-verify", feature = "net2-verify", feature = "net3-verify", feature = "net4-runtime-verify", feature = "compat-elf-backend-verify", feature = "compat-syscall-verify", feature = "compat-dynamic-libc-verify", feature = "pex1-verify", feature = "pex2-verify", feature = "sec6-verify",
    feature = "s2-only", feature = "s4-soak",
)))]
const FULL: &[Step] = &[
    case("krn0-tlb", Stage::Smp, "", krn0_tlb),
    case("msi", Stage::Smp, "msi", msi),
    case("msix", Stage::Smp, "msix", msix),
    st(Stage::IdleTick),
    case("nohz", Stage::IdleTick, "nohz", nohz),
    timed("arbiter", Stage::Smp, "arbiter", arbiter),
    st(Stage::UserRuntime),
    case("user-ring3", Stage::UserRuntime, "user", user_ring3),
    case("user-syscall", Stage::UserRuntime, "user", user_syscall),
    case("user-pointers", Stage::UserRuntime, "user", user_pointers),
    case("user-process", Stage::UserRuntime, "user", user_process),
    #[cfg(feature = "user-programs")]
    case("user-elf", Stage::UserRuntime, "user", user_elf),
    #[cfg(feature = "user-programs")]
    case("abi-generation", Stage::UserRuntime, "abi", abi_generation),
    #[cfg(feature = "user-programs")]
    case("user-lifecycle", Stage::UserRuntime, "user", user_lifecycle),
    case("user-handles", Stage::UserRuntime, "user", user_handles),
    #[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
    case("device-objects", Stage::UserRuntime, "drv1c", device_objects),
    #[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
    case("irq-ring", Stage::UserRuntime, "drv2c1", irq_ring),
    #[cfg(all(feature = "user-programs", target_arch = "x86_64"))]
    timed("irq-storm", Stage::UserRuntime, "drv2c2", irq_storm),
    case("krn0-counter", Stage::Smp, "krn0", krn0_counter),
    case("krn0-dma", Stage::Smp, "krn0", krn0_dma),
    case("krn0-mmio", Stage::Smp, "krn0", krn0_mmio),
    case("fixes", Stage::Smp, "fix", fixes),
    #[cfg(target_arch = "x86_64")]
    case("hwv1-vcpu", Stage::Smp, "hwv1", hardware_virt_vcpu),
    #[cfg(feature = "user-programs")]
    case("async-ring", Stage::UserRuntime, "ring", async_ring),
    #[cfg(feature = "user-programs")]
    case("ipc-channel", Stage::UserRuntime, "ipc", ipc_channel),
    #[cfg(feature = "user-programs")]
    case("programs", Stage::UserRuntime, "prog", programs),
    #[cfg(feature = "user-programs")]
    case("robustness", Stage::UserRuntime, "robust", robustness),
    #[cfg(feature = "user-programs")]
    timed("user-rt", Stage::UserRuntime, "rt", user_rt),
    #[cfg(feature = "user-programs")]
    case("uptr-races", Stage::UserRuntime, "uptr", uptr_races),
    #[cfg(feature = "user-programs")]
    case("long-run", Stage::UserRuntime, "longrun", long_run),
    #[cfg(all(feature = "user-programs", not(feature = "sched-rr")))]
    timed("qos", Stage::UserRuntime, "qos", qos),
    #[cfg(not(feature = "sched-rr"))]
    timed("priority-inheritance", Stage::Smp, "pi", priority_inheritance),
    #[cfg(not(feature = "sched-rr"))]
    timed("balance", Stage::Smp, "balance", balance),
    #[cfg(not(feature = "sched-rr"))]
    timed("irq-scaling", Stage::Smp, "irq", irq_scaling),
    #[cfg(not(feature = "sched-rr"))]
    timed("scale", Stage::Smp, "scale", scale),
    #[cfg(all(feature = "user-programs", not(feature = "sched-rr")))]
    case("overload", Stage::UserRuntime, "overload", overload),
    #[cfg(feature = "user-programs")]
    timed("bench", Stage::UserRuntime, "bench", bench),
    case("appid", Stage::Smp, "appid", appid),
    case("l10n", Stage::Assembly, "l10n", l10n),
    case("wcet-report", Stage::Timer, "", wcet_report),
    case("sync-counters", Stage::HighRes, "nssync", sync_counters),
    #[cfg(target_arch = "x86_64")]
    case("hwv3-svm", Stage::Smp, "hwv3", hardware_virt_svm),
    #[cfg(target_arch = "x86_64")]
    case("hwv2-vmx", Stage::Smp, "hwv2", hardware_virt_vmx),
    #[cfg(target_arch = "x86_64")]
    case("hwv4-vmm", Stage::Smp, "hwv4", hardware_virt_vmm),
    case("failure-gate", Stage::Timer, "", failure_gate),
    #[cfg(all(feature = "s2-fuzz", target_arch = "x86_64"))]
    case("s2-campaign", Stage::UserRuntime, "", s2_campaign),
    #[cfg(all(feature = "krn1-soak", target_arch = "x86_64"))]
    case("soak", Stage::UserRuntime, "", soak),
    PlanItem::Finish(finish_full),
];

#[cfg(not(any(
    feature = "rt1-verify", feature = "rt2-verify", feature = "rt3-verify", feature = "budget-window-verify",
    feature = "krn3-fast-tick-verify", feature = "krn3-postsplit-verify", feature = "krn3-p999-verify",
    feature = "evt1-verify", feature = "evt2-verify", feature = "evt2-broadcast-verify",
    feature = "s3-nohz-verify", feature = "shm1-verify", feature = "hwv1-verify", feature = "hwv2-verify", feature = "hwv3-verify", feature = "hwv4-verify", feature = "hwv5-prod-verify", feature = "jaso1-verify", feature = "drv3-verify", feature = "arch2-verify", feature = "fs1-ext4-verify", feature = "blk1-verify", feature = "fs0-journal-verify", feature = "mod1-verify", feature = "boot-stage-rollback-verify", feature = "pex0-verify", feature = "usi1-verify", feature = "usi2-verify", feature = "sec1-verify", feature = "sec2-verify", feature = "sec3-verify", feature = "sec4-verify", feature = "sec5-verify", feature = "net2-verify", feature = "net3-verify", feature = "net4-runtime-verify", feature = "compat-elf-backend-verify", feature = "compat-syscall-verify", feature = "compat-dynamic-libc-verify", feature = "pex1-verify", feature = "pex2-verify", feature = "sec6-verify",
    feature = "s2-only", feature = "s4-soak",
)))]
pub use full_selected::{NAME, PLAN};

#[cfg(not(any(
    feature = "rt1-verify", feature = "rt2-verify", feature = "rt3-verify", feature = "budget-window-verify",
    feature = "krn3-fast-tick-verify", feature = "krn3-postsplit-verify", feature = "krn3-p999-verify",
    feature = "evt1-verify", feature = "evt2-verify", feature = "evt2-broadcast-verify",
    feature = "s3-nohz-verify", feature = "shm1-verify", feature = "hwv1-verify", feature = "hwv2-verify", feature = "hwv3-verify", feature = "hwv4-verify", feature = "hwv5-prod-verify", feature = "jaso1-verify", feature = "drv3-verify", feature = "arch2-verify", feature = "fs1-ext4-verify", feature = "blk1-verify", feature = "fs0-journal-verify", feature = "mod1-verify", feature = "boot-stage-rollback-verify", feature = "pex0-verify", feature = "usi1-verify", feature = "usi2-verify", feature = "sec1-verify", feature = "sec2-verify", feature = "sec3-verify", feature = "sec4-verify", feature = "sec5-verify", feature = "net2-verify", feature = "net3-verify", feature = "net4-runtime-verify", feature = "compat-elf-backend-verify", feature = "compat-syscall-verify", feature = "compat-dynamic-libc-verify", feature = "pex1-verify", feature = "pex2-verify", feature = "sec6-verify",
    feature = "s2-only", feature = "s4-soak",
)))]
mod full_selected {
    use super::*;
    pub const NAME: &str = "full";
    pub const PLAN: &[&[Step]] = &[PREFIX, CLASSES, SMP_UP, HIGHRES, FULL];
}

// ---- 专项计划：每个特性一份，多个专项特性同开时编译失败 ----

/// 同时打开的专项特性数。Number of dedicated plan features enabled at once.
const DEDICATED_SELECTED: usize = cfg!(feature = "rt1-verify") as usize
    + cfg!(feature = "rt2-verify") as usize
    + cfg!(feature = "rt3-verify") as usize
    + cfg!(feature = "budget-window-verify") as usize
    + cfg!(feature = "krn3-fast-tick-verify") as usize
    + cfg!(feature = "krn3-postsplit-verify") as usize
    + cfg!(feature = "krn3-p999-verify") as usize
    + cfg!(feature = "evt1-verify") as usize
    + cfg!(feature = "evt2-verify") as usize
    + cfg!(feature = "evt2-broadcast-verify") as usize
    + cfg!(feature = "s3-nohz-verify") as usize
    + cfg!(feature = "shm1-verify") as usize
    + cfg!(feature = "hwv1-verify") as usize
    + cfg!(feature = "hwv2-verify") as usize
    + cfg!(feature = "hwv3-verify") as usize
    + cfg!(all(feature = "hwv4-verify", not(feature = "hwv5-verify"))) as usize
    + cfg!(feature = "hwv5-verify") as usize
    + cfg!(feature = "hwv5-prod-verify") as usize
    + cfg!(feature = "jaso1-verify") as usize
    + cfg!(feature = "drv3-verify") as usize
    + cfg!(feature = "arch2-verify") as usize
    + cfg!(feature = "fs1-ext4-verify") as usize
    + cfg!(feature = "blk1-verify") as usize
    + cfg!(feature = "fs0-journal-verify") as usize
    + cfg!(feature = "mod1-verify") as usize
    + cfg!(feature = "boot-stage-rollback-verify") as usize
    + cfg!(feature = "pex0-verify") as usize
    + cfg!(feature = "usi1-verify") as usize
    + cfg!(feature = "usi2-verify") as usize
    + cfg!(feature = "sec1-verify") as usize
    + cfg!(feature = "sec2-verify") as usize
    + cfg!(feature = "sec3-verify") as usize
    + cfg!(feature = "sec4-verify") as usize
    + cfg!(feature = "sec5-verify") as usize
    + cfg!(feature = "net2-verify") as usize
    + cfg!(feature = "net3-verify") as usize
    + cfg!(feature = "net4-runtime-verify") as usize
    + cfg!(feature = "compat-elf-backend-verify") as usize
    + cfg!(feature = "compat-syscall-verify") as usize
    + cfg!(feature = "compat-dynamic-libc-verify") as usize
    + cfg!(feature = "pex1-verify") as usize
    + cfg!(feature = "pex2-verify") as usize
    + cfg!(feature = "sec6-verify") as usize
    + cfg!(feature = "s2-only") as usize
    + cfg!(feature = "s4-soak") as usize;
const _: () = assert!(DEDICATED_SELECTED <= 1, "专项验收特性只能选一个");

/// 专项计划的收尾：按失败数退出。Finish a dedicated plan on a failure count.
#[allow(dead_code)]
fn exit_on(failed: u64) {
    arch::exit_emulator(if failed == 0 { ExitStatus::Success } else { ExitStatus::Failure });
}

#[cfg(feature = "s4-soak")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "s4";

    fn finish(_: &mut BootCtx) {
        let passed = crate::s4_soak::run();
        kprintln!("[JSR-EXIT] {}", if passed { "success" } else { "failure" });
        exit_on(u64::from(!passed));
    }

    pub const PLAN: &[&[Step]] =
        &[PREFIX, SMP_UP, &[st(Stage::HighRes), st(Stage::IdleTick), PlanItem::Finish(finish)]];
}

#[cfg(feature = "rt3-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "rt3";
    fn finish(_: &mut BootCtx) {
        exit_on(u64::from(crate::rt3_demo::run()));
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "rt2-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "rt2";
    fn finish(_: &mut BootCtx) {
        crate::rt2_demo::run();
        // issue #2：高精度睡眠、取消与预算到期都走完之后，汇报脏集合校验（校验内核专用）。
        if cfg!(feature = "ns-dirty-audit") {
            sync_counters_ns_only();
        }
        exit_on(0);
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

/// 只输出高精度同步计数（RT2 校验内核）。Only the deadline sync counters, for the RT2 audit build.
#[cfg(feature = "rt2-verify")]
fn sync_counters_ns_only() {
    let stats = sched::ns_sync_stats();
    let budget = sched::ns_budget_stats();
    let (mismatch, audits) = sched::ns_audit();
    assert_eq!(budget.table_slots, 0, "budget settlement scanned the task table");
    assert!(budget.running_settlements > 0, "RT2 must settle a running budget");
    assert!(budget.inactive_settlements > 0, "RT2 must refill an inactive budget");
    kprintln!(
        "[JSR-NS-SYNC] passes={} synced={} unchanged={} writes={} inserted={} rescheduled={} moved={} removed={} balanced={} audit_mismatch={} audits={}",
        stats.passes, stats.synced, stats.unchanged, stats.writes(), stats.inserted, stats.rescheduled, stats.moved, stats.removed, stats.balanced(), mismatch, audits
    );
    kprintln!(
        "[JSR-NS-BUDGET] passes={} budget_cpu_checks={} due_cpu_checks={} due_cpus={} table_slots={} due_events={} running_settlements={} inactive_settlements={} heap_ops={} max_settle_cycles={}",
        budget.passes, budget.budget_cpu_checks, budget.due_cpu_checks, budget.due_cpus,
        budget.table_slots, budget.due_events, budget.running_settlements,
        budget.inactive_settlements, stats.writes().saturating_add(budget.due_events),
        budget.max_settle_cycles
    );
}

#[cfg(feature = "rt1-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "rt1";
    fn finish(_: &mut BootCtx) {
        crate::rt1_demo::run();
        exit_on(0);
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "budget-window-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "budget-window";
    fn finish(_: &mut BootCtx) {
        balance_demo::run_limit_diagnostic();
        exit_on(u64::from(balance_demo::failed()));
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "krn3-fast-tick-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "krn3-fast-tick";
    fn finish(_: &mut BootCtx) {
        let failed = scale_demo::run_fast_leaf_tick_contract() + balance_demo::run_affinity_diagnostic();
        exit_on(u64::from(failed));
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "krn3-postsplit-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "krn3-postsplit";
    fn finish(ctx: &mut BootCtx) {
        kprintln!(
            "[JSR-KRN3-POSTSPLIT] start cpus={} high_resolution={} nohz_divisor={}",
            sched::online_cpus().len(),
            crate::hrtime::enabled(),
            ctx.idle_divisor
        );
        scale_demo::run();
        let failed = scale_demo::failed();
        let timing = scale_demo::timing_failed();
        kprintln!("[JSR-KRN3-POSTSPLIT] done failed={} timing_failed={}", failed, timing);
        arch::exit_emulator(if failed != 0 {
            ExitStatus::Failure
        } else if timing != 0 {
            ExitStatus::TimingOnly
        } else {
            ExitStatus::Success
        });
    }
    pub const PLAN: &[&[Step]] =
        &[PREFIX, SMP_UP, &[st(Stage::HighRes), st(Stage::IdleTick), PlanItem::Finish(finish)]];
}

#[cfg(feature = "krn3-p999-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "krn3-p999";
    fn finish(ctx: &mut BootCtx) {
        kprintln!(
            "[JSR-KRN3-P999] start cpus={} high_resolution={} nohz_divisor={}",
            sched::online_cpus().len(),
            crate::hrtime::enabled(),
            ctx.idle_divisor
        );
        exit_on(u64::from(scale_demo::run_wake_latency_contract()));
    }
    pub const PLAN: &[&[Step]] =
        &[PREFIX, SMP_UP, &[st(Stage::HighRes), st(Stage::IdleTick), PlanItem::Finish(finish)]];
}

#[cfg(feature = "evt2-broadcast-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "evt2-broadcast";
    fn finish(_: &mut BootCtx) {
        crate::subscription_broadcast_demo::run();
        exit_on(0);
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "evt2-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "evt2";
    fn finish(_: &mut BootCtx) {
        crate::subscription_demo::run();
        exit_on(0);
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "s3-nohz-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "s3-nohz";
    fn finish(_: &mut BootCtx) {
        nohz_demo::run();
        kprintln!("[JSR-NOHZ-DIAGNOSTIC] failed={}", nohz_demo::failed());
        exit_on(u64::from(nohz_demo::failed()));
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "shm1-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "shm1";
    fn finish(_: &mut BootCtx) {
        exit_on(crate::shm_demo::run() as u64);
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "hwv1-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "hwv1";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::hwv1_demo::run();
        exit_on(u64::from(crate::hwv1_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-HWV1] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "hwv2-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "hwv2";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::hwv2_demo::run();
        exit_on(u64::from(crate::hwv2_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-HWV2] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "hwv3-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "hwv3";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::hwv3_demo::run();
        exit_on(u64::from(crate::hwv3_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-HWV3] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(all(feature = "hwv4-verify", not(feature = "hwv5-verify")))]
mod dedicated {
    use super::*;

    pub const NAME: &str = "hwv4";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::hwv4_demo::run();
        exit_on(u64::from(crate::hwv4_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-HWV4] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "hwv5-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "hwv5";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::hwv5_demo::run();
        exit_on(u64::from(crate::hwv5_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-HWV5] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "hwv5-prod-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "hwv5-prod";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::hwv5_demo::run();
        exit_on(u64::from(crate::hwv5_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-HWV5-PROD] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "jaso1-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "jaso1";

    fn finish(_: &mut BootCtx) {
        exit_on(u64::from(crate::rt_demo::run_jaso1()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "drv3-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "drv3";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        exit_on(u64::from(crate::drv3_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-DRV3] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "arch2-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "arch2";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::arch2_demo::run();
        exit_on(u64::from(crate::arch2_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-ARCH2] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "blk1-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "blk1";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        exit_on(u64::from(crate::blk1_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-BLK1] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "fs0-journal-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "fs0";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::fs0_demo::run();
        exit_on(u64::from(crate::fs0_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-FS0] unsupported_arch=true failed=1");
        exit_on(1);
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "fs1-ext4-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "fs1";

    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        crate::fs1_demo::run();
        exit_on(u64::from(crate::fs1_demo::failed()));
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-FS1] unsupported_arch=true failed=1");
        exit_on(1);
    }

    // FS-1 owns the only ext4-formatted block device. Do not run the generic
    // BLK-1 sector drill first: it intentionally overwrites sectors with a
    // poison pattern and would destroy the filesystem under test.
    const STAGES: &[Step] = &[
        st(Stage::Console),
        st(Stage::Platform),
        st(Stage::Timer),
        st(Stage::Frames),
        st(Stage::KernelMap),
        st(Stage::Heap),
        st(Stage::Capacity),
        st(Stage::Devices),
        st(Stage::Profile),
        st(Stage::Assembly),
        st(Stage::SchedMode),
        st(Stage::Space),
        st(Stage::Smp),
        st(Stage::HighRes),
        st(Stage::IdleTick),
        st(Stage::UserRuntime),
    ];

    pub const PLAN: &[&[Step]] = &[STAGES, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "mod1-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "mod1";

    fn finish(_: &mut BootCtx) {
        exit_on(u64::from(
            crate::mech_demo::failed() + crate::profile_demo::failed(),
        ));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "evt1-verify")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "evt1";
    fn finish(ctx: &mut BootCtx) {
        kprintln!("[JSR-EVT1-NOHZ] divisor={}", ctx.idle_divisor);
        let failed = crate::evt1_demo::run();
        kprintln!("[JSR-EVT1-EXIT] failed={}", failed);
        exit_on(failed as u64);
    }
    // 独立机制 guest 只初始化地址空间、SMP 与空闲停表；原完整验收仍走全量计划。
    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[st(Stage::IdleTick), PlanItem::Finish(finish)]];
}

#[cfg(feature = "boot-stage-rollback-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "boot-stage-rollback";

    fn duplicate_probe(ctx: &mut BootCtx) {
        let refused = ctx.probe_duplicate(Stage::Capacity);
        kprintln!(
            "[JSR-BOOT-DUPLICATE] stage=capacity result={} state_unchanged={}",
            if refused { "duplicate" } else { "accepted" },
            refused
        );
        if !refused {
            arch::exit_emulator(ExitStatus::Failure);
        }
    }

    fn arm_assembly_failure(_: &mut BootCtx) {
        let nth = crate::fault_inject::BOOT_ACTIVATION
            .arm(0x7d03, 1)
            .expect("one-shot boot activation fault window");
        kprintln!("[JSR-BOOT-FAULT] point=assembly_activation nth={} armed=true", nth);
    }

    fn finish(_: &mut BootCtx) {
        kprintln!("[JSR-BOOT-FAULT] point=assembly_activation observed=false");
        arch::exit_emulator(ExitStatus::Failure);
    }

    pub const PLAN: &[&[Step]] = &[&[
        st(Stage::Console),
        st(Stage::Platform),
        st(Stage::Timer),
        st(Stage::Frames),
        st(Stage::KernelMap),
        st(Stage::Heap),
        st(Stage::Capacity),
        st(Stage::Devices),
        st(Stage::Profile),
        case("boot-duplicate-probe", Stage::Profile, "", duplicate_probe),
        case("arm-boot-assembly-failure", Stage::Profile, "", arm_assembly_failure),
        st(Stage::Assembly),
        st(Stage::SchedMode),
        st(Stage::Space),
        st(Stage::Smp),
        st(Stage::HighRes),
        st(Stage::IdleTick),
        st(Stage::UserRuntime),
        PlanItem::Finish(finish),
    ]];
}

#[cfg(feature = "s2-only")]
mod dedicated {
    use super::*;
    pub const NAME: &str = "s2";
    #[cfg(target_arch = "x86_64")]
    fn finish(_: &mut BootCtx) {
        exit_on(u64::from(!crate::s2::run()));
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn finish(_: &mut BootCtx) {
        exit_on(1);
    }
    pub const PLAN: &[&[Step]] = &[PREFIX, CLASSES, SMP_UP, HIGHRES, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "pex0-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "pex0";

    fn finish(_: &mut BootCtx) {
        bench_demo::run();
        ring_demo::run();
        scale_demo::run();
        crate::pex0_demo::run();
        let failed = u64::from(
            bench_demo::failed()
                + ring_demo::failed()
                + scale_demo::failed()
                + crate::pex0_demo::failed(),
        );
        exit_on(failed);
    }

    pub const PLAN: &[&[Step]] = &[
        PREFIX,
        CLASSES,
        SMP_UP,
        HIGHRES,
        &[st(Stage::UserRuntime), PlanItem::Finish(finish)],
    ];
}

#[cfg(feature = "usi1-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "usi1";

    fn finish(_: &mut BootCtx) {
        crate::usi1_demo::run();
        exit_on(u64::from(crate::usi1_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "usi2-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "usi2";

    fn finish(_: &mut BootCtx) {
        crate::usi2_demo::run();
        exit_on(u64::from(crate::usi2_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "sec1-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "sec1";

    fn finish(_: &mut BootCtx) {
        crate::sec1_demo::run();
        exit_on(u64::from(crate::sec1_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "sec2-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "sec2";

    fn finish(_: &mut BootCtx) {
        crate::sec2_demo::run();
        exit_on(u64::from(crate::sec2_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "sec3-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "sec3";

    fn finish(_: &mut BootCtx) {
        crate::sec3_demo::run();
        exit_on(u64::from(crate::sec3_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "sec4-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "sec4";

    fn finish(_: &mut BootCtx) {
        crate::sec4_demo::run();
        exit_on(u64::from(crate::sec4_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "sec5-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "sec5";

    fn finish(_: &mut BootCtx) {
        crate::sec5_demo::run();
        exit_on(u64::from(crate::sec5_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "net2-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "net2";

    fn finish(_: &mut BootCtx) {
        crate::net2_demo::run();
        exit_on(u64::from(crate::net2_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "net3-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "net3";

    fn finish(_: &mut BootCtx) {
        crate::net3_demo::run();
        exit_on(u64::from(crate::net3_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "net4-runtime-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "net4-runtime";

    fn finish(_: &mut BootCtx) {
        crate::net4_runtime_demo::run();
        exit_on(u64::from(crate::net4_runtime_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "compat-elf-backend-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "compat-elf-backend";

    fn finish(_: &mut BootCtx) {
        crate::compat_elf_demo::run();
        exit_on(u64::from(crate::compat_elf_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(all(feature = "compat-syscall-verify", target_arch = "x86_64"))]
mod dedicated {
    use super::*;

    pub const NAME: &str = "compat-syscall";

    fn finish(_: &mut BootCtx) {
        crate::linux_abi_demo::run();
        exit_on(u64::from(crate::linux_abi_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(all(feature = "compat-dynamic-libc-verify", target_arch = "x86_64"))]
mod dedicated {
    use super::*;

    pub const NAME: &str = "compat-dynamic-libc";

    fn finish(_: &mut BootCtx) {
        crate::compat_dynamic_demo::run();
        exit_on(u64::from(crate::compat_dynamic_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "pex1-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "pex1";

    fn finish(_: &mut BootCtx) {
        crate::scale_demo::run();
        exit_on(u64::from(crate::scale_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "pex2-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "pex2";

    fn finish(_: &mut BootCtx) {
        crate::pex0_demo::run();
        exit_on(u64::from(crate::pex0_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(feature = "sec6-verify")]
mod dedicated {
    use super::*;

    pub const NAME: &str = "sec6";

    fn finish(_: &mut BootCtx) {
        crate::sec6_demo::run();
        exit_on(u64::from(crate::sec6_demo::failed()));
    }

    pub const PLAN: &[&[Step]] = &[PREFIX, SMP_UP, &[PlanItem::Finish(finish)]];
}

#[cfg(any(
    feature = "rt1-verify", feature = "rt2-verify", feature = "rt3-verify", feature = "budget-window-verify",
    feature = "krn3-fast-tick-verify", feature = "krn3-postsplit-verify", feature = "krn3-p999-verify",
    feature = "evt1-verify", feature = "evt2-verify", feature = "evt2-broadcast-verify",
    feature = "s3-nohz-verify", feature = "shm1-verify", feature = "hwv1-verify", feature = "hwv2-verify", feature = "hwv3-verify", feature = "hwv4-verify", feature = "hwv5-prod-verify", feature = "jaso1-verify", feature = "drv3-verify", feature = "arch2-verify", feature = "fs1-ext4-verify", feature = "blk1-verify", feature = "fs0-journal-verify", feature = "mod1-verify", feature = "boot-stage-rollback-verify", feature = "pex0-verify", feature = "usi1-verify", feature = "usi2-verify", feature = "sec1-verify", feature = "sec2-verify", feature = "sec3-verify", feature = "sec4-verify", feature = "sec5-verify", feature = "net2-verify", feature = "net3-verify", feature = "net4-runtime-verify", feature = "compat-elf-backend-verify", feature = "compat-syscall-verify", feature = "compat-dynamic-libc-verify", feature = "pex1-verify", feature = "pex2-verify", feature = "sec6-verify",
    feature = "s2-only", feature = "s4-soak",
))]
pub use dedicated::{NAME, PLAN};
