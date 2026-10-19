//! 架构无关的内核主流程：引导适配层（`main.rs`）完成平台入口后调用 [`start`]。
//!
//! 只通过 `arch::*` 使用硬件；换 ISA 时本文件不改。
//! 当前流程即 M1.1–M1.5 的验收序列：横幅 → 异常验证 → 时钟中断 → 协作式调度 → 抢占式调度 →
//! 机制演练（kernel-core）→ 物理页帧分配（M2.1）→ 退出。

use crate::arch::{self, ExitStatus};
use crate::boot::BootSpec;
use crate::{balance_demo, clock, irq_demo, config, counter_demo, fix_demo, irq, job_demo, kprint, kprintln, mech_demo, mm, pi_demo, profile, profile_demo, sched, smp, user_demo};
#[cfg(feature = "user-programs")]
use crate::{bench_demo, ipc_demo, overload_demo, prog_demo, qos_demo, ring_demo, robust_demo, rt_demo};

/// 内核版本（横幅中输出）。
pub const VERSION: &str = "0.0.1";
/// 定时器频率（取自配置档）。
const TIMER_HZ: u32 = config::ACTIVE.clock.timer_hz;
/// 启动自检至少等到的 tick 数（取自配置档）。
const BOOT_TICKS: u64 = config::ACTIVE.clock.boot_ticks;
/// 等 tick 的兜底次数：定时器没配好时必须报错退出，而不是永远睡下去。
const MAX_WAITS: u64 = 20_000_000;

/// 内核主流程（永不返回）。`boot` 是引导适配层转换好的交接信息。
pub fn start(boot: &'static BootSpec) -> ! {
    arch::console_init();
    kprintln!("[JSR-BOOT] jasper-os rust kernel {} {}", VERSION, arch::NAME);
    config::report();
    arch::early_init();

    // 证明异常处理已接通。
    arch::debug_breakpoint();

    // M1.2：中断控制器 + 定时器，开中断后等到足够多的 tick。
    arch::irq_init(TIMER_HZ);
    arch::irq_enable();
    let mut waits: u64 = 0;
    while clock::ticks() < BOOT_TICKS {
        arch::wait_for_interrupt();
        irq::poll_and_handle();
        waits += 1;
        if waits > MAX_WAITS {
            kprintln!("[JSR-TICK-TIMEOUT] n={}", clock::ticks());
            arch::exit_emulator(ExitStatus::Failure);
        }
    }
    // 收尾关中断，保证随后的协作式演示输出可复现。
    arch::irq_disable();

    // M1.3：协作式调度（关中断）。
    sched::demo::run();

    // M1.4：定时器抢占（需要开中断才能收到定时器中断）。
    arch::irq_enable();
    sched::demo::run_preemptive();
    arch::irq_disable();

    // 64 位计数单元：宽值与「与定时器中断共享」（32 位目标上没有 64 位原子指令，这里证明实现不会在中断中自锁）。
    counter_demo::run();
    if counter_demo::failed() > 0 {
        kprintln!("[JSR-EXIT] failure counter64_failed={}", counter_demo::failed());
        arch::exit_emulator(ExitStatus::Failure);
    }

    // M1.5：以内核任务演练 kernel-core 的全部机制（任务内自行开关中断）。
    mech_demo::run();
    if mech_demo::failed() > 0 {
        kprintln!("[JSR-EXIT] failure mech_failed={}", mech_demo::failed());
        arch::exit_emulator(ExitStatus::Failure);
    }

    // M2.1：物理页帧分配（真实内存图 + 真实读写校验）。
    mm::demo::run(boot);
    // 多处理器：趁低端内存尚未被占用时预留平台需要的启动帧（平台不需要时什么也不做）。
    if !smp::reserve_start_frame() {
        kprintln!("[JSR-SMP] start_frame unavailable");
    }
    // M2.2：架构无关映射 API（x86_64 由 4 级页表实现）。
    mm::demo::run_map(boot);
    // M2.3：内核堆（Box/Vec/String 可用，按需增长）。
    mm::demo::run_heap();
    // 堆就绪：为其余调度槽位预留内核栈（此后并发任务数不再受静态栈数量限制）。
    // 预留之后把堆的空闲余量补回预留前的值（见 `heap::ensure_free`）。
    let (_, heap_slack, _, _) = mm::heap::stats();
    let reserved = sched::reserve_stacks();
    if mm::heap::ensure_free(heap_slack).is_err() {
        kprintln!("[JSR-SCHED] capacity heap_slack_restore_failed want={}", heap_slack);
    }
    match reserved {
        Ok(n) => kprintln!(
            "[JSR-SCHED] capacity slots={} static_stacks={} max={} policy={} preemption=default_on",
            n,
            sched::stack::STATIC_STACKS,
            sched::MAX_TASKS,
            sched::policy_name()
        ),
        Err(e) => kprintln!("[JSR-SCHED] capacity reserve_failed available={}", e.available),
    }
    // POL-2：系统 Profile（模块面 + 参数档）在堆就绪后立刻校验；不合法就拒绝启动，
    // 因为后面的服务判定、配额与调度类别都以这份声明为前提。
    let profile_failed = profile::boot_report();
    if profile_failed > 0 {
        kprintln!("[JSR-EXIT] failure profile_failed={}", profile_failed);
        arch::exit_emulator(ExitStatus::Failure);
    }
    profile_demo::run();
    // POL-3：批处理作业（依赖 / 优先级 / 取消 / 终态 / 满载下交互性）。
    job_demo::run();
    // M2.4：独立地址空间（同一虚拟地址、不同物理帧，真实切换）。
    mm::demo::run_space();
    // SMP-1：启动其他处理器（每核数据、各自计时、核间中断、跨核调用、TLB 击落）。
    smp::demo::run(smp::start_secondaries(TIMER_HZ));
    // M3.1：真实进入 Ring 3；用户态异常只终止该任务。
    user_demo::run();
    // M3.2：系统调用入口 + 稳定 ID 登记表 + 统一权限检查。
    user_demo::run_syscall();
    // M3.3：用户指针安全（校验 + 经物理映射复制）。
    user_demo::run_user_pointers();
    // M3.4：进程 / 线程对象（同一进程两个线程、句柄、退出与回收）。
    user_demo::run_process();
    // M5.1-pre：从 ELF 文件装载并运行用户程序。
    #[cfg(feature = "user-programs")]
    user_demo::run_elf();
    // M4.1：对象生命周期（外部所有权 / 内部引用 / 清理过程级联）。
    #[cfg(feature = "user-programs")]
    user_demo::run_lifecycle();
    // M4.2：Handle/Rights（duplicate/restrict 只降权；跨进程原子转移）。
    user_demo::run_handles();
    // 基础设施修复的回归演练：失败路径与回滚。
    fix_demo::run();
    #[cfg(feature = "user-programs")]
    {
        // M4.3：用户态异步环（提交 → 完成；完成信用；取消；closing；配额）。
        ring_demo::run();
        // M4.4：IPC Channel（send/recv 经 ring；两阶段 send；原子交付；取消竞争；页帧固定）。
        ipc_demo::run();
        // M5.1：最小非特权程序（特权级 3、隔离、用户异常、坏指针、进程终止与等待、完全回收）。
        prog_demo::run();
        // S-1：系统调用健壮性回归（真实用户态、固定种子、有界调用、资源回到基线）。
        robust_demo::run();
        // J-1：用户态运行时（匿名内存系统调用；用运行时写成的普通 Rust 程序：堆、线程、Channel、异步环）。
        rt_demo::run();
        // SCHED-1：服务质量分级调度（档位规则、动态任务数、过载下的唤醒延迟、压力撤销后恢复）。
        // 纯轮转策略不提供分级语义，其构建跳过这些依赖 QoS 保证的演练（分时构建照常执行）。
        #[cfg(not(feature = "sched-rr"))]
        qos_demo::run();
    }
    // SCHED-2：优先级继承（三任务反转有界、传递继承、拒绝路径、持有者退出、压力撤销后恢复）。
    #[cfg(not(feature = "sched-rr"))]
    pi_demo::run();
    // SMP-2：每核运行队列与负载均衡（各核都忙、窃取、过载下交互延迟有上界、恢复、亲和与迁移、跨核继承与上限）。
    // 其中的延迟与继承判据依赖 QoS 保证，纯轮转构建跳过（分时构建照常执行）。
    #[cfg(not(feature = "sched-rr"))]
    balance_demo::run();
    // SMP-3：中断与服务的多核化（送达、均衡、风暴预算下交互延迟有上界、恢复、分片服务各核均衡）。
    #[cfg(not(feature = "sched-rr"))]
    irq_demo::run();
    #[cfg(feature = "user-programs")]
    {
        // SCHED-3：过载防护（每进程 CPU 上限、看门狗、内存压力分级准入、压力撤销后回到基线）。
        #[cfg(not(feature = "sched-rr"))]
        overload_demo::run();
        // T-2：基准（时钟中断、上下文切换、页帧、堆、系统调用、异步环、IPC 往返）与按预算评估参数取值。
        bench_demo::run();
    }
    // 各演练的断言失败数（顺序即输出顺序）；未编译的演练不出现。
    let fails: &[(&str, u32)] = &[
        ("mm", mm::demo::failed()),
        ("smp", smp::demo::failed()),
        ("balance", balance_demo::failed()),
        ("irq", irq_demo::failed()),
        ("user", user_demo::failed()),
        ("fix", fix_demo::failed()),
        ("profile", profile_demo::failed()),
        ("job", job_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("ring", ring_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("ipc", ipc_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("prog", prog_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("robust", robust_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("rt", rt_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("qos", qos_demo::failed()),
        ("pi", pi_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("overload", overload_demo::failed()),
        #[cfg(feature = "user-programs")]
        ("bench", bench_demo::failed()),
    ];
    if fails.iter().any(|&(_, f)| f > 0) {
        kprint!("[JSR-EXIT] failure");
        for (name, f) in fails {
            kprint!(" {}_failed={}", name, f);
        }
        kprintln!();
        arch::exit_emulator(ExitStatus::Failure);
    }
    // 未内嵌用户程序时如实说明：依赖用户程序的演练没有运行。
    if !cfg!(feature = "user-programs") {
        kprintln!("[JSR-STAGE] user_programs=absent skipped=elf,lifecycle,ring,ipc,prog,rt,qos,overload,bench");
    }
    kprintln!("[JSR-EXIT] success");
    arch::exit_emulator(ExitStatus::Success)
}
