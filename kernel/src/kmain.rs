//! 架构无关的内核主流程：引导适配层（`main.rs`）完成平台入口后调用 [`start`]。
//!
//! 只通过 `arch::*` 使用硬件；换 ISA 时本文件不改。
//! 当前流程即 M1.1–M1.5 的验收序列：横幅 → 异常验证 → 时钟中断 → 协作式调度 → 抢占式调度 →
//! 机制演练（kernel-core）→ 物理页帧分配（M2.1）→ 退出。

use crate::arch::{self, ExitStatus};
use crate::boot::BootSpec;
use crate::{clock, config, fix_demo, ipc_demo, irq, kprintln, mech_demo, mm, overload_demo, pi_demo, prog_demo, qos_demo, ring_demo, rt_demo, sched, user_demo};

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

    // M1.5：以内核任务演练 kernel-core 的全部机制（任务内自行开关中断）。
    mech_demo::run();
    if mech_demo::failed() > 0 {
        kprintln!("[JSR-EXIT] failure mech_failed={}", mech_demo::failed());
        arch::exit_emulator(ExitStatus::Failure);
    }

    // M2.1：物理页帧分配（真实内存图 + 真实读写校验）。
    mm::demo::run(boot);
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
    // M2.4：独立地址空间（同一虚拟地址、不同物理帧，真实切换）。
    mm::demo::run_space();
    // M3.1：真实进入 Ring 3；用户态异常只终止该任务。
    user_demo::run();
    // M3.2：系统调用入口 + 稳定 ID 登记表 + 统一权限检查。
    user_demo::run_syscall();
    // M3.3：用户指针安全（校验 + 经物理映射复制）。
    user_demo::run_user_pointers();
    // M3.4：进程 / 线程对象（同一进程两个线程、句柄、退出与回收）。
    user_demo::run_process();
    // M5.1-pre：从 ELF 文件装载并运行用户程序。
    user_demo::run_elf();
    // M4.1：对象生命周期（外部所有权 / 内部引用 / 清理过程级联）。
    user_demo::run_lifecycle();
    // M4.2：Handle/Rights（duplicate/restrict 只降权；跨进程原子转移）。
    user_demo::run_handles();
    // 基础设施修复的回归演练：失败路径与回滚。
    fix_demo::run();
    // M4.3：用户态异步环（提交 → 完成；完成信用；取消；closing；配额）。
    ring_demo::run();
    // M4.4：IPC Channel（send/recv 经 ring；两阶段 send；原子交付；取消竞争；页帧固定）。
    ipc_demo::run();
    // M5.1：最小非特权程序（特权级 3、隔离、用户异常、坏指针、进程终止与等待、完全回收）。
    prog_demo::run();
    // J-1：用户态运行时（匿名内存系统调用；用运行时写成的普通 Rust 程序：堆、线程、Channel、异步环）。
    rt_demo::run();
    // SCHED-1：服务质量分级调度（档位规则、动态任务数、过载下的唤醒延迟、压力撤销后恢复）。
    qos_demo::run();
    // SCHED-2：优先级继承（三任务反转有界、传递继承、拒绝路径、持有者退出、压力撤销后恢复）。
    pi_demo::run();
    // SCHED-3：过载防护（每进程 CPU 上限、看门狗、内存压力分级准入、压力撤销后回到基线）。
    overload_demo::run();
    let fails = [
        mm::demo::failed(),
        user_demo::failed(),
        fix_demo::failed(),
        ring_demo::failed(),
        ipc_demo::failed(),
        prog_demo::failed(),
        rt_demo::failed(),
        qos_demo::failed(),
        pi_demo::failed(),
        overload_demo::failed(),
    ];
    if fails.iter().any(|&f| f > 0) {
        kprintln!(
            "[JSR-EXIT] failure mm_failed={} user_failed={} fix_failed={} ring_failed={} ipc_failed={} prog_failed={} rt_failed={} qos_failed={} pi_failed={} overload_failed={}",
            fails[0],
            fails[1],
            fails[2],
            fails[3],
            fails[4],
            fails[5],
            fails[6],
            fails[7],
            fails[8],
            fails[9]
        );
        arch::exit_emulator(ExitStatus::Failure);
    }

    kprintln!("[JSR-EXIT] success");
    arch::exit_emulator(ExitStatus::Success)
}
