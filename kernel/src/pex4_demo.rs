//! PEX-4 local scheduling-selection path evaluation.
//! PEX-4 本地调度选择路径评估。
//!
//! The profile measures visited run-list entries, candidates consumed by the
//! policy, candidate density and selection latency without changing the policy.
//! 本配置测量运行列表遍历项、策略实际消费的候选、候选密度和选择延迟，不改变策略。

use alloc::vec;
use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::bench::{summarize, Summary};
use kernel_core::smp::CpuSet;

use crate::task::TaskId;
use crate::{hrtime, kprintln, sched};

const YIELDS_PER_TASK: usize = 32;
const TASK_BASE: u64 = 0x5045_5834_0000;

#[derive(Clone, Copy)]
struct Density {
    name: &'static str,
    tasks_per_cpu: usize,
}

const DENSITIES: [Density; 3] = [
    Density {
        name: "low",
        tasks_per_cpu: 1,
    },
    Density {
        name: "medium",
        tasks_per_cpu: 4,
    },
    Density {
        name: "high",
        tasks_per_cpu: 8,
    },
];

static NEXT_TASK: AtomicU32 = AtomicU32::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static TASKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn fail(message: core::fmt::Arguments<'_>) {
    FAILED.fetch_add(1, Ordering::Relaxed);
    kprintln!("[JSR-PEX4-FAIL] {}", message);
}

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

fn worker() {
    let index = NEXT_TASK.fetch_add(1, Ordering::AcqRel);
    if index >= TASKS.load(Ordering::Acquire) {
        return;
    }
    while GO.load(Ordering::Acquire) == 0 {
        sched::pause();
    }
    for _ in 0..YIELDS_PER_TASK {
        sched::yield_now();
    }
    DONE.fetch_add(1, Ordering::AcqRel);
}

fn reset(tasks: usize) {
    NEXT_TASK.store(0, Ordering::Relaxed);
    GO.store(0, Ordering::Relaxed);
    DONE.store(0, Ordering::Relaxed);
    TASKS.store(tasks as u32, Ordering::Relaxed);
}

fn run_density(density: Density, density_index: usize, cpus: CpuSet) {
    let cpu_list: alloc::vec::Vec<usize> = cpus.iter().collect();
    let desired_tasks = cpu_list.len().saturating_mul(density.tasks_per_cpu);
    // Slot 0 is permanently occupied by the boot worker. The standard
    // profile therefore exposes 63 worker slots from its 64 total slots.
    // 槽位 0 永久由引导线程占用；标准档位总槽位为 64 时，实际可创建 63
    // 个 worker。高密度矩阵在 8 vCPU 上按目标 8/核申请，但必须按真实容量
    // 饱和，不能向调度器提交一个必然失败的请求。
    let capacity_workers = sched::capacity().saturating_sub(1);
    let tasks = desired_tasks.min(capacity_workers);
    if tasks == 0 || cpu_list.is_empty() {
        fail(format_args!(
            "density={} unsupported_tasks={} worker_capacity={}",
            density.name, desired_tasks, capacity_workers
        ));
        return;
    }
    // Workers run on APs as soon as their spawn request is processed. Keep the
    // boot worker from being preempted between publishing the task count and
    // opening the start barrier: otherwise high-density workers can all sleep
    // on `GO == 0` while the only context that can set `GO` is not runnable.
    // Worker creation and barrier publication are therefore one setup window.
    // AP 工作线程在 spawn 请求被处理后即可运行。任务数与启动屏障发布之间必须
    // 阻止引导线程被抢占；否则高密度 worker 会全部睡在 `GO == 0` 上，而唯一
    // 能设置 `GO` 的上下文无法恢复。因此把创建与屏障发布放在同一个配置窗口。
    let previous_preemption = sched::set_preemption(false);
    reset(tasks);
    let mut spawned = true;
    for index in 0..tasks {
        let mut affinity = CpuSet::EMPTY;
        spawned &= affinity.insert(cpu_list[index % cpu_list.len()]);
        spawned &= sched::spawn_on(
            TaskId(TASK_BASE + (density_index * 0x1000 + index) as u64),
            "pex4-select",
            worker,
            None,
            affinity,
        )
        .is_ok();
    }
    if !spawned {
        sched::set_preemption(previous_preemption);
        fail(format_args!("density={} spawn", density.name));
        return;
    }
    sched::pex4_probe::reset();
    let switches_before = sched::switch_count();
    GO.store(1, Ordering::Release);
    // Measure the configured mixed workload with the scheduler's normal
    // preemption policy, then restore the caller's setting.
    // 按调度器正常抢占策略测量混合负载，结束后恢复调用方设置。
    sched::set_preemption(true);
    sched::run();
    sched::set_preemption(previous_preemption);
    let switches = sched::switch_count().saturating_sub(switches_before);
    let snapshot = sched::pex4_probe::snapshot(sched::pex4_probe::MAX_SAMPLES);
    let mut samples = vec![0u64; snapshot.samples];
    let (sample_count, dropped) = sched::pex4_probe::copy_samples(&mut samples);
    let summary: Option<Summary> = summarize(&mut samples[..sample_count]);
    let (p50, p99, p999, max) = summary
        .map(|value| (value.p50, value.p99, value.p999, value.max))
        .unwrap_or((0, 0, 0, 0));
    let average_visited_permille = if snapshot.picks == 0 {
        0
    } else {
        snapshot.visited.saturating_mul(1_000) / snapshot.picks
    };
    let candidate_density_permille = if snapshot.visited == 0 {
        0
    } else {
        snapshot.candidates.saturating_mul(1_000) / snapshot.visited
    };
    let complete = DONE.load(Ordering::Acquire) == tasks as u32
        && snapshot.picks > 0
        && sample_count > 0
        && dropped == 0
        && snapshot.dropped == 0;
    if !complete {
        fail(format_args!("density={} complete=false", density.name));
    }
    kprintln!(
        "[JSR-PEX4] density={} vcpus={} tasks={} capacity_workers={} tasks_per_cpu={} yields={} switches={} picks={} visited={} candidates={} avg_visited_permille={} candidate_density_permille={} max_visited={} max_candidates={} samples={} dropped={} p50_cycles={} p99_cycles={} p999_cycles={} max_cycles={} p50_ns={} p99_ns={} p999_ns={} complete={}",
        density.name,
        cpu_list.len(),
        tasks,
        capacity_workers,
        density.tasks_per_cpu,
        tasks * YIELDS_PER_TASK,
        switches,
        snapshot.picks,
        snapshot.visited,
        snapshot.candidates,
        average_visited_permille,
        candidate_density_permille,
        snapshot.max_visited,
        snapshot.max_candidates,
        sample_count,
        dropped.saturating_add(snapshot.dropped.saturating_sub(dropped)),
        p50,
        p99,
        p999,
        max,
        hrtime::counts_to_ns(p50).unwrap_or(0),
        hrtime::counts_to_ns(p99).unwrap_or(0),
        hrtime::counts_to_ns(p999).unwrap_or(0),
        complete,
    );
}

pub fn run() {
    FAILED.store(0, Ordering::Relaxed);
    let cpus = sched::online_cpus();
    if cpus.is_empty() || cpus.len() > kernel_core::smp::MAX_CPUS {
        fail(format_args!("unsupported online CPU set"));
        return;
    }
    for (index, density) in DENSITIES.into_iter().enumerate() {
        run_density(density, index, cpus);
    }
}
