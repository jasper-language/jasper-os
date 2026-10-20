//! 内核参数与构建期配置档（Profile）：把散落在各模块里的可调常量收拢到一处。
//! Kernel parameters and build-time profiles: one place for every tunable constant.
//!
//! # 职责
//! * 定义 [`KernelConfig`]：按领域分组（时钟、调度、内存、对象、异步环、IPC、诊断）的全部可调参数；
//! * 给出两个配置档 [`KernelConfig::STANDARD`]（默认）与 [`KernelConfig::COMPACT`]（更高时钟频率、
//!   更短时间片、更小的表与配额，用于小内存 / 交互优先的场景）；
//! * [`KernelConfig::validate`] 在**编译期**（内核以 `const` 断言调用）与宿主测试中检查参数之间的约束，
//!   不合法的配置档根本无法构建出内核；
//! * [`KernelConfig::for_each_field`] 以「名 + 值」逐项列出生效参数，供启动时输出结构化事件。
//!
//! # 边界（为什么放在这里）
//! * 纯数据 + 纯校验，不依赖硬件，因此在宿主上可测；内核只负责「选哪一个档」与「把值接到各模块」。
//! * 只收拢**可调**参数。属于用户态二进制契约的常量（单条消息上限、单条消息句柄数、每端点队列消息数、
//!   控制台单次写上限、提交/完成记录布局等）**不在**配置档里：用户程序按固定值编写，换档不得改变它们。
//! * 地址布局（堆起点、匿名映射基址）与页大小也不在这里：它们是内存布局约定，不是调优参数。
//!
//! # 扩展方式
//! 新增参数 = 在对应分组加字段 + 两个配置档各给一个值 + 在 `validate` 里写出它的约束 + 在
//! `for_each_field` 里列出。已有字段的含义不改；新档位只加常量，不改旧档的值。

use crate::pressure::PressureParams;
use crate::sched::{QosParams, QOS_CLASSES};

/// 页大小（字节）：栈、堆增长步长都必须是它的整数倍。
const PAGE: u64 = 4096;

/// 时钟参数。
/// Clock parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockParams {
    /// 定时器中断频率（Hz）。
    pub timer_hz: u32,
    /// 启动自检阶段至少等待的 tick 数。
    pub boot_ticks: u64,
}

/// 调度参数。
/// Scheduler parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedParams {
    /// QoS 策略参数（各档时间片、最低份额、用量衰减周期、欠账上限）。
    pub qos: QosParams,
    /// 任务槽位总数上限（含引导线程）。
    pub max_tasks: usize,
    /// 单个任务内核栈的字节数。
    pub kernel_stack_bytes: usize,
    /// 看门狗阈值（tick）：连续占用处理器这么久而不让出的任务被记录。
    pub watchdog_ticks: u32,
    /// 看门狗记录保留的条数。
    pub watchdog_log: usize,
    /// CPU 组默认的令牌桶容量（tick）。
    pub cpu_burst_ticks: u32,
}

/// 内存参数。
/// Memory parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryParams {
    /// 内核堆虚拟区间上限（字节，按需映射）。
    pub heap_max: u64,
    /// 内核堆每次至少增长的字节数。
    pub heap_grow_step: u64,
    /// 内存压力分级与保留帧。
    pub pressure: PressureParams,
    /// 每个进程最多拥有的数据帧数。
    pub max_process_frames: usize,
    /// 单次映射 / 取消映射最多涉及的页数。
    pub max_map_pages: u64,
    /// 页帧位图的字数（每字 64 帧；16K 字 ≈ 4 GiB，256K 字 ≈ 64 GiB）。
    pub frame_bitmap_words: usize,
}

/// 对象与句柄参数。
/// Object and handle parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectParams {
    /// 全系统内核对象总数上限。
    pub max_objects: usize,
    /// 每个进程句柄表的容量。
    pub handles_per_process: usize,
}

/// 异步环参数。
/// Async-ring parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingParams {
    /// 完成队列容量上限（创建时可指定 1..=该值）。
    pub cq_capacity: usize,
    /// 每个环的请求控制块容量。
    pub blocks_per_ring: usize,
    /// 单次进入最多带入的提交数。
    pub sq_batch: usize,
    /// 每进程环数上限。
    pub max_rings_per_process: u32,
    /// 每进程跨所有环的在飞请求上限。
    pub max_in_flight_per_process: u32,
}

/// IPC 配额参数（单条消息上限属于用户态契约，不在此处）。
/// IPC quota parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcParams {
    /// 每进程端点数上限。
    pub max_endpoints_per_process: u32,
    /// 每个端点接收队列的总字节上限。
    pub max_queue_bytes: usize,
    /// 每进程仍在队列中的消息体总字节上限。
    pub max_process_bytes: usize,
    /// 全系统仍在队列中的消息体总字节上限。
    pub max_total_bytes: usize,
}

/// 诊断参数。
/// Diagnostics parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagParams {
    /// 内核事件追踪环保留的最近事件条数。
    pub trace_capacity: usize,
    /// 中断延迟处理队列长度。
    pub irq_queue_len: usize,
}

/// 内存治理策略。
/// Memory management strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPolicy {
    /// 压力感知：按缺页延迟与换入换出频率分级。
    PressureAware,
    /// 固定阈值：只看水位线，简单但容易抖动。
    FixedThreshold,
}

impl MemoryPolicy {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            MemoryPolicy::PressureAware => "pressure-aware",
            MemoryPolicy::FixedThreshold => "fixed-threshold",
        }
    }
}

/// 功耗策略。
/// Power management strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerPolicy {
    /// 空闲时拉长 tick 间隔（等价于浅层 tickless）。
    Tickless,
    /// 固定周期 tick。
    Periodic,
}

impl PowerPolicy {
    /// 稳定文本名。
    pub const fn as_str(self) -> &'static str {
        match self {
            PowerPolicy::Tickless => "tickless",
            PowerPolicy::Periodic => "periodic",
        }
    }
}

/// 策略选择（POL-6）：内存与功耗各自可替换。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyParams {
    /// 内存治理策略。
    pub memory: MemoryPolicy,
    /// 功耗策略。
    pub power: PowerPolicy,
    /// 空闲时 tick 间隔的倍率（Tickless 下 ≥2；Periodic 下必须为 1）。
    pub idle_tick_divisor: u32,
    /// 新建 CPU 组的默认份额（千分比）：未显式指定时使用。
    pub group_share_permille: u32,
}

/// 一个完整的内核配置档。
/// A complete kernel configuration profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelConfig {
    /// 配置档名（启动时输出）。
    pub name: &'static str,
    /// 时钟。
    pub clock: ClockParams,
    /// 调度。
    pub sched: SchedParams,
    /// 内存。
    pub memory: MemoryParams,
    /// 对象与句柄。
    pub objects: ObjectParams,
    /// 异步环。
    pub ring: RingParams,
    /// IPC 配额。
    pub ipc: IpcParams,
    /// 诊断。
    pub diag: DiagParams,
    /// 策略选择。
    pub policy: PolicyParams,
}

/// 配置不合法：`field` 是违反约束的参数名（与 [`KernelConfig::for_each_field`] 的名字一致）。
/// Invalid configuration; `field` names the offending parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    /// 违反约束的参数名。
    pub field: &'static str,
}

/// 参数取值的上下界（校验用；也是文档：超出这些范围的值没有被验证过）。
/// Validation bounds for parameters.
pub mod bounds {
    /// 定时器频率下限（Hz）：再低则时间片粒度过粗。
    pub const MIN_TIMER_HZ: u32 = 50;
    /// 定时器频率上限（Hz）：再高则中断开销压过有效工作。
    pub const MAX_TIMER_HZ: u32 = 1000;
    /// 任务槽位下限：引导线程 + 至少一个工作任务 + 静态栈覆盖的槽位。
    pub const MIN_TASKS: usize = 8;
    /// 任务槽位上限：调度机制按槽位线性扫描，更大的规模未经验证。
    pub const MAX_TASKS: usize = 128;
    /// 内核栈下限（字节）：系统调用路径会在栈上临时构造较大的内核对象。
    pub const MIN_KERNEL_STACK: usize = 32 * 1024;
    /// 单条消息体上限（字节，用户态契约）：每端点队列字节配额不得小于它。
    pub const MSG_BYTES: usize = 64 * 1024;
}

impl KernelConfig {
    /// 默认配置档：100 Hz；时间片 2/2/4/4 tick；64 个任务槽位；64 KiB 内核栈；堆上限 64 MiB、
    /// 每次增长 64 KiB；1024 个内核对象；每进程 64 个句柄。
    pub const STANDARD: KernelConfig = KernelConfig {
        name: "standard",
        clock: ClockParams { timer_hz: 100, boot_ticks: 25 },
        sched: SchedParams {
            qos: QosParams::DEFAULT,
            max_tasks: 64,
            kernel_stack_bytes: 64 * 1024,
            watchdog_ticks: 50,
            watchdog_log: 16,
            cpu_burst_ticks: 4,
        },
        memory: MemoryParams {
            heap_max: 64 * 1024 * 1024,
            heap_grow_step: 64 * 1024,
            pressure: PressureParams::DEFAULT,
            max_process_frames: 8192,
            max_map_pages: 1024,
            // 256K 字 × 64 帧 × 4 KiB = 64 GiB 物理内存（.bss 占 2 MiB）。
            frame_bitmap_words: 256 * 1024,
        },
        objects: ObjectParams { max_objects: 1024, handles_per_process: 64 },
        ring: RingParams {
            cq_capacity: 64,
            blocks_per_ring: 64,
            sq_batch: 64,
            max_rings_per_process: 8,
            max_in_flight_per_process: 256,
        },
        ipc: IpcParams {
            max_endpoints_per_process: 64,
            max_queue_bytes: 1024 * 1024,
            max_process_bytes: 4 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
        },
        diag: DiagParams { trace_capacity: 32, irq_queue_len: 64 },
        policy: PolicyParams { memory: MemoryPolicy::PressureAware, power: PowerPolicy::Tickless, idle_tick_divisor: 4, group_share_permille: 250 },
    };

    /// 紧凑配置档：250 Hz、时间片减半（交互档 1 tick），看门狗阈值按相同的墙钟时间（0.5 秒）换算；
    /// 任务槽位、内核对象、在飞请求、IPC 字节配额与堆增长步长都更小；内存压力阈值与保留帧更低。
    pub const COMPACT: KernelConfig = KernelConfig {
        name: "compact",
        clock: ClockParams { timer_hz: 250, boot_ticks: 25 },
        sched: SchedParams {
            qos: QosParams { quantum: [1, 1, 2, 2], ..QosParams::DEFAULT },
            max_tasks: 32,
            kernel_stack_bytes: 64 * 1024,
            watchdog_ticks: 125,
            watchdog_log: 8,
            cpu_burst_ticks: 4,
        },
        memory: MemoryParams {
            heap_max: 32 * 1024 * 1024,
            heap_grow_step: 16 * 1024,
            pressure: PressureParams { low_permille: 100, critical_permille: 40, reserve_frames: 128 },
            max_process_frames: 8192,
            max_map_pages: 1024,
            // 紧凑档只覆盖 4 GiB，把 .bss 压回 128 KiB。
            frame_bitmap_words: 16 * 1024,
        },
        objects: ObjectParams { max_objects: 512, handles_per_process: 64 },
        ring: RingParams {
            cq_capacity: 64,
            blocks_per_ring: 64,
            sq_batch: 64,
            max_rings_per_process: 8,
            max_in_flight_per_process: 128,
        },
        ipc: IpcParams {
            max_endpoints_per_process: 32,
            max_queue_bytes: 512 * 1024,
            max_process_bytes: 2 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
        },
        diag: DiagParams { trace_capacity: 16, irq_queue_len: 32 },
        policy: PolicyParams { memory: MemoryPolicy::FixedThreshold, power: PowerPolicy::Periodic, idle_tick_divisor: 1, group_share_permille: 500 },
    };

    /// 检查参数之间的约束；通过返回 `Ok(())`，否则返回第一个违反约束的参数名。`const`：内核在编译期调用。
    /// Check all parameter constraints (usable in `const` context).
    pub const fn validate(&self) -> Result<(), ConfigError> {
        // 策略与空闲倍率必须自洽：tickless 需要拉长间隔，periodic 必须保持 1。
        match (self.policy.power, self.policy.idle_tick_divisor) {
            (PowerPolicy::Tickless, d) if d >= 2 => {}
            (PowerPolicy::Periodic, 1) => {}
            _ => return Err(ConfigError { field: "policy.idle_tick_divisor" }),
        }
        // 组份额必须在 (0, 1000] 内，否则组永远得不到处理器或永远独占。
        if self.policy.group_share_permille == 0 || self.policy.group_share_permille > 1000 {
            return Err(ConfigError { field: "policy.group_share_permille" });
        }
        macro_rules! require {
            ($cond:expr, $field:literal) => {
                if !$cond {
                    return Err(ConfigError { field: $field });
                }
            };
        }
        let c = &self.clock;
        require!(c.timer_hz >= bounds::MIN_TIMER_HZ && c.timer_hz <= bounds::MAX_TIMER_HZ, "timer_hz");
        require!(c.boot_ticks >= 1, "boot_ticks");

        let s = &self.sched;
        let mut i = 0;
        let mut max_quantum = 0;
        while i < QOS_CLASSES {
            require!(s.qos.quantum[i] >= 1, "quantum");
            require!(s.qos.min_share_permille[i] <= 1000, "min_share_permille");
            if s.qos.quantum[i] > max_quantum {
                max_quantum = s.qos.quantum[i];
            }
            i += 1;
        }
        require!(s.qos.decay_period >= 1, "decay_period");
        require!(s.max_tasks >= bounds::MIN_TASKS && s.max_tasks <= bounds::MAX_TASKS, "max_tasks");
        require!(
            s.kernel_stack_bytes >= bounds::MIN_KERNEL_STACK && s.kernel_stack_bytes as u64 % PAGE == 0,
            "kernel_stack_bytes"
        );
        // 看门狗必须比任何一档的时间片都长，否则正常用完时间片的任务也会被记录。
        require!(s.watchdog_ticks > max_quantum, "watchdog_ticks");
        require!(s.watchdog_log >= 1, "watchdog_log");
        require!(s.cpu_burst_ticks >= 1 && s.cpu_burst_ticks <= crate::sched::limit::MAX_BURST_TICKS, "cpu_burst_ticks");

        let m = &self.memory;
        require!(m.heap_grow_step >= PAGE && m.heap_grow_step % PAGE == 0, "heap_grow_step");
        require!(m.heap_max % PAGE == 0 && m.heap_max >= m.heap_grow_step, "heap_max");
        // IPC 队列里的消息体都在内核堆上：全系统配额必须给堆留下至少同样多的余量。
        require!(self.ipc.max_total_bytes as u64 * 2 <= m.heap_max, "heap_max");
        require!(
            m.pressure.critical_permille > 0
                && m.pressure.critical_permille < m.pressure.low_permille
                && m.pressure.low_permille <= 1000,
            "pressure"
        );
        require!(m.max_process_frames >= 1, "max_process_frames");
        require!(m.max_map_pages >= 1, "max_map_pages");

        let o = &self.objects;
        require!(o.handles_per_process >= 1 && o.max_objects >= o.handles_per_process, "max_objects");

        let r = &self.ring;
        require!(r.cq_capacity >= 1 && r.blocks_per_ring >= r.cq_capacity, "blocks_per_ring");
        require!(r.sq_batch >= 1 && r.sq_batch <= r.blocks_per_ring, "sq_batch");
        require!(r.max_rings_per_process >= 1, "max_rings_per_process");
        require!(r.max_in_flight_per_process as usize >= r.blocks_per_ring, "max_in_flight_per_process");

        let p = &self.ipc;
        require!(p.max_endpoints_per_process >= 1, "max_endpoints_per_process");
        require!(
            p.max_queue_bytes >= bounds::MSG_BYTES
                && p.max_queue_bytes <= p.max_process_bytes
                && p.max_process_bytes <= p.max_total_bytes,
            "ipc_bytes"
        );

        let d = &self.diag;
        require!(d.trace_capacity >= 1, "trace_capacity");
        require!(d.irq_queue_len >= 1, "irq_queue_len");
        Ok(())
    }

    /// 逐项列出生效参数（名 + 十进制值），顺序固定；时间片按档位从高到低列为 `quantum.<i>`。
    /// Enumerate every effective parameter as (name, value) in a fixed order.
    pub fn for_each_field(&self, mut f: impl FnMut(&'static str, u64)) {
        const QUANTUM: [&str; QOS_CLASSES] = ["quantum.0", "quantum.1", "quantum.2", "quantum.3"];
        f("timer_hz", self.clock.timer_hz as u64);
        f("boot_ticks", self.clock.boot_ticks);
        for (name, q) in QUANTUM.iter().zip(self.sched.qos.quantum) {
            f(name, q as u64);
        }
        f("decay_period", self.sched.qos.decay_period as u64);
        f("max_tasks", self.sched.max_tasks as u64);
        f("kernel_stack_bytes", self.sched.kernel_stack_bytes as u64);
        f("watchdog_ticks", self.sched.watchdog_ticks as u64);
        f("watchdog_log", self.sched.watchdog_log as u64);
        f("cpu_burst_ticks", self.sched.cpu_burst_ticks as u64);
        f("heap_max", self.memory.heap_max);
        f("heap_grow_step", self.memory.heap_grow_step);
        f("pressure_low_permille", self.memory.pressure.low_permille as u64);
        f("pressure_critical_permille", self.memory.pressure.critical_permille as u64);
        f("pressure_reserve_frames", self.memory.pressure.reserve_frames as u64);
        f("max_process_frames", self.memory.max_process_frames as u64);
        f("max_map_pages", self.memory.max_map_pages);
        f("max_objects", self.objects.max_objects as u64);
        f("handles_per_process", self.objects.handles_per_process as u64);
        f("cq_capacity", self.ring.cq_capacity as u64);
        f("blocks_per_ring", self.ring.blocks_per_ring as u64);
        f("sq_batch", self.ring.sq_batch as u64);
        f("max_rings_per_process", self.ring.max_rings_per_process as u64);
        f("max_in_flight_per_process", self.ring.max_in_flight_per_process as u64);
        f("max_endpoints_per_process", self.ipc.max_endpoints_per_process as u64);
        f("ipc_max_queue_bytes", self.ipc.max_queue_bytes as u64);
        f("ipc_max_process_bytes", self.ipc.max_process_bytes as u64);
        f("ipc_max_total_bytes", self.ipc.max_total_bytes as u64);
        f("trace_capacity", self.diag.trace_capacity as u64);
        f("irq_queue_len", self.diag.irq_queue_len as u64);
    }

    /// 时间换算：`ms` 毫秒对应的 tick 数（向上取整，至少 1）。
    /// Convert milliseconds to ticks at this profile's timer frequency (rounded up, at least 1).
    pub const fn ms_to_ticks(&self, ms: u64) -> u64 {
        let t = (ms * self.clock.timer_hz as u64).div_ceil(1000);
        if t == 0 { 1 } else { t }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILES: [KernelConfig; 2] = [KernelConfig::STANDARD, KernelConfig::COMPACT];

    #[test]
    fn both_profiles_valid() {
        for p in PROFILES {
            assert_eq!(p.validate(), Ok(()), "{}", p.name);
        }
        // 编译期也能校验（内核依赖这一点）。
        const _: () = assert!(KernelConfig::STANDARD.validate().is_ok());
        const _: () = assert!(KernelConfig::COMPACT.validate().is_ok());
    }

    #[test]
    fn standard_matches_previous_constants() {
        // 默认档必须与参数化之前的取值一致：换成配置模块不得改变默认行为。
        let s = KernelConfig::STANDARD;
        assert_eq!((s.clock.timer_hz, s.clock.boot_ticks), (100, 25));
        assert_eq!(s.sched.qos, QosParams::DEFAULT);
        assert_eq!((s.sched.max_tasks, s.sched.kernel_stack_bytes, s.sched.watchdog_ticks), (64, 64 * 1024, 50));
        assert_eq!(s.memory.pressure, PressureParams::DEFAULT);
        assert_eq!((s.memory.heap_max, s.memory.heap_grow_step), (64 << 20, 64 << 10));
        assert_eq!((s.objects.max_objects, s.objects.handles_per_process), (1024, 64));
        assert_eq!((s.ring.cq_capacity, s.ring.max_in_flight_per_process), (64, 256));
        assert_eq!(s.ipc.max_total_bytes, 16 << 20);
    }

    #[test]
    fn profiles_differ_and_keep_watchdog_wall_time() {
        let (s, c) = (KernelConfig::STANDARD, KernelConfig::COMPACT);
        assert_ne!(s, c);
        assert_ne!(s.name, c.name);
        // 看门狗阈值在两档下都是 0.5 秒墙钟时间。
        assert_eq!(s.ms_to_ticks(500), s.sched.watchdog_ticks as u64);
        assert_eq!(c.ms_to_ticks(500), c.sched.watchdog_ticks as u64);
    }

    #[test]
    fn ms_to_ticks_rounds_up_and_is_never_zero() {
        let c = KernelConfig::STANDARD; // 100 Hz：1 tick = 10 ms
        assert_eq!(c.ms_to_ticks(0), 1);
        assert_eq!(c.ms_to_ticks(1), 1);
        assert_eq!(c.ms_to_ticks(10), 1);
        assert_eq!(c.ms_to_ticks(11), 2);
        assert_eq!(KernelConfig::COMPACT.ms_to_ticks(10), 3); // 250 Hz：2.5 tick 向上取整
    }

    #[test]
    #[test]
    fn policy_must_match_idle_divisor() {
        let mut bad = KernelConfig::STANDARD;
        bad.policy.idle_tick_divisor = 1; // tickless 却要求每 tick 都唤醒
        assert!(bad.validate().is_err(), "tickless 与 divisor=1 必须被拒");
        let mut ok = KernelConfig::COMPACT;
        ok.policy.power = crate::config::PowerPolicy::Tickless;
        ok.policy.idle_tick_divisor = 2;
        assert!(ok.validate().is_ok(), "periodic→tickless 且倍率≥2 应通过");
    }

    #[test]
    fn for_each_field_lists_unique_names_in_stable_order() {
        let mut names: Vec<&str> = Vec::new();
        let mut values: Vec<u64> = Vec::new();
        KernelConfig::COMPACT.for_each_field(|n, v| {
            names.push(n);
            values.push(v);
        });
        assert_eq!(names.first(), Some(&"timer_hz"));
        assert_eq!(values[0], 250);
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "参数名不得重复");
        // 两个档列出的名字序列完全相同（只是取值不同）。
        let mut std_names: Vec<&str> = Vec::new();
        KernelConfig::STANDARD.for_each_field(|n, _| std_names.push(n));
        assert_eq!(std_names, names);
    }

    /// 改坏一个参数 ⇒ 被拒，报出的参数名正确；原配置档本身不受影响（值类型，拷贝后修改）。
    fn rejects(field: &str, edit: impl FnOnce(&mut KernelConfig)) {
        let mut c = KernelConfig::STANDARD;
        edit(&mut c);
        assert_eq!(c.validate().map_err(|e| e.field), Err(field), "{field}");
        assert_eq!(KernelConfig::STANDARD.validate(), Ok(()));
    }

    #[test]
    fn invalid_parameters_are_rejected_by_name() {
        rejects("timer_hz", |c| c.clock.timer_hz = 10);
        rejects("timer_hz", |c| c.clock.timer_hz = 5000);
        rejects("boot_ticks", |c| c.clock.boot_ticks = 0);
        rejects("quantum", |c| c.sched.qos.quantum[2] = 0);
        rejects("min_share_permille", |c| c.sched.qos.min_share_permille[1] = 1001);
        rejects("decay_period", |c| c.sched.qos.decay_period = 0);
        rejects("max_tasks", |c| c.sched.max_tasks = 4);
        rejects("max_tasks", |c| c.sched.max_tasks = 129);
        rejects("kernel_stack_bytes", |c| c.sched.kernel_stack_bytes = 16 * 1024);
        rejects("kernel_stack_bytes", |c| c.sched.kernel_stack_bytes = 64 * 1024 + 8);
        rejects("watchdog_ticks", |c| c.sched.watchdog_ticks = 4);
        rejects("watchdog_log", |c| c.sched.watchdog_log = 0);
        rejects("cpu_burst_ticks", |c| c.sched.cpu_burst_ticks = 0);
        rejects("cpu_burst_ticks", |c| c.sched.cpu_burst_ticks = 65);
        rejects("heap_grow_step", |c| c.memory.heap_grow_step = 100);
        rejects("heap_max", |c| c.memory.heap_max = 32 * 1024);
        rejects("heap_max", |c| c.memory.heap_max = 16 * 1024 * 1024);
        rejects("pressure", |c| c.memory.pressure.critical_permille = 200);
        rejects("pressure", |c| c.memory.pressure.critical_permille = 0);
        rejects("max_process_frames", |c| c.memory.max_process_frames = 0);
        rejects("max_map_pages", |c| c.memory.max_map_pages = 0);
        rejects("max_objects", |c| c.objects.max_objects = 10);
        rejects("blocks_per_ring", |c| c.ring.blocks_per_ring = 32);
        rejects("sq_batch", |c| c.ring.sq_batch = 0);
        rejects("max_rings_per_process", |c| c.ring.max_rings_per_process = 0);
        rejects("max_in_flight_per_process", |c| c.ring.max_in_flight_per_process = 10);
        rejects("max_endpoints_per_process", |c| c.ipc.max_endpoints_per_process = 0);
        rejects("ipc_bytes", |c| c.ipc.max_queue_bytes = 1024);
        rejects("ipc_bytes", |c| c.ipc.max_process_bytes = c.ipc.max_total_bytes + 1);
        rejects("trace_capacity", |c| c.diag.trace_capacity = 0);
        rejects("irq_queue_len", |c| c.diag.irq_queue_len = 0);
    }
}
