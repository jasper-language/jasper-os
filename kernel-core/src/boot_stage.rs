//! 启动阶段图与阶段跟踪器（issue #7 第一切片）。
//! Boot stage graph and stage tracker (issue #7, slice 1).
//!
//! 内核主流程按「阶段」推进全局初始化：每个阶段在 [`GRAPH`] 中声明它依赖的前序阶段，
//! [`Tracker`] 在运行时保证四件事：
//! 1. 依赖未完成的阶段不得开始（缺失依赖被拒，并指出最靠前的缺失项）；
//! 2. 同一阶段不得初始化两次（重复初始化被拒）；
//! 3. 任一阶段失败后，之后的任何阶段都不得开始（失败阻止不安全的下一阶段）；
//! 4. 阶段在引导处理器上严格串行（同一时刻至多一个阶段在运行）。
//!
//! The kernel advances global initialisation stage by stage. Each stage declares its prerequisite
//! stages in [`GRAPH`]; [`Tracker`] enforces at run time that a stage never starts with a missing
//! prerequisite, never starts twice, never starts after any stage failed, and that stages run one
//! at a time on the boot processor.
//!
//! 依赖用位掩码表示，且只允许指向声明顺序更靠前的阶段：声明顺序即一个拓扑序，图因此在类型层面无环
//! （[`graph_well_formed`] 在编译期断言）。本模块是纯数据与纯状态机，不触碰硬件；
//! 各阶段的真实动作由内核 `kmain` 执行，这里只裁决「能否开始」与记录结果。
//! Dependencies are bit masks that may only point to earlier stages, so declaration order is a
//! topological order and the graph is acyclic by construction (const-asserted by
//! [`graph_well_formed`]). This module is pure data plus a pure state machine; the kernel performs
//! the real work of each stage and only asks this module whether a stage may start.

/// 全局启动阶段。声明顺序 = 生产启动的执行顺序，也是依赖图的一个拓扑序。
/// Global boot stages. Declaration order is the production execution order and a topological
/// order of the dependency graph.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Stage {
    /// 串口控制台、横幅与配置档报告。Serial console, banner and profile report.
    Console = 0,
    /// 架构早期初始化（描述符表、异常入口）并以断点异常证明异常路径接通。
    /// Architecture early init (descriptor tables, exception entry), proven by a breakpoint trap.
    Platform = 1,
    /// 中断控制器与定时器，等到足够多的时钟中断。Interrupt controller and timer, wait for ticks.
    Timer = 2,
    /// 物理页帧分配器（读取引导器内存图）。Physical frame allocator (from the boot memory map).
    Frames = 3,
    /// 内核映射器（经引导器提供的物理内存映射）。Kernel mapper (via the boot physical-memory map).
    KernelMap = 4,
    /// 内核堆首批映射。First mapping of the kernel heap.
    Heap = 5,
    /// 启动期容量：对象表、实时表、任务表与内核栈。Boot capacity: object, RT and task tables.
    Capacity = 6,
    /// 设备枚举（PCI 配置空间访问者与只读设备表）。Device enumeration (PCI config access, table).
    Devices = 7,
    /// 系统 Profile 校验（模块面与参数档）。System Profile validation (modules and parameters).
    Profile = 8,
}

impl Stage {
    /// 阶段个数。Number of stages.
    pub const COUNT: usize = 9;
    /// 全部阶段，下标即 [`Stage::index`]。All stages, indexed by [`Stage::index`].
    pub const ALL: [Stage; Stage::COUNT] = [
        Stage::Console,
        Stage::Platform,
        Stage::Timer,
        Stage::Frames,
        Stage::KernelMap,
        Stage::Heap,
        Stage::Capacity,
        Stage::Devices,
        Stage::Profile,
    ];

    /// 阶段在 [`GRAPH`] 与 [`Stage::ALL`] 中的下标。Index into [`GRAPH`] and [`Stage::ALL`].
    pub const fn index(self) -> usize {
        self as usize
    }

    /// 阶段在依赖位掩码中的位。The stage's bit in dependency masks.
    pub const fn bit(self) -> u32 {
        1 << (self as u32)
    }

    /// 阶段的静态声明。The stage's static declaration.
    pub const fn spec(self) -> &'static StageSpec {
        &GRAPH[self.index()]
    }

    /// 稳定的英文名（输出标记用，不随翻译变化）。Stable ASCII name used in boot markers.
    pub const fn name(self) -> &'static str {
        self.spec().name
    }
}

/// 全部阶段位的并集。Union of all stage bits.
pub const ALL_MASK: u32 = (1 << Stage::COUNT) - 1;

/// 一个阶段的静态声明。Static declaration of one stage.
#[derive(Clone, Copy, Debug)]
pub struct StageSpec {
    /// 本阶段（必须等于它在表中的位置）。This stage (must equal its table position).
    pub stage: Stage,
    /// 稳定英文名。Stable ASCII name.
    pub name: &'static str,
    /// 直接依赖的阶段位掩码（只能含声明更靠前的阶段）。Direct prerequisites (earlier stages only).
    pub requires: u32,
}

const fn bits2(a: Stage, b: Stage) -> u32 {
    a.bit() | b.bit()
}

/// 唯一登记点：生产启动阶段及其直接依赖。新增阶段只改这里与 [`Stage`]。
/// The single registry of production boot stages and their direct prerequisites.
///
/// 依赖说明 / rationale：
/// - Platform 需要控制台报告异常；Timer 需要异常/中断入口；
/// - Frames 需要引导交接信息与控制台（不依赖定时器）；KernelMap 需要页帧分配页表；
/// - Heap 需要映射器与页帧；Capacity 在堆上安装对象表、实时表与任务栈；
/// - Devices 需要映射器（ECAM 窗口）与堆（设备表）；Profile 校验需要堆（模块表）。
pub const GRAPH: [StageSpec; Stage::COUNT] = [
    StageSpec { stage: Stage::Console, name: "console", requires: 0 },
    StageSpec { stage: Stage::Platform, name: "platform", requires: Stage::Console.bit() },
    StageSpec { stage: Stage::Timer, name: "timer", requires: Stage::Platform.bit() },
    StageSpec { stage: Stage::Frames, name: "frames", requires: Stage::Platform.bit() },
    StageSpec { stage: Stage::KernelMap, name: "kernel_map", requires: Stage::Frames.bit() },
    StageSpec { stage: Stage::Heap, name: "heap", requires: bits2(Stage::Frames, Stage::KernelMap) },
    StageSpec { stage: Stage::Capacity, name: "capacity", requires: Stage::Heap.bit() },
    StageSpec { stage: Stage::Devices, name: "devices", requires: bits2(Stage::KernelMap, Stage::Heap) },
    StageSpec { stage: Stage::Profile, name: "profile", requires: Stage::Heap.bit() },
];

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// 阶段图良构：长度等于阶段数；表位置 = 阶段；名字非空且互异；依赖只指向更靠前的阶段
/// （因此无环、无自环），且不含越界位。
/// The graph is well formed: one entry per stage at its own index, non-empty distinct names, and
/// every prerequisite strictly earlier (hence acyclic, no self loop) with no out-of-range bits.
pub const fn graph_well_formed(g: &[StageSpec]) -> bool {
    if g.len() != Stage::COUNT {
        return false;
    }
    let mut i = 0;
    while i < g.len() {
        if g[i].stage.index() != i || g[i].name.is_empty() {
            return false;
        }
        // 只允许低于自身的位：requires ⊆ [0, i)。Only bits below i are allowed.
        if g[i].requires & !((1u32 << i) - 1) != 0 {
            return false;
        }
        let mut j = 0;
        while j < i {
            if str_eq(g[i].name, g[j].name) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const _: () = assert!(graph_well_formed(&GRAPH));

/// 传递依赖闭包（不含自身）：开始 `stage` 前必须已经完成的全部阶段。
/// Transitive prerequisites of `stage` (excluding itself).
pub const fn closure(g: &[StageSpec], stage: Stage) -> u32 {
    // 依赖只指向更靠前的阶段，因此从高到低扫一遍即可得到闭包。
    // Prerequisites point only backwards, so one descending sweep yields the closure.
    let mut acc = g[stage.index()].requires;
    let mut i = stage.index();
    while i > 0 {
        i -= 1;
        if acc & (1 << i) != 0 {
            acc |= g[i].requires;
        }
    }
    acc
}

/// 阶段的运行状态。Run state of a stage.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StageState {
    /// 尚未开始。Not started.
    Pending,
    /// 正在运行。Running.
    Running,
    /// 已成功完成。Completed successfully.
    Done,
    /// 已失败（启动停止在此）。Failed; boot stops here.
    Failed,
}

/// 阶段转移被拒的原因。Why a stage transition was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StageError {
    /// 已有阶段失败，任何阶段都不得再开始。A stage failed earlier; nothing may start.
    Halted { failed: Stage },
    /// 另一个阶段正在运行（阶段严格串行）。Another stage is running (stages are serial).
    Busy { running: Stage },
    /// 该阶段已经开始过（重复初始化）。The stage was already started (duplicate init).
    Duplicate(Stage),
    /// 直接依赖未完成；`missing` 是声明最靠前的缺失项。A direct prerequisite is not done.
    MissingDependency { stage: Stage, missing: Stage },
    /// 结束一个并未在运行的阶段。Finishing a stage that is not running.
    NotRunning(Stage),
}

impl StageError {
    /// 稳定的英文原因名（输出标记用）。Stable ASCII reason for boot markers.
    pub const fn as_str(self) -> &'static str {
        match self {
            StageError::Halted { .. } => "halted",
            StageError::Busy { .. } => "busy",
            StageError::Duplicate(_) => "duplicate",
            StageError::MissingDependency { .. } => "missing_dependency",
            StageError::NotRunning(_) => "not_running",
        }
    }
}

/// 阶段跟踪器：只在引导处理器上、由内核主流程独占使用（不跨核共享）。
/// Stage tracker, owned exclusively by the kernel main flow on the boot processor (never shared).
#[derive(Clone, Copy, Debug)]
pub struct Tracker {
    started: u32,
    done: u32,
    running: Option<Stage>,
    failed: Option<Stage>,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    /// 全部阶段待开始。All stages pending.
    pub const fn new() -> Self {
        Self { started: 0, done: 0, running: None, failed: None }
    }

    /// 申请开始 `stage`。检查顺序：已失败 → 有阶段在运行 → 重复 → 缺失依赖。
    /// Ask to start `stage`. Checks, in order: halted, busy, duplicate, missing prerequisite.
    pub fn begin(&mut self, stage: Stage) -> Result<(), StageError> {
        if let Some(failed) = self.failed {
            return Err(StageError::Halted { failed });
        }
        if let Some(running) = self.running {
            return Err(StageError::Busy { running });
        }
        if self.started & stage.bit() != 0 {
            return Err(StageError::Duplicate(stage));
        }
        let missing = stage.spec().requires & !self.done;
        if missing != 0 {
            let missing = Stage::ALL[missing.trailing_zeros() as usize];
            return Err(StageError::MissingDependency { stage, missing });
        }
        self.started |= stage.bit();
        self.running = Some(stage);
        Ok(())
    }

    /// 正在运行的 `stage` 成功完成。The running `stage` completed successfully.
    pub fn complete(&mut self, stage: Stage) -> Result<(), StageError> {
        if self.running != Some(stage) {
            return Err(StageError::NotRunning(stage));
        }
        self.running = None;
        self.done |= stage.bit();
        Ok(())
    }

    /// 正在运行的 `stage` 失败：此后任何阶段都不得开始。
    /// The running `stage` failed; no stage may start afterwards.
    pub fn fail(&mut self, stage: Stage) -> Result<(), StageError> {
        if self.running != Some(stage) {
            return Err(StageError::NotRunning(stage));
        }
        self.running = None;
        self.failed = Some(stage);
        Ok(())
    }

    /// 某阶段的状态。State of one stage.
    pub fn state(&self, stage: Stage) -> StageState {
        if self.done & stage.bit() != 0 {
            StageState::Done
        } else if self.running == Some(stage) {
            StageState::Running
        } else if self.failed == Some(stage) {
            StageState::Failed
        } else {
            StageState::Pending
        }
    }

    /// 已完成阶段的位掩码。Mask of completed stages.
    pub fn done_mask(&self) -> u32 {
        self.done
    }

    /// 失败的阶段（若有）。The failed stage, if any.
    pub fn failed(&self) -> Option<Stage> {
        self.failed
    }

    /// 因失败而永远不会开始、且传递依赖于失败阶段的阶段位掩码（用于失败报告）。
    /// Stages that transitively depend on the failed stage and therefore will never start.
    pub fn blocked_mask(&self) -> u32 {
        let Some(f) = self.failed else {
            return 0;
        };
        let mut mask = 0;
        let mut i = f.index() + 1;
        while i < Stage::COUNT {
            if closure(&GRAPH, Stage::ALL[i]) & f.bit() != 0 {
                mask |= 1 << i;
            }
            i += 1;
        }
        mask
    }

    /// 全部阶段都已完成。Every stage is done.
    pub fn all_done(&self) -> bool {
        self.done == ALL_MASK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_all(t: &mut Tracker) {
        for s in Stage::ALL {
            t.begin(s).unwrap();
            t.complete(s).unwrap();
        }
    }

    #[test]
    fn production_order_runs_to_completion() {
        let mut t = Tracker::new();
        run_all(&mut t);
        assert!(t.all_done());
        assert_eq!(t.failed(), None);
        assert_eq!(t.blocked_mask(), 0);
    }

    #[test]
    fn duplicate_and_missing_dependency_are_refused() {
        let mut t = Tracker::new();
        assert_eq!(
            t.begin(Stage::Heap),
            Err(StageError::MissingDependency { stage: Stage::Heap, missing: Stage::Frames })
        );
        t.begin(Stage::Console).unwrap();
        assert_eq!(t.begin(Stage::Platform), Err(StageError::Busy { running: Stage::Console }));
        t.complete(Stage::Console).unwrap();
        assert_eq!(t.begin(Stage::Console), Err(StageError::Duplicate(Stage::Console)));
        assert_eq!(t.complete(Stage::Console), Err(StageError::NotRunning(Stage::Console)));
        assert_eq!(t.state(Stage::Console), StageState::Done);
    }

    #[test]
    fn failure_halts_every_later_stage() {
        let mut t = Tracker::new();
        for s in [Stage::Console, Stage::Platform, Stage::Timer, Stage::Frames] {
            t.begin(s).unwrap();
            t.complete(s).unwrap();
        }
        t.begin(Stage::KernelMap).unwrap();
        t.fail(Stage::KernelMap).unwrap();
        assert_eq!(t.state(Stage::KernelMap), StageState::Failed);
        for s in Stage::ALL {
            assert_eq!(t.begin(s), Err(StageError::Halted { failed: Stage::KernelMap }));
        }
        // Heap/Capacity/Devices/Profile 都传递依赖 KernelMap。
        let expect = Stage::Heap.bit() | Stage::Capacity.bit() | Stage::Devices.bit() | Stage::Profile.bit();
        assert_eq!(t.blocked_mask(), expect);
    }

    #[test]
    fn closure_is_transitive() {
        assert_eq!(closure(&GRAPH, Stage::Console), 0);
        let c = closure(&GRAPH, Stage::Capacity);
        let expect = Stage::Console.bit()
            | Stage::Platform.bit()
            | Stage::Frames.bit()
            | Stage::KernelMap.bit()
            | Stage::Heap.bit();
        assert_eq!(c, expect);
    }

    #[test]
    fn malformed_graphs_are_rejected() {
        let mut g = GRAPH;
        g[2].requires = Stage::Timer.bit(); // 自环 self loop
        assert!(!graph_well_formed(&g));
        let mut g = GRAPH;
        g[1].requires = Stage::Profile.bit(); // 指向后方 forward edge
        assert!(!graph_well_formed(&g));
        let mut g = GRAPH;
        g[4].name = "frames"; // 重名 duplicate name
        assert!(!graph_well_formed(&g));
        let mut g = GRAPH;
        g.swap(3, 4); // 位置错 wrong position
        assert!(!graph_well_formed(&g));
        assert!(!graph_well_formed(&GRAPH[..Stage::COUNT - 1]));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn any_stage() -> Stage {
        Stage::ALL[kani::any::<usize>() % Stage::COUNT]
    }

    /// 任意长度 ≤ 12 的 begin/complete/fail 操作序列中，跟踪器不变量始终成立：
    /// done ⊆ started；运行中的阶段已开始未完成；begin 成功 ⇒ 依赖已完成且此前未开始且未失败；
    /// 失败之后 begin 一律被拒。
    /// For any sequence of up to 12 operations the tracker invariants hold.
    #[kani::proof]
    #[kani::unwind(13)]
    fn tracker_invariants_hold_for_any_sequence() {
        let mut t = Tracker::new();
        let n: usize = kani::any();
        kani::assume(n <= 12);
        let mut i = 0;
        while i < n {
            let s = any_stage();
            let op: u8 = kani::any();
            let before = t;
            match op % 3 {
                0 => {
                    let r = t.begin(s);
                    if r.is_ok() {
                        assert!(before.failed.is_none());
                        assert!(before.running.is_none());
                        assert!(before.started & s.bit() == 0);
                        assert!(s.spec().requires & !before.done == 0);
                        assert!(t.running == Some(s));
                    } else {
                        assert!(t.started == before.started && t.done == before.done);
                        assert!(t.running == before.running && t.failed == before.failed);
                    }
                    if before.failed.is_some() {
                        assert!(r.is_err());
                    }
                }
                1 => {
                    let r = t.complete(s);
                    assert_eq!(r.is_ok(), before.running == Some(s));
                }
                _ => {
                    let r = t.fail(s);
                    assert_eq!(r.is_ok(), before.running == Some(s));
                    if r.is_ok() {
                        assert!(t.failed == Some(s));
                    }
                }
            }
            assert!(t.done & !t.started == 0);
            assert!(t.done & !ALL_MASK == 0);
            if let Some(r) = t.running {
                assert!(t.started & r.bit() != 0 && t.done & r.bit() == 0);
            }
            // 每个已完成阶段的直接依赖都已完成（依赖先于自身完成）。
            let mut k = 0;
            while k < Stage::COUNT {
                if t.done & (1 << k) != 0 {
                    assert!(GRAPH[k].requires & !t.done == 0);
                }
                k += 1;
            }
            i += 1;
        }
    }

    /// 生产阶段图良构，且每个阶段的闭包只含更靠前的阶段、包含直接依赖。
    /// The production graph is well formed; closures contain direct prerequisites, earlier only.
    #[kani::proof]
    #[kani::unwind(12)]
    fn graph_and_closure_are_consistent() {
        assert!(graph_well_formed(&GRAPH));
        let s = any_stage();
        let c = closure(&GRAPH, s);
        assert!(c & !((1u32 << s.index()) - 1) == 0);
        assert!(c & s.spec().requires == s.spec().requires);
    }
}
