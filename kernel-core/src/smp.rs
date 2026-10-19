//! 多处理器的纯机制：处理器集合、拓扑、启动状态机、核间中断种类、TLB 击落与跨核调用协议。
//! Pure multiprocessor mechanisms: CPU sets, topology, start-up state machine, IPI kinds,
//! TLB shootdown and cross-CPU call protocols.
//!
//! # 职责
//! * [`CpuSet`] —— 按逻辑处理器下标的位集合（下标 0 起，与硬件标识无关）
//! * [`Topology`] —— 固件报告的处理器硬件标识列表与引导处理器的下标（超出容量的计数、不静默丢弃）
//! * [`CpuStateCell`] —— 每个处理器的启动状态机（缺席 → 启动中 → 在线 / 失败），跨核用原子比较交换推进
//! * [`ShootdownBoard`] —— TLB 击落：发起方登记范围与目标集合，各目标在核间中断里作废本地 TLB 后应答
//! * [`CallSlot`] —— 跨核调用：在目标处理器上执行一个函数并取回结果（每个目标一格，单发起者）
//!
//! # 边界
//! 不含任何指令集代码：作废 TLB、发送核间中断等硬件动作由调用者以闭包或函数指针注入，
//! 因此全部协议都能在宿主上用多线程测试。所有锁都是叶子锁：持锁期间不再获取其他锁。
//!
//! # 为什么这样分
//! 协议的正确性（谁能发起、何时算完成、超时后如何撤销而不留残留状态）与硬件无关，
//! 放在这里可以被每个指令集复用，并在宿主上覆盖成功与失败路径。

use core::sync::atomic::{AtomicU8, Ordering};

use crate::sync::SpinLock;

/// 内核支持的逻辑处理器数上限（[`CpuSet`] 的位宽）。
/// Maximum number of logical processors.
pub const MAX_CPUS: usize = 16;

/// 一次击落允许的最大页数（超过时调用者应改为整体作废）。
/// Maximum pages in a single shootdown request.
pub const MAX_SHOOTDOWN_PAGES: u64 = 512;

/// 页大小（击落范围按页对齐）。
const PAGE: u64 = 4096;

/// 多处理器操作的错误。
/// Multiprocessor operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpError {
    /// 处理器下标不存在（超出拓扑或容量）。
    NoSuchCpu,
    /// 处理器存在但不在线。
    NotOnline,
    /// 目标是发起者自己（核间中断不发给自己；本地动作应直接执行）。
    SelfTarget,
    /// 同类请求正在进行，本次被拒绝（状态未改动）。
    Busy,
    /// 范围非法（未对齐、为空、过大或地址溢出）。
    BadRange,
    /// 等待应答超时（请求已撤销）。
    Timeout,
    /// 状态迁移非法（例如对已在线的处理器再次启动）。
    BadState,
    /// 平台启动处理器失败。
    StartFailed,
}

impl SmpError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            SmpError::NoSuchCpu => "system.cpu.error.no_such_cpu",
            SmpError::NotOnline => "system.cpu.error.not_online",
            SmpError::SelfTarget => "system.cpu.error.self_target",
            SmpError::Busy => "system.cpu.error.busy",
            SmpError::BadRange => "system.cpu.error.bad_range",
            SmpError::Timeout => "system.cpu.error.timeout",
            SmpError::BadState => "system.cpu.error.bad_state",
            SmpError::StartFailed => "system.cpu.error.start_failed",
        }
    }
}

/// 核间中断的种类（指令集层把它映射到具体向量 / 软件中断号）。
/// Kind of inter-processor interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiKind {
    /// 请目标处理器重新调度（运行队列有变化）。
    Reschedule,
    /// 请目标处理器处理 TLB 击落请求。
    TlbShootdown,
    /// 请目标处理器执行投递给它的跨核调用。
    Call,
}

impl IpiKind {
    /// 全部种类（顺序固定，用于计数数组下标）。
    /// All kinds in a fixed order.
    pub const ALL: [IpiKind; 3] = [IpiKind::Reschedule, IpiKind::TlbShootdown, IpiKind::Call];

    /// 在 [`IpiKind::ALL`] 中的下标。
    /// Index into [`IpiKind::ALL`].
    pub const fn index(self) -> usize {
        match self {
            IpiKind::Reschedule => 0,
            IpiKind::TlbShootdown => 1,
            IpiKind::Call => 2,
        }
    }

    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            IpiKind::Reschedule => "system.cpu.ipi.reschedule",
            IpiKind::TlbShootdown => "system.cpu.ipi.tlb_shootdown",
            IpiKind::Call => "system.cpu.ipi.call",
        }
    }
}

/// 逻辑处理器下标的位集合。
/// Bit set of logical processor indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuSet(u32);

impl CpuSet {
    /// 空集合。
    /// Empty set.
    pub const EMPTY: CpuSet = CpuSet(0);

    /// 前 `n` 个处理器（`n` 超过容量时截到容量）。
    /// The first `n` processors.
    pub const fn first(n: usize) -> CpuSet {
        if n >= MAX_CPUS {
            CpuSet(u32::MAX >> (32 - MAX_CPUS))
        } else {
            CpuSet((1u32 << n) - 1)
        }
    }

    /// 加入下标；超出容量返回 `false` 且集合不变。
    /// Insert `cpu`; returns `false` (unchanged) if out of range.
    pub fn insert(&mut self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        self.0 |= 1 << cpu;
        true
    }

    /// 移除下标。
    /// Remove `cpu`.
    pub fn remove(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            self.0 &= !(1 << cpu);
        }
    }

    /// 是否包含下标。
    /// Whether `cpu` is a member.
    pub const fn contains(self, cpu: usize) -> bool {
        cpu < MAX_CPUS && self.0 & (1 << cpu) != 0
    }

    /// 是否为空。
    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// 成员数。
    /// Number of members.
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// 去掉某个下标后的集合。
    /// The set without `cpu`.
    pub fn without(mut self, cpu: usize) -> CpuSet {
        self.remove(cpu);
        self
    }

    /// 原始位（诊断输出用）。
    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// 按升序遍历成员。
    /// Iterate members in ascending order.
    pub fn iter(self) -> impl Iterator<Item = usize> {
        (0..MAX_CPUS).filter(move |&c| self.contains(c))
    }
}

/// 处理器拓扑：逻辑下标 i ↔ 硬件标识 `hw_ids[i]`；引导处理器总在下标 0。
/// Processor topology; the boot processor is always index 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topology {
    hw_ids: [u32; MAX_CPUS],
    count: usize,
    /// 超出 [`MAX_CPUS`] 而未纳入的处理器数。
    pub dropped: usize,
    /// 固件报告存在但未启用的处理器数。
    pub disabled: usize,
}

impl Topology {
    /// 只有引导处理器的拓扑。
    /// Topology with only the boot processor.
    pub const fn boot_only(boot_hw_id: u32) -> Topology {
        let mut hw_ids = [0u32; MAX_CPUS];
        hw_ids[0] = boot_hw_id;
        Topology { hw_ids, count: 1, dropped: 0, disabled: 0 }
    }

    /// 追加一个已启用的处理器；与引导处理器或已有项重复的标识被忽略，满了计入 `dropped`。
    /// Add an enabled processor; duplicates are ignored, overflow is counted.
    pub fn push(&mut self, hw_id: u32) {
        if self.ids().contains(&hw_id) {
            return;
        }
        if self.count < MAX_CPUS {
            self.hw_ids[self.count] = hw_id;
            self.count += 1;
        } else {
            self.dropped += 1;
        }
    }

    /// 逻辑处理器数（含引导处理器）。
    /// Number of logical processors.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// 全部硬件标识（下标即逻辑下标）。
    /// Hardware identifiers indexed by logical index.
    pub fn ids(&self) -> &[u32] {
        &self.hw_ids[..self.count]
    }

    /// 逻辑下标对应的硬件标识。
    /// Hardware identifier of logical index `cpu`.
    pub fn hw_id(&self, cpu: usize) -> Option<u32> {
        self.ids().get(cpu).copied()
    }

    /// 硬件标识对应的逻辑下标。
    /// Logical index of hardware identifier `hw_id`.
    pub fn index_of(&self, hw_id: u32) -> Option<usize> {
        self.ids().iter().position(|&h| h == hw_id)
    }
}

/// 处理器启动状态。
/// Processor start-up state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CpuState {
    /// 尚未启动（或不存在）。
    Absent = 0,
    /// 已发出启动命令，等待它报到。
    Starting = 1,
    /// 已报到，正在运行。
    Online = 2,
    /// 启动失败或超时未报到。
    Failed = 3,
}

impl CpuState {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            CpuState::Absent => "absent",
            CpuState::Starting => "starting",
            CpuState::Online => "online",
            CpuState::Failed => "failed",
        }
    }

    const fn from_u8(v: u8) -> CpuState {
        match v {
            1 => CpuState::Starting,
            2 => CpuState::Online,
            3 => CpuState::Failed,
            _ => CpuState::Absent,
        }
    }
}

/// 跨核可见的启动状态单元：只允许 缺席→启动中、启动中→在线、启动中→失败 三种迁移。
/// Cross-CPU start-up state cell with only the legal transitions.
pub struct CpuStateCell(AtomicU8);

impl CpuStateCell {
    /// 新建（缺席）。
    /// New cell in `Absent`.
    pub const fn new() -> Self {
        CpuStateCell(AtomicU8::new(CpuState::Absent as u8))
    }

    /// 当前状态。
    /// Current state.
    pub fn get(&self) -> CpuState {
        CpuState::from_u8(self.0.load(Ordering::Acquire))
    }

    fn transit(&self, from: CpuState, to: CpuState) -> Result<(), SmpError> {
        self.0
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| SmpError::BadState)
    }

    /// 缺席 → 启动中（发起方在发出启动命令之前调用）。
    /// `Absent` → `Starting`.
    pub fn begin_start(&self) -> Result<(), SmpError> {
        self.transit(CpuState::Absent, CpuState::Starting)
    }

    /// 启动中 → 在线（被启动的处理器自己报到）。
    /// `Starting` → `Online`.
    pub fn mark_online(&self) -> Result<(), SmpError> {
        self.transit(CpuState::Starting, CpuState::Online)
    }

    /// 启动中 → 失败（发起方等待超时或平台报错）；之后该处理器即使迟到也不能再报到。
    /// `Starting` → `Failed`.
    pub fn mark_failed(&self) -> Result<(), SmpError> {
        self.transit(CpuState::Starting, CpuState::Failed)
    }
}

impl Default for CpuStateCell {
    fn default() -> Self {
        Self::new()
    }
}

/// 击落请求的内部状态。
struct Shootdown {
    start: u64,
    pages: u64,
    pending: CpuSet,
    generation: u32,
}

/// TLB 击落公告板：同一时刻至多一个请求；发起方登记后发核间中断，目标作废后应答，全部应答即完成。
///
/// 发起方在等待期间也应调用 [`service`](Self::service) 处理发给自己的请求（若两个处理器同时发起，
/// 后到者得到 [`SmpError::Busy`]，在重试循环里服务先到者的请求，因此不会互相等死）。
/// TLB shootdown board: at most one request in flight.
pub struct ShootdownBoard {
    state: SpinLock<BoardState>,
}

/// 公告板受锁保护的全部状态（一把锁，持锁期间不取其他锁）。
struct BoardState {
    request: Option<Shootdown>,
    next_generation: u32,
}

impl ShootdownBoard {
    /// 新建（空闲）。
    /// New idle board.
    pub const fn new() -> Self {
        ShootdownBoard { state: SpinLock::new(BoardState { request: None, next_generation: 1 }) }
    }

    /// 登记一次击落：`start` 页对齐，`pages` 在 1..=[`MAX_SHOOTDOWN_PAGES`]，范围不溢出。
    /// 目标为空时立即完成（返回的代号已完成）。有请求在途时返回 `Busy` 且不改动。
    /// Post a shootdown; returns its generation.
    pub fn begin(&self, targets: CpuSet, start: u64, pages: u64) -> Result<u32, SmpError> {
        if start % PAGE != 0 || pages == 0 || pages > MAX_SHOOTDOWN_PAGES {
            return Err(SmpError::BadRange);
        }
        if pages.checked_mul(PAGE).and_then(|len| start.checked_add(len)).is_none() {
            return Err(SmpError::BadRange);
        }
        let mut st = self.state.lock();
        if st.request.is_some() {
            return Err(SmpError::Busy);
        }
        let generation = st.next_generation;
        st.next_generation = generation.wrapping_add(1).max(1);
        if !targets.is_empty() {
            st.request = Some(Shootdown { start, pages, pending: targets, generation });
        }
        Ok(generation)
    }

    /// 目标处理器 `cpu` 处理发给自己的请求：若有，调用 `flush(start, pages)` 后应答。返回是否处理了。
    /// Service a pending request addressed to `cpu`.
    pub fn service(&self, cpu: usize, flush: impl FnOnce(u64, u64)) -> bool {
        let mut st = self.state.lock();
        let Some(req) = st.request.as_mut() else { return false };
        if !req.pending.contains(cpu) {
            return false;
        }
        flush(req.start, req.pages);
        req.pending.remove(cpu);
        if req.pending.is_empty() {
            st.request = None;
        }
        true
    }

    /// 代号为 `generation` 的请求是否已完成（全部目标已应答或已撤销）。
    /// Whether request `generation` has completed.
    pub fn is_complete(&self, generation: u32) -> bool {
        !matches!(&self.state.lock().request, Some(req) if req.generation == generation)
    }

    /// 撤销尚未完成的请求（等待超时时调用），返回仍未应答的目标；请求已完成时返回空集。
    /// Abandon request `generation`; returns the targets that never answered.
    pub fn abandon(&self, generation: u32) -> CpuSet {
        let mut st = self.state.lock();
        match &st.request {
            Some(req) if req.generation == generation => {
                let left = req.pending;
                st.request = None;
                left
            }
            _ => CpuSet::EMPTY,
        }
    }

    /// 是否空闲（无在途请求）。
    /// Whether no request is in flight.
    pub fn is_idle(&self) -> bool {
        self.state.lock().request.is_none()
    }
}

impl Default for ShootdownBoard {
    fn default() -> Self {
        Self::new()
    }
}

/// 跨核调用的函数形态：参数与结果都是 64 位值。
/// Cross-CPU call function shape.
pub type CallFn = fn(u64) -> u64;

/// 跨核调用格的状态。
#[derive(Clone, Copy)]
enum Call {
    Idle,
    Posted(CallFn, u64),
    Done(u64),
}

/// 每个目标处理器一格的跨核调用：发起方投递 → 目标在核间中断里执行 → 发起方取回结果。
/// One cross-CPU call slot per target processor.
pub struct CallSlot {
    state: SpinLock<Call>,
}

impl CallSlot {
    /// 新建（空闲）。
    /// New idle slot.
    pub const fn new() -> Self {
        CallSlot { state: SpinLock::new(Call::Idle) }
    }

    /// 投递一次调用；格子不空闲时返回 `Busy` 且不改动。
    /// Post a call; `Busy` (unchanged) if the slot is in use.
    pub fn post(&self, f: CallFn, arg: u64) -> Result<(), SmpError> {
        let mut st = self.state.lock();
        match *st {
            Call::Idle => {
                *st = Call::Posted(f, arg);
                Ok(())
            }
            _ => Err(SmpError::Busy),
        }
    }

    /// 目标处理器执行已投递的调用（在锁外执行函数）；返回是否执行了。
    /// Run a posted call on the target processor.
    pub fn run(&self) -> bool {
        let posted = {
            let st = self.state.lock();
            match *st {
                Call::Posted(f, arg) => Some((f, arg)),
                _ => None,
            }
        };
        let Some((f, arg)) = posted else { return false };
        let value = f(arg);
        let mut st = self.state.lock();
        // 发起方可能已因超时撤销：只有仍是这次投递时才写结果
        if matches!(*st, Call::Posted(..)) {
            *st = Call::Done(value);
        }
        true
    }

    /// 取回结果（完成则格子回到空闲）；尚未完成返回 `None`。
    /// Collect the result if done.
    pub fn collect(&self) -> Option<u64> {
        let mut st = self.state.lock();
        match *st {
            Call::Done(v) => {
                *st = Call::Idle;
                Some(v)
            }
            _ => None,
        }
    }

    /// 撤销（等待超时）：无论处于何种状态都回到空闲。
    /// Abandon: return to idle whatever the state.
    pub fn abandon(&self) {
        *self.state.lock() = Call::Idle;
    }

    /// 是否空闲。
    /// Whether the slot is idle.
    pub fn is_idle(&self) -> bool {
        matches!(*self.state.lock(), Call::Idle)
    }
}

impl Default for CallSlot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32};
    use std::sync::Arc;

    #[test]
    fn cpuset_basic_and_out_of_range_rejected() {
        let mut s = CpuSet::EMPTY;
        assert!(s.is_empty());
        assert!(s.insert(0) && s.insert(3) && s.insert(MAX_CPUS - 1));
        assert!(!s.insert(MAX_CPUS));
        assert_eq!(s.len(), 3);
        assert!(s.contains(3) && !s.contains(2) && !s.contains(MAX_CPUS));
        assert_eq!(s.iter().collect::<Vec<_>>(), vec![0, 3, MAX_CPUS - 1]);
        assert_eq!(s.without(3).len(), 2);
        assert_eq!(CpuSet::first(4).bits(), 0b1111);
        assert_eq!(CpuSet::first(100).len(), MAX_CPUS);
        assert!(CpuSet::first(0).is_empty());
    }

    #[test]
    fn topology_boot_first_dedup_and_overflow_counted() {
        let mut t = Topology::boot_only(7);
        t.push(7); // 重复：忽略
        t.push(1);
        t.push(2);
        assert_eq!(t.ids(), &[7, 1, 2]);
        assert_eq!(t.index_of(2), Some(2));
        assert_eq!(t.hw_id(0), Some(7));
        assert_eq!(t.hw_id(3), None);
        for i in 100..120 {
            t.push(i);
        }
        assert_eq!(t.count(), MAX_CPUS);
        assert_eq!(t.dropped, 3 + 20 - MAX_CPUS);
    }

    #[test]
    fn state_machine_legal_and_illegal_transitions() {
        let c = CpuStateCell::new();
        assert_eq!(c.get(), CpuState::Absent);
        assert_eq!(c.mark_online(), Err(SmpError::BadState));
        assert_eq!(c.get(), CpuState::Absent);
        c.begin_start().unwrap();
        assert_eq!(c.begin_start(), Err(SmpError::BadState));
        c.mark_online().unwrap();
        assert_eq!(c.get(), CpuState::Online);
        assert_eq!(c.mark_failed(), Err(SmpError::BadState));
        assert_eq!(c.get(), CpuState::Online);

        // 超时判失败后，迟到的报到被拒
        let late = CpuStateCell::new();
        late.begin_start().unwrap();
        late.mark_failed().unwrap();
        assert_eq!(late.mark_online(), Err(SmpError::BadState));
        assert_eq!(late.get(), CpuState::Failed);
    }

    #[test]
    fn shootdown_completes_after_all_targets_answer() {
        let b = ShootdownBoard::new();
        let mut targets = CpuSet::EMPTY;
        targets.insert(1);
        targets.insert(2);
        let g = b.begin(targets, 0x40_0000, 2).unwrap();
        assert!(!b.is_complete(g));
        let mut seen = Vec::new();
        assert!(!b.service(3, |_, _| seen.push(99))); // 不是目标：不动作
        assert!(b.service(1, |s, n| seen.push(s + n)));
        assert!(!b.service(1, |_, _| seen.push(98))); // 只处理一次
        assert!(!b.is_complete(g));
        assert!(b.service(2, |s, n| seen.push(s + n)));
        assert!(b.is_complete(g));
        assert!(b.is_idle());
        assert_eq!(seen, vec![0x40_0002, 0x40_0002]);
    }

    #[test]
    fn shootdown_rejections_leave_board_unchanged() {
        let b = ShootdownBoard::new();
        let one = CpuSet::first(2).without(0);
        assert_eq!(b.begin(one, 0x1001, 1), Err(SmpError::BadRange));
        assert_eq!(b.begin(one, 0x1000, 0), Err(SmpError::BadRange));
        assert_eq!(b.begin(one, 0x1000, MAX_SHOOTDOWN_PAGES + 1), Err(SmpError::BadRange));
        assert_eq!(b.begin(one, u64::MAX - 0xfff, 2), Err(SmpError::BadRange));
        assert!(b.is_idle());
        let g = b.begin(one, 0x1000, 1).unwrap();
        assert_eq!(b.begin(one, 0x2000, 1), Err(SmpError::Busy));
        // Busy 不改动在途请求：目标看到的仍是第一次的范围
        let mut got = 0;
        assert!(b.service(1, |s, _| got = s));
        assert_eq!(got, 0x1000);
        assert!(b.is_complete(g));
        // 空目标立即完成
        let g2 = b.begin(CpuSet::EMPTY, 0x1000, 1).unwrap();
        assert!(b.is_complete(g2) && b.is_idle());
    }

    #[test]
    fn shootdown_abandon_reports_missing_targets_and_frees_board() {
        let b = ShootdownBoard::new();
        let g = b.begin(CpuSet::first(4).without(0), 0x5000, 1).unwrap();
        assert!(b.service(2, |_, _| {}));
        let left = b.abandon(g);
        assert_eq!(left.iter().collect::<Vec<_>>(), vec![1, 3]);
        assert!(b.is_idle() && b.is_complete(g));
        // 撤销后迟到的应答不产生动作
        assert!(!b.service(1, |_, _| panic!("撤销后不应再作废")));
        assert_eq!(b.abandon(g), CpuSet::EMPTY);
    }

    #[test]
    fn shootdown_concurrent_responders() {
        let b = Arc::new(ShootdownBoard::new());
        let flushed = Arc::new(AtomicU32::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let mut hs = Vec::new();
        for cpu in 1..4 {
            let (b, f, stop) = (b.clone(), flushed.clone(), stop.clone());
            hs.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    b.service(cpu, |_, n| {
                        f.fetch_add(n as u32, Ordering::Relaxed);
                    });
                    std::hint::spin_loop();
                }
            }));
        }
        for round in 0..200u64 {
            let g = loop {
                match b.begin(CpuSet::first(4).without(0), round * PAGE, 1) {
                    Ok(g) => break g,
                    Err(SmpError::Busy) => std::hint::spin_loop(),
                    Err(e) => panic!("{:?}", e),
                }
            };
            while !b.is_complete(g) {
                std::hint::spin_loop();
            }
        }
        stop.store(true, Ordering::Release);
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(flushed.load(Ordering::Relaxed), 200 * 3);
        assert!(b.is_idle());
    }

    fn double(x: u64) -> u64 {
        x * 2
    }

    #[test]
    fn call_slot_post_run_collect_and_busy() {
        let s = CallSlot::new();
        assert!(!s.run());
        assert_eq!(s.collect(), None);
        s.post(double, 21).unwrap();
        assert_eq!(s.post(double, 1), Err(SmpError::Busy));
        assert_eq!(s.collect(), None);
        assert!(s.run());
        assert!(!s.run()); // 已完成：不重复执行
        assert_eq!(s.collect(), Some(42));
        assert!(s.is_idle());
        // 撤销：投递后未执行即撤销，目标随后不再执行
        s.post(double, 5).unwrap();
        s.abandon();
        assert!(!s.run());
        assert!(s.is_idle());
    }

    #[test]
    fn call_slot_across_threads() {
        let s = Arc::new(CallSlot::new());
        let s2 = s.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let h = std::thread::spawn(move || {
            while !stop2.load(Ordering::Acquire) {
                s2.run();
                std::hint::spin_loop();
            }
        });
        for i in 0..100 {
            s.post(double, i).unwrap();
            let v = loop {
                if let Some(v) = s.collect() {
                    break v;
                }
                std::hint::spin_loop();
            };
            assert_eq!(v, i * 2);
        }
        stop.store(true, Ordering::Release);
        h.join().unwrap();
    }

    #[test]
    fn names_are_canonical() {
        for k in IpiKind::ALL {
            assert!(k.name().starts_with("system.cpu.ipi."));
            assert_eq!(IpiKind::ALL[k.index()], k);
        }
        assert_eq!(SmpError::Busy.name(), "system.cpu.error.busy");
        assert_eq!(CpuState::Online.name(), "online");
    }
}
