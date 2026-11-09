//! 服务装配契约（issue #6）：模块声明 → 依赖检查 → 初始化 → 运行时可用 → 能力发布 → 停用。
//! Service assembly contract: declaration → dependency check → initialisation → ready →
//! capability publication → deactivation.
//!
//! # 为什么需要它
//! [`crate::profile`] 只回答「这份 Profile **声明**了什么」；它不知道某个模块是否真的初始化成功。
//! 以前内核直接把声明当作可用（`has_capability` 查的是声明表），于是「声明了 `sched.realtime`
//! 但实时表没装上」也会被报告为可用。本模块把两件事分开：
//! * 声明（编译期 + Profile 选择）：[`SystemProfile`] / [`ResolvedProfile`]；
//! * 运行时可用：[`Assembly`] 中每个模块的 [`State`]，只有 [`State::Ready`] 的模块所提供的能力
//!   才进入发布掩码 [`Assembly::published_mask`]。
//!
//! # 生命周期（每个模块）
//! ```text
//! Declared ──依赖全部 Ready──▶ Initializing ──activate Ok──▶ Ready ──stop──▶ Stopped
//!    │                              └──activate Err──▶ Failed
//!    └──某个依赖不是 Ready──▶ Blocked
//! ```
//! `Ready` 之外的任何状态都不发布能力；`Stopped`、`Failed`、`Blocked` 都是本次启动的终态。
//! 健康状态与生命周期正交：`Ready` 的服务可以是 healthy、degraded 或 unhealthy；只有 healthy /
//! degraded 且全部依赖健康时才发布能力。健康状态不能把常驻模块变成可停用模块。
//!
//! # 裁决（issue #6 工作要求 2）
//! * **依赖顺序**：由能力依赖自动推出（稳定拓扑序：同一层按声明顺序），不再由调用者硬编码；
//!   依赖成环在构造时即拒绝（[`AssemblyError::DependencyCycle`]）。
//! * **缺依赖**：Profile 自身缺依赖由 [`crate::profile::resolve`] 拒绝（构造失败）；
//!   运行时依赖未就绪（提供者失败或被阻塞）⇒ 本模块 `Blocked`，`activate` **不被调用**，原因记为缺的能力名。
//! * **初始化中途失败**：`activate` 必须原子——返回 `Err` 时不得留下半初始化状态（由绑定方保证）；
//!   [`Policy::AllOrNothing`] 下首个失败即按启动逆序回滚全部已就绪模块（可停用者调用 `deactivate`），
//!   所有模块都不再发布能力，未尝试的模块保持 `Declared`；
//!   [`Policy::Partial`] 下失败模块的传递依赖者 `Blocked`，与之无关的模块照常启动（部分启动）。
//! * **重复初始化**：一份 [`Assembly`] 只能 [`Assembly::start`] 一次，第二次返回
//!   [`AssemblyError::AlreadyStarted`] 且不调用任何 `activate`；同名模块重复绑定在构造时拒绝。
//! * **停用**：仍被就绪模块依赖时拒绝（[`AssemblyError::InUse`]）；没有 `deactivate` 的模块是
//!   启动期常驻服务，拒绝停用（[`AssemblyError::Permanent`]），而不是假装停掉。
//!   发布方必须**先撤回能力再调用 `deactivate`**（见 [`Assembly::stop`] 的返回值约定）。
//! * 本切片不支持停用后重新启动、动态装载或热卸载（issue #6 工作要求 3）。
//!
//! # 边界
//! 纯数据结构，`no_std`、零分配、不含锁；发布到多核可见的方式（原子掩码）由内核侧负责。

use crate::profile::{self, ModuleDecl, ResolvedProfile, SystemProfile};

/// 一份装配最多容纳的模块数（依赖关系以 `u16` 位图表示）。
pub const MAX_MODULES: usize = 16;

/// 模块的运行时状态。
/// Runtime state of one declared module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// 已声明，尚未尝试启动。
    Declared,
    /// 某个依赖不是 `Ready`，`activate` 未被调用。
    Blocked,
    /// 正在执行 `activate`（只在 `start` 内部短暂存在）。
    Initializing,
    /// 初始化成功，能力已可发布。
    Ready,
    /// `activate` 返回失败。
    Failed,
    /// 已停用或因整体回滚而撤回。
    Stopped,
}

impl State {
    /// 规范状态名。
    pub const fn as_str(self) -> &'static str {
        match self {
            State::Declared => "declared",
            State::Blocked => "blocked",
            State::Initializing => "initializing",
            State::Ready => "ready",
            State::Failed => "failed",
            State::Stopped => "stopped",
        }
    }
}

/// 运行时健康状态；与声明、生命周期和用户授权分开记录。
/// Runtime health, distinct from declaration, lifecycle and caller authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// 尚未启动或尚未探测。
    Unknown,
    /// 提供完整声明的服务。
    Healthy,
    /// 服务仍可用，但已进入降级状态。
    Degraded,
    /// 服务不得发布；依赖它的能力也必须撤回。
    Unhealthy,
}

impl Health {
    /// 规范状态名。
    pub const fn as_str(self) -> &'static str {
        match self {
            Health::Unknown => "unknown",
            Health::Healthy => "healthy",
            Health::Degraded => "degraded",
            Health::Unhealthy => "unhealthy",
        }
    }

    /// 该健康状态是否允许服务被访问。
    pub const fn usable(self) -> bool {
        matches!(self, Health::Healthy | Health::Degraded)
    }
}

/// 模块激活：检查/建立服务真正可用所需的状态；失败时返回静态原因，且不得留下半初始化状态。
pub type Activate = fn() -> Result<(), &'static str>;
/// 模块停用：释放 `activate` 建立的状态。
pub type Deactivate = fn();

/// 模块名到实现的绑定。内核为它能构建的全部模块各给一条；
/// 生效 Profile 声明的每个模块必须恰好有一条绑定，未被声明的绑定被忽略。
#[derive(Clone, Copy)]
pub struct Binding {
    /// 对应 [`ModuleDecl::name`]。
    pub module: &'static str,
    /// 本实现声明的 `major.minor.patch` 版本。
    pub version: &'static str,
    /// 不能与这些模块同时装配的模块名。
    pub conflicts: &'static [&'static str],
    /// 激活函数。
    pub activate: Activate,
    /// 停用函数；`None` = 启动期常驻服务，不可停用。
    pub deactivate: Option<Deactivate>,
}

/// 启动失败时的整体策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// 任一模块失败 ⇒ 回滚全部已就绪模块，什么都不发布。
    AllOrNothing,
    /// 失败只影响其传递依赖者，其余照常启动。
    Partial,
}

/// 装配错误（`system.module.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssemblyError {
    /// Profile 自身不合法（[`profile::resolve`] 失败）。
    ProfileInvalid,
    /// 模块数超过 [`MAX_MODULES`]。
    TooManyModules,
    /// 声明的模块没有绑定。
    MissingBinding(&'static str),
    /// 同一模块有多条绑定。
    DuplicateBinding(&'static str),
    /// 绑定版本不是规范的 `major.minor.patch`。
    InvalidVersion(&'static str),
    /// 两个已选模块声明互相冲突。
    Conflict(&'static str, &'static str),
    /// 依赖成环（报告环上第一个按声明顺序的模块）。
    DependencyCycle(&'static str),
    /// 已经启动过。
    AlreadyStarted,
    /// 尚未启动。
    NotStarted,
    /// 没有这个模块。
    UnknownModule,
    /// 模块当前不是 `Ready`。
    NotReady(State),
    /// 仍被这个就绪模块依赖。
    InUse(&'static str),
    /// 启动期常驻模块，不可停用。
    Permanent,
    /// 另一个生命周期或健康事务正在进行。
    Busy,
    /// 健康状态未通过发布掩码审计。
    AuditFailed,
    /// 不支持的运行时健康状态。
    InvalidHealth,
}

impl AssemblyError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            AssemblyError::ProfileInvalid => "system.module.error.profile_invalid",
            AssemblyError::TooManyModules => "system.module.error.table_full",
            AssemblyError::MissingBinding(_) => "system.module.error.missing_binding",
            AssemblyError::DuplicateBinding(_) => "system.module.error.duplicate_binding",
            AssemblyError::InvalidVersion(_) => "system.module.error.invalid_version",
            AssemblyError::Conflict(_, _) => "system.module.error.conflict",
            AssemblyError::DependencyCycle(_) => "system.module.error.dependency_cycle",
            AssemblyError::AlreadyStarted => "system.module.error.already_started",
            AssemblyError::NotStarted => "system.module.error.not_started",
            AssemblyError::UnknownModule => "system.module.error.not_loaded",
            AssemblyError::NotReady(_) => "system.module.error.not_ready",
            AssemblyError::InUse(_) => "system.module.error.in_use",
            AssemblyError::Permanent => "system.module.error.permanent",
            AssemblyError::Busy => "system.module.error.busy",
            AssemblyError::AuditFailed => "system.module.error.audit_failed",
            AssemblyError::InvalidHealth => "system.module.error.invalid_health",
        }
    }
}

/// 能力查询结果：区分「没声明」与「声明了但没就绪」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// 生效 Profile 没有声明这项能力。
    NotDeclared,
    /// 声明了，但提供它的模块处于给定状态（不是 `Ready`）。
    Pending(State),
    /// 服务可用，但自身或依赖处于降级健康状态。
    Degraded,
    /// 自身或传递依赖不健康，能力不得发布。
    Unhealthy,
    /// 提供者已就绪，能力可用。
    Ready,
}

/// 一个已登记系统操作在 Profile 声明中的唯一所有者。
///
/// `core` 模块提供的操作归为内核基础调用；其他模块提供的操作归为模块服务。
/// 当前 Profile 未声明所有者的操作不是“无门禁”，调用方必须拒绝执行。
/// One declared owner of a registered operation. An operation absent from the active
/// profile is unavailable, never ungated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationRoute {
    /// 提供该操作所属服务的模块。
    pub module: &'static str,
    /// 匹配到的服务前缀。
    pub service: &'static str,
}

impl OperationRoute {
    /// 是否属于内核基础调用（当前唯一基础模块是 `core`）。
    /// Whether this is a kernel-base operation (the current base module is `core`).
    pub fn is_kernel_base(self) -> bool {
        self.module == "core"
    }
}

/// 在 Profile 中查找系统操作的唯一服务所有者。
///
/// 前缀只按点边界匹配。Profile 校验拒绝互相包含的服务前缀，因此一个操作至多有一个所有者。
/// Find the unique service owner of an operation in a profile.
pub fn operation_route(profile: &SystemProfile, operation: &str) -> Option<OperationRoute> {
    for module in profile.modules {
        for service in module.services {
            if operation
                .strip_prefix(service)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
            {
                return Some(OperationRoute { module: module.name, service });
            }
        }
    }
    None
}

/// 一次 [`Assembly::start`] 的结果统计。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Report {
    /// 结束时处于 `Ready` 的模块数。
    pub ready: u8,
    /// `activate` 失败的模块数。
    pub failed: u8,
    /// 因依赖未就绪而未尝试的模块数。
    pub blocked: u8,
    /// 整体回滚撤回的模块数。
    pub rolled_back: u8,
    /// 回滚后从未尝试的模块数（保持 `Declared`）。
    pub unattempted: u8,
}

/// 发布掩码与声明不一致之处（[`Assembly::audit`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// 掩码发布了一项提供者不是 `Ready` 的能力（「未启动却报告可用」）。
    PublishedNotReady(&'static str),
    /// 提供者已就绪但能力没发布。
    ReadyNotPublished(&'static str),
    /// 掩码含声明表之外的位。
    UnknownBit(u32),
    /// 就绪模块的某个依赖不是 `Ready`。
    DependencyNotReady(&'static str),
    /// 健康假设引用了不存在的模块。
    UnknownModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Started,
}

/// 一份 Profile 的运行时装配状态。
#[derive(Clone)]
pub struct Assembly {
    modules: [Option<&'static ModuleDecl>; MAX_MODULES],
    bindings: [Option<Binding>; MAX_MODULES],
    state: [State; MAX_MODULES],
    reason: [&'static str; MAX_MODULES],
    /// 第 i 个模块依赖的提供者模块位图。
    deps: [u16; MAX_MODULES],
    /// 第 i 个模块提供的能力位图（对应解析后的 Profile 能力顺序）。
    provides_mask: [u32; MAX_MODULES],
    /// 第 i 个模块的运行时健康状态。
    health: [Health; MAX_MODULES],
    /// 启动顺序（模块下标）。
    order: [u8; MAX_MODULES],
    /// 实际就绪顺序（用于逆序回滚 / 停用）。
    started: [u8; MAX_MODULES],
    started_len: usize,
    count: usize,
    phase: Phase,
}

impl Assembly {
    /// 为一份 Profile 建立装配：校验 Profile、为每个声明的模块找唯一绑定、推出依赖与启动顺序。
    /// English: build the assembly; validates the profile, bindings and dependency order.
    pub fn new(profile: &'static SystemProfile, bindings: &[Binding]) -> Result<Self, AssemblyError> {
        let declared = profile::resolve(profile).map_err(|_| AssemblyError::ProfileInvalid)?;
        if profile.modules.len() > MAX_MODULES {
            return Err(AssemblyError::TooManyModules);
        }
        let count = profile.modules.len();
        let mut a = Assembly {
            modules: [None; MAX_MODULES],
            bindings: [None; MAX_MODULES],
            state: [State::Declared; MAX_MODULES],
            reason: [""; MAX_MODULES],
            deps: [0; MAX_MODULES],
            provides_mask: [0; MAX_MODULES],
            health: [Health::Unknown; MAX_MODULES],
            order: [0; MAX_MODULES],
            started: [0; MAX_MODULES],
            started_len: 0,
            count,
            phase: Phase::Idle,
        };
        for (i, m) in profile.modules.iter().enumerate() {
            a.modules[i] = Some(m);
            let mut found = None;
            for b in bindings.iter().filter(|b| b.module == m.name) {
                if found.is_some() {
                    return Err(AssemblyError::DuplicateBinding(m.name));
                }
                found = Some(*b);
            }
            a.bindings[i] = Some(found.ok_or(AssemblyError::MissingBinding(m.name))?);
        }
        for i in 0..count {
            let binding = a.bindings[i].expect("binding slot below count is filled");
            if !valid_module_version(binding.version) {
                return Err(AssemblyError::InvalidVersion(binding.module));
            }
            for conflict in binding.conflicts {
                if (0..count).any(|j| j != i && a.module(j).name == *conflict) {
                    return Err(AssemblyError::Conflict(binding.module, conflict));
                }
            }
        }
        // resolve 已保证每项所需能力恰好有一个提供者，且模块不依赖自己提供的能力。
        for i in 0..count {
            let m = a.module(i);
            for (bit, capability) in declared.capabilities().iter().enumerate() {
                if m.provides.contains(capability) {
                    a.provides_mask[i] |= 1 << bit;
                }
            }
            for cap in m.requires {
                debug_assert!(declared.has_capability(cap));
                if let Some(p) = a.provider(cap) {
                    a.deps[i] |= 1 << p;
                }
            }
        }
        a.order_by_dependencies()?;
        Ok(a)
    }

    fn module(&self, i: usize) -> &'static ModuleDecl {
        self.modules[i].expect("module slot below count is filled")
    }

    /// 提供某能力的模块下标。
    fn provider(&self, cap: &str) -> Option<usize> {
        (0..self.count).find(|&i| self.module(i).provides.contains(&cap))
    }

    /// 稳定拓扑序（Kahn）：每轮取声明顺序最靠前、依赖已全部排入的模块。
    fn order_by_dependencies(&mut self) -> Result<(), AssemblyError> {
        let mut placed: u16 = 0;
        for slot in 0..self.count {
            let next = (0..self.count).find(|&i| placed & (1 << i) == 0 && self.deps[i] & !placed == 0);
            match next {
                Some(i) => {
                    self.order[slot] = i as u8;
                    placed |= 1 << i;
                }
                None => {
                    let first = (0..self.count).find(|&i| placed & (1 << i) == 0).unwrap_or(0);
                    return Err(AssemblyError::DependencyCycle(self.module(first).name));
                }
            }
        }
        Ok(())
    }

    fn ready_mask(&self) -> u16 {
        (0..self.count).filter(|&i| self.state[i] == State::Ready).fold(0, |m, i| m | (1 << i))
    }

    /// 模块自身及其全部传递依赖的生效健康状态。
    /// Effective health over the module and every transitive dependency.
    fn effective_health_at(&self, i: usize) -> Health {
        if self.state[i] != State::Ready || !self.health[i].usable() {
            return Health::Unhealthy;
        }
        let mut result = self.health[i];
        for j in 0..self.count {
            if self.deps[i] & (1 << j) != 0 {
                match self.effective_health_at(j) {
                    Health::Unhealthy => return Health::Unhealthy,
                    Health::Degraded | Health::Unknown => result = Health::Degraded,
                    Health::Healthy => {}
                }
            }
        }
        result
    }

    /// 首个不是 `Ready` 的依赖能力名。
    fn first_unmet(&self, i: usize) -> &'static str {
        for cap in self.module(i).requires {
            if let Some(p) = self.provider(cap) {
                if self.state[p] != State::Ready {
                    return cap;
                }
            }
        }
        ""
    }

    /// 按依赖顺序启动全部模块。只能调用一次。
    /// English: start every module in dependency order; callable once.
    pub fn start(&mut self, policy: Policy) -> Result<Report, AssemblyError> {
        if self.phase != Phase::Idle {
            return Err(AssemblyError::AlreadyStarted);
        }
        self.phase = Phase::Started;
        let mut report = Report::default();
        let mut aborted = false;
        for k in 0..self.count {
            let i = self.order[k] as usize;
            if aborted {
                report.unattempted += 1;
                continue;
            }
            if self.deps[i] & !self.ready_mask() != 0 {
                self.state[i] = State::Blocked;
                self.reason[i] = self.first_unmet(i);
                report.blocked += 1;
                continue;
            }
            self.state[i] = State::Initializing;
            let binding = self.bindings[i].expect("binding slot below count is filled");
            match (binding.activate)() {
                Ok(()) => {
                    self.state[i] = State::Ready;
                    self.health[i] = Health::Healthy;
                    self.started[self.started_len] = i as u8;
                    self.started_len += 1;
                }
                Err(why) => {
                    self.state[i] = State::Failed;
                    self.reason[i] = why;
                    report.failed += 1;
                    if policy == Policy::AllOrNothing {
                        aborted = true;
                        report.rolled_back = self.rollback();
                    }
                }
            }
        }
        report.ready = self.ready_mask().count_ones() as u8;
        Ok(report)
    }

    /// 按就绪逆序撤回全部就绪模块；可停用者调用 `deactivate`。返回撤回个数。
    fn rollback(&mut self) -> u8 {
        let mut n = 0;
        while self.started_len > 0 {
            self.started_len -= 1;
            let i = self.started[self.started_len] as usize;
            self.state[i] = State::Stopped;
            self.health[i] = Health::Unknown;
            if let Some(fini) = self.bindings[i].and_then(|b| b.deactivate) {
                fini();
            }
            n += 1;
        }
        n
    }

    /// 停用前检查：返回该模块的发布位，且尚未改变状态。
    ///
    /// 被就绪模块依赖时返回 [`AssemblyError::InUse`]；没有停用函数的启动期常驻模块返回
    /// [`AssemblyError::Permanent`]。调用者可据此先撤位、等待读者退出，再调用 [`Self::stop_with`]。
    /// English: validate a stop and return its publication bits without changing state.
    pub fn preflight_stop(&self, name: &str) -> Result<u32, AssemblyError> {
        if self.phase != Phase::Started {
            return Err(AssemblyError::NotStarted);
        }
        let i = (0..self.count).find(|&i| self.module(i).name == name).ok_or(AssemblyError::UnknownModule)?;
        if self.state[i] != State::Ready {
            return Err(AssemblyError::NotReady(self.state[i]));
        }
        if let Some(user) = (0..self.count).find(|&j| self.state[j] == State::Ready && self.deps[j] & (1 << i) != 0) {
            return Err(AssemblyError::InUse(self.module(user).name));
        }
        self.bindings[i].and_then(|b| b.deactivate).ok_or(AssemblyError::Permanent)?;
        Ok(self.provides_mask[i])
    }

    /// 停用一个就绪模块。`withdraw` 必须先清除本模块能力位并等待旧读者退出，随后才调用停用函数。
    ///
    /// 所有拒绝条件在调用 `withdraw` 之前检查，因此 `in_use` / `permanent` 不会造成部分撤位。
    /// English: stop one module after the publisher withdraws its bits and drains readers.
    pub fn stop_with(&mut self, name: &str, mut withdraw: impl FnMut(u32)) -> Result<(), AssemblyError> {
        let bits = self.preflight_stop(name)?;
        let i = (0..self.count).find(|&i| self.module(i).name == name).expect("preflight found the module");
        let fini = self.bindings[i].and_then(|b| b.deactivate).expect("preflight checked deactivate");
        withdraw(bits);
        self.state[i] = State::Stopped;
        self.health[i] = Health::Unknown;
        let at = self.started[..self.started_len].iter().position(|&s| s as usize == i).expect("ready module is in the started list");
        self.started.copy_within(at + 1..self.started_len, at);
        self.started_len -= 1;
        fini();
        Ok(())
    }

    /// 无外部发布门时的顺序契约入口；生产发布方应使用 [`Self::preflight_stop`] 与
    /// [`Self::stop_with`] 完成“撤位 → 排空 → 停用”。
    /// English: stop without an external publisher.
    pub fn stop(&mut self, name: &str) -> Result<(), AssemblyError> {
        self.stop_with(name, |_| {})
    }

    /// 按就绪逆序停用全部可停用模块；返回 (停用个数, 因常驻或仍被常驻模块依赖而保留的个数)。
    pub fn stop_all(&mut self) -> (usize, usize) {
        let (mut stopped, mut kept) = (0, 0);
        let mut k = self.started_len;
        while k > 0 {
            k -= 1;
            let i = self.started[k] as usize;
            match self.stop(self.module(i).name) {
                Ok(()) => stopped += 1,
                Err(_) => kept += 1,
            }
        }
        (stopped, kept)
    }

    /// 模块个数。
    pub fn len(&self) -> usize {
        self.count
    }

    /// 是否没有模块（构造成功时恒为 false：Profile 至少有一个模块）。
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// 第 k 个启动的模块名（依赖顺序）。
    pub fn order(&self, k: usize) -> Option<&'static str> {
        (k < self.count).then(|| self.module(self.order[k] as usize).name)
    }

    /// 某模块的状态与原因（失败原因或缺的能力名；无则为空串）。
    pub fn state(&self, name: &str) -> Option<(State, &'static str)> {
        (0..self.count).find(|&i| self.module(i).name == name).map(|i| (self.state[i], self.reason[i]))
    }

    /// 某模块的运行时健康状态。
    /// Runtime health of one module.
    pub fn health(&self, name: &str) -> Option<Health> {
        (0..self.count).find(|&i| self.module(i).name == name).map(|i| self.health[i])
    }

    /// 已绑定实现版本。
    pub fn version(&self, name: &str) -> Option<&'static str> {
        (0..self.count)
            .find(|&i| self.module(i).name == name)
            .and_then(|i| self.bindings[i])
            .map(|binding| binding.version)
    }

    /// 模块及其传递依赖的生效健康状态。
    /// Effective health over one module and its transitive dependencies.
    pub fn effective_health(&self, name: &str) -> Option<Health> {
        (0..self.count)
            .find(|&i| self.module(i).name == name)
            .map(|i| self.effective_health_at(i))
    }

    /// 更新一个已就绪模块的健康状态；返回更新前的状态。
    ///
    /// 发布方必须在把状态改为 [`Health::Unhealthy`] 前撤掉所有将失效的能力位，并在公开恢复后
    /// 才重新置位。本方法与生命周期停用分开，常驻模块也可以健康降级。
    /// English: update runtime health without changing the module lifecycle.
    pub fn set_health(&mut self, name: &str, health: Health) -> Result<Health, AssemblyError> {
        if health == Health::Unknown {
            return Err(AssemblyError::InvalidHealth);
        }
        let i = (0..self.count).find(|&i| self.module(i).name == name).ok_or(AssemblyError::UnknownModule)?;
        if self.state[i] != State::Ready {
            return Err(AssemblyError::NotReady(self.state[i]));
        }
        let old = self.health[i];
        self.health[i] = health;
        Ok(old)
    }

    /// 模块提供的能力位图。
    /// Capability bits provided by one module.
    pub fn module_mask(&self, name: &str) -> Option<u32> {
        (0..self.count).find(|&i| self.module(i).name == name).map(|i| self.provides_mask[i])
    }

    /// 假设只改变一个模块的健康状态时，装配应发布的完整掩码；不修改装配。
    /// Publication mask that would follow one health change, without mutating the assembly.
    pub fn mask_with_health(&self, name: &str, health: Health, declared: &ResolvedProfile) -> Option<u32> {
        let i = (0..self.count).find(|&i| self.module(i).name == name)?;
        let mut copy = self.clone();
        copy.health[i] = health;
        Some(copy.published_mask(declared))
    }

    /// 假设一个模块健康状态改变后，用同一假设状态审计候选发布掩码；不修改装配。
    /// Audit a candidate mask under one prospective health change, without mutating the assembly.
    pub fn audit_with_health(
        &self,
        name: &str,
        health: Health,
        declared: &ResolvedProfile,
        mask: u32,
    ) -> Result<(), AuditError> {
        let i = (0..self.count).find(|&i| self.module(i).name == name).ok_or(AuditError::UnknownModule)?;
        let mut copy = self.clone();
        copy.health[i] = health;
        copy.audit(declared, mask)
    }

    /// 能力查询：区分未声明、未就绪与可用。
    pub fn availability(&self, cap: &str) -> Availability {
        match self.provider(cap) {
            None => Availability::NotDeclared,
            Some(p) if self.state[p] != State::Ready => Availability::Pending(self.state[p]),
            Some(p) => match self.effective_health_at(p) {
                Health::Healthy => Availability::Ready,
                Health::Degraded => Availability::Degraded,
                Health::Unknown | Health::Unhealthy => Availability::Unhealthy,
            },
        }
    }

    /// 发布掩码：第 b 位 = `declared.capabilities()[b]` 当前可用。
    /// `declared` 必须是同一份 Profile 的解析结果（能力数 ≤ 24，装得进 u32）。
    pub fn published_mask(&self, declared: &ResolvedProfile) -> u32 {
        declared
            .capabilities()
            .iter()
            .enumerate()
            .filter(|(_, c)| matches!(self.availability(c), Availability::Ready | Availability::Degraded))
            .fold(0, |m, (b, _)| m | (1 << b))
    }

    /// 自动比对：给定的发布掩码必须与装配状态逐项一致，且每个就绪模块的依赖都就绪。
    /// English: audit a published mask against the runtime state.
    pub fn audit(&self, declared: &ResolvedProfile, mask: u32) -> Result<(), AuditError> {
        let caps = declared.capabilities();
        let known = if caps.len() >= 32 { u32::MAX } else { (1u32 << caps.len()) - 1 };
        if mask & !known != 0 {
            return Err(AuditError::UnknownBit(mask & !known));
        }
        for (b, cap) in caps.iter().enumerate() {
            let published = mask & (1 << b) != 0;
            let ready = matches!(self.availability(cap), Availability::Ready | Availability::Degraded);
            if published && !ready {
                return Err(AuditError::PublishedNotReady(cap));
            }
            if ready && !published {
                return Err(AuditError::ReadyNotPublished(cap));
            }
        }
        for i in 0..self.count {
            if mask & self.provides_mask[i] != 0 && self.effective_health_at(i) == Health::Unhealthy {
                return Err(AuditError::DependencyNotReady(self.module(i).name));
            }
        }
        Ok(())
    }
}

/// 读发布掩码：`cap` 在 `declared` 中且对应位已置 ⇒ 可用。
/// English: true when `cap` is declared and its bit is set in `mask`.
pub fn mask_has(declared: &ResolvedProfile, mask: u32, cap: &str) -> bool {
    declared.capabilities().iter().position(|c| *c == cap).is_some_and(|b| b < 32 && mask & (1 << b) != 0)
}

/// Validate the stable module version form without allocation.
pub fn valid_module_version(version: &str) -> bool {
    let mut parts = version.split('.');
    for _ in 0..3 {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KernelConfig;
    use crate::profile::{SchedClass, HEADLESS};
    use std::sync::Mutex;

    static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
    /// 激活函数写同一份日志：调用它们的测试须串行，否则并行测试的记录会互相混入。
    /// Activations share one log, so tests that run them are serialised to keep their records apart.
    static SERIAL: Mutex<()> = Mutex::new(());
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn log(s: &str) {
        LOG.lock().unwrap().push(s.to_string());
    }
    fn take(prefix: &str) -> Vec<String> {
        let mut l = LOG.lock().unwrap();
        let (mine, rest): (Vec<_>, Vec<_>) = l.drain(..).partition(|s| s.starts_with(prefix));
        *l = rest;
        mine
    }

    const fn decl(name: &'static str, provides: &'static [&'static str], requires: &'static [&'static str]) -> ModuleDecl {
        ModuleDecl {
            name,
            provides,
            requires,
            services: &[],
            hot_load: false,
            sched_class: SchedClass::Interactive,
            min_tasks: 0,
            min_objects: 0,
        }
    }

    /// 声明顺序故意与依赖顺序相反：top 依赖 mid，mid 依赖 base，side 独立。
    static T_MODULES: &[ModuleDecl] = &[
        decl("top", &["t.top"], &["t.mid"]),
        decl("mid", &["t.mid"], &["t.base"]),
        decl("base", &["t.base"], &[]),
        decl("side", &["t.side"], &[]),
    ];
    const T_BASE: SystemProfile = SystemProfile {
        name: "assembly-test",
        display_zh: "装配测试",
        display_en: "assembly test",
        config: KernelConfig::STANDARD,
        modules: T_MODULES,
        guarantees: &[],
        hot_load: false,
    };
    static T_PROFILE: SystemProfile = T_BASE;

    fn ok_top() -> Result<(), &'static str> {
        log("a:top");
        Ok(())
    }
    fn ok_mid() -> Result<(), &'static str> {
        log("a:mid");
        Ok(())
    }
    fn ok_base() -> Result<(), &'static str> {
        log("a:base");
        Ok(())
    }
    fn ok_side() -> Result<(), &'static str> {
        log("a:side");
        Ok(())
    }
    fn bad_mid() -> Result<(), &'static str> {
        log("a:mid-fail");
        Err("mid broke")
    }
    fn fini_base() {
        log("a:fini base");
    }
    fn fini_side() {
        log("a:fini side");
    }
    fn fini_top() {
        log("a:fini top");
    }

    const fn b(module: &'static str, activate: Activate, deactivate: Option<Deactivate>) -> Binding {
        Binding {
            module,
            version: "1.0.0",
            conflicts: &[],
            activate,
            deactivate,
        }
    }

    #[test]
    fn order_follows_dependencies_and_publishes_only_ready() {
        let _serial = serial();
        let binds = [
            b("top", ok_top, Some(fini_top)),
            b("mid", ok_mid, None),
            b("base", ok_base, Some(fini_base)),
            b("side", ok_side, Some(fini_side)),
            b("unused", ok_side, None),
        ];
        let mut a = Assembly::new(&T_PROFILE, &binds).unwrap();
        let order: Vec<_> = (0..4).map(|k| a.order(k).unwrap()).collect();
        assert_eq!(order, ["base", "mid", "top", "side"]);
        let declared = profile::resolve(&T_PROFILE).unwrap();
        assert_eq!(a.published_mask(&declared), 0, "nothing is published before start");
        assert_eq!(a.availability("t.base"), Availability::Pending(State::Declared));
        assert_eq!(a.availability("t.none"), Availability::NotDeclared);
        let r = a.start(Policy::AllOrNothing).unwrap();
        assert_eq!(r, Report { ready: 4, ..Report::default() });
        assert_eq!(take("a:"), ["a:base", "a:mid", "a:top", "a:side"]);
        let mask = a.published_mask(&declared);
        assert_eq!(mask.count_ones(), 4);
        assert!(mask_has(&declared, mask, "t.top"));
        assert_eq!(a.audit(&declared, mask), Ok(()));
        assert_eq!(a.start(Policy::AllOrNothing), Err(AssemblyError::AlreadyStarted));
        assert!(take("a:").is_empty(), "repeated start runs no activate");
        // 停用：被依赖者拒绝；常驻拒绝；依赖者先停后才能停被依赖者。
        assert_eq!(a.stop("base"), Err(AssemblyError::InUse("mid")));
        assert_eq!(a.stop("mid"), Err(AssemblyError::InUse("top")));
        a.stop("top").unwrap();
        assert_eq!(a.stop("top"), Err(AssemblyError::NotReady(State::Stopped)));
        assert_eq!(a.stop("mid"), Err(AssemblyError::Permanent));
        assert_eq!(a.stop_all(), (1, 2));
        assert_eq!(take("a:"), ["a:fini top", "a:fini side"]);
        let mask = a.published_mask(&declared);
        assert!(!mask_has(&declared, mask, "t.top") && mask_has(&declared, mask, "t.base"));
        assert_eq!(a.audit(&declared, mask), Ok(()));
    }

    #[test]
    fn failure_all_or_nothing_rolls_back_and_publishes_nothing() {
        let _serial = serial();
        let binds = [
            b("top", ok_top, None),
            b("mid", bad_mid, None),
            b("base", ok_base, Some(fini_base)),
            b("side", ok_side, None),
        ];
        let mut a = Assembly::new(&T_PROFILE, &binds).unwrap();
        let r = a.start(Policy::AllOrNothing).unwrap();
        assert_eq!(r, Report { ready: 0, failed: 1, blocked: 0, rolled_back: 1, unattempted: 2 });
        assert_eq!(take("a:"), ["a:base", "a:mid-fail", "a:fini base"]);
        assert_eq!(a.state("mid"), Some((State::Failed, "mid broke")));
        assert_eq!(a.state("base"), Some((State::Stopped, "")));
        assert_eq!(a.state("top"), Some((State::Declared, "")));
        let declared = profile::resolve(&T_PROFILE).unwrap();
        assert_eq!(a.published_mask(&declared), 0);
        assert_eq!(a.audit(&declared, 1), Err(AuditError::PublishedNotReady(declared.capabilities()[0])));
    }

    #[test]
    fn failure_partial_blocks_dependents_only() {
        let _serial = serial();
        let binds = [b("top", ok_top, None), b("mid", bad_mid, None), b("base", ok_base, None), b("side", ok_side, None)];
        let mut a = Assembly::new(&T_PROFILE, &binds).unwrap();
        let r = a.start(Policy::Partial).unwrap();
        assert_eq!(r, Report { ready: 2, failed: 1, blocked: 1, rolled_back: 0, unattempted: 0 });
        assert_eq!(take("a:"), ["a:base", "a:mid-fail", "a:side"], "blocked top never activates");
        assert_eq!(a.state("top"), Some((State::Blocked, "t.mid")));
        assert_eq!(a.availability("t.top"), Availability::Pending(State::Blocked));
        let declared = profile::resolve(&T_PROFILE).unwrap();
        let mask = a.published_mask(&declared);
        assert!(mask_has(&declared, mask, "t.side") && !mask_has(&declared, mask, "t.mid"));
        assert_eq!(a.audit(&declared, mask), Ok(()));
        let all = (1u32 << declared.capabilities().len()) - 1;
        assert!(matches!(a.audit(&declared, all), Err(AuditError::PublishedNotReady(_))));
        assert!(matches!(a.audit(&declared, 0), Err(AuditError::ReadyNotPublished(_))));
        assert_eq!(a.audit(&declared, 1 << 20), Err(AuditError::UnknownBit(1 << 20)));
    }

    static C_MODULES: &[ModuleDecl] = &[decl("x", &["c.x"], &["c.y"]), decl("y", &["c.y"], &["c.x"])];
    static C_PROFILE: SystemProfile = SystemProfile { modules: C_MODULES, name: "cycle-test", ..T_BASE };

    #[test]
    fn construction_rejects_bad_bindings_cycles_and_invalid_profiles() {
        let binds = [b("top", ok_top, None), b("mid", ok_mid, None), b("base", ok_base, None)];
        assert_eq!(Assembly::new(&T_PROFILE, &binds).err(), Some(AssemblyError::MissingBinding("side")));
        let dup = [b("top", ok_top, None), b("mid", ok_mid, None), b("base", ok_base, None), b("side", ok_side, None), b("mid", ok_mid, None)];
        assert_eq!(Assembly::new(&T_PROFILE, &dup).err(), Some(AssemblyError::DuplicateBinding("mid")));
        let cb = [b("x", ok_top, None), b("y", ok_mid, None)];
        assert_eq!(Assembly::new(&C_PROFILE, &cb).err(), Some(AssemblyError::DependencyCycle("x")));
        static BAD_MODULES: &[ModuleDecl] = &[decl("lonely", &["b.x"], &["b.missing"])];
        static BAD: SystemProfile = SystemProfile { modules: BAD_MODULES, name: "bad", ..T_BASE };
        assert_eq!(Assembly::new(&BAD, &[b("lonely", ok_top, None)]).err(), Some(AssemblyError::ProfileInvalid));
        let mut a = Assembly::new(&T_PROFILE, &dup[..4]).unwrap();
        assert_eq!(a.stop("top"), Err(AssemblyError::NotStarted));
        assert_eq!(AssemblyError::DependencyCycle("").name(), "system.module.error.dependency_cycle");
        take("a:");
    }

    #[test]
    fn module_identity_version_and_conflicts_are_failure_atomic() {
        let mut bad_version = [
            b("top", ok_top, None),
            b("mid", ok_mid, None),
            b("base", ok_base, None),
            b("side", ok_side, None),
        ];
        bad_version[2].version = "1.0";
        assert_eq!(
            Assembly::new(&T_PROFILE, &bad_version).err(),
            Some(AssemblyError::InvalidVersion("base"))
        );

        let mut conflict = [
            b("top", ok_top, None),
            b("mid", ok_mid, None),
            b("base", ok_base, None),
            b("side", ok_side, None),
        ];
        conflict[3].conflicts = &["base"];
        assert_eq!(
            Assembly::new(&T_PROFILE, &conflict).err(),
            Some(AssemblyError::Conflict("side", "base"))
        );

        let good = [
            b("top", ok_top, None),
            b("mid", ok_mid, None),
            b("base", ok_base, None),
            b("side", ok_side, None),
        ];
        let assembly = Assembly::new(&T_PROFILE, &good).unwrap();
        assert_eq!(assembly.version("mid"), Some("1.0.0"));
        assert!(valid_module_version("0.0.0"));
        assert!(!valid_module_version("1.2.3.4"));
        assert!(!valid_module_version("1..3"));
        take("a:");
    }

    #[test]
    fn builtin_headless_orders_core_first() {
        let _serial = serial();
        fn ok() -> Result<(), &'static str> {
            Ok(())
        }
        let names = ["core", "memory", "time", "sched", "channel", "realtime", "job", "async", "devices"];
        let binds: Vec<Binding> = names.iter().map(|n| b(n, ok, None)).collect();
        let mut a = Assembly::new(&HEADLESS, &binds).unwrap();
        assert_eq!(a.order(0), Some("core"));
        a.start(Policy::AllOrNothing).unwrap();
        let declared = profile::resolve(&HEADLESS).unwrap();
        let mask = a.published_mask(&declared);
        assert_eq!(mask.count_ones() as usize, declared.capabilities().len());
        assert_eq!(a.audit(&declared, mask), Ok(()));
        let degraded = a.mask_with_health("devices", Health::Unhealthy, &declared).unwrap();
        assert_eq!(a.availability("device.pci"), Availability::Ready);
        assert!(!mask_has(&declared, degraded, "device.pci"));
        assert_eq!(
            a.audit_with_health("devices", Health::Unhealthy, &declared, degraded),
            Ok(()),
            "prospective health audit must use the prospective state"
        );
        take("a:");
    }

    #[test]
    fn every_registered_operation_has_one_builtin_owner() {
        let registry = include_str!("../../abi/system-ids.txt");
        let mut operations = 0usize;
        let mut kernel_base = 0usize;
        let mut module_services = 0usize;
        for line in registry.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('\t').collect();
            assert!(fields.len() >= 7, "malformed registry line: {line}");
            if fields[1] != "op" {
                continue;
            }
            let name = fields[2];
            let route = operation_route(&HEADLESS, name)
                .unwrap_or_else(|| panic!("registered operation has no profile owner: {name}"));
            operations += 1;
            if route.is_kernel_base() {
                kernel_base += 1;
            } else {
                module_services += 1;
            }
        }
        assert!(operations >= 57);
        assert_eq!(operations, kernel_base + module_services);
        assert_eq!(
            operation_route(&HEADLESS, "system.sync.mutex.try.acquire"),
            Some(OperationRoute { module: "core", service: "system.sync" })
        );
        assert_eq!(
            operation_route(&HEADLESS, "system.event.source.create"),
            Some(OperationRoute { module: "async", service: "system.event" })
        );
        assert_eq!(
            operation_route(&profile::HEADLESS_MIN, "system.event.source.create"),
            None,
            "the compact profile does not assemble the async owner"
        );
        assert_eq!(
            operation_route(&profile::HEADLESS_MIN, "system.time.now"),
            Some(OperationRoute { module: "time", service: "system.time" })
        );
        assert_eq!(operation_route(&HEADLESS, "system.taskish.escape"), None);
    }

    #[test]
    fn stop_withdraws_before_deactivate_and_rejects_in_use_before_withdrawal() {
        let _serial = serial();
        let binds = [
            b("top", ok_top, Some(fini_top)),
            b("mid", ok_mid, None),
            b("base", ok_base, Some(fini_base)),
            b("side", ok_side, Some(fini_side)),
        ];
        let mut a = Assembly::new(&T_PROFILE, &binds).unwrap();
        a.start(Policy::AllOrNothing).unwrap();
        take("a:");

        assert_eq!(a.preflight_stop("base"), Err(AssemblyError::InUse("mid")));
        assert_eq!(a.preflight_stop("mid"), Err(AssemblyError::InUse("top")));
        let bits = a.preflight_stop("top").unwrap();
        let declared = profile::resolve(&T_PROFILE).unwrap();
        assert!(bits & a.published_mask(&declared) != 0);
        a.stop_with("top", |withdrawn| {
            assert_eq!(withdrawn, bits);
            log("a:withdraw top");
        })
        .unwrap();
        assert_eq!(take("a:"), ["a:withdraw top", "a:fini top"]);
        assert_eq!(a.preflight_stop("mid"), Err(AssemblyError::Permanent));
        assert_eq!(a.health("top"), Some(Health::Unknown));
        assert_eq!(a.audit(&declared, a.published_mask(&declared)), Ok(()));
    }

    #[test]
    fn health_is_separate_from_lifecycle_and_cascades_to_dependents() {
        let _serial = serial();
        let binds = [
            b("top", ok_top, None),
            b("mid", ok_mid, None),
            b("base", ok_base, None),
            b("side", ok_side, None),
        ];
        let mut a = Assembly::new(&T_PROFILE, &binds).unwrap();
        a.start(Policy::AllOrNothing).unwrap();
        let declared = profile::resolve(&T_PROFILE).unwrap();
        let all = a.published_mask(&declared);
        assert_eq!(a.set_health("base", Health::Unknown), Err(AssemblyError::InvalidHealth));
        assert_eq!(a.health("base"), Some(Health::Healthy));
        assert_eq!(a.set_health("missing", Health::Degraded), Err(AssemblyError::UnknownModule));
        assert_eq!(a.set_health("base", Health::Degraded), Ok(Health::Healthy));
        assert_eq!(a.availability("t.base"), Availability::Degraded);
        assert_eq!(a.availability("t.mid"), Availability::Degraded);
        assert_eq!(a.published_mask(&declared), all, "degraded services stay reachable");

        let next = a.mask_with_health("base", Health::Unhealthy, &declared).unwrap();
        assert!(!mask_has(&declared, next, "t.base"));
        assert!(!mask_has(&declared, next, "t.mid"));
        assert!(!mask_has(&declared, next, "t.top"));
        assert!(mask_has(&declared, next, "t.side"));
        assert_eq!(a.set_health("base", Health::Unhealthy), Ok(Health::Degraded));
        assert_eq!(a.state("base"), Some((State::Ready, "")));
        assert_eq!(a.health("base"), Some(Health::Unhealthy));
        assert_eq!(a.published_mask(&declared), next);
        assert_eq!(a.audit(&declared, next), Ok(()));
        assert!(matches!(a.audit(&declared, all), Err(AuditError::PublishedNotReady(_))));
        assert_eq!(a.set_health("base", Health::Healthy), Ok(Health::Unhealthy));
        assert_eq!(a.published_mask(&declared), all);
        assert_eq!(a.audit(&declared, all), Ok(()));
        take("a:");
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::config::KernelConfig;
    use crate::profile::SchedClass;

    const fn decl(name: &'static str, provides: &'static [&'static str], requires: &'static [&'static str]) -> ModuleDecl {
        ModuleDecl {
            name,
            provides,
            requires,
            services: &[],
            hot_load: false,
            sched_class: SchedClass::Interactive,
            min_tasks: 0,
            min_objects: 0,
        }
    }
    static K_MODULES: &[ModuleDecl] = &[
        decl("c", &["k.c"], &["k.b"]),
        decl("b", &["k.b"], &["k.a"]),
        decl("a", &["k.a"], &[]),
    ];
    static K_PROFILE: SystemProfile = SystemProfile {
        name: "kani",
        display_zh: "k",
        display_en: "k",
        config: KernelConfig::STANDARD,
        modules: K_MODULES,
        guarantees: &[],
        hot_load: false,
    };

    fn ok() -> Result<(), &'static str> {
        Ok(())
    }
    fn bad() -> Result<(), &'static str> {
        Err("x")
    }

    /// 任意成败组合 × 两种策略：发布掩码恒通过审计（未就绪绝不发布），
    /// 且就绪模块的依赖全部就绪；全有全无策略下有失败 ⇒ 什么都不发布。
    #[kani::proof]
    #[kani::unwind(10)]
    fn published_mask_never_reports_unready() {
        let pick = |x: bool| -> Activate { if x { ok } else { bad } };
        let binds = [
            Binding { module: "c", version: "1.0.0", conflicts: &[], activate: pick(kani::any()), deactivate: None },
            Binding { module: "b", version: "1.0.0", conflicts: &[], activate: pick(kani::any()), deactivate: None },
            Binding { module: "a", version: "1.0.0", conflicts: &[], activate: pick(kani::any()), deactivate: None },
        ];
        let all_or_nothing: bool = kani::any();
        let policy = if all_or_nothing { Policy::AllOrNothing } else { Policy::Partial };
        let mut a = Assembly::new(&K_PROFILE, &binds).unwrap();
        let r = a.start(policy).unwrap();
        let declared = profile::resolve(&K_PROFILE).unwrap();
        let mask = a.published_mask(&declared);
        assert!(a.audit(&declared, mask).is_ok());
        if all_or_nothing && r.failed > 0 {
            assert!(mask == 0);
        }
        assert!(r.ready as u32 == mask.count_ones());
        assert!(a.start(policy) == Err(AssemblyError::AlreadyStarted));
    }

    /// 任意单位翻转的掩码（偏离真实状态）都被审计拒绝。
    #[kani::proof]
    #[kani::unwind(10)]
    fn audit_rejects_any_divergent_mask() {
        let binds = [
            Binding { module: "c", version: "1.0.0", conflicts: &[], activate: ok, deactivate: None },
            Binding { module: "b", version: "1.0.0", conflicts: &[], activate: bad, deactivate: None },
            Binding { module: "a", version: "1.0.0", conflicts: &[], activate: ok, deactivate: None },
        ];
        let mut a = Assembly::new(&K_PROFILE, &binds).unwrap();
        a.start(Policy::Partial).unwrap();
        let declared = profile::resolve(&K_PROFILE).unwrap();
        let mask = a.published_mask(&declared);
        let flip: u32 = kani::any();
        kani::assume(flip != 0);
        assert!(a.audit(&declared, mask ^ flip).is_err());
    }

    /// 任意模块健康组合：发布掩码始终通过审计；标记为 unhealthy 的模块不得出现在发布面。
    #[kani::proof]
    #[kani::unwind(10)]
    fn health_changes_never_publish_unavailable_service() {
        let binds = [
            Binding { module: "c", version: "1.0.0", conflicts: &[], activate: ok, deactivate: None },
            Binding { module: "b", version: "1.0.0", conflicts: &[], activate: ok, deactivate: None },
            Binding { module: "a", version: "1.0.0", conflicts: &[], activate: ok, deactivate: None },
        ];
        let mut a = Assembly::new(&K_PROFILE, &binds).unwrap();
        a.start(Policy::AllOrNothing).unwrap();
        let health = |pick: u8| match pick % 3 {
            0 => Health::Healthy,
            1 => Health::Degraded,
            _ => Health::Unhealthy,
        };
        a.set_health("a", health(kani::any())).unwrap();
        a.set_health("b", health(kani::any())).unwrap();
        a.set_health("c", health(kani::any())).unwrap();
        let declared = profile::resolve(&K_PROFILE).unwrap();
        let mask = a.published_mask(&declared);
        assert!(a.audit(&declared, mask).is_ok());
        for i in 0..3 {
            let name = ["c", "b", "a"][i];
            if a.effective_health(name) == Some(Health::Unhealthy) {
                let bits = a.module_mask(name).unwrap();
                assert!(mask & bits == 0);
            }
        }
    }
}
