//! 系统 Profile：声明启用哪些模块、它们提供/需要什么能力、暴露哪些系统服务，
//! 以及由这些模块共同决定的最低资源下限。
//! System profiles: which modules are enabled, what they provide and require,
//! which system services they expose, and the resource floor they imply.
//!
//! # 职责
//! * 定义 [`SystemProfile`]：名字、中英文显示名、参数档、模块表、运行保证、热加载开关；
//! * 在启动期解析校验（[`resolve`]）：缺依赖、能力冲突、服务冲突、资源下限不可满足、
//!   热加载未获授权，一律拒绝并给出**结构化原因**（码 + 主体）；
//! * 提供服务门（[`ResolvedProfile::allows_op`]）：按服务前缀判定某个系统接口是否属于
//!   当前 Profile。它只做判定，真正的授权仍由系统调用入口的集合检查完成。
//!
//! # 边界与约束
//! * 纯数据 + 纯校验：不碰硬件、不读时钟、不做 IO，因此可在宿主上完整测试；
//! * **不使用堆分配**：本 crate 会被极小的用户态程序链接，任何一处 `Vec` 都会把它们
//!   变成「需要全局分配器」，所以解析结果与错误列表都是定长数组。
//!
//! # 探索阶段说明
//! 当前是演示与探索阶段：字段与命令形状会继续调整。已实现的行为是真实的
//! （校验与门都会运行），但不要把它当作冻结的对外契约。

use crate::config::KernelConfig;

/// 解析结果能容纳的能力数上限。
pub const MAX_CAPABILITIES: usize = 24;
/// 解析结果能容纳的服务数上限。
pub const MAX_SERVICES: usize = 24;
/// 一次校验能报告的错误条数上限。
pub const MAX_ERRORS: usize = 16;

/// 模块声明的调度类别。
/// Scheduling class declared by a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedClass {
    /// 交互优先（分时策略的低延迟档）。
    Interactive,
    /// 批处理（只用空闲容量但有最低份额）。
    Batch,
    /// 实时（需要预算与准入）。
    Realtime,
}

impl SchedClass {
    /// 稳定文本名（进入结构化输出）。
    pub const fn as_str(self) -> &'static str {
        match self {
            SchedClass::Interactive => "interactive",
            SchedClass::Batch => "batch",
            SchedClass::Realtime => "realtime",
        }
    }
}

/// 一个模块声明。
/// One module declaration.
#[derive(Debug, Clone, Copy)]
pub struct ModuleDecl {
    /// 模块名（kebab-case，Profile 内唯一）。
    pub name: &'static str,
    /// 提供的能力（点分小写）。
    pub provides: &'static [&'static str],
    /// 需要的能力（必须被本 Profile 内某个模块提供）。
    pub requires: &'static [&'static str],
    /// 暴露的系统服务前缀（如 `system.async`；空表示不暴露系统接口）。
    pub services: &'static [&'static str],
    /// 是否允许热加载。
    pub hot_load: bool,
    /// 调度类别（声明用，仲裁在后续阶段接入）。
    pub sched_class: SchedClass,
    /// 该模块要求的最小任务槽位。
    pub min_tasks: usize,
    /// 该模块要求的最小对象表容量。
    pub min_objects: usize,
}

/// 一条运行保证：名字 + 中英文说明 + 数值（数值含义由名字决定）。
/// One runtime guarantee.
#[derive(Debug, Clone, Copy)]
pub struct Guarantee {
    /// 稳定名字（进入结构化输出）。
    pub name: &'static str,
    /// 中文说明。
    pub display_zh: &'static str,
    /// 英文说明。
    pub display_en: &'static str,
    /// 保证对应的数值（例如延迟上界的 tick 数）。
    pub value: u64,
}

/// 一份完整的系统 Profile。
/// A complete system profile.
#[derive(Debug, Clone, Copy)]
pub struct SystemProfile {
    /// Profile 名（kebab-case）。
    pub name: &'static str,
    /// 中文显示名。
    pub display_zh: &'static str,
    /// 英文显示名。
    pub display_en: &'static str,
    /// 参数部分（时钟/调度/内存/对象/环/IPC/诊断）。
    pub config: KernelConfig,
    /// 模块表。
    pub modules: &'static [ModuleDecl],
    /// 运行保证。
    pub guarantees: &'static [Guarantee],
    /// 是否允许任何模块热加载。
    pub hot_load: bool,
}

/// 校验失败的原因码。
/// Failure codes of profile validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileErrorCode {
    /// 没有任何模块。
    NoModules,
    /// 名字不是 kebab-case / 能力名不是点分小写 / 服务名不以 `system.` 开头。
    InvalidName,
    /// 模块名重复。
    DuplicateModule,
    /// 同一能力被多个模块提供。
    DuplicateCapability,
    /// 模块同时提供并需要同一能力。
    CapabilityConflict,
    /// 需要的能力没有模块提供。
    MissingCapability,
    /// 系统服务被多个模块声明。
    ServiceConflict,
    /// 模块要求的最小任务槽位超过参数档。
    UnsatisfiableTasks,
    /// 模块要求的最小对象表容量超过参数档。
    UnsatisfiableObjects,
    /// 模块声明热加载但 Profile 未开启热加载。
    HotLoadNotAllowed,
    /// 能力或服务数量超过解析结果容量。
    TooMany,
}

impl ProfileErrorCode {
    /// 稳定文本名（进入结构化输出，便于工具分类）。
    pub const fn as_str(self) -> &'static str {
        match self {
            ProfileErrorCode::NoModules => "no_modules",
            ProfileErrorCode::InvalidName => "invalid_name",
            ProfileErrorCode::DuplicateModule => "duplicate_module",
            ProfileErrorCode::DuplicateCapability => "duplicate_capability",
            ProfileErrorCode::CapabilityConflict => "capability_conflict",
            ProfileErrorCode::MissingCapability => "missing_capability",
            ProfileErrorCode::ServiceConflict => "service_conflict",
            ProfileErrorCode::UnsatisfiableTasks => "unsatisfiable_tasks",
            ProfileErrorCode::UnsatisfiableObjects => "unsatisfiable_objects",
            ProfileErrorCode::HotLoadNotAllowed => "hot_load_not_allowed",
            ProfileErrorCode::TooMany => "too_many",
        }
    }
}

/// 一条校验失败原因：码 + 主体（模块名、能力名或服务名）。
/// One validation failure: code plus the offending subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileError {
    /// 原因码。
    pub code: ProfileErrorCode,
    /// 违反约束的主体（模块 / 能力 / 服务）。
    pub subject: &'static str,
}

/// 定长的错误列表：一次报告全部问题（超出容量时标记 truncated）。
/// Fixed-capacity error list: reports every problem, marks truncation.
#[derive(Debug, Clone, Copy)]
pub struct ProfileErrors {
    items: [ProfileError; MAX_ERRORS],
    len: usize,
    truncated: bool,
}

impl ProfileErrors {
    /// 空列表。
    const fn new() -> Self {
        let placeholder = ProfileError { code: ProfileErrorCode::NoModules, subject: "" };
        Self { items: [placeholder; MAX_ERRORS], len: 0, truncated: false }
    }

    /// 追加一条；容量用尽后只置 truncated，不再写。
    fn push(&mut self, code: ProfileErrorCode, subject: &'static str) {
        if self.len < MAX_ERRORS {
            self.items[self.len] = ProfileError { code, subject };
            self.len += 1;
        } else {
            self.truncated = true;
        }
    }

    /// 错误条数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 是否因容量不足而截断了后续问题。
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// 逐条遍历。
    pub fn iter(&self) -> impl Iterator<Item = ProfileError> + '_ {
        self.items[..self.len].iter().copied()
    }
}

/// 解析后的 Profile：去重排序后的能力与服务，以及对参数档的硬性下限要求。
/// Resolved profile: de-duplicated capabilities and services plus resource floors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedProfile {
    capabilities: [&'static str; MAX_CAPABILITIES],
    capability_count: usize,
    services: [&'static str; MAX_SERVICES],
    service_count: usize,
    /// 全部模块要求的最小任务槽位（取最大值）。
    pub min_tasks: usize,
    /// 全部模块要求的最小对象表容量（取最大值）。
    pub min_objects: usize,
    /// 允许热加载的模块数。
    pub hot_load_modules: usize,
}

impl ResolvedProfile {
    const fn empty() -> Self {
        Self {
            capabilities: [""; MAX_CAPABILITIES],
            capability_count: 0,
            services: [""; MAX_SERVICES],
            service_count: 0,
            min_tasks: 0,
            min_objects: 0,
            hot_load_modules: 0,
        }
    }

    /// 生效能力（字典序）。
    pub fn capabilities(&self) -> &[&'static str] {
        &self.capabilities[..self.capability_count]
    }

    /// 生效系统服务前缀（字典序）。
    pub fn services(&self) -> &[&'static str] {
        &self.services[..self.service_count]
    }

    /// 判定某个系统接口是否属于本 Profile 暴露的服务。
    ///
    /// 规则：接口名以某个服务前缀开头，且前缀之后紧跟 `.` 或结束——
    /// 这样 `system.async` 不会误匹配 `system.asynchronous...`。
    /// English: true when the operation name belongs to an exposed service prefix.
    pub fn allows_op(&self, op_name: &str) -> bool {
        self.services().iter().any(|service| {
            op_name
                .strip_prefix(service)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        })
    }

    /// 追加一个能力（插入排序，保持字典序）。
    fn add_capability(&mut self, value: &'static str) {
        let at = self.capabilities[..self.capability_count]
            .partition_point(|existing| *existing < value);
        self.capabilities.copy_within(at..self.capability_count, at + 1);
        self.capabilities[at] = value;
        self.capability_count += 1;
    }

    /// 追加一个服务（插入排序，保持字典序）。
    fn add_service(&mut self, value: &'static str) {
        let at = self.services[..self.service_count]
            .partition_point(|existing| *existing < value);
        self.services.copy_within(at..self.service_count, at + 1);
        self.services[at] = value;
        self.service_count += 1;
    }
}

/// kebab-case 判定（小写字母开头，只含小写字母/数字/连字符，1..=32）。
fn is_kebab(text: &str) -> bool {
    if text.is_empty() || text.len() > 32 {
        return false;
    }
    let mut prev_dash = true;
    for (index, ch) in text.bytes().enumerate() {
        let ok = match ch {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'-' => !prev_dash && index + 1 < text.len(),
            _ => false,
        };
        if !ok || (index == 0 && !ch.is_ascii_lowercase()) {
            return false;
        }
        prev_dash = ch == b'-';
    }
    !prev_dash
}

/// 点分小写能力名判定（`kernel.core`、`async.ring`）。
fn is_capability(text: &str) -> bool {
    !text.is_empty() && text.len() <= 64 && text.split('.').all(is_kebab)
}

/// 解析并校验一份 Profile。
///
/// 返回**全部**问题而不是第一个：Profile 作者一次就能看到所有违规项。
/// 失败时调用方必须拒绝启动或拒绝接受该 Profile。
/// English: validate a profile, returning every problem found.
pub fn resolve(profile: &SystemProfile) -> Result<ResolvedProfile, ProfileErrors> {
    let mut errors = ProfileErrors::new();
    let mut resolved = ResolvedProfile::empty();

    if !is_kebab(profile.name) {
        errors.push(ProfileErrorCode::InvalidName, profile.name);
    }
    if profile.modules.is_empty() {
        errors.push(ProfileErrorCode::NoModules, profile.name);
        return Err(errors);
    }

    let mut module_names: [&'static str; 16] = [""; 16];
    let mut module_count = 0usize;

    for module in profile.modules {
        if !is_kebab(module.name) {
            errors.push(ProfileErrorCode::InvalidName, module.name);
        }
        if module_names[..module_count].contains(&module.name) {
            errors.push(ProfileErrorCode::DuplicateModule, module.name);
        } else if module_count < module_names.len() {
            module_names[module_count] = module.name;
            module_count += 1;
        }
        if module.hot_load {
            resolved.hot_load_modules += 1;
            if !profile.hot_load {
                errors.push(ProfileErrorCode::HotLoadNotAllowed, module.name);
            }
        }
        resolved.min_tasks = resolved.min_tasks.max(module.min_tasks);
        resolved.min_objects = resolved.min_objects.max(module.min_objects);

        for capability in module.provides {
            if !is_capability(capability) {
                errors.push(ProfileErrorCode::InvalidName, capability);
                continue;
            }
            if resolved.capabilities().contains(capability) {
                errors.push(ProfileErrorCode::DuplicateCapability, capability);
            } else if resolved.capability_count < MAX_CAPABILITIES {
                resolved.add_capability(capability);
            } else {
                errors.push(ProfileErrorCode::TooMany, capability);
            }
            if module.requires.contains(capability) {
                errors.push(ProfileErrorCode::CapabilityConflict, capability);
            }
        }
        for capability in module.requires {
            if !is_capability(capability) {
                errors.push(ProfileErrorCode::InvalidName, capability);
            }
        }
        for service in module.services {
            if !service.starts_with("system.") || !is_capability(service) {
                errors.push(ProfileErrorCode::InvalidName, service);
                continue;
            }
            if resolved.services().contains(service) {
                errors.push(ProfileErrorCode::ServiceConflict, service);
            } else if resolved.service_count < MAX_SERVICES {
                resolved.add_service(service);
            } else {
                errors.push(ProfileErrorCode::TooMany, service);
            }
        }
    }

    for module in profile.modules {
        for capability in module.requires {
            if is_capability(capability) && !resolved.capabilities().contains(capability) {
                errors.push(ProfileErrorCode::MissingCapability, capability);
            }
        }
    }

    if resolved.min_tasks > profile.config.sched.max_tasks {
        errors.push(ProfileErrorCode::UnsatisfiableTasks, profile.name);
    }
    if resolved.min_objects > profile.config.objects.max_objects {
        errors.push(ProfileErrorCode::UnsatisfiableObjects, profile.name);
    }

    if errors.is_empty() {
        Ok(resolved)
    } else {
        Err(errors)
    }
}

// ---- 内建 Profile ----------------------------------------------------------

/// 无头 Profile 的模块表：完整服务面（进程、内存、时间、通道、异步环）。
/// Headless profile with the full service surface.
pub const HEADLESS_MODULES: &[ModuleDecl] = &[
    ModuleDecl {
        name: "core",
        provides: &["kernel.core"],
        requires: &[],
        services: &[
            "system.task",
            "system.process",
            "system.handle",
            "system.error",
            "system.console",
            "system.profile",
        ],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        // 下限取真实要求（引导线程 + 若干任务），不取 standard 档的 64：
        // 否则 compact 档下这份 Profile 会被自己判为不可满足。
        min_tasks: 32,
        min_objects: 256,
    },
    ModuleDecl {
        name: "memory",
        provides: &["memory.virtual"],
        requires: &["kernel.core"],
        services: &["system.memory"],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "time",
        provides: &["time.monotonic"],
        requires: &["kernel.core"],
        services: &["system.time"],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "sched",
        provides: &["sched.qos"],
        requires: &["kernel.core"],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 32,
        min_objects: 0,
    },
    ModuleDecl {
        name: "channel",
        provides: &["ipc.channel"],
        requires: &["kernel.core", "memory.virtual"],
        services: &["system.channel"],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 128,
    },
    ModuleDecl {
        name: "job",
        provides: &["sched.batch"],
        requires: &["kernel.core", "sched.qos"],
        services: &["system.job"],
        hot_load: false,
        sched_class: SchedClass::Batch,
        min_tasks: 8,
        min_objects: 32,
    },
    ModuleDecl {
        name: "async",
        provides: &["async.ring"],
        requires: &["kernel.core", "memory.virtual"],
        services: &["system.async"],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 128,
    },
];

/// 精简 Profile 的模块表：去掉通道与异步环，服务面因此真实变小。
/// Minimal headless profile: no channel and no async ring.
pub const HEADLESS_MIN_MODULES: &[ModuleDecl] = &[
    ModuleDecl {
        name: "core",
        provides: &["kernel.core"],
        requires: &[],
        services: &[
            "system.task",
            "system.process",
            "system.handle",
            "system.error",
            "system.console",
            "system.profile",
        ],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 32,
        min_objects: 128,
    },
    ModuleDecl {
        name: "memory",
        provides: &["memory.virtual"],
        requires: &["kernel.core"],
        services: &["system.memory"],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "time",
        provides: &["time.monotonic"],
        requires: &["kernel.core"],
        services: &["system.time"],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 0,
        min_objects: 0,
    },
    ModuleDecl {
        name: "sched",
        provides: &["sched.qos"],
        requires: &["kernel.core"],
        services: &[],
        hot_load: false,
        sched_class: SchedClass::Interactive,
        min_tasks: 32,
        min_objects: 0,
    },
];

/// 运行保证：Headless。
pub const HEADLESS_GUARANTEES: &[Guarantee] = &[
    Guarantee {
        name: "interactive_latency_ticks",
        display_zh: "过载下交互唤醒延迟上界（tick）",
        display_en: "Interactive wake-up latency bound under overload (ticks)",
        value: 2,
    },
    Guarantee {
        name: "no_global_kernel_lock",
        display_zh: "不存在全局内核大锁（1 表示成立）",
        display_en: "No global kernel lock (1 means holds)",
        value: 1,
    },
];

/// 默认 Profile：完整服务面 + standard 参数档。
pub const HEADLESS: SystemProfile = SystemProfile {
    name: "headless",
    display_zh: "无头服务",
    display_en: "Headless services",
    config: KernelConfig::STANDARD,
    modules: HEADLESS_MODULES,
    guarantees: HEADLESS_GUARANTEES,
    hot_load: false,
};

/// 精简 Profile：去掉通道与异步环 + compact 参数档。
pub const HEADLESS_MIN: SystemProfile = SystemProfile {
    name: "headless-min",
    display_zh: "精简无头",
    display_en: "Minimal headless",
    config: KernelConfig::COMPACT,
    modules: HEADLESS_MIN_MODULES,
    guarantees: HEADLESS_GUARANTEES,
    hot_load: false,
};

/// 内建 Profile 表（顺序稳定，索引进入 `system.profile.get`）。
pub const BUILTIN: &[SystemProfile] = &[HEADLESS, HEADLESS_MIN];

#[cfg(test)]
mod tests;
