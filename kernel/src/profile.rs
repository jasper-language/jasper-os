//! 本次构建生效的系统 Profile：选择、启动期校验与结构化查询。
//! The effective system profile: selection, boot-time validation and structured queries.
//!
//! # 职责
//! * 声明 [`ACTIVE`]：模块表取 headless，参数部分跟随 `profile-compact` 特性；
//! * [`boot_report`]：把内建表与生效 Profile 都交给 `kernel_core::profile::resolve` 校验，
//!   不合法就逐条打印结构化原因并让内核拒绝继续启动；
//! * [`render`]：把某个 Profile 渲染成「键=值」的行式文本，供 `system.profile.get`
//!   写入用户缓冲区（内核里没有 JSON 编码器，也不值得为此引入一个）。
//!
//! # 边界
//! 只做选择、校验与渲染；不初始化模块（装配见 `crate::assembly`），也不做权限判定（那是系统调用入口的事）。

use core::fmt::Write;

use kernel_core::profile::{self, ResolvedProfile, SystemProfile};

use crate::syscall::{table::{AbiKind, ENTRIES}, SyscallSet};
use crate::{config::ACTIVE as CONFIG, kprintln};

/// 本次构建生效的 Profile。
///
/// 参数部分直接取 `crate::config::ACTIVE`（受 `profile-compact` 特性影响），
/// 模块表与运行保证取 headless。这样「参数档」与「模块面」共享同一份声明，
/// 不会出现两份互相矛盾的配置。
#[cfg(feature="rt1-no-realtime")]
const BASE:SystemProfile=profile::HEADLESS_MIN;
#[cfg(not(feature="rt1-no-realtime"))]
const BASE:SystemProfile=profile::HEADLESS;
pub const ACTIVE: SystemProfile = SystemProfile {
    name: BASE.name,
    display_zh: BASE.display_zh,
    display_en: BASE.display_en,
    config: CONFIG,
    modules: BASE.modules,
    guarantees: BASE.guarantees,
    hot_load: BASE.hot_load,
};

/// 渲染缓冲区的最小长度（再小一定放不下）。
pub const MIN_TEXT: usize = 1536;

/// 内建 Profile 的数量。
pub fn count() -> usize {
    profile::BUILTIN.len()
}

/// 生效 Profile 在内建表中的下标（同名即同一份声明）。
pub fn active_index() -> usize {
    profile::BUILTIN
        .iter()
        .position(|p| p.name == ACTIVE.name)
        .unwrap_or(0)
}

/// 解析生效 Profile；失败返回 None（启动期已经报告过原因）。
pub fn resolved() -> Option<ResolvedProfile> {
    profile::resolve(&ACTIVE).ok()
}

/// 某项能力（例如 `sched.realtime`）当前是否**可用**：生效 Profile 声明了它，且提供它的模块已在
/// 启动期装配中初始化成功并发布（见 [`crate::assembly`]）。只声明未就绪、或装配之前查询，一律为假。
/// 只想知道声明面时用 [`resolved`]。
/// English: true only when the capability is declared *and* published by the boot-time assembly.
pub fn has_capability(capability: &str) -> bool {
    crate::assembly::acquire(capability).is_some()
}

/// 启动期校验：逐个解析内建表，再解析生效 Profile。
///
/// 返回失败条目数（0 = 通过）。任何一条不合法都意味着「声明的模块面自相矛盾」，
/// 内核必须拒绝启动——带着互相矛盾的 Profile 跑起来，后面的服务判定全是猜的。
pub fn boot_report() -> u32 {
    let mut failed = 0u32;
    for (index, declared) in profile::BUILTIN.iter().enumerate() {
        match profile::resolve(declared) {
            Ok(r) => kprintln!(
                "[JSR-PROFILE] table idx={} name={} valid=true modules={} services={} capabilities={} min_tasks={} min_objects={} hot_load={}",
                index,
                declared.name,
                declared.modules.len(),
                r.services().len(),
                r.capabilities().len(),
                r.min_tasks,
                r.min_objects,
                r.hot_load_modules
            ),
            Err(errors) => {
                failed += 1;
                for e in errors.iter() {
                    kprintln!(
                        "[JSR-PROFILE] table idx={} name={} valid=false code={} subject={}",
                        index,
                        declared.name,
                        e.code.as_str(),
                        e.subject
                    );
                }
            }
        }
    }
    match profile::resolve(&ACTIVE) {
        Ok(r) => kprintln!(
            "[JSR-PROFILE] active name={} valid=true params={} modules={} services={} capabilities={} guarantees={}",
            ACTIVE.name,
            ACTIVE.config.name,
            ACTIVE.modules.len(),
            r.services().len(),
            r.capabilities().len(),
            ACTIVE.guarantees.len()
        ),
        Err(errors) => {
            failed += 1;
            for e in errors.iter() {
                kprintln!(
                    "[JSR-PROFILE] active name={} valid=false code={} subject={}",
                    ACTIVE.name,
                    e.code.as_str(),
                    e.subject
                );
            }
        }
    }
    failed
}

/// 把第 `index` 个内建 Profile 渲染成行式结构化文本。
///
/// 返回写入的字节数；下标越界、Profile 自身不合法或缓冲区不足时返回 None。
/// English: render one built-in profile into `out`; None when it does not fit.
pub fn render(index: usize, out: &mut [u8]) -> Option<usize> {
    render_with(index, out, None)
}

/// 按调用者系统调用授权集合渲染 Profile；授权只影响报告，不改变声明或运行时状态。
/// Render a profile with caller authorization, which never changes declaration or runtime state.
pub fn render_for_caller(index: usize, out: &mut [u8], calls: SyscallSet) -> Option<usize> {
    render_with(index, out, Some(calls))
}

fn render_with(index: usize, out: &mut [u8], calls: Option<SyscallSet>) -> Option<usize> {
    if out.len() < MIN_TEXT {
        return None;
    }
    let declared = profile::BUILTIN.get(index)?;
    let resolved = profile::resolve(declared).ok()?;
    let mut sink = Sink { buf: out, len: 0, overflow: false };
    let _ = write!(
        sink,
        "profile={}\ndisplay_zh={}\ndisplay_en={}\nactive={}\nparams={}\nmodules={}\nmemory_policy={}\npower_policy={}\nhot_load={}\n",
        declared.name,
        declared.display_zh,
        declared.display_en,
        u8::from(index == active_index()),
        declared.config.name,
        declared.modules.len(),
        declared.config.policy.memory.as_str(),
        declared.config.policy.power.as_str(),
        u8::from(declared.hot_load)
    );
    let _ = write!(sink, "services=");
    write_join(&mut sink, resolved.services());
    let _ = write!(sink, "\ncapabilities=");
    write_join(&mut sink, resolved.capabilities());
    // 运行时已发布（真正可用）的能力：只对生效 Profile 有意义，其他 Profile 恒为空。
    let _ = write!(sink, "\npublished=");
    let mask = if index == active_index() { crate::assembly::published_mask() } else { 0 };
    let mut first = true;
    for (b, cap) in resolved.capabilities().iter().enumerate() {
        if mask & (1 << b) != 0 {
            if !first {
                let _ = sink.write_str(",");
            }
            let _ = sink.write_str(cap);
            first = false;
        }
    }
    let statuses = if index == active_index() { Some(crate::assembly::statuses()) } else { None };
    let mut feature_count = 0u32;
    let mut runtime_count = 0u32;
    let mut healthy_count = 0u32;
    let mut authorization_count = 0u32;
    let _ = write!(sink, "\nmodules_detail={}", declared.modules.len());
    for module in declared.modules.iter() {
        let compiled = crate::assembly::feature_compiled(module.name);
        let status = statuses.and_then(|snapshot| snapshot.modules().find(|s| s.name == module.name));
        let (runtime, health) = match status {
            Some(s) if s.available => ("available", s.effective_health.as_str()),
            Some(s) if s.state == kernel_core::assembly::State::Ready => ("withdrawn", s.effective_health.as_str()),
            Some(s) => (s.state.as_str(), s.effective_health.as_str()),
            None if index == active_index() => ("missing", "unknown"),
            None => ("not_selected", "unknown"),
        };
        let authorization = match calls {
            Some(calls) => service_authorization(module, calls).as_str(),
            None => Authorization::NotEvaluated.as_str(),
        };
        if compiled {
            feature_count += 1;
        }
        if runtime == "available" {
            runtime_count += 1;
        }
        if health == "healthy" {
            healthy_count += 1;
        }
        if authorization != "not_applicable" && authorization != "not_evaluated" {
            authorization_count += 1;
        }
        let _ = write!(
            sink,
            "\nmodule={} feature={} config=declared runtime={} health={} authorization={}",
            module.name,
            if compiled { "compiled" } else { "missing" },
            runtime,
            health,
            authorization
        );
    }
    let _ = write!(
        sink,
        "\navailability=feature:{},config:{},runtime:{},health:{},authorization:{}\n",
        feature_count,
        declared.modules.len(),
        runtime_count,
        healthy_count,
        authorization_count
    );
    let _ = write!(sink, "\nguarantees=");
    for (i, g) in declared.guarantees.iter().enumerate() {
        if i > 0 {
            let _ = sink.write_str(";");
        }
        let _ = write!(sink, "{}={}", g.name, g.value);
    }
    let _ = sink.write_str("\n");
    if sink.overflow {
        None
    } else {
        Some(sink.len)
    }
}

/// 调用者对某模块服务前缀的授权分布。
/// Caller authorization distribution over a module's service prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Authorization {
    Granted,
    Partial,
    Denied,
    NotApplicable,
    NotEvaluated,
}

impl Authorization {
    const fn as_str(self) -> &'static str {
        match self {
            Authorization::Granted => "granted",
            Authorization::Partial => "partial",
            Authorization::Denied => "denied",
            Authorization::NotApplicable => "not_applicable",
            Authorization::NotEvaluated => "not_evaluated",
        }
    }
}

fn service_authorization(module: &kernel_core::profile::ModuleDecl, calls: SyscallSet) -> Authorization {
    if module.services.is_empty() {
        return Authorization::NotApplicable;
    }
    let mut seen = 0u32;
    let mut allowed = 0u32;
    for entry in ENTRIES.iter().filter(|e| e.kind == AbiKind::Op) {
        if module.services.iter().any(|service| {
            entry.name.strip_prefix(service).is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
        }) {
            seen += 1;
            if calls.contains(entry.id as u64) {
                allowed += 1;
            }
        }
    }
    if seen == 0 {
        Authorization::NotApplicable
    } else if allowed == 0 {
        Authorization::Denied
    } else if allowed == seen {
        Authorization::Granted
    } else {
        Authorization::Partial
    }
}

/// 用逗号连接一串名字。
fn write_join(sink: &mut Sink<'_>, items: &[&str]) {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            let _ = sink.write_str(",");
        }
        let _ = sink.write_str(item);
    }
}

/// 固定缓冲区的写入器：越界后置位并继续吞掉后续写入，
/// 这样格式化宏不需要在每处判断错误，最后统一检查一次。
struct Sink<'a> {
    buf: &'a mut [u8],
    len: usize,
    overflow: bool,
}

impl Write for Sink<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            self.overflow = true;
            return Ok(());
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}
