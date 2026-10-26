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
//! 只做选择、校验与渲染；不初始化模块，也不做权限判定（那是系统调用入口的事）。

use core::fmt::Write;

use kernel_core::profile::{self, ResolvedProfile, SystemProfile};

use crate::{kprintln, config::ACTIVE as CONFIG};

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
pub const MIN_TEXT: usize = 512;

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

/// 当前 Profile 是否提供某项能力（例如 `sched.realtime`）。
pub fn has_capability(capability: &str) -> bool {
    resolved().is_some_and(|r| r.has_capability(capability))
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
