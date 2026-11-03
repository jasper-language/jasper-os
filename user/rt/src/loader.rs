//! `.jaso` L1 运行期装载入口（SPEC §12.2）：模块表、依赖、服务发现、`stop`、卸载答复。
//! The L1 runtime load entry point: module table, dependencies, service discovery, stop and the beta unload reply.
//!
//! 校验、映射、`init`、`start` 由 [`crate::module`] 完成；任何一步失败都不留下映射，也不进模块表。
//!
//! * **依赖**：`core.depends` 只由表中运行中的模块满足；不会自动获取
//! * **服务发现**：只读清单与导出表（[`Loaded::services`]、[`Loaded::manifest_value`]），不靠反射
//! * **stop**：有运行中的依赖者时拒绝；否则调用 `jaso_stop`（若导出），此后 [`Loaded::function`] 返回 `None`
//! * **卸载**：beta 没有 L2——`plugin` 答复推迟、`system` 答复拒绝，模块都保持映射
//! * **进程内借用**：[`Function`] 借用 `Loader`，而 `stop` 要 `&mut Loader`，所以活动中的调用与 `stop` 在编译期互斥；
//!   隔离运行（[`crate::isolate`]）不经本入口，模块随容器进程结束
//!
//! `Loader` 被丢弃时（进程结束前的收尾）按装入的逆序停止并取消映射，这不是卸载请求。

use alloc::string::String;
use alloc::vec::Vec;

pub use jaso::lifecycle::{ModuleId, Phase, Registry, StopError, UnloadReply};

use crate::module::{Function, Grant, LoadError, Module, Site};

struct Slot {
    module: Module,
    manifest: String,
}

/// L1 模块表及其持有的模块。
pub struct Loader {
    registry: Registry,
    slots: Vec<Slot>,
}

/// 表中一个模块的只读视图（不暴露下层的卸载）。
pub struct Loaded<'l> {
    slot: &'l Slot,
    phase: Phase,
}

impl Loaded<'_> {
    /// 模块名。
    pub fn name(&self) -> &str {
        self.slot.module.name()
    }

    /// 模块版本。
    pub fn version(&self) -> (u32, u32, u32) {
        self.slot.module.version()
    }

    /// 签名发布者（开发模式放行的未签名模块为 `None`）。
    pub fn publisher(&self) -> Option<&str> {
        self.slot.module.publisher()
    }

    /// 装入基址。
    pub fn base(&self) -> u64 {
        self.slot.module.base()
    }

    /// 阶段。
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// 模块提供的服务：导出表中除生命周期导出之外的函数名。
    pub fn services(&self) -> impl Iterator<Item = &str> {
        self.slot.module.exports().map(|(n, _)| n.as_str()).filter(|n| !jaso::binding::is_lifecycle_symbol(n))
    }

    /// 清单扩展键的取值（如 `web.route`）。
    pub fn manifest_value(&self, key: &str) -> Option<&str> {
        // 清单在装入时已通过校验，这里的解析不会失败
        jaso::Manifest::parse(&self.slot.manifest).ok()?.extension(key)
    }

    /// 以函数指针类型 `F` 取出导出函数；模块已停止时为 `None`。
    ///
    /// # Safety
    /// `F` 必须是与模块中该函数真实签名一致的 `extern "C" fn` 指针类型。
    pub unsafe fn function<F: Copy>(&self, name: &str) -> Option<Function<'_, F>> {
        if self.phase != Phase::Running {
            return None;
        }
        self.slot.module.function(name)
    }
}

impl Loader {
    /// 空的模块表。
    pub const fn new() -> Loader {
        Loader { registry: Registry::new(), slots: Vec::new() }
    }

    /// 表中模块数（含已停止的）。
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// 表是否为空。
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// 走完 L1 全流程：成功后模块已 `init` + `start`，并进入模块表。
    pub fn load(&mut self, bytes: &[u8], grant: Grant<'_>) -> Result<ModuleId, LoadError> {
        let registry = &self.registry;
        let module = Module::load_in(bytes, grant, Site::Host, &|d| registry.satisfies(d), &|n| registry.contains(n))?;
        // 文件已通过校验；清单文本只从校验过的文件取，解析失败只可能是装载器缺陷，按格式错误拒绝
        let file = jaso::Jaso::parse(bytes).map_err(LoadError::Format)?;
        let id = self.registry.insert(&file.manifest);
        self.slots.push(Slot { module, manifest: String::from(file.manifest.text()) });
        Ok(id)
    }

    /// 取模块的视图。
    pub fn get(&self, id: ModuleId) -> Option<Loaded<'_>> {
        Some(Loaded { slot: self.slots.get(id.0)?, phase: self.registry.phase(id)? })
    }

    /// 停止模块：有运行中的依赖者时拒绝（不调用 `jaso_stop`）；`jaso_stop` 返回非 0 时报告 [`StopError::Hook`]，模块同样已停止服务。
    pub fn stop(&mut self, id: ModuleId) -> Result<(), StopError> {
        self.registry.begin_stop(id)?;
        match self.slots[id.0].module.call_stop() {
            None | Some(0) => Ok(()),
            Some(rc) => Err(StopError::Hook(rc)),
        }
    }

    /// 卸载请求：beta 只答复推迟或拒绝，不改变任何状态（没有这个模块为 `None`）。
    pub fn unload(&self, id: ModuleId) -> Option<UnloadReply> {
        self.registry.unload_request(id)
    }
}

impl Default for Loader {
    fn default() -> Loader {
        Loader::new()
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        // 依赖只指向更早装入的模块，逆序停止不会遇到运行中的依赖者
        for i in (0..self.slots.len()).rev() {
            let _ = self.stop(ModuleId(i));
        }
        while self.slots.pop().is_some() {}
    }
}
