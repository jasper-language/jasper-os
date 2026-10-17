//! 模块装配（`system.module` 领域）：编译期描述符 + 依赖检查 + 顺序装载 / 逆序卸载。
//!
//! # 职责
//! * [`ModuleDescriptor`]：模块是什么——名字、依赖、`init` / `fini`
//! * [`ModuleManager`]：按给定顺序装载、装载前检查依赖、被依赖者拒绝单独卸载、整体逆序卸载
//! * [`ModuleEvent`]：装载/卸载的结构化事件，交给可选的观察者（Observer 模式，内核接到 trace）
//!
//! # 为什么这样设计
//! * Phase 1 不做动态装载（当前阶段不在范围：动态卸载），模块是**编译期** `static` 描述符；
//!   管理器只保存 `&'static` 引用，零堆分配。
//! * 依赖必须**先**装载：管理器不做拓扑排序，顺序由系统 Profile（调用者）决定，
//!   错了就明确报 `missing_dependency`，而不是悄悄重排——装配顺序是可审计的配置，不是隐式行为。
//! * `no_std` 下没有 `TypeId`/`Any`，服务注册表以字符串名为键（留给 M3.x 的服务层）。

/// 模块初始化函数：失败时返回中文/英文原因（静态字符串）。
pub type ModuleInit = fn() -> Result<(), &'static str>;
/// 模块收尾函数。
pub type ModuleFini = fn();

/// 编译期模块描述符。
pub struct ModuleDescriptor {
    /// 模块名（ASCII 小写 + 下划线）。
    pub name: &'static str,
    /// 依赖的模块名，必须先于本模块装载。
    pub requires: &'static [&'static str],
    /// 装载时调用。
    pub init: ModuleInit,
    /// 卸载时调用。
    pub fini: ModuleFini,
}

/// 模块错误（`system.module.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleError {
    /// 同名模块已装载。
    AlreadyLoaded(&'static str),
    /// 依赖未装载：`(模块, 缺少的依赖)`。
    MissingDependency(&'static str, &'static str),
    /// `init` 失败：`(模块, 原因)`。
    InitFailed(&'static str, &'static str),
    /// 仍被其他已装载模块依赖：`(模块, 依赖它的模块)`。
    InUse(&'static str, &'static str),
    /// 模块未装载。
    NotLoaded,
    /// 模块表已满。
    TableFull,
}

impl ModuleError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            ModuleError::AlreadyLoaded(_) => "system.module.error.already_loaded",
            ModuleError::MissingDependency(..) => "system.module.error.missing_dependency",
            ModuleError::InitFailed(..) => "system.module.error.init_failed",
            ModuleError::InUse(..) => "system.module.error.in_use",
            ModuleError::NotLoaded => "system.module.error.not_loaded",
            ModuleError::TableFull => "system.module.error.table_full",
        }
    }
}

/// 模块生命周期事件（事件名为过去分词，命名约定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleEvent {
    /// 已装载。
    Loaded(&'static str),
    /// 已卸载。
    Unloaded(&'static str),
}

impl ModuleEvent {
    /// 规范事件名。
    pub const fn name(self) -> &'static str {
        match self {
            ModuleEvent::Loaded(_) => "system.module.loaded",
            ModuleEvent::Unloaded(_) => "system.module.unloaded",
        }
    }

    /// 事件涉及的模块名。
    pub const fn module(self) -> &'static str {
        match self {
            ModuleEvent::Loaded(m) | ModuleEvent::Unloaded(m) => m,
        }
    }
}

/// 模块事件观察者。
pub type ModuleObserver = fn(ModuleEvent);

/// 最多管理 `N` 个模块的装配器。
pub struct ModuleManager<const N: usize> {
    loaded: [Option<&'static ModuleDescriptor>; N],
    len: usize,
    observer: Option<ModuleObserver>,
}

impl<const N: usize> ModuleManager<N> {
    /// 新建。
    pub const fn new() -> Self {
        ModuleManager { loaded: [None; N], len: 0, observer: None }
    }

    /// 安装观察者。
    pub fn set_observer(&mut self, o: ModuleObserver) {
        self.observer = Some(o);
    }

    fn notify(&self, e: ModuleEvent) {
        if let Some(o) = self.observer {
            o(e);
        }
    }

    /// 按装载顺序遍历已装载模块。
    pub fn loaded(&self) -> impl Iterator<Item = &'static ModuleDescriptor> + '_ {
        self.loaded[..self.len].iter().flatten().copied()
    }

    /// 是否已装载。
    pub fn is_loaded(&self, name: &str) -> bool {
        self.loaded().any(|m| m.name == name)
    }

    /// 已装载个数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否没有已装载模块。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 装载一个模块（`system.module.load`）：检查重名、依赖与容量后调用 `init`。
    pub fn load(&mut self, m: &'static ModuleDescriptor) -> Result<(), ModuleError> {
        if self.is_loaded(m.name) {
            return Err(ModuleError::AlreadyLoaded(m.name));
        }
        if let Some(missing) = m.requires.iter().find(|r| !self.is_loaded(r)) {
            return Err(ModuleError::MissingDependency(m.name, missing));
        }
        if self.len == N {
            return Err(ModuleError::TableFull);
        }
        (m.init)().map_err(|why| ModuleError::InitFailed(m.name, why))?;
        self.loaded[self.len] = Some(m);
        self.len += 1;
        self.notify(ModuleEvent::Loaded(m.name));
        Ok(())
    }

    /// 按顺序装载一组模块；遇到第一个错误即停止（已装载的保持装载，由调用者决定是否回滚）。
    pub fn load_all(&mut self, ms: &[&'static ModuleDescriptor]) -> Result<usize, ModuleError> {
        for m in ms {
            self.load(m)?;
        }
        Ok(ms.len())
    }

    /// 卸载单个模块（`system.module.unload`）；仍被依赖时拒绝。
    pub fn unload(&mut self, name: &str) -> Result<(), ModuleError> {
        let i = self.loaded[..self.len]
            .iter()
            .position(|m| m.is_some_and(|m| m.name == name))
            .ok_or(ModuleError::NotLoaded)?;
        let target = self.loaded[i].ok_or(ModuleError::NotLoaded)?;
        if let Some(user) = self.loaded().find(|m| m.requires.contains(&target.name)) {
            return Err(ModuleError::InUse(target.name, user.name));
        }
        (target.fini)();
        self.loaded.copy_within(i + 1..self.len, i);
        self.len -= 1;
        self.loaded[self.len] = None;
        self.notify(ModuleEvent::Unloaded(target.name));
        Ok(())
    }

    /// 按装载的**逆序**全部卸载，返回卸载个数。逆序保证每个模块卸载时它的依赖仍然在。
    pub fn unload_all(&mut self) -> usize {
        let n = self.len;
        while self.len > 0 {
            let m = self.loaded[self.len - 1].take();
            self.len -= 1;
            if let Some(m) = m {
                (m.fini)();
                self.notify(ModuleEvent::Unloaded(m.name));
            }
        }
        n
    }
}

impl<const N: usize> Default for ModuleManager<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 记录 init/fini 调用顺序（各测试用各自的描述符名，互不干扰）。
    static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn log(s: &str) {
        LOG.lock().unwrap().push(s.to_string());
    }
    fn take(prefix: &str) -> Vec<String> {
        let mut l = LOG.lock().unwrap();
        let (mine, rest): (Vec<_>, Vec<_>) = l.drain(..).partition(|s| s.starts_with(prefix));
        *l = rest;
        mine
    }

    static BASE: ModuleDescriptor = ModuleDescriptor {
        name: "t1_base",
        requires: &[],
        init: || {
            log("t1:init base");
            Ok(())
        },
        fini: || log("t1:fini base"),
    };
    static TOP: ModuleDescriptor = ModuleDescriptor {
        name: "t1_top",
        requires: &["t1_base"],
        init: || {
            log("t1:init top");
            Ok(())
        },
        fini: || log("t1:fini top"),
    };

    #[test]
    fn loads_in_order_and_unloads_in_reverse() {
        let mut mm: ModuleManager<4> = ModuleManager::new();
        assert_eq!(mm.load_all(&[&BASE, &TOP]), Ok(2));
        assert!(mm.is_loaded("t1_top"));
        assert_eq!(mm.load(&BASE), Err(ModuleError::AlreadyLoaded("t1_base")));
        assert_eq!(mm.unload_all(), 2);
        assert_eq!(take("t1:"), ["t1:init base", "t1:init top", "t1:fini top", "t1:fini base"]);
        assert!(mm.is_empty());
    }

    #[test]
    fn missing_dependency_is_reported_and_init_not_called() {
        let mut mm: ModuleManager<4> = ModuleManager::new();
        assert_eq!(mm.load(&TOP), Err(ModuleError::MissingDependency("t1_top", "t1_base")));
        assert_eq!(ModuleError::MissingDependency("", "").name(), "system.module.error.missing_dependency");
        assert!(mm.is_empty());
    }

    static NEEDED: ModuleDescriptor = ModuleDescriptor { name: "t3_needed", requires: &[], init: || Ok(()), fini: || {} };
    static USER: ModuleDescriptor =
        ModuleDescriptor { name: "t3_user", requires: &["t3_needed"], init: || Ok(()), fini: || {} };
    static BROKEN: ModuleDescriptor =
        ModuleDescriptor { name: "t3_broken", requires: &[], init: || Err("故意失败"), fini: || {} };

    #[test]
    fn unload_refuses_in_use_and_init_failure_is_not_loaded() {
        let mut mm: ModuleManager<2> = ModuleManager::new();
        mm.load_all(&[&NEEDED, &USER]).unwrap();
        assert_eq!(mm.unload("t3_needed"), Err(ModuleError::InUse("t3_needed", "t3_user")));
        assert_eq!(mm.load(&BROKEN), Err(ModuleError::TableFull));
        mm.unload("t3_user").unwrap();
        assert_eq!(mm.load(&BROKEN), Err(ModuleError::InitFailed("t3_broken", "故意失败")));
        assert!(!mm.is_loaded("t3_broken"));
        assert_eq!(mm.unload("t3_user"), Err(ModuleError::NotLoaded));
        assert_eq!(mm.loaded().map(|m| m.name).collect::<Vec<_>>(), ["t3_needed"]);
    }

    #[test]
    fn observer_sees_lifecycle_events() {
        static EVENTS: Mutex<Vec<(&str, &str)>> = Mutex::new(Vec::new());
        fn obs(e: ModuleEvent) {
            EVENTS.lock().unwrap().push((e.name(), e.module()));
        }
        static SOLO: ModuleDescriptor = ModuleDescriptor { name: "t4_solo", requires: &[], init: || Ok(()), fini: || {} };
        let mut mm: ModuleManager<1> = ModuleManager::new();
        mm.set_observer(obs);
        mm.load(&SOLO).unwrap();
        mm.unload_all();
        assert_eq!(
            *EVENTS.lock().unwrap(),
            [("system.module.loaded", "t4_solo"), ("system.module.unloaded", "t4_solo")]
        );
    }
}
