//! 内核对象类型登记与生命周期契约（issue #4 第一切片）。
//! Kernel object type registry and lifetime contracts (issue #4, slice 1).
//!
//! # 为什么需要
//! 内核对象表（唯一 `ObjectTable`）里的每一种对象都有一组类型特有的规则：句柄类型、合法权限上限、
//! 能否经 Channel 转移、外部所有权归零时是否有 closing 动作、内部引用归零后销毁是否需要在锁外做事，
//! 以及它对其他对象持有哪些强引用。这些规则原先散落在中心匹配逻辑与各处常量里，新增类型时容易漏掉一处。
//! 本模块把它们收拢为**一张编译期常量表** [`REGISTRY`]，并给出可由编译器与验证工具检查的良构条件
//! [`registry_well_formed`]：内核侧以 `const` 断言要求登记表良构，不良构即编译失败。
//! Every kernel object kind's rules are declared once in [`REGISTRY`]; the kernel asserts
//! [`registry_well_formed`] at compile time.
//!
//! # 不变的部分（安全正确性所需的集中依赖）
//! * 对象身份、世代、引用计数、最后所有权释放与销毁入队**仍只由 `ObjectTable` 管理**；本表不登记回调、
//!   不持有计数，只描述类型。
//! * 权限只能衰减：句柄创建时权限必须是本类型合法上限的子集（[`check_grant`]），之后复制 / 降权只会更小。
//!
//! # 强引用图（[`Contract::strong`]）
//! 「强边」是对象存活期间对另一对象持有的内部引用（或发布者锚定的外部所有权），在 closing 或销毁时释放。
//! 良构条件要求每条强边都指向枚举顺序**更靠后**的类型，因此任意强引用路径上类型序号严格递增，
//! 类型层面不可能成环（唯一例外是进程 → 子进程的树形自边 [`Contract::tree_self`]：
//! 子进程总是在父进程存活时由父进程创建、从不反向挂接，实例层面构成树）。
//! 携带句柄的类型（[`Carry`]）另有约束：可转移类型必须是叶子——不携带句柄，且其强引用闭包中没有携带句柄的类型——
//! 这保证消息里的句柄不会把端点或进程拉进环里。
//! Strong edges must point to later kinds, so the kind-level strong graph is acyclic.

use crate::object::{ObjectType, Rights};

/// 对象种类（与内核 `KObject` 的变体一一对应；顺序即强引用图的拓扑序）。
/// Object kind; the declaration order is the topological order of the strong-reference graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// 进程。
    Process,
    /// 异步环。
    Ring,
    /// 线程。
    Task,
    /// 设备中断。
    Interrupt,
    /// 事件订阅。
    Subscription,
    /// Channel 端点。
    Endpoint,
    /// 退出状态（无句柄）。
    ExitState,
    /// 事件源。
    EventSource,
    /// 用户互斥量。
    Mutex,
    /// 共享内存页存储。
    Memory,
    /// 事件。
    Event,
    /// 设备。
    Device,
}

impl Kind {
    /// 种类数。
    pub const COUNT: usize = 12;
    /// 全部种类（按声明顺序）。
    pub const ALL: [Kind; Kind::COUNT] = [
        Kind::Process,
        Kind::Ring,
        Kind::Task,
        Kind::Interrupt,
        Kind::Subscription,
        Kind::Endpoint,
        Kind::ExitState,
        Kind::EventSource,
        Kind::Mutex,
        Kind::Memory,
        Kind::Event,
        Kind::Device,
    ];

    /// 在 [`REGISTRY`] 中的下标（= 声明顺序）。
    pub const fn index(self) -> usize {
        self as usize
    }

    /// 本种类的契约。
    pub const fn contract(self) -> &'static Contract {
        &REGISTRY[self as usize]
    }
}

/// 外部所有权归零（且对象尚未死亡）时的 closing 动作。
/// Closing action when the last external ownership is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closing {
    /// 无 closing 动作。
    None,
    /// 在对象表锁内执行有界的 closing 动作（拒绝新操作、取消 / 终结等待、释放 closing 阶段可释放的强边）。
    /// 必须在释放最后一份外部所有权**之前**执行：无内部引用的对象会在同一刻死亡离表。
    InLock,
}

/// 对象死亡（两种计数都归零）后的销毁动作。
/// Destroy action after the object dies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destroy {
    /// 无需额外动作（丢弃对象值即可）。
    None,
    /// 清理过程在**不持对象表锁**时执行（可能很重：销毁地址空间、归还配额、释放强边）。
    OutsideLock,
}

/// 销毁声明是否与内核侧「存在模块销毁钩子」一致。
/// `Destroy::None` 必须没有钩子；`Destroy::OutsideLock` 必须有钩子。
/// English: true only when hook presence agrees with the declared destroy action.
pub const fn destroy_hook_matches(declared: Destroy, hook_present: bool) -> bool {
    matches!(declared, Destroy::OutsideLock) == hook_present
}

/// 对象是否携带其他对象的句柄（外部所有权）。
/// Whether the object carries handles (external ownerships) of other objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carry {
    /// 不携带。
    Nothing,
    /// 只携带可转移（叶子）类型的句柄（Channel 消息队列）。
    TransferableOnly,
    /// 可携带任意类型的句柄（进程句柄表）；进程退出时关闭句柄表，环由此断开。
    AnyClosedOnExit,
}

/// 一种对象的生命周期契约。
/// Lifetime contract of one object kind.
#[derive(Debug, Clone, Copy)]
pub struct Contract {
    /// 种类（须等于它在 [`REGISTRY`] 中的位置）。
    pub kind: Kind,
    /// 类型名（日志用；全表互异）。
    pub name: &'static str,
    /// 句柄上的类型；`None` = 不可经句柄访问（只被内部引用）。
    pub handle: Option<ObjectType>,
    /// 句柄权限的合法上限（任何句柄的权限都必须是它的子集）。
    pub rights: Rights,
    /// 能否经 Channel 转移（⇔ 上限含 `TRANSFER`）。
    pub transferable: bool,
    /// closing 动作。
    pub closing: Closing,
    /// 销毁动作。
    pub destroy: Destroy,
    /// 强边指向的种类。
    pub strong: &'static [Kind],
    /// 是否有同种类的树形强边（进程 → 子进程）。
    pub tree_self: bool,
    /// 是否携带句柄。
    pub carries: Carry,
}

/// 线程句柄的合法权限上限。
const TASK_RIGHTS: Rights =
    Rights::WAIT.union(Rights::CONTROL).union(Rights::DUPLICATE).union(Rights::TRANSFER).union(Rights::SUBSCRIBE);

/// 对象类型登记表（按 [`Kind`] 声明顺序；唯一登记点）。
/// The object type registry (single point of registration).
pub const REGISTRY: [Contract; Kind::COUNT] = [
    Contract {
        kind: Kind::Process,
        name: "Process",
        handle: Some(ObjectType::Process),
        rights: Rights::WAIT.union(Rights::SUBSCRIBE),
        transferable: false,
        closing: Closing::InLock, // 用户创建的子进程仍在运行则终止
        destroy: Destroy::OutsideLock, // 地址空间、页帧、线程表 / 子进程表 / 退出状态引用
        strong: &[Kind::Task, Kind::ExitState],
        tree_self: true,
        carries: Carry::AnyClosedOnExit,
    },
    Contract {
        kind: Kind::Ring,
        name: "Ring",
        handle: Some(ObjectType::Ring),
        rights: Rights::WRITE.union(Rights::WAIT).union(Rights::CONTROL).union(Rights::DUPLICATE),
        transferable: false,
        closing: Closing::InLock, // 拒绝新提交、取消可取消请求、丢弃未消费完成记录
        destroy: Destroy::OutsideLock, // 归还所属进程的 Ring 配额
        strong: &[Kind::Interrupt, Kind::Subscription, Kind::Endpoint, Kind::ExitState], // 在飞请求的等待目标
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Task,
        name: "Task",
        handle: Some(ObjectType::Task),
        rights: TASK_RIGHTS,
        transferable: true,
        closing: Closing::None,
        destroy: Destroy::OutsideLock, // 释放对退出状态的内部引用
        strong: &[Kind::ExitState],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Interrupt,
        name: "Interrupt",
        handle: Some(ObjectType::Interrupt),
        rights: Rights::WAIT.union(Rights::CONTROL).union(Rights::SUBSCRIBE),
        transferable: false,
        closing: Closing::InLock, // 解绑硬件、以「已关闭」终态完成等待、结束事件发布者
        destroy: Destroy::None,
        strong: &[Kind::EventSource],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Subscription,
        name: "Subscription",
        handle: Some(ObjectType::Subscription),
        rights: Rights::READ.union(Rights::WAIT),
        transferable: false,
        closing: Closing::InLock, // 摘除订阅、释放对事件源的内部引用
        destroy: Destroy::None,
        strong: &[Kind::EventSource],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Endpoint,
        name: "Endpoint",
        handle: Some(ObjectType::Channel),
        rights: Rights::READ.union(Rights::WRITE).union(Rights::WAIT).union(Rights::CONTROL).union(Rights::DUPLICATE),
        transferable: false,
        closing: Closing::InLock, // 销毁队列消息（释放其中句柄）、取消接收等待、通知对端
        destroy: Destroy::OutsideLock, // 归还创建者的端点配额
        strong: &[],
        tree_self: false,
        carries: Carry::TransferableOnly,
    },
    Contract {
        kind: Kind::ExitState,
        name: "ExitState",
        handle: None,
        rights: Rights::NONE,
        transferable: false,
        closing: Closing::None,
        destroy: Destroy::OutsideLock, // 结束退出事件的发布者
        strong: &[Kind::EventSource],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::EventSource,
        name: "EventSource",
        handle: Some(ObjectType::EventSource),
        rights: Rights::READ.union(Rights::SUBSCRIBE).union(Rights::DUPLICATE),
        transferable: false,
        closing: Closing::InLock, // 非发布者持有的源关闭并通知订阅者
        destroy: Destroy::None,
        strong: &[],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Mutex,
        name: "Mutex",
        handle: Some(ObjectType::Mutex),
        rights: Rights::WAIT.union(Rights::CONTROL).union(Rights::DUPLICATE).union(Rights::TRANSFER),
        transferable: true,
        closing: Closing::InLock, // 关闭并唤醒等待者
        destroy: Destroy::None,
        strong: &[],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Memory,
        name: "Memory",
        handle: Some(ObjectType::Memory),
        rights: Rights::READ.union(Rights::WRITE).union(Rights::MAP).union(Rights::DUPLICATE).union(Rights::TRANSFER),
        transferable: true,
        closing: Closing::None,
        destroy: Destroy::None, // 页引用由映射与固定各自持有，丢弃对象值即归还
        strong: &[],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Event,
        name: "Event",
        handle: Some(ObjectType::Event),
        rights: Rights::WAIT.union(Rights::TRANSFER),
        transferable: true,
        closing: Closing::None,
        destroy: Destroy::None,
        strong: &[],
        tree_self: false,
        carries: Carry::Nothing,
    },
    Contract {
        kind: Kind::Device,
        name: "Device",
        handle: Some(ObjectType::Device),
        rights: Rights::READ.union(Rights::MAP).union(Rights::CONTROL).union(Rights::DUPLICATE).union(Rights::TRANSFER),
        transferable: true,
        closing: Closing::None,
        destroy: Destroy::None, // 设备表项常驻，句柄关闭不销毁它
        strong: &[],
        tree_self: false,
        carries: Carry::Nothing,
    },
];

/// 句柄创建检查的结论。
/// Outcome of the handle-creation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantCheck {
    /// 允许。
    Allowed,
    /// 句柄类型与对象种类不符（或该种类不可经句柄访问）。
    WrongType,
    /// 请求了 `TRANSFER`，但该种类不可转移。
    NotTransferable,
    /// 请求的权限超出该种类的合法上限。
    RightsDenied,
}

/// 检查「为 `kind` 种类的对象创建类型为 `ty`、权限为 `rights` 的句柄」是否合法。
/// 顺序固定：先类型，再可转移性，再权限上限。
/// Checks a handle creation against the kind's contract: type, then transferability, then the rights ceiling.
pub const fn check_grant(kind: Kind, ty: ObjectType, rights: Rights) -> GrantCheck {
    let c = kind.contract();
    match c.handle {
        Some(h) if h as u8 == ty as u8 => {}
        _ => return GrantCheck::WrongType,
    }
    if rights.contains(Rights::TRANSFER) && !c.transferable {
        return GrantCheck::NotTransferable;
    }
    if !c.rights.contains(rights) {
        return GrantCheck::RightsDenied;
    }
    GrantCheck::Allowed
}

/// 句柄类型对应的对象种类（没有对象种类使用该句柄类型 ⇒ `None`）。
pub const fn kind_for_handle(ty: ObjectType) -> Option<Kind> {
    let mut i = 0;
    while i < Kind::COUNT {
        if let Some(h) = REGISTRY[i].handle {
            if h as u8 == ty as u8 {
                return Some(REGISTRY[i].kind);
            }
        }
        i += 1;
    }
    None
}

/// 强边 `from → to` 是否符合拓扑序（指向声明顺序更靠后的种类）。
pub const fn edge_ordered(from: Kind, to: Kind) -> bool {
    to.index() > from.index()
}

/// 两个名字是否相同（const 环境下的字节比较）。
const fn same_name(a: &str, b: &str) -> bool {
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

/// 种类 `k` 及其强引用闭包中是否有携带句柄的种类（`reg` 须已通过位置与拓扑序检查）。
const fn closure_carries(reg: &[Contract], k: usize) -> bool {
    // 拓扑序保证强边只指向更大的下标：从大到小计算一遍即得闭包结论。
    let mut carries = [false; Kind::COUNT];
    let mut i = reg.len();
    while i > k {
        i -= 1;
        let c = &reg[i];
        let mut v = !matches!(c.carries, Carry::Nothing);
        let mut e = 0;
        while e < c.strong.len() {
            if carries[c.strong[e].index()] {
                v = true;
            }
            e += 1;
        }
        carries[i] = v;
    }
    carries[k]
}

/// 登记表良构条件（全部满足才返回 `true`）：
/// 1. 表长 = 种类数，第 i 项的种类就是第 i 个种类；类型名互异；
/// 2. 不可经句柄访问 ⇒ 权限上限为空、不可转移、无 closing 动作；
/// 3. 可经句柄访问 ⇒ 句柄类型互异、权限上限非空；可转移 ⇔ 上限含 `TRANSFER` ⇔ 句柄类型属于 v1 可转移类型；
/// 4. 每条强边指向声明顺序更靠后的种类（类型层面无环）；只有携带任意句柄的种类可以有树形自边；
/// 5. 有强边或携带句柄 ⇒ 有 closing 或锁外销毁动作来释放它们；
/// 6. 可转移 ⇒ 叶子：不携带句柄，且强引用闭包中没有携带句柄的种类。
///
/// Registry well-formedness; the kernel asserts it at compile time.
pub const fn registry_well_formed(reg: &[Contract]) -> bool {
    if reg.len() != Kind::COUNT {
        return false;
    }
    let mut i = 0;
    while i < reg.len() {
        let c = &reg[i];
        if c.kind.index() != i {
            return false;
        }
        let mut j = 0;
        while j < i {
            if same_name(reg[j].name, c.name) {
                return false;
            }
            if let (Some(a), Some(b)) = (reg[j].handle, c.handle) {
                if a as u8 == b as u8 {
                    return false;
                }
            }
            j += 1;
        }
        match c.handle {
            None => {
                if !c.rights.is_empty() || c.transferable || !matches!(c.closing, Closing::None) {
                    return false;
                }
            }
            Some(ty) => {
                if c.rights.is_empty()
                    || c.transferable != c.rights.contains(Rights::TRANSFER)
                    || c.transferable != ty.is_transferable_v1()
                {
                    return false;
                }
            }
        }
        let mut e = 0;
        while e < c.strong.len() {
            if !edge_ordered(c.kind, c.strong[e]) {
                return false;
            }
            e += 1;
        }
        if c.tree_self && !matches!(c.carries, Carry::AnyClosedOnExit) {
            return false;
        }
        let holds = !c.strong.is_empty() || c.tree_self || !matches!(c.carries, Carry::Nothing);
        if holds && matches!(c.closing, Closing::None) && matches!(c.destroy, Destroy::None) {
            return false;
        }
        i += 1;
    }
    let mut k = 0;
    while k < reg.len() {
        if reg[k].transferable && closure_carries(reg, k) {
            return false;
        }
        k += 1;
    }
    true
}

const _: () = assert!(registry_well_formed(&REGISTRY));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_well_formed_and_indexed() {
        assert!(registry_well_formed(&REGISTRY));
        for (i, k) in Kind::ALL.iter().enumerate() {
            assert_eq!(k.index(), i);
            assert_eq!(k.contract().kind, *k);
        }
    }

    #[test]
    fn handle_types_round_trip() {
        for k in Kind::ALL {
            if let Some(ty) = k.contract().handle {
                assert_eq!(kind_for_handle(ty), Some(k));
            }
        }
        assert_eq!(kind_for_handle(ObjectType::Timer), None);
        assert_eq!(kind_for_handle(ObjectType::AddressSpace), None);
    }

    #[test]
    fn grant_check_order() {
        let tr = Rights::WAIT.union(Rights::TRANSFER);
        assert_eq!(check_grant(Kind::Event, ObjectType::Event, tr), GrantCheck::Allowed);
        assert_eq!(check_grant(Kind::Event, ObjectType::Task, tr), GrantCheck::WrongType);
        assert_eq!(check_grant(Kind::ExitState, ObjectType::Event, Rights::NONE), GrantCheck::WrongType);
        assert_eq!(check_grant(Kind::Process, ObjectType::Process, tr), GrantCheck::NotTransferable);
        assert_eq!(check_grant(Kind::Event, ObjectType::Event, Rights::READ), GrantCheck::RightsDenied);
        assert_eq!(check_grant(Kind::Process, ObjectType::Process, Rights::NONE), GrantCheck::Allowed);
    }

    #[test]
    fn destroy_none_requires_an_empty_hook() {
        assert!(destroy_hook_matches(Destroy::None, false));
        assert!(!destroy_hook_matches(Destroy::None, true));
        assert!(destroy_hook_matches(Destroy::OutsideLock, true));
        assert!(!destroy_hook_matches(Destroy::OutsideLock, false));
    }

    #[test]
    fn mutations_are_rejected() {
        let mut r = REGISTRY;
        r[Kind::Process.index()].transferable = true;
        assert!(!registry_well_formed(&r));
        let mut r = REGISTRY;
        r[Kind::EventSource.index()].strong = &[Kind::Ring];
        assert!(!registry_well_formed(&r));
        let mut r = REGISTRY;
        r[Kind::Event.index()].carries = Carry::TransferableOnly;
        r[Kind::Event.index()].destroy = Destroy::OutsideLock;
        assert!(!registry_well_formed(&r));
        let mut r = REGISTRY;
        r[Kind::Interrupt.index()].closing = Closing::None;
        assert!(!registry_well_formed(&r));
        let mut r = REGISTRY;
        r.swap(0, 1);
        assert!(!registry_well_formed(&r));
        assert!(!registry_well_formed(&REGISTRY[..11]));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// 生产登记表良构；check_grant 对全部种类 × 全部句柄类型 × 任意权限位与规格一致。
    #[kani::proof]
    fn grant_check_matches_spec_for_all_inputs() {
        assert!(registry_well_formed(&REGISTRY));
        let k = Kind::ALL[kani::any::<usize>() % Kind::COUNT];
        let ty = ObjectType::ALL[kani::any::<usize>() % ObjectType::ALL.len()];
        let rights = Rights::from_bits_truncate(kani::any());
        let c = k.contract();
        let type_ok = matches!(c.handle, Some(h) if h == ty);
        let r = check_grant(k, ty, rights);
        if r == GrantCheck::Allowed {
            assert!(type_ok && c.rights.contains(rights));
            assert!(!rights.contains(Rights::TRANSFER) || c.transferable);
        }
        assert_eq!(r == GrantCheck::WrongType, !type_ok);
        if type_ok && c.rights.contains(rights) {
            assert_eq!(r, GrantCheck::Allowed);
        }
        assert_eq!(kind_for_handle(ty).map(|x| x == k).unwrap_or(false), type_ok);
    }

    /// 符合拓扑序的强边组成的任意路径（长度 ≤ 4）都不会回到起点。
    #[kani::proof]
    #[kani::unwind(6)]
    fn ordered_edges_admit_no_cycle() {
        let path: [usize; 4] = [kani::any(), kani::any(), kani::any(), kani::any()];
        let n: usize = kani::any();
        kani::assume((2..=4).contains(&n));
        let mut ok = true;
        let mut i = 0;
        while i < n {
            kani::assume(path[i] < Kind::COUNT);
            i += 1;
        }
        i = 0;
        while i + 1 < n {
            ok &= edge_ordered(Kind::ALL[path[i]], Kind::ALL[path[i + 1]]);
            i += 1;
        }
        if ok {
            assert!(path[n - 1] != path[0]);
        }
    }
}
