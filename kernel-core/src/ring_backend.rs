//! 异步 Ring 后端登记表与后端契约（issue #5 第一片）。
//! Closed, statically registered asynchronous-ring backends and their per-backend contract.
//!
//! # 为什么需要它
//! 内核的 Ring 层（`kernel::ring`）原来在「哪些操作可经 Ring 提交」「开始执行时是否可中止」
//! 「是否访问用户缓冲区」三处各自写死操作列表；新增一个后端要同时改多个分支，漏改不会报错
//! （例如解析用户提交时未列出的操作会落进兜底分支）。本模块把这三项收敛为一张**编译期静态、类型封闭**的表：
//! * [`Kind`]：全部可经用户提交的后端，封闭枚举；内核侧按它做穷举 `match`（无兜底分支），
//!   加入新后端时编译器指出每一个必须补的位置。
//! * [`Contract`]：每个后端的静态契约（开始执行时的可中止性、是否在提交时即裁决、是否持有用户缓冲区）。
//! * [`Route`]：操作编号 → 后端。操作编号由 ABI 生成表给出（本 crate 不写死编号），
//!   内核用 [`routes_well_formed`] 在编译期断言路由表良构：编号非零且互不相同、每个后端至少一条路由。
//!
//! 请求状态机（裁决、完成信用、发布、销毁）仍只有 `crate::async_ring` 一套，本模块不重复实现。
//!
//! # 后端生命周期契约（全部后端共用）
//! 1. **校验**（锁外）：标志位、路由存在、调用者被授予该操作；用户内存在此之前复制或固定。
//! 2. **预留**（对象表锁内，原子）：每进程在飞配额、控制块与完成信用；任一失败 ⇒ 释放工作已持有的资源，不留半项。
//! 3. **启动**：按 [`Contract::exec`] 调用状态机 `start`。
//! 4. **推进**：瞬时后端（[`Contract::settles_at_submit`]）在提交内裁决终态；其余登记到等待源，由事件或到期推进。
//! 5. **完成 / 取消**：终态至多裁决一次（状态机保证）；取消可中止请求 ⇒ 中止后端。
//! 6. **静止**：持有用户缓冲区的后端（[`Contract::uses_buffer`]）先静止、后发布完成。
//! 7. **释放**：撤销等待登记、释放内部引用与固定；每个已启动后端恰好释放一次。
//!
//! Lifecycle: validate → reserve (atomic) → start → progress → finish/cancel (once) → quiesce → release (once).

use crate::async_ring::Exec;

/// 可经用户提交的 Ring 后端（封闭集合）。内核自检用的人工后端不在其中。
/// The closed set of user-submittable ring backends (the kernel-only manual backend is excluded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// 读当前时钟（瞬时）。
    Now,
    /// 等到截止时刻（可中止）。
    Wait,
    /// 两阶段发送（提交时即裁决，不可中止）。
    Send,
    /// 接收消息到固定的用户缓冲区（可中止）。
    Recv,
    /// 等待任务 / 进程退出（可中止）。
    ExitWait,
    /// 等待设备中断（可中止）。
    InterruptWait,
    /// 等待事件订阅交付到用户缓冲区（可中止）。
    SubscriptionWait,
}

/// 后端的静态契约。The static contract of one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contract {
    /// 开始执行时的可中止性（状态机 `start` 的参数）。
    pub exec: Exec,
    /// 提交内即裁决终态（瞬时后端）：不会进入执行中集合，也不登记等待源。
    pub settles_at_submit: bool,
    /// 访问用户缓冲区：完成须等后端静止后才发布。
    pub uses_buffer: bool,
}

impl Kind {
    /// 全部后端（顺序即编号顺序）。All backends.
    pub const ALL: [Kind; 7] =
        [Kind::Now, Kind::Wait, Kind::Send, Kind::Recv, Kind::ExitWait, Kind::InterruptWait, Kind::SubscriptionWait];

    /// 后端的紧凑序号（`ALL` 中的位置）。Dense index of the backend in [`Kind::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Kind::Now => 0,
            Kind::Wait => 1,
            Kind::Send => 2,
            Kind::Recv => 3,
            Kind::ExitWait => 4,
            Kind::InterruptWait => 5,
            Kind::SubscriptionWait => 6,
        }
    }

    /// 后端的静态契约。The backend's static contract.
    pub const fn contract(self) -> Contract {
        match self {
            Kind::Now | Kind::Send => Contract { exec: Exec::NonAbortable, settles_at_submit: true, uses_buffer: false },
            Kind::Wait | Kind::ExitWait | Kind::InterruptWait => {
                Contract { exec: Exec::Abortable, settles_at_submit: false, uses_buffer: false }
            }
            Kind::Recv | Kind::SubscriptionWait => Contract { exec: Exec::Abortable, settles_at_submit: false, uses_buffer: true },
        }
    }
}

/// 一条路由：操作编号 → 后端。One route: operation id → backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// 操作编号（ABI 生成表中的值）。
    pub op: u32,
    /// 承担该操作的后端。
    pub kind: Kind,
}

/// 路由表是否良构：编号非零（0 保留给内核人工后端）、互不相同，且每个后端至少有一条路由。
/// Whether a route table is well formed: non-zero, pairwise-distinct ops and every backend routed at least once.
pub const fn routes_well_formed(routes: &[Route]) -> bool {
    let mut covered = [false; Kind::ALL.len()];
    let mut i = 0;
    while i < routes.len() {
        if routes[i].op == 0 {
            return false;
        }
        let mut j = i + 1;
        while j < routes.len() {
            if routes[j].op == routes[i].op {
                return false;
            }
            j += 1;
        }
        covered[routes[i].kind.index()] = true;
        i += 1;
    }
    let mut k = 0;
    while k < covered.len() {
        if !covered[k] {
            return false;
        }
        k += 1;
    }
    true
}

/// 按操作编号查后端；不在表中 ⇒ `None`（不可经 Ring 提交）。良构表中至多一条匹配。
/// Look up the backend for `op`; `None` means the operation cannot be submitted through a ring.
pub const fn route(routes: &[Route], op: u32) -> Option<Kind> {
    let mut i = 0;
    while i < routes.len() {
        if routes[i].op == op {
            return Some(routes[i].kind);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: [Route; 8] = [
        Route { op: 10, kind: Kind::Now },
        Route { op: 11, kind: Kind::Wait },
        Route { op: 20, kind: Kind::Send },
        Route { op: 21, kind: Kind::Recv },
        Route { op: 30, kind: Kind::ExitWait },
        Route { op: 31, kind: Kind::ExitWait },
        Route { op: 40, kind: Kind::InterruptWait },
        Route { op: 50, kind: Kind::SubscriptionWait },
    ];
    const _: () = assert!(routes_well_formed(&TABLE));

    #[test]
    fn index_matches_all_order() {
        for (i, k) in Kind::ALL.iter().enumerate() {
            assert_eq!(k.index(), i);
        }
    }

    #[test]
    fn contracts_are_consistent() {
        for k in Kind::ALL {
            let c = k.contract();
            // 持有用户缓冲区的后端必须可中止且不在提交内裁决（否则无法在关闭时静止后解除固定）
            if c.uses_buffer {
                assert_eq!(c.exec, Exec::Abortable);
                assert!(!c.settles_at_submit);
            }
            // 瞬时后端不可中止（提交返回前已有结果）
            if c.settles_at_submit {
                assert_eq!(c.exec, Exec::NonAbortable);
            }
        }
    }

    #[test]
    fn route_finds_every_entry_and_rejects_others() {
        for r in TABLE {
            assert_eq!(route(&TABLE, r.op), Some(r.kind));
        }
        assert_eq!(route(&TABLE, 0), None);
        assert_eq!(route(&TABLE, 12), None);
        assert_eq!(route(&TABLE, u32::MAX), None);
    }

    #[test]
    fn malformed_tables_are_rejected() {
        let mut dup = TABLE;
        dup[7].op = 10;
        assert!(!routes_well_formed(&dup));
        let mut zero = TABLE;
        zero[0].op = 0;
        assert!(!routes_well_formed(&zero));
        let mut uncovered = TABLE;
        uncovered[7].kind = Kind::Recv;
        assert!(!routes_well_formed(&uncovered));
        assert!(!routes_well_formed(&[]));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_kind() -> Kind {
        let i: usize = kani::any();
        kani::assume(i < Kind::ALL.len());
        Kind::ALL[i]
    }

    /// 任意 8 条路由的表、任意操作编号：`route` 的结果恰好对应表中第一条同编号路由；
    /// 表良构时该路由唯一，且所有后端都被覆盖。
    #[kani::proof]
    #[kani::unwind(10)]
    fn route_agrees_with_table_and_well_formed_implies_unique() {
        let routes: [Route; 8] = core::array::from_fn(|_| Route { op: kani::any(), kind: any_kind() });
        let op: u32 = kani::any();
        match route(&routes, op) {
            Some(k) => {
                let i: usize = kani::any();
                kani::assume(i < routes.len() && routes[i].op == op);
                if routes_well_formed(&routes) {
                    assert_eq!(routes[i].kind, k);
                }
            }
            None => {
                let i: usize = kani::any();
                kani::assume(i < routes.len());
                assert_ne!(routes[i].op, op);
            }
        }
        if routes_well_formed(&routes) {
            let i: usize = kani::any();
            let j: usize = kani::any();
            kani::assume(i < routes.len() && j < routes.len() && i != j);
            assert_ne!(routes[i].op, routes[j].op);
            assert_ne!(routes[i].op, 0);
            let k = any_kind();
            assert!(route_kind_covered(&routes, k));
        }
    }

    fn route_kind_covered(routes: &[Route; 8], k: Kind) -> bool {
        routes.iter().any(|r| r.kind == k)
    }

    /// 契约的内部一致性：持缓冲 ⇒ 可中止且非瞬时；瞬时 ⇒ 不可中止。
    #[kani::proof]
    fn contract_buffer_and_instant_rules() {
        let c = any_kind().contract();
        if c.uses_buffer {
            assert!(c.exec == Exec::Abortable && !c.settles_at_submit);
        }
        if c.settles_at_submit {
            assert!(c.exec == Exec::NonAbortable);
        }
    }
}
