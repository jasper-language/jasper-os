//! 退出状态（ExitState）：进程或线程的「是否已退出 + 退出码 + 等待者登记」，独立于其所属对象存活。
//! Exit state of a process or task: survives its owner so that accepted waits never lose their result.
//!
//! # 模型
//! * 每个 Process 与 Task 创建时附带一个 ExitState（对象表中的独立对象）；所属对象持有它的一个内部引用，
//!   在飞的 wait 请求也各持一个——因此目标被销毁后，已接受的 wait 仍能取得退出码。
//! * ExitState 位于强引用图的最底层：**没有任何强引用出边**。等待者登记 `(Ring, 请求 ID)` 是非拥有式的；
//!   请求结束时（无论完成还是取消）先从这里撤销登记，再释放对 ExitState 的引用。
//! * 退出时：写入退出码 → 取出全部登记 → 逐个让请求以退出码完成（请求若已被取消则什么也不做）。
//!   单 CPU 上这些都在对象表锁内一次完成，与取消之间由同一把锁裁决先后，不存在「已摘除登记、控制块已释放」的窗口。
//!
//! # 退出码的报告
//! wait 的结果是退出码按 **32 位无符号**值报告（因此总是非负，不与 `-(错误 ID)` 混淆）；故障终止记为 `0xFFFF_FFFF`。

use alloc::vec::Vec;

use kernel_core::objtable::ObjId;

use crate::kobj::{KObject, Table};

/// 退出状态对象。
pub struct ExitState {
    /// 退出码（未退出为 `None`）。
    code: Option<i64>,
    /// 等待者登记 (Ring, 请求 ID)——非拥有式。
    waiters: Vec<(ObjId, u64)>,
}

fn es_mut(t: &mut Table, id: ObjId) -> Option<&mut ExitState> {
    match t.get_mut(id) {
        Ok(KObject::ExitState(e)) => Some(e),
        _ => None,
    }
}

/// 新建一个退出状态（锁内），初始由所属对象持有一个内部引用。
pub(crate) fn create_in(t: &mut Table) -> Option<ObjId> {
    t.insert(KObject::ExitState(ExitState { code: None, waiters: Vec::new() }), 0, 1).ok()
}

/// 已退出则返回退出码。
pub(crate) fn code_in(t: &mut Table, id: ObjId) -> Option<i64> {
    es_mut(t, id).and_then(|e| e.code)
}

/// 登记一个等待者。
pub(crate) fn add_waiter_in(t: &mut Table, id: ObjId, w: (ObjId, u64)) {
    if let Some(e) = es_mut(t, id) {
        e.waiters.push(w);
    }
}

/// 撤销一个等待者登记（请求结束时调用；已被退出通知摘除则无事可做）。
pub(crate) fn remove_waiter_in(t: &mut Table, id: ObjId, w: (ObjId, u64)) {
    if let Some(e) = es_mut(t, id) {
        e.waiters.retain(|x| *x != w);
    }
}

/// 写入退出码并通知全部等待者（只生效一次）。
pub(crate) fn notify_in(t: &mut Table, id: ObjId, code: i64) {
    let Some(e) = es_mut(t, id) else { return };
    if e.code.is_some() {
        return;
    }
    e.code = Some(code);
    let waiters: Vec<(ObjId, u64)> = e.waiters.drain(..).collect();
    for (ring, req) in waiters {
        crate::ring::complete_waiter_in(t, ring, req, report(code));
    }
}

/// 退出码 → wait 的结果值（32 位无符号，见模块文档）。
pub fn report(code: i64) -> i64 {
    (code as u32) as i64
}
