//! 用户进程创建子进程：`system.process.spawn`（架构无关）。
//! Process creation by user processes (`system.process.spawn`).
//!
//! # 职责
//! 让一个用户进程从自己内存中的 ELF 映像创建子进程，并且**只能把自己拥有的权力的子集交给它**：
//! * 系统调用集合 ⊆ 调用者的集合（无状态规则见 `kernel_core::spawn_abi::check`）
//! * 子进程起步时句柄表里只有一个句柄：与父进程相连的**引导通道**端点；其它句柄只能由父进程经该通道
//!   主动发送（Channel 只移动带 TRANSFER 的叶子对象），因此子进程能接触的对象全部经父进程授权
//! * 可选的 CPU 上限：失控的子进程最多占用这个比例的处理器
//!
//! # 生命周期
//! 父进程得到的进程句柄（权限 WAIT）就是子进程唯一的外部所有权。子进程仍在运行时这份所有权被释放
//! （父进程关闭句柄，或父进程自己退出、句柄表被关闭）⇒ 子进程被终止（退出码 [`KILLED_CODE`]）——
//! 隔离出去的代码活不过它的宿主，也不会成为无人能回收的孤儿。
//!
//! # 配额与回收
//! 每个父进程最多同时持有 `MAX_CHILDREN` 个子进程（以进程句柄计）；配额在父进程释放该句柄时归还
//! （而不是等子进程销毁：被终止的子进程要到下一个调度点才停止，销毁更晚）。
//! 子进程的内存在清理过程中销毁时归还；创建前先以有界预算推进一次清理（在需要资源的地方回收），
//! 因此反复「创建—关闭」不会让已死亡的子进程无限积压。
//!
//! # 全有或全无
//! 参数块、调用集合、映像大小在改动任何状态之前检查；之后任何一步失败都撤销已做的部分
//! （已建的子进程经「无线程退出 + 释放所有权」销毁，已发放的句柄被收回），调用者的句柄表与配额保持原样。

use alloc::vec;

use kernel_core::frame::FRAME_SIZE;
use kernel_core::object::{HandleId, ObjectId, ObjectRef, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::paging::MapFlags;
use kernel_core::spawn_abi::{self, SpawnDesc, SpawnReject, CPU_UNLIMITED, MAX_CHILDREN, SPAWN_DESC_SIZE};

use super::{receiver, ProcError, ProcState};
use crate::kobj::{self, KObject};
use crate::syscall::table::*;
use crate::syscall::{err, SyscallSet};
use crate::{arch, kprintln};

/// 子进程因父进程释放了最后一个句柄而被终止时的退出码。
/// Exit code of a child terminated because its last handle was released.
pub const KILLED_CODE: i64 = -2;

/// 子进程主线程初始栈：栈顶相对私有窗口起点的偏移与页数（运行时随后切换到自己映射的大栈）。
const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;
/// 子进程在内核日志中的名字。
const CHILD_NAME: &str = "spawned";
/// 每次创建前最多销毁的死亡对象数（有界：系统调用路径上的额外工作不随积压增长）。
const RECLAIM_BUDGET: usize = 32;

/// 创建成功：父进程中的两个句柄。
/// Handles the parent receives on success.
#[derive(Debug, Clone, Copy)]
pub struct Spawned {
    /// 指向子进程（WAIT）。
    pub process: HandleId,
    /// 引导通道在父进程一侧的端点。
    pub channel: HandleId,
}

/// 创建失败的原因（每一项都已撤销了之前的改动）。
/// Why a spawn failed; nothing was left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// 无状态规则未通过。
    Rejected(SpawnReject),
    /// 父进程的子进程配额已满。
    TooManyChildren,
    /// 映像不是可装载的 ELF。
    BadImage,
    /// 进程层操作失败（父进程已退出、句柄表满、帧不足等）。
    Proc(ProcError),
    /// 通道创建失败（已映射为系统调用错误码）。
    Channel(i64),
}

/// 已登记的全部操作 ID 的集合（`spawn_abi::check` 的 `known`）。
fn known_calls() -> u64 {
    ENTRIES.iter().filter(|e| e.kind == AbiKind::Op && e.id < 64).fold(0u64, |m, e| m | 1 << e.id)
}

/// 在锁内：子进程最后一份外部所有权即将释放时的 closing 动作——归还父进程的配额；仍在运行就发起终止。
/// 没有线程的子进程直接进入 exited；有线程的在各自的下一个调度点停止（与 `process.exit` 相同的路径）。
/// Closing action of a spawned process: return the parent's quota and terminate it if still running.
pub(crate) fn close_in(t: &mut kobj::Table, id: ObjId) {
    let (parent, idle) = match t.get_mut(id) {
        Ok(KObject::Process(p)) if p.kill_on_release => {
            let running = p.state == ProcState::Running;
            if running {
                p.state = ProcState::Exiting { code: KILLED_CODE };
            }
            (p.spawned_by.take(), running.then_some(p.threads_live == 0))
        }
        _ => return,
    };
    if let Some(Ok(KObject::Process(p))) = parent.map(|pid| t.get_mut(pid)) {
        p.spawned_live = p.spawned_live.saturating_sub(1);
    }
    let Some(idle) = idle else { return };
    let n = super::release_resources_in(t, id);
    kprintln!("[JSR-PROC] event=system.process.killed id={:#x} cause=last_handle_released code={} handles_closed={}", id.raw(), KILLED_CODE, n);
    if idle {
        super::finish_exit_in(t, id, KILLED_CODE);
    }
}

/// 撤销尚未交给父进程的子进程：无线程退出 + 释放创建者所有权（随后由清理过程销毁）。
fn discard(child: ObjId) {
    let _ = super::exit_idle(child, KILLED_CODE);
    let _ = super::reap(child);
}

/// 为父进程 `parent` 从 `image` 创建子进程（见模块文档）。`calls` 须已通过无状态检查。
/// Creates a child of `parent` from an ELF image; all-or-nothing.
pub fn spawn_child(parent: ObjId, image: &[u8], calls: SyscallSet, arg: u64, cpu_limit: u32) -> Result<Spawned, SpawnError> {
    // 先回收已死亡的对象（有界）：销毁发生在清理过程里——不在这里推进，
    // 父进程关闭了句柄、已经退出的子进程会一直占着内存
    kobj::run_cleanup(RECLAIM_BUDGET);
    // 预检（不改状态）：父进程仍在运行、配额未满、句柄表放得下两个句柄
    kobj::with(|t| {
        let p = receiver(t, parent).map_err(SpawnError::Proc)?;
        if p.spawned_live as usize >= MAX_CHILDREN {
            return Err(SpawnError::TooManyChildren);
        }
        if p.handles.free_slots() < 2 {
            return Err(SpawnError::Proc(ProcError::Handle(kernel_core::object::HandleError::TableFull)));
        }
        Ok(())
    })?;
    let child = super::create(CHILD_NAME, calls).map_err(SpawnError::Proc)?;
    let base = arch::USER_WINDOW.0;
    let prepared = (|| {
        let entry = super::load_elf(child, image).map_err(|_| SpawnError::BadImage)?;
        for i in 1..=STACK_PAGES {
            super::map_new(child, base + STACK_TOP_OFF - i * FRAME_SIZE, MapFlags::USER | MapFlags::WRITE).map_err(SpawnError::Proc)?;
        }
        if cpu_limit < CPU_UNLIMITED {
            super::set_cpu_limit(child, cpu_limit).map_err(|_| SpawnError::Proc(ProcError::NoTaskSlot))?;
        }
        Ok(entry)
    })();
    let entry = match prepared {
        Ok(e) => e,
        Err(e) => {
            discard(child);
            return Err(e);
        }
    };
    let (ha, hb) = match crate::ipc::create_pair(parent, child) {
        Ok(x) => x,
        Err(code) => {
            discard(child);
            return Err(SpawnError::Channel(code));
        }
    };
    // 把创建者所有权转成父进程中的句柄，并登记生命周期关系（同一把锁内，失败则收回通道端点）
    let handed = kobj::with(|t| {
        let r = (|| {
            let p = receiver(t, parent)?;
            if p.spawned_live as usize >= MAX_CHILDREN {
                return Err(ProcError::NoTaskSlot);
            }
            let hp = p.handles.put(ObjectRef { id: ObjectId(child.raw()), ty: ObjectType::Process }, Rights::WAIT).map_err(ProcError::Handle)?;
            p.spawned_live += 1;
            Ok(hp)
        })();
        match r {
            Ok(hp) => {
                if let Ok(KObject::Process(c)) = t.get_mut(child) {
                    c.kill_on_release = true;
                    c.spawned_by = Some(parent);
                }
                Ok(hp)
            }
            Err(e) => {
                if let Ok(id) = super::take_handle_in(t, parent, ha) {
                    let _ = kobj::release_owner_in(t, id);
                }
                Err(e)
            }
        }
    });
    let hp = match handed {
        Ok(h) => h,
        Err(e) => {
            discard(child);
            return Err(SpawnError::Proc(e));
        }
    };
    if let Err(e) = super::spawn_thread(child, CHILD_NAME, entry, base + STACK_TOP_OFF, hb.raw() as u64, arg) {
        // 收回两个句柄：进程句柄是子进程唯一的外部所有权 ⇒ closing 终止（无线程，直接 exited）并销毁
        kobj::with(|t| {
            for h in [ha, hp] {
                if let Ok(id) = super::take_handle_in(t, parent, h) {
                    let _ = kobj::release_owner_in(t, id);
                }
            }
        });
        return Err(SpawnError::Proc(e));
    }
    kprintln!(
        "[JSR-PROC] event=system.process.spawned parent={:#x} child={:#x} calls={:#x} cpu_limit={} image_bytes={}",
        parent.raw(),
        child.raw(),
        calls.0,
        cpu_limit,
        image.len()
    );
    Ok(Spawned { process: hp, channel: ha })
}

fn spawn_err(e: SpawnError) -> i64 {
    match e {
        SpawnError::Rejected(SpawnReject::Escalation) => err(SYSTEM_ERROR_RIGHTS_DENIED),
        SpawnError::Rejected(_) | SpawnError::BadImage => err(SYSTEM_ERROR_INVALID_ARGUMENT),
        SpawnError::TooManyChildren => err(SYSTEM_ERROR_QUOTA_EXCEEDED),
        SpawnError::Proc(ProcError::OutOfFrames) => err(SYSTEM_MEMORY_ERROR_OUT_OF_MEMORY),
        SpawnError::Proc(e) => crate::syscall::proc_err(e),
        SpawnError::Channel(code) => code,
    }
}

/// `system.process.spawn(desc_ptr)`：按参数块创建子进程，成功时把两个句柄写回参数块的输出字段并返回 0。
/// 参数块的输出位置在创建之前先确认可写：不会出现「子进程建了却交不回句柄」。
/// System call entry of `system.process.spawn`.
pub fn sys_spawn(desc_ptr: u64) -> i64 {
    let Some(pid) = super::current_process() else { return err(SYSTEM_ERROR_RIGHTS_DENIED) };
    let mut raw = [0u8; SPAWN_DESC_SIZE];
    if let Err(e) = crate::mm::user::copy_from_user(&mut raw, desc_ptr, SPAWN_DESC_SIZE) {
        return crate::ring::user_err(e);
    }
    let d = SpawnDesc::decode(&raw);
    if let Err(r) = spawn_abi::check(&d, crate::sched::current_syscalls().0, known_calls()) {
        return spawn_err(SpawnError::Rejected(r));
    }
    if let Err(e) = crate::mm::user::copy_to_user(desc_ptr, &raw, SPAWN_DESC_SIZE) {
        return crate::ring::user_err(e);
    }
    let len = d.image_len as usize;
    let mut image = vec![0u8; len];
    if let Err(e) = crate::mm::user::copy_from_user(&mut image, d.image_ptr, len) {
        return crate::ring::user_err(e);
    }
    match spawn_child(pid, &image, SyscallSet(d.calls), d.arg, d.cpu_limit_permille) {
        Ok(s) => {
            let out = d.with_outputs(s.process.raw(), s.channel.raw());
            match crate::mm::user::copy_to_user(desc_ptr, &out, SPAWN_DESC_SIZE) {
                Ok(()) => 0,
                // 上面已确认可写；若父进程的另一个线程在此期间取消了映射，句柄仍在父进程句柄表中，
                // 随父进程退出被关闭（子进程随之终止），不会泄漏
                Err(e) => crate::ring::user_err(e),
            }
        }
        Err(e) => spawn_err(e),
    }
}
