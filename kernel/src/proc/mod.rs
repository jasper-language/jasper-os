//! 进程与线程对象（M3.4 引入，M4.1 接入对象表；架构无关）。
//! Process and thread objects, managed through the kernel object table.
//!
//! # 模型
//! * **进程** = 地址空间（[`VmSpace`]）+ 句柄表 + 它拥有的物理帧 + 线程表 + 退出码 + 可用系统调用集合。资源归进程所有。
//! * **线程** = 调度器里的一个任务 + 对象表中的一个 Task 对象（句柄可见），记着所属进程（带世代的弱回指）。
//!
//! # 引用关系（M4.0 规范 v0.6 第 1、2 节）
//! | 持有者 | 对象 | 种类 |
//! |---|---|---|
//! | 创建者（内核或父进程） | Process | 外部所有权（[`reap`] 时释放） |
//! | 进程句柄表中的句柄 | 所指对象 | 外部所有权（关闭句柄或进程退出时释放） |
//! | 线程执行上下文 | 自己的 Task、所属 Process | 内部引用（线程停止时释放） |
//! | 进程线程表 | 其中的 Task | 内部引用（进程销毁时释放） |
//!
//! # 生命周期
//! 创建 → 运行 → **exited**（最后一个线程停止：确定退出码、关闭整张句柄表）→ 创建者 [`reap`]（释放其所有权）→
//! 全部强引用归零后由清理过程 [`crate::kobj::run_cleanup`] 调用 [`destroy`]：销毁地址空间、归还帧、释放线程表引用（级联）。

use alloc::boxed::Box;
use alloc::vec::Vec;

use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::object::{HandleError, HandleId, HandleTable, ObjectId, ObjectRef, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::paging::{MapError, MapFlags, VirtPage};

use crate::kobj::{self, KObject, TaskObj};
use crate::mm::space::{in_private_window, VmSpace};
use crate::mm::{frame, phys_to_virt};
use crate::sync::IrqSpinLock;
use crate::syscall::SyscallSet;
use crate::task::TaskId;
use crate::{arch, kprintln, sched};

/// 每个进程句柄表的容量。
pub const HANDLES_PER_PROCESS: usize = 64;

/// 进程状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    /// 至少有一个线程存活。
    Running,
    /// 已发起终止（`system.process.exit` 或故障）：句柄表与子进程表已关闭，之后的提交原子失败；
    /// 其余线程在下一个调度点（系统调用入口、从用户态被时钟中断时）停止。退出码已确定。
    Exiting {
        /// 退出码。
        code: i64,
    },
    /// 最后一个线程已停止。
    Exited {
        /// 退出码（最后停止的线程给出；故障终止记为 -1）。
        code: i64,
    },
}

/// 进程对象（存放在内核对象表中）。
pub struct Process {
    name: &'static str,
    space: VmSpace,
    handles: HandleTable<ObjectRef, HANDLES_PER_PROCESS>,
    /// 进程拥有的数据帧（销毁时归还）。
    frames: Vec<PhysFrame>,
    /// 线程表：每项持有对应 Task 对象的一个内部引用。
    threads: Vec<ObjId>,
    syscalls: SyscallSet,
    /// 资源配额记账（Ring、在飞请求、Channel 端点）。
    ring_quota: ResourceQuota,
    /// 本进程的退出状态（持有一个内部引用）。
    exit_state: ObjId,
    /// 子进程表：每项持有子进程的一个内部引用（父 → 子单向）；本进程退出时释放。
    children: Vec<ObjId>,
    threads_live: u32,
    threads_total: u32,
    state: ProcState,
    /// CPU 组（设置过 CPU 上限时有值；进程的全部线程受同一份上限约束，进程销毁时归还）。
    cpu_group: Option<sched::scheduler::CpuGroupId>,
}

/// 进程的资源配额记账（开发默认值见 `crate::ring`、`crate::ipc` 中的常量）。
/// Per-process resource quota accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceQuota {
    /// 尚未销毁的 Ring 数。
    pub rings: u32,
    /// 跨所有 Ring、尚未销毁（X）的请求控制块数。
    pub in_flight: u32,
    /// 尚未销毁的 Channel 端点数。
    pub endpoints: u32,
    /// 本进程发出、仍在接收队列中的消息体总字节数。
    pub ipc_bytes: u32,
}

/// 线程的启动参数（线程首次被调度时读取）。
#[derive(Clone, Copy)]
struct ThreadStart {
    task: TaskId,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
}

/// 运行中线程的身份：任务 → (所属进程, 自己的 Task 对象)。
#[derive(Clone, Copy)]
struct Member {
    task: TaskId,
    process: ObjId,
    task_obj: ObjId,
}

struct Registry {
    starts: Vec<ThreadStart>,
    members: Vec<Member>,
}

static REG: IrqSpinLock<Registry> = IrqSpinLock::new(Registry { starts: Vec::new(), members: Vec::new() });
/// 线程任务 ID 分配（与其它演示任务的 ID 区分开）。
static TASK_IDS: kernel_core::object::IdAllocator = kernel_core::object::IdAllocator::new();

/// 进程操作错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcError {
    /// 进程不存在、已死亡或已销毁。
    NoSuchProcess,
    /// 进程已退出，不能再创建线程。
    Exited,
    /// 地址不在私有窗口或映射失败。
    Map(MapError),
    /// 没有空闲物理帧。
    OutOfFrames,
    /// 调度器槽位已满或对象表已满。
    NoTaskSlot,
    /// 句柄错误。
    Handle(HandleError),
    /// 对象在 v1 不可经 IPC 传递（非叶子对象，M4.0 规范 v0.6 §2.1）。
    NotTransferable,
}

/// 回收时返回的退出信息。
#[derive(Debug, Clone, Copy)]
pub struct ExitInfo {
    /// 退出码。
    pub code: i64,
    /// 生命周期内创建过的线程数。
    pub threads: u32,
    /// 进程拥有的数据帧数（销毁时归还）。
    pub frames: usize,
}

/// 新建进程（还没有线程）。调用者获得一份外部所有权，最终须经 [`reap`] 释放。
pub fn create(name: &'static str, syscalls: SyscallSet) -> Result<ObjId, ProcError> {
    let space = VmSpace::new().map_err(ProcError::Map)?;
    let exit_state = kobj::with(crate::exit_state::create_in).ok_or(ProcError::NoTaskSlot)?;
    let p = Box::new(Process {
        name,
        space,
        handles: HandleTable::new(),
        frames: Vec::new(),
        threads: Vec::new(),
        syscalls,
        ring_quota: ResourceQuota::default(),
        exit_state,
        children: Vec::new(),
        threads_live: 0,
        threads_total: 0,
        state: ProcState::Running,
        cpu_group: None,
    });
    let id = match kobj::insert(KObject::Process(p), 1, 0) {
        Ok(id) => id,
        Err(_) => {
            let _ = kobj::release_internal(exit_state); // 回滚：退出状态随之死亡
            return Err(ProcError::NoTaskSlot);
        }
    };
    kprintln!("[JSR-PROC] event=system.process.created id={:#x} name={}", id.raw(), name);
    Ok(id)
}

/// 在对象表锁内对进程执行 `f`。
fn with_proc<R>(id: ObjId, f: impl FnOnce(&mut Process) -> Result<R, ProcError>) -> Result<R, ProcError> {
    kobj::with(|t| match t.get_mut(id) {
        Ok(KObject::Process(p)) => f(p),
        _ => Err(ProcError::NoSuchProcess),
    })
}

/// 为进程分配一个清零的帧并映射到 `va`（帧归进程所有）。
pub fn map_new(id: ObjId, va: u64, flags: MapFlags) -> Result<PhysFrame, ProcError> {
    let f = frame::allocate().map_err(|_| ProcError::OutOfFrames)?;
    if let Some(p) = phys_to_virt(f.start()) {
        // SAFETY：刚分出的帧，经全物理内存映射清零。
        unsafe { core::ptr::write_bytes(p, 0, FRAME_SIZE as usize) };
    }
    let r = with_proc(id, |p| {
        p.space.map(VirtPage::containing(va), f, flags).map_err(ProcError::Map)?;
        p.frames.push(f);
        Ok(f)
    });
    if r.is_err() {
        let _ = frame::deallocate(f);
    }
    r
}

/// 取消进程中一页的映射并放弃该页的数据帧（仍被在飞请求固定时，帧延后到最后一次解除固定才归还）。
/// Unmaps one page of a process; its frame is returned now or, if pinned, after the last unpin.
pub fn unmap_page(id: ObjId, va: u64) -> Result<(), ProcError> {
    let f = with_proc(id, |p| {
        let f = p.space.unmap(VirtPage::containing(va)).map_err(ProcError::Map)?;
        p.frames.retain(|x| *x != f);
        Ok(f)
    })?;
    crate::mm::pin::release(f);
    Ok(())
}

/// 每个进程最多拥有的数据帧数（ELF 段、栈与匿名映射合计）。
/// Upper bound on data frames owned by one process (image, stacks and anonymous mappings together).
pub const MAX_PROCESS_FRAMES: usize = 8192;
/// 单次 `system.memory.map` / `unmap` 最多涉及的页数。
pub const MAX_MAP_PAGES: u64 = 1024;

/// 匿名映射 / 取消映射的失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    /// 起点未按页对齐、页数为 0 或超限、区间越出私有窗口。
    InvalidRange,
    /// 区间内已有映射（映射时）。
    AlreadyMapped,
    /// 区间内有未映射的页（取消映射时）。
    NotMapped,
    /// 超出进程的帧配额。
    Quota,
    /// 内存压力下按请求者的服务质量档位拒绝（低档先被拒，保证高档与内核仍有内存可用）。
    Pressure,
    /// 物理帧或页表帧不足。
    OutOfMemory,
    /// 进程不存在或已退出。
    NoSuchProcess,
}

/// 检查 `[va, va + pages × 页)` 是否是私有窗口内、按页对齐、页数在限额内的区间。
fn checked_range(va: u64, pages: u64) -> Result<(), MemError> {
    if va % FRAME_SIZE != 0 || pages == 0 || pages > MAX_MAP_PAGES {
        return Err(MemError::InvalidRange);
    }
    let end = pages.checked_mul(FRAME_SIZE).and_then(|len| va.checked_add(len)).ok_or(MemError::InvalidRange)?;
    if !in_private_window(va) || end > arch::USER_WINDOW.1 {
        return Err(MemError::InvalidRange);
    }
    Ok(())
}

/// 在进程 `pid` 的 `[va, va + pages 页)` 映射清零的匿名页（`writable` 决定可写；匿名页永不可执行）。
///
/// **全有或全无**：先在锁外分配并清零全部数据帧，再在锁内复核配额、确认区间内无映射、逐页建立映射；
/// 任何一步失败都撤销已建立的映射并归还全部数据帧，进程地址空间与帧记账保持调用前的样子
/// （建页表时新分配的中间页表帧归地址空间所有，随地址空间销毁回收）。
/// Maps zeroed anonymous pages, all-or-nothing.
pub fn map_anon(pid: ObjId, va: u64, pages: u64, writable: bool) -> Result<(), MemError> {
    checked_range(va, pages)?;
    let n = pages as usize;
    // 先按当前记账粗查配额，避免为必然失败的请求分配并清零大量帧（锁内仍会复核）。
    let owned = with_proc(pid, |p| Ok(p.frames.len())).map_err(|_| MemError::NoSuchProcess)?;
    if owned + n > MAX_PROCESS_FRAMES {
        return Err(MemError::Quota);
    }
    // 内存压力准入：在分配任何帧之前判定，被拒时不留任何改动。
    crate::mm::pressure::admit(sched::current_effective_qos(), n).map_err(|_| MemError::Pressure)?;
    let mut fresh: Vec<PhysFrame> = Vec::new();
    if fresh.try_reserve_exact(n).is_err() {
        return Err(MemError::OutOfMemory);
    }
    for _ in 0..n {
        match frame::allocate() {
            Ok(f) => {
                if let Some(p) = phys_to_virt(f.start()) {
                    // SAFETY：刚分出的帧，经全物理内存映射清零。
                    unsafe { core::ptr::write_bytes(p, 0, FRAME_SIZE as usize) };
                }
                fresh.push(f);
            }
            Err(_) => {
                for f in fresh {
                    let _ = frame::deallocate(f);
                }
                return Err(MemError::OutOfMemory);
            }
        }
    }
    let flags = if writable { MapFlags::USER.union(MapFlags::WRITE) } else { MapFlags::USER };
    let r = kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else { return Err(MemError::NoSuchProcess) };
        if p.state != ProcState::Running {
            return Err(MemError::NoSuchProcess);
        }
        if p.frames.len() + n > MAX_PROCESS_FRAMES {
            return Err(MemError::Quota);
        }
        if p.frames.try_reserve(n).is_err() {
            return Err(MemError::OutOfMemory);
        }
        for i in 0..pages {
            if p.space.translate(VirtPage::containing(va + i * FRAME_SIZE)).is_some() {
                return Err(MemError::AlreadyMapped);
            }
        }
        for (i, f) in fresh.iter().enumerate() {
            let page = VirtPage::containing(va + i as u64 * FRAME_SIZE);
            if let Err(e) = p.space.map(page, *f, flags) {
                for j in 0..i {
                    let _ = p.space.unmap(VirtPage::containing(va + j as u64 * FRAME_SIZE));
                }
                return Err(match e {
                    MapError::AlreadyMapped => MemError::AlreadyMapped,
                    MapError::OutOfFrames => MemError::OutOfMemory,
                    _ => MemError::InvalidRange,
                });
            }
        }
        p.frames.extend_from_slice(&fresh);
        Ok(())
    });
    if r.is_err() {
        for f in fresh {
            let _ = frame::deallocate(f);
        }
    }
    r
}

/// 取消进程 `pid` 中 `[va, va + pages 页)` 的映射并放弃这些页的数据帧。
///
/// **全有或全无**：区间内任一页未映射 ⇒ 什么也不做，返回 [`MemError::NotMapped`]。
/// 仍被在飞请求固定的帧延后到最后一次解除固定时归还（与 [`unmap_page`] 相同）。
/// Unmaps a range of pages, all-or-nothing.
pub fn unmap_range(pid: ObjId, va: u64, pages: u64) -> Result<(), MemError> {
    checked_range(va, pages)?;
    let mut gone: Vec<PhysFrame> = Vec::new();
    if gone.try_reserve_exact(pages as usize).is_err() {
        return Err(MemError::OutOfMemory);
    }
    kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else { return Err(MemError::NoSuchProcess) };
        for i in 0..pages {
            if p.space.translate(VirtPage::containing(va + i * FRAME_SIZE)).is_none() {
                return Err(MemError::NotMapped);
            }
        }
        for i in 0..pages {
            // 上面已确认每页都有映射；单 CPU 上锁内无人能在其间改动这张页表。
            if let Ok(f) = p.space.unmap(VirtPage::containing(va + i * FRAME_SIZE)) {
                gone.push(f);
            }
        }
        gone.sort_unstable_by_key(|f| f.start());
        p.frames.retain(|f| gone.binary_search_by_key(&f.start(), |g| g.start()).is_err());
        Ok(())
    })?;
    for f in gone {
        crate::mm::pin::release(f);
    }
    Ok(())
}

/// 修改进程 `pid` 中 `[va, va + pages 页)` 的访问权限：`writable` 与 `executable` 不能同时为真（W^X）。
///
/// **全有或全无**：区间内任一页未映射 ⇒ 什么也不改，返回 [`MemError::NotMapped`]。
/// 帧与记账不变；只改权限位。可执行权限只能经本接口获得（`map_anon` 映射的页永不可执行）。
/// Changes access rights of a mapped range (W^X enforced), all-or-nothing.
pub fn protect_range(pid: ObjId, va: u64, pages: u64, writable: bool, executable: bool) -> Result<(), MemError> {
    if writable && executable {
        return Err(MemError::InvalidRange);
    }
    checked_range(va, pages)?;
    let mut flags = MapFlags::USER;
    if writable {
        flags = flags.union(MapFlags::WRITE);
    }
    if executable {
        flags = flags.union(MapFlags::EXECUTE);
    }
    kobj::with(|t| {
        let Ok(KObject::Process(p)) = t.get_mut(pid) else { return Err(MemError::NoSuchProcess) };
        if p.state != ProcState::Running {
            return Err(MemError::NoSuchProcess);
        }
        for i in 0..pages {
            if p.space.translate(VirtPage::containing(va + i * FRAME_SIZE)).is_none() {
                return Err(MemError::NotMapped);
            }
        }
        for i in 0..pages {
            // 上面已确认每页都有 4 KiB 映射；单 CPU 上锁内无人能在其间改动这张页表。
            p.space.protect(VirtPage::containing(va + i * FRAME_SIZE), flags).map_err(|_| MemError::InvalidRange)?;
        }
        Ok(())
    })
}

/// 进程中 `va` 所在页的映射标志（未映射为 `None`；诊断与验收用）。
pub fn page_flags(pid: ObjId, va: u64) -> Option<MapFlags> {
    with_proc(pid, |p| Ok(p.space.translate(VirtPage::containing(va)).map(|(_, f)| f))).ok().flatten()
}

/// 进程当前拥有的数据帧数（诊断与验收用）。
pub fn frame_count(pid: ObjId) -> Option<usize> {
    with_proc(pid, |p| Ok(p.frames.len())).ok()
}

/// 在锁内固定进程 `pid` 的用户区间 `[va, va+len)`：区间须位于私有窗口、每页已映射且带用户权限（`write` 时还须可写）。
/// 返回的范围此后只经物理映射访问；任一页不满足 ⇒ 不固定任何帧。
/// Pins a user range of `pid` (all-or-nothing).
pub(crate) fn pin_user_in(
    t: &mut kobj::Table,
    pid: ObjId,
    va: u64,
    len: usize,
    write: bool,
) -> Result<crate::mm::pin::PinnedRange, ProcError> {
    let bad = ProcError::Map(MapError::InvalidAddress);
    let p = match t.get(pid) {
        Ok(KObject::Process(p)) => p,
        _ => return Err(ProcError::NoSuchProcess),
    };
    let mut segs = Vec::new();
    if len > 0 {
        let end = va.checked_add(len as u64).ok_or(bad)?;
        if !in_private_window(va) || !in_private_window(end - 1) {
            return Err(bad);
        }
        let mut cur = va;
        while cur < end {
            let off = cur % FRAME_SIZE;
            let n = (FRAME_SIZE - off).min(end - cur);
            let (f, flags) = p.space.translate(VirtPage::containing(cur)).ok_or(bad)?;
            if !flags.contains(MapFlags::USER) || (write && !flags.contains(MapFlags::WRITE)) {
                return Err(bad);
            }
            segs.push((f, off as u32, n as u32));
            cur += n;
        }
    }
    Ok(crate::mm::pin::PinnedRange::new(segs))
}

/// 向进程内存写入字节（经页表查询 + 物理映射；目标必须已映射）。用于装载代码与初始数据。
pub fn write(id: ObjId, va: u64, bytes: &[u8]) -> Result<(), ProcError> {
    with_proc(id, |p| {
        let mut done = 0usize;
        while done < bytes.len() {
            let cur = va + done as u64;
            let off = cur % FRAME_SIZE;
            let n = ((FRAME_SIZE - off) as usize).min(bytes.len() - done);
            let (f, _) = p.space.translate(VirtPage::containing(cur)).ok_or(ProcError::Map(MapError::NotMapped))?;
            let k = phys_to_virt(f.start() + off).ok_or(ProcError::Map(MapError::InvalidAddress))?;
            // SAFETY：目标帧属于该进程且已映射；n 不越过页尾。
            unsafe { core::ptr::copy_nonoverlapping(bytes[done..].as_ptr(), k, n) };
            done += n;
        }
        Ok(())
    })
}

/// 装载 ELF 失败的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// 文件本身不合法（见 `kernel_core::elf::ElfError`）。
    Elf(kernel_core::elf::ElfError),
    /// 某个段不在用户私有窗口内。
    OutsideWindow,
    /// 映射或复制失败。
    Proc(ProcError),
}

impl LoadError {
    /// 规范错误名。
    pub fn name(self) -> &'static str {
        match self {
            LoadError::Elf(e) => e.name(),
            LoadError::OutsideWindow => "system.memory.error.invalid_address",
            LoadError::Proc(_) => "system.memory.error.out_of_frames",
        }
    }
}

/// 把 ELF64 静态可执行文件装进进程，返回入口地址（按段权限映射，先清零再复制，BSS 天然为零）。
pub fn load_elf(id: ObjId, image: &[u8]) -> Result<u64, LoadError> {
    let elf = kernel_core::elf::parse(image, arch::ELF_MACHINE).map_err(LoadError::Elf)?;
    for seg in elf.segments() {
        // 解析器保证 memsz > 0 且页区间可表示；这里仍用检查式算术，任何溢出都按「窗口外」拒绝
        let (lo, hi) = seg.page_range().ok_or(LoadError::OutsideWindow)?;
        if !in_private_window(lo) || !in_private_window(hi - 1) {
            return Err(LoadError::OutsideWindow);
        }
    }
    for seg in elf.segments() {
        let mut flags = MapFlags::USER;
        if seg.flags.write {
            flags = flags | MapFlags::WRITE;
        }
        if seg.flags.execute {
            flags = flags | MapFlags::EXECUTE;
        }
        let (lo, hi) = seg.page_range().ok_or(LoadError::OutsideWindow)?;
        let mut va = lo;
        while va < hi {
            map_new(id, va, flags).map_err(LoadError::Proc)?;
            va += FRAME_SIZE;
        }
        write(id, seg.vaddr, seg.file_bytes(image)).map_err(LoadError::Proc)?;
    }
    Ok(elf.entry)
}

/// 读进程内存中的一个 64 位字（诊断与验收用）。
pub fn read_u64(id: ObjId, va: u64) -> Option<u64> {
    with_proc(id, |p| {
        let (f, _) = p.space.translate(VirtPage::containing(va)).ok_or(ProcError::Map(MapError::NotMapped))?;
        let k = phys_to_virt(f.start() + va % FRAME_SIZE).ok_or(ProcError::Map(MapError::InvalidAddress))?;
        // SAFETY：已映射的进程帧，调用者保证 8 字节对齐。
        Ok(unsafe { (k as *const u64).read_volatile() })
    })
    .ok()
}

/// 线程首次运行的入口：取出启动参数 → 切到进程空间与调用集合 → 进入用户态。
fn thread_entry() {
    let (me, _) = sched::current();
    let (start, member) = {
        let reg = REG.lock();
        (
            reg.starts.iter().find(|s| s.task == me).copied(),
            reg.members.iter().find(|m| m.task == me).copied(),
        )
    };
    let (Some(s), Some(m)) = (start, member) else {
        return;
    };
    let Ok((root, syscalls)) = with_proc(m.process, |p| Ok((p.space.root(), p.syscalls))) else {
        return;
    };
    sched::set_current_space(Some(root));
    sched::set_current_syscalls(syscalls);
    // SAFETY：entry/stack 已校验位于私有窗口，代码与栈页由创建方映射；内核栈顶由调度器设置。
    unsafe { arch::enter_user(s.entry, s.stack, s.arg0, s.arg1) }
}

/// 在进程中创建线程（入口与栈顶必须位于私有窗口内）。返回调度任务标识与 Task 对象标识。
///
/// Task 对象初始持有 2 个内部引用：线程执行上下文、进程线程表；执行上下文另持有 Process 的 1 个内部引用。
pub fn spawn_thread(
    id: ObjId,
    name: &'static str,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
) -> Result<(TaskId, ObjId), ProcError> {
    // 栈顶为 0 时 `stack - 1` 会下溢：用检查式算术，失败按非法地址拒绝
    let stack_last = stack.checked_sub(1).ok_or(ProcError::Map(MapError::InvalidAddress))?;
    if !in_private_window(entry) || !in_private_window(stack_last) {
        return Err(ProcError::Map(MapError::InvalidAddress));
    }
    with_proc(id, |p| if p.state == ProcState::Running { Ok(()) } else { Err(ProcError::Exited) })?;
    // 任务号用尽 ⇒ 拒绝（不回绕复用旧任务号）；此时尚未创建任何资源，无需回滚
    let task = TASK_IDS
        .allocate()
        .and_then(|n| n.checked_add(1000))
        .map(TaskId)
        .ok_or(ProcError::NoTaskSlot)?;
    let task_obj = kobj::with(|t| {
        let es = crate::exit_state::create_in(t).ok_or(ProcError::NoTaskSlot)?;
        match t.insert(KObject::Task(TaskObj { task, process: id, exit_state: es }), 0, 2) {
            Ok(obj) => Ok(obj),
            Err(_) => {
                let _ = t.release_internal(es); // 回滚：退出状态随之死亡
                Err(ProcError::NoTaskSlot)
            }
        }
    })?;
    {
        let mut reg = REG.lock();
        reg.starts.push(ThreadStart { task, entry, stack, arg0, arg1 });
        reg.members.push(Member { task, process: id, task_obj });
    }
    // 先完成全部记账（执行上下文 → Process、线程表 → Task），再交给调度器：
    // 否则新线程可能在记账完成前就运行并退出。
    // 先确认进程仍在运行，再取内部引用：两步在同一次对象表访问内完成，失败时不留下半份记账
    let accounted = kobj::with(|t| {
        match t.get_mut(id) {
            Ok(KObject::Process(p)) if p.state == ProcState::Running => {}
            Ok(KObject::Process(_)) => return Err(ProcError::Exited),
            _ => return Err(ProcError::NoSuchProcess),
        }
        t.acquire_internal(id).map_err(|_| ProcError::NoSuchProcess)?;
        if let Ok(KObject::Process(p)) = t.get_mut(id) {
            p.threads_live += 1;
            p.threads_total += 1;
            p.threads.push(task_obj);
        }
        Ok(())
    });
    let rollback = |reason: ProcError, accounted: bool| {
        {
            let mut reg = REG.lock();
            reg.starts.retain(|s| s.task != task);
            reg.members.retain(|m| m.task != task);
        }
        kobj::with(|t| {
            if accounted {
                if let Ok(KObject::Process(p)) = t.get_mut(id) {
                    p.threads_live -= 1;
                    p.threads_total -= 1;
                    p.threads.retain(|x| *x != task_obj);
                }
                let _ = t.release_internal(id);
            }
            let _ = t.release_internal(task_obj);
            let _ = t.release_internal(task_obj);
        });
        reason
    };
    if let Err(e) = accounted {
        return Err(rollback(e, false));
    }
    // 新线程与进程的其它线程同属一个 CPU 组。交给调度器之后再核对一次：设置上限与创建线程并发时，
    // 两边总有一边把新线程放进组里。
    let group = with_proc(id, |p| Ok(p.cpu_group)).ok().flatten();
    let spawned = match group {
        Some(g) => sched::spawn_in(task, name, thread_entry, g),
        None => sched::spawn(task, name, thread_entry),
    };
    if spawned.is_err() {
        return Err(rollback(ProcError::NoTaskSlot, true));
    }
    if let Some(g) = with_proc(id, |p| Ok(p.cpu_group)).ok().flatten() {
        let _ = sched::assign_cpu_group(task, Some(g));
    }
    kprintln!(
        "[JSR-PROC] event=system.task.spawned process={:#x} task={} task_obj={:#x} name={}",
        id.raw(),
        task.0,
        task_obj.raw(),
        name
    );
    Ok((task, task_obj))
}

/// 设置 CPU 上限失败的原因。失败时进程与调度器状态不变。
/// Why setting a process CPU limit was refused; nothing is changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuLimitError {
    /// 进程不存在或已不在运行。
    NoSuchProcess,
    /// 上限不在 `1..=1000` 千分比之内，或 CPU 组表已满。
    Refused(sched::scheduler::GroupError),
}

/// 设置进程 `pid` 的 CPU 上限（千分比，1000 = 不限）：进程的全部线程（现有的与以后创建的）合计
/// 在任意时间窗内最多运行约这个比例的 tick，超出即被限速——失控的进程拖不垮整机。
/// 由进程的创建方（管理者）调用；可重复调用以修改上限。
/// Sets the CPU limit of process `pid` (permille of the processor, shared by all its threads).
pub fn set_cpu_limit(pid: ObjId, limit_permille: u32) -> Result<(), CpuLimitError> {
    let existing = with_proc(pid, |p| if p.state == ProcState::Running { Ok(p.cpu_group) } else { Err(ProcError::Exited) })
        .map_err(|_| CpuLimitError::NoSuchProcess)?;
    if let Some(g) = existing {
        return sched::set_cpu_group_limit(g, limit_permille).map_err(CpuLimitError::Refused);
    }
    let g = sched::create_cpu_group(limit_permille).map_err(CpuLimitError::Refused)?;
    let stored = with_proc(pid, |p| {
        if p.state == ProcState::Running && p.cpu_group.is_none() {
            p.cpu_group = Some(g);
            Ok(())
        } else {
            Err(ProcError::Exited)
        }
    });
    if stored.is_err() {
        let _ = sched::release_cpu_group(g); // 回滚：组从未有成员，随之释放
        return Err(CpuLimitError::NoSuchProcess);
    }
    let tasks: Vec<TaskId> = REG.lock().members.iter().filter(|m| m.process == pid).map(|m| m.task).collect();
    for t in tasks {
        let _ = sched::assign_cpu_group(t, Some(g)); // 已退出的线程无需加入
    }
    Ok(())
}

/// 进程 `pid` 的 CPU 记账（设置过上限时有值；进程销毁后 `None`）。
pub fn cpu_stats(pid: ObjId) -> Option<sched::policy::CpuLimitStats> {
    let g = with_proc(pid, |p| Ok(p.cpu_group)).ok().flatten()?;
    sched::cpu_group_stats(g)
}

/// 当前任务所属的进程（内核任务为 `None`）。
pub fn current_process() -> Option<ObjId> {
    let (me, _) = sched::current();
    REG.lock().members.iter().find(|m| m.task == me).map(|m| m.process)
}

/// 取得一个**允许接收新句柄**的进程（存在且处于 Running）。
///
/// 进程进入 exited 时已经关闭并释放了整张句柄表；之后若再放入句柄，这些句柄持有的外部所有权
/// 将不再有任何路径释放（泄漏）。因此所有「向进程放入句柄」的入口都必须先经此检查，
/// 并且检查与放入发生在同一把对象表锁内（之间不存在进程退出的时间窗）。
/// Returns the process only if it may still receive handles (exists and is Running).
fn receiver<'a>(t: &'a mut kobj::Table, pid: ObjId) -> Result<&'a mut Process, ProcError> {
    match t.get_mut(pid) {
        Ok(KObject::Process(p)) if p.state == ProcState::Running => Ok(p),
        Ok(KObject::Process(_)) => Err(ProcError::Exited),
        _ => Err(ProcError::NoSuchProcess),
    }
}

/// 在当前进程的句柄表中放入一个指向 Task 对象的句柄（同时增加该对象的一个外部所有权）。
pub fn put_task_handle(task_obj: ObjId, rights: Rights) -> Result<HandleId, ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    kobj::with(|t| {
        receiver(t, pid)?; // 先确认可接收，再取所有权（失败路径无需回滚）
        t.acquire_owner(task_obj).map_err(|_| ProcError::Handle(HandleError::Invalid))?;
        let r = receiver(t, pid).and_then(|p| {
            p.handles
                .put(ObjectRef { id: ObjectId(task_obj.raw()), ty: ObjectType::Task }, rights)
                .map_err(ProcError::Handle)
        });
        if r.is_err() {
            let _ = kobj::release_owner_in(t, task_obj);
        }
        r
    })
}

/// 把一个已存在的对象发放给进程：增加一份外部所有权并放进其句柄表（全有或全无）。
/// 接收进程已退出 ⇒ [`ProcError::Exited`]，对象引用计数不变。
pub fn grant(pid: ObjId, obj: ObjId, ty: ObjectType, rights: Rights) -> Result<HandleId, ProcError> {
    kobj::with(|t| {
        let room = receiver(t, pid)?.handles.free_slots();
        if room == 0 {
            return Err(ProcError::Handle(HandleError::TableFull));
        }
        t.acquire_owner(obj).map_err(|_| ProcError::Handle(HandleError::Invalid))?;
        // 已确认可接收且有空位：以下 put 不会失败；仍保留回滚以防御未来的修改。
        let r = receiver(t, pid)
            .and_then(|p| p.handles.put(ObjectRef { id: ObjectId(obj.raw()), ty }, rights).map_err(ProcError::Handle));
        if r.is_err() {
            let _ = kobj::release_owner_in(t, obj);
        }
        r
    })
}

/// 新建一个对象并直接发放给进程（对象的唯一外部所有权就是这个句柄）。
///
/// 「检查接收方 → 建对象 → 放句柄」在同一把锁内完成：接收方已退出或句柄表已满时**根本不创建对象**，
/// 因此失败路径上不存在需要回收的新对象。
/// Creates an object and hands it to `pid` atomically; on failure no object is created.
pub fn grant_new(pid: ObjId, obj: KObject, ty: ObjectType, rights: Rights) -> Result<HandleId, ProcError> {
    kobj::with(|t| grant_new_in(t, pid, obj, ty, rights).map(|(h, _)| h))
}

/// [`grant_new`] 的锁内版本：调用者已持有对象表锁（可与自己的配额检查合成一个原子步骤）。
/// 返回（新句柄, 新对象标识）。
/// In-lock variant of [`grant_new`]; returns the handle and the new object's id.
pub(crate) fn grant_new_in(
    t: &mut kobj::Table,
    pid: ObjId,
    obj: KObject,
    ty: ObjectType,
    rights: Rights,
) -> Result<(HandleId, ObjId), ProcError> {
    if receiver(t, pid)?.handles.free_slots() == 0 {
        return Err(ProcError::Handle(HandleError::TableFull));
    }
    let id = t.insert(obj, 1, 0).map_err(|_| ProcError::NoTaskSlot)?;
    let r = receiver(t, pid)
        .and_then(|p| p.handles.put(ObjectRef { id: ObjectId(id.raw()), ty }, rights).map_err(ProcError::Handle));
    match r {
        Ok(h) => Ok((h, id)),
        Err(e) => {
            let _ = kobj::release_owner_in(t, id); // 防御：对象随即死亡入队，由清理过程销毁
            Err(e)
        }
    }
}

/// 在锁内把进程 `pid` 的句柄 `h` 解析为对象标识：类型须为 `ty`，且句柄权限须包含 `need`。
/// 进程须仍在运行（已退出的进程句柄表已关闭）。
/// Resolves a handle of `pid` to an object id, checking its type and rights.
pub(crate) fn resolve_in(t: &mut kobj::Table, pid: ObjId, h: HandleId, ty: ObjectType, need: Rights) -> Result<ObjId, ProcError> {
    let p = receiver(t, pid)?;
    let (r, have) = p.handles.get(h).map_err(ProcError::Handle)?;
    if r.ty != ty {
        return Err(ProcError::Handle(HandleError::Invalid));
    }
    if !have.contains(need) {
        return Err(ProcError::Handle(HandleError::RightsDenied));
    }
    ObjId::from_raw(r.id.0).ok_or(ProcError::Handle(HandleError::Invalid))
}

/// 在锁内读取进程 `pid` 的句柄 `h`（对象引用与权限）。进程须仍在运行。
pub(crate) fn handle_in(t: &mut kobj::Table, pid: ObjId, h: HandleId) -> Result<(ObjectRef, Rights), ProcError> {
    let p = receiver(t, pid)?;
    p.handles.get(h).map(|(r, x)| (*r, x)).map_err(ProcError::Handle)
}

/// 在锁内从进程 `pid` 的句柄表移出句柄 `h`，返回其对象标识；**不释放**它持有的外部所有权
/// （所有权随句柄转给调用者，例如放进消息）。
pub(crate) fn take_handle_in(t: &mut kobj::Table, pid: ObjId, h: HandleId) -> Result<ObjId, ProcError> {
    let p = receiver(t, pid)?;
    let r = p.handles.remove(h).map_err(ProcError::Handle)?;
    ObjId::from_raw(r.id.0).ok_or(ProcError::Handle(HandleError::Invalid))
}

/// 在锁内把一份已持有的外部所有权作为新句柄放进进程 `pid` 的句柄表（不再增加计数）。
pub(crate) fn put_handle_in(t: &mut kobj::Table, pid: ObjId, r: ObjectRef, rights: Rights) -> Result<HandleId, ProcError> {
    receiver(t, pid)?.handles.put(r, rights).map_err(ProcError::Handle)
}

/// 在锁内查询进程 `pid` 句柄表的空位数（进程不在运行时为 0）。
pub(crate) fn free_slots_in(t: &mut kobj::Table, pid: ObjId) -> usize {
    receiver(t, pid).map(|p| p.handles.free_slots()).unwrap_or(0)
}

/// 在锁内取进程的异步环配额记账（进程已退出也可取，用于收尾时归还；进程已销毁返回 `None`）。
pub(crate) fn ring_quota_in(t: &mut kobj::Table, pid: ObjId) -> Option<&mut ResourceQuota> {
    match t.get_mut(pid) {
        Ok(KObject::Process(p)) => Some(&mut p.ring_quota),
        _ => None,
    }
}

/// 在锁内取进程可用的系统调用集合（进程须仍在运行）。
pub(crate) fn syscalls_in(t: &mut kobj::Table, pid: ObjId) -> Result<SyscallSet, ProcError> {
    receiver(t, pid).map(|p| p.syscalls)
}

/// 进程的异步环配额记账（诊断与验收用）。
pub fn ring_quota(pid: ObjId) -> Option<ResourceQuota> {
    kobj::with(|t| ring_quota_in(t, pid).copied())
}

/// 进程 `pid` 中句柄 `h` 的（对象, 权限）；无效返回 `None`（诊断与验收用）。
pub fn handle_info(pid: ObjId, h: HandleId) -> Option<(ObjectRef, Rights)> {
    with_proc(pid, |p| p.handles.get(h).map(|(r, rights)| (*r, rights)).map_err(ProcError::Handle)).ok()
}

/// 进程 `pid` 的句柄表还能容纳的句柄数。
pub fn free_handle_slots(pid: ObjId) -> usize {
    with_proc(pid, |p| Ok(p.handles.free_slots())).unwrap_or(0)
}

/// 复制当前进程中的句柄，新句柄权限为 `rights`：原句柄须带 `DUPLICATE`，且 `rights` ⊆ 原权限（只可降权）。
/// 新句柄是同一对象的又一份外部所有权。
pub fn duplicate_current(h: HandleId, rights: Rights) -> Result<HandleId, ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    kobj::with(|t| {
        let (r, have) = match t.get(pid) {
            Ok(KObject::Process(p)) => p.handles.get(h).map(|(r, x)| (*r, x)).map_err(ProcError::Handle)?,
            _ => return Err(ProcError::NoSuchProcess),
        };
        if !have.contains(Rights::DUPLICATE) || !have.contains(rights) {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        let obj = ObjId::from_raw(r.id.0).ok_or(ProcError::Handle(HandleError::Invalid))?;
        receiver(t, pid)?;
        t.acquire_owner(obj).map_err(|_| ProcError::Handle(HandleError::Invalid))?;
        let put = receiver(t, pid).and_then(|p| p.handles.put(r, rights).map_err(ProcError::Handle));
        if put.is_err() {
            let _ = kobj::release_owner_in(t, obj);
        }
        put
    })
}

/// 原地降低当前进程中句柄的权限（只减不增）。
pub fn restrict_current(h: HandleId, rights: Rights) -> Result<(), ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    with_proc(pid, |p| p.handles.reduce_rights(h, rights).map_err(ProcError::Handle))
}

/// **原子**地把进程 `from` 的句柄 `h` 移到进程 `to`（M4.0 规范 v0.6 §3.2 的转移原语；M4.4 的 send/recv 建立在它之上）。
///
/// 在同一把对象表锁内：先检查（句柄有效、带 `TRANSFER`、对象是 v1 叶子、接收方句柄表有空位），
/// 全部通过后才「从 from 移出 → 放进 to」。检查之后不存在可失败的步骤，因此失败时发送方句柄表原样不变；
/// 成功时外部所有权总数不变（从 from 的句柄转为 to 的句柄），发送方旧句柄值永久失效。
pub fn transfer(from: ObjId, h: HandleId, to: ObjId) -> Result<HandleId, ProcError> {
    kobj::with(|t| {
        let (r, rights) = match t.get(from) {
            Ok(KObject::Process(p)) => p.handles.get(h).map(|(r, x)| (*r, x)).map_err(ProcError::Handle)?,
            _ => return Err(ProcError::NoSuchProcess),
        };
        if !rights.contains(Rights::TRANSFER) {
            return Err(ProcError::Handle(HandleError::RightsDenied));
        }
        if !r.ty.is_transferable_v1() {
            return Err(ProcError::NotTransferable);
        }
        // 接收方必须仍可接收句柄（Running），且句柄表有空位
        if receiver(t, to)?.handles.free_slots() == 0 {
            return Err(ProcError::Handle(HandleError::TableFull));
        }
        // —— 提交：以下步骤在检查通过后不会失败 ——
        if let Ok(KObject::Process(p)) = t.get_mut(from) {
            p.handles.remove(h).map_err(ProcError::Handle)?;
        }
        match t.get_mut(to) {
            Ok(KObject::Process(p)) => p.handles.put(r, rights).map_err(ProcError::Handle),
            _ => Err(ProcError::NoSuchProcess),
        }
    })
}

/// 进程的线程计数 `(存活, 累计创建)`（诊断与回滚验收用）。
/// Live and total thread counts of a process (diagnostics).
pub fn thread_counts(pid: ObjId) -> Option<(u32, u32)> {
    kobj::with(|t| match t.get(pid) {
        Ok(KObject::Process(p)) => Some((p.threads_live, p.threads_total)),
        _ => None,
    })
}

/// 线程登记表中的条目数 `(待启动, 运行身份)`（诊断与回滚验收用）。
/// Number of entries in the thread registry (diagnostics).
pub fn registry_len() -> (usize, usize) {
    let reg = REG.lock();
    (reg.starts.len(), reg.members.len())
}

/// 让一个没有线程的进程进入 exited（关闭其句柄表）；有线程存活时不做任何事并返回 `false`。
pub fn exit_idle(pid: ObjId, code: i64) -> bool {
    kobj::with(|t| {
        let ok = matches!(t.get(pid), Ok(KObject::Process(p)) if p.threads_live == 0 && p.state == ProcState::Running);
        if ok {
            release_resources_in(t, pid);
            finish_exit_in(t, pid, code);
        }
        ok
    })
}

/// 关闭进程的句柄表并释放其子进程表（exiting 或 exited 时；只做一次，之后两表为空）。返回关闭的句柄数。
fn release_resources_in(t: &mut kobj::Table, pid: ObjId) -> usize {
    let mut closed: Vec<ObjectRef> = Vec::new();
    let mut children = Vec::new();
    let n = match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            children = core::mem::take(&mut p.children);
            p.handles.close_all(|r| closed.push(r))
        }
        _ => 0,
    };
    for r in closed {
        if let Some(id) = ObjId::from_raw(r.id.0) {
            let _ = kobj::release_owner_in(t, id);
        }
    }
    for c in children {
        let _ = t.release_internal(c);
    }
    n
}

/// 进入 exited：确定退出码、写入退出状态并通知等待者（wait 在此刻完成，而不是 exiting 时）。
fn finish_exit_in(t: &mut kobj::Table, pid: ObjId, code: i64) {
    let es = match t.get_mut(pid) {
        Ok(KObject::Process(p)) => {
            p.state = ProcState::Exited { code };
            p.exit_state
        }
        _ => return,
    };
    crate::exit_state::notify_in(t, es, code);
}

/// 发起进程终止（exiting）：确定退出码，关闭句柄表与子进程表（其后的提交原子失败）；
/// 其余线程在各自的下一个调度点停止，最后一个线程停止时进入 exited。没有线程的进程直接进入 exited。
/// 进程不在运行（已在退出）时返回 `false`。
/// 开始终止后唤醒该进程所有在睡的线程：长时间的定时等待（`time.wait`）也要尽快观察到 exiting。
/// Begins process termination (exiting phase).
pub fn begin_exit(pid: ObjId, code: i64) -> bool {
    let started = begin_exit_in_table(pid, code);
    if started {
        wake_threads(pid);
    }
    started
}

/// 唤醒进程 `pid` 的全部睡眠线程（不在睡眠的线程不受影响）。调度器不持锁，可在登记表锁内调用。
fn wake_threads(pid: ObjId) {
    let reg = REG.lock();
    for m in reg.members.iter().filter(|m| m.process == pid) {
        sched::wake(m.task);
    }
}

/// [`begin_exit`] 的对象表部分：状态迁移、关闭句柄表、无线程时直接进入 exited。
fn begin_exit_in_table(pid: ObjId, code: i64) -> bool {
    kobj::with(|t| {
        let idle = match t.get_mut(pid) {
            Ok(KObject::Process(p)) if p.state == ProcState::Running => {
                p.state = ProcState::Exiting { code };
                p.threads_live == 0
            }
            _ => return false,
        };
        let n = release_resources_in(t, pid);
        kprintln!("[JSR-PROC] event=system.process.exiting id={:#x} code={} handles_closed={}", pid.raw(), code, n);
        if idle {
            finish_exit_in(t, pid, code);
        }
        true
    })
}

/// 当前线程所属进程是否处于 exiting（调度点据此停止该线程）。
pub fn current_exiting() -> bool {
    let Some(pid) = current_process() else { return false };
    kobj::with(|t| matches!(t.get(pid), Ok(KObject::Process(p)) if matches!(p.state, ProcState::Exiting { .. })))
}

/// 阻塞等待被进程终止打断（[`block_step`] 的错误）。
/// The blocking wait was interrupted because the owning process is exiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupted;

/// 系统调用内阻塞等待的一步：让出处理器并休眠到下一个中断，醒来后检查所属进程是否已在 exiting。
///
/// 为什么需要它：线程停在内核里等待时不会经过「系统调用入口 / 从用户态被中断」这两个调度点，
/// 若等待循环只检查自己的完成条件，`process.exit` 或故障终止就无法让它停止，进程停留在 exiting、资源不回收。
/// 返回 [`Interrupted`] 时，调用者须**先释放本次等待持有的全部资源**（内部引用、固定、等待登记），
/// 再以错误返回；系统调用出口会随后经线程退出路径停止该线程（返回值不会到达用户态）。
/// One step of an in-kernel blocking wait that also observes process termination.
pub fn block_step() -> Result<(), Interrupted> {
    sched::pause();
    if current_exiting() {
        Err(Interrupted)
    } else {
        Ok(())
    }
}

/// 系统调用内的定时等待：睡眠到时刻 `deadline`（tick，期间不占用处理器），醒来后检查所属进程是否已在 exiting。
/// 进程开始终止时睡眠线程会被提前唤醒，因此长时间的等待也能及时以 [`Interrupted`] 返回。
/// 返回 `Ok(())` 只表示醒来且进程仍在运行，调用者须自行确认时刻已到（可能被提前唤醒）。
/// A timed in-kernel wait that also observes process termination.
pub fn block_until(deadline: u64) -> Result<(), Interrupted> {
    sched::sleep_until(deadline);
    if current_exiting() {
        Err(Interrupted)
    } else {
        Ok(())
    }
}

/// 父进程收养子进程：子进程表取得子进程的一个内部引用（父 → 子单向）。父进程须仍在运行。
pub fn adopt(parent: ObjId, child: ObjId) -> Result<(), ProcError> {
    kobj::with(|t| {
        receiver(t, parent)?;
        t.acquire_internal(child).map_err(|_| ProcError::NoSuchProcess)?;
        if let Ok(KObject::Process(p)) = t.get_mut(parent) {
            p.children.push(child);
        }
        Ok(())
    })
}

/// 父进程从子进程表释放一个子进程（例如回收它之后）。不在表中返回 `false`。
pub fn release_child(parent: ObjId, child: ObjId) -> bool {
    kobj::with(|t| {
        let found = match t.get_mut(parent) {
            Ok(KObject::Process(p)) => match p.children.iter().position(|c| *c == child) {
                Some(i) => {
                    p.children.swap_remove(i);
                    true
                }
                None => false,
            },
            _ => false,
        };
        if found {
            let _ = t.release_internal(child);
        }
        found
    })
}

/// 进程句柄 / 线程句柄所指对象的退出状态（锁内）：句柄须带 WAIT。取得退出状态的一个内部引用后返回。
pub(crate) fn acquire_exit_state_in(t: &mut kobj::Table, pid: ObjId, h: HandleId, ty: ObjectType) -> Result<ObjId, ProcError> {
    let obj = resolve_in(t, pid, h, ty, Rights::WAIT)?;
    let es = match t.get(obj) {
        Ok(KObject::Process(p)) => p.exit_state,
        Ok(KObject::Task(task)) => task.exit_state,
        _ => return Err(ProcError::Handle(HandleError::Invalid)),
    };
    t.acquire_internal(es).map_err(|_| ProcError::Handle(HandleError::Invalid))?;
    Ok(es)
}

/// 关闭当前进程中的一个句柄：移出句柄表并释放它持有的那份外部所有权（INV-01：不等于销毁对象）。
pub fn close_handle(h: HandleId) -> Result<(), ProcError> {
    let pid = current_process().ok_or(ProcError::NoSuchProcess)?;
    kobj::with(|t| {
        let obj = match t.get_mut(pid) {
            Ok(KObject::Process(p)) => p.handles.remove(h).map_err(ProcError::Handle)?,
            _ => return Err(ProcError::NoSuchProcess),
        };
        if let Some(id) = ObjId::from_raw(obj.id.0) {
            let _ = kobj::release_owner_in(t, id);
        }
        Ok(())
    })
}

/// 线程退出（正常退出或故障终止的唯一出口；永不返回）：进程记账、释放执行上下文的内部引用后结束任务。
///
/// 最后一个线程停止 ⇒ 进程进入 exited：确定退出码并**关闭整张句柄表**（释放各句柄的外部所有权）。
/// 这里只做计数与入队；任何销毁动作都留给清理过程（这条路径可能处在中断上下文）。
pub fn thread_exit(code: i64, cause: &'static str) -> ! {
    let (me, _) = sched::current();
    let member = {
        let mut reg = REG.lock();
        let m = reg.members.iter().find(|m| m.task == me).copied();
        reg.starts.retain(|s| s.task != me);
        reg.members.retain(|m| m.task != me);
        m
    };
    if let Some(m) = member {
        let exited = kobj::with(|t| {
            // 线程自己的退出状态：写入本线程的退出码
            if let Ok(KObject::Task(task)) = t.get(m.task_obj) {
                let es = task.exit_state;
                crate::exit_state::notify_in(t, es, code);
            }
            let mut out = None;
            let last = match t.get_mut(m.process) {
                Ok(KObject::Process(p)) => {
                    p.threads_live = p.threads_live.saturating_sub(1);
                    // exiting 中的进程以发起终止时确定的退出码结束
                    let final_code = match p.state {
                        ProcState::Exiting { code: c } => c,
                        _ => code,
                    };
                    (p.threads_live == 0).then_some((final_code, p.name, p.threads_total))
                }
                _ => None,
            };
            if let Some((final_code, name, threads)) = last {
                let n = release_resources_in(t, m.process);
                finish_exit_in(t, m.process, final_code);
                out = Some((name, threads, n, final_code));
            }
            let _ = t.release_internal(m.task_obj); // 执行上下文 → Task
            let _ = t.release_internal(m.process); // 执行上下文 → Process
            out
        });
        if let Some((name, threads, handles, code)) = exited {
            kprintln!(
                "[JSR-PROC] event=system.process.exited id={:#x} name={} code={} threads={} handles_closed={}",
                m.process.raw(),
                name,
                code,
                threads,
                handles
            );
        }
    }
    sched::exit_current(cause)
}

/// 进程状态（已死亡或已销毁返回 `None`）。
pub fn state(id: ObjId) -> Option<ProcState> {
    with_proc(id, |p| Ok(p.state)).ok()
}

/// 创建者回收已退出的进程：读取退出信息并**释放创建者持有的外部所有权**。未退出返回 `None`。
///
/// 进程对象在全部强引用释放后才被清理过程销毁（[`destroy`]）；调用者需要立即回收资源时调用 `kobj::run_cleanup`。
pub fn reap(id: ObjId) -> Option<ExitInfo> {
    let info = kobj::with(|t| {
        let info = match t.get(id) {
            Ok(KObject::Process(p)) => match p.state {
                ProcState::Exited { code } => ExitInfo { code, threads: p.threads_total, frames: p.frames.len() },
                ProcState::Running | ProcState::Exiting { .. } => return None,
            },
            _ => return None,
        };
        kobj::release_owner_in(t, id).ok()?;
        Some(info)
    })?;
    kprintln!(
        "[JSR-PROC] event=system.process.reaped id={:#x} frames={} threads={} code={}",
        id.raw(),
        info.frames,
        info.threads,
        info.code
    );
    Some(info)
}

/// 进程对象的销毁动作（只由清理过程调用，不持对象表锁）：销毁地址空间、归还帧、释放线程表引用（级联）。
///
/// 正常路径上句柄表在 exited 时已被关闭；这里**不依赖该假设**：仍有残余句柄则逐个释放其外部所有权，
/// 并输出诊断标记（出现即说明某条路径漏了检查）。
pub fn destroy(p: Box<Process>) {
    let Process { space, frames, threads, mut handles, name, exit_state, children, cpu_group, .. } = *p;
    if let Some(g) = cpu_group {
        let _ = sched::release_cpu_group(g); // 持有者引用；线程早已全部退出，组随之释放
    }
    let mut residual: Vec<ObjectRef> = Vec::new();
    let n = handles.close_all(|r| residual.push(r));
    if n > 0 {
        kprintln!("[JSR-LIFE] warning residual_handles={} process={}", n, name);
    }
    for r in residual {
        if let Some(id) = ObjId::from_raw(r.id.0) {
            let _ = kobj::release_owner(id);
        }
    }
    drop(handles);
    drop(space); // 先销毁地址空间（回收私有页表帧），再归还数据帧
    for f in frames {
        crate::mm::pin::release(f); // 仍被在飞请求固定的帧延后到最后一次解除固定时归还
    }
    for t in threads {
        let _ = kobj::release_internal(t); // 线程表 → Task；可能使 Task 死亡并入队（下一轮清理）
    }
    for c in children {
        let _ = kobj::release_internal(c); // 防御：子进程表正常应已在退出时释放
    }
    let _ = kobj::release_internal(exit_state); // 进程 → 退出状态（在飞 wait 仍可持有它）
}
