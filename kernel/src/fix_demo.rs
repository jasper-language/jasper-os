//! 基础设施修复的回归演练：在真机（QEMU）上逐一触发此前未被覆盖的**失败路径**，并验证回滚后资源回到基线。
//! Regression drill for infrastructure fixes: exercises failure paths on real hardware and checks rollback.
//!
//! # 覆盖
//! 1. 向已退出 / 已回收的进程发放或转移句柄被拒，且不创建对象、不改变所有权计数
//! 2. 内核堆扩容在「分配帧」或「建立映射」中途失败 ⇒ 整体回滚（帧数、映射、堆容量都不变），之后可再次扩容
//! 3. 内核共享部分的顶级表预分配「全有或全无」：失败时临时顶级表一项未改、帧全部归还；准备失败的状态会拒绝创建地址空间
//! 4. 用户指针查询走只读翻译：结果与地址空间自身的映射器一致，内核地址不带「用户可访问」
//! 5. ID 分配器用尽后拒绝，不回绕
//! 6. 线程创建在「栈顶为 0」「对象表满」「调度器槽位满」时失败，线程登记、对象、内部引用全部恢复；腾出资源后再次创建成功
//!
//! 每项打印 `[JSR-FIX]` 标记并当场断言；最后输出 `checks=<n> failed=<m>`，验收要求 `failed=0`。
//!
//! # 边界
//! 与 `user_demo` 相同：是机制的「客户」，删掉本文件与 `kmain` 中的一行调用不影响机制本身。不含 ISA 代码。

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;
use kernel_core::frame::{FrameAllocator, FrameError, PhysFrame, FRAME_SIZE};
use kernel_core::heap::LinkedListHeap;
use kernel_core::object::{IdAllocator, ObjectType, Rights};
use kernel_core::objtable::ObjId;
use kernel_core::paging::{MapError, MapFlags, VirtPage};

use crate::arch::{self, UserProbe};
use crate::kobj::{self, KObject};
use crate::mm::heap::{self, GrowEnv, GrowError, KernelGrowEnv};
use crate::mm::map;
use crate::mm::space::{self, VmSpace};
use crate::mm::frame;
use crate::proc::{self, ProcError, ProcState};
use crate::syscall::{table as abi, SyscallSet};
use crate::task::TaskId;
use crate::{boot, kprintln, sched};

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

/// 断言：失败时打印 `[JSR-FIX-FAIL]` 而不是 panic，让后续用例继续运行。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-FIX-FAIL] {}", what);
    }
}

/// 失败断言数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 用户程序布局（与其他演练一致：代码、数据、栈各占私有窗口内的一页）。
const CODE_OFF: u64 = 0x40_0000;
const DATA_OFF: u64 = 0x80_0000;
const STACK_OFF: u64 = 0xC0_0000;

/// 运行全部回归演练。
pub fn run() {
    // 页帧基线由各用例在自己的范围内检查（演练窗口会保留中间页表、全局堆只增不缩，整体帧数不作为判据）
    let (live0, _, _) = kobj::stats();
    exited_receiver();
    heap_rollback();
    kernel_space_prepare();
    readonly_translate();
    id_exhaustion();
    spawn_rollback();
    kobj::run_cleanup(usize::MAX);
    let (live1, pending1, _) = kobj::stats();
    check(live1 == live0 && pending1 == 0, "回归演练结束后对象未回到基线");
    kprintln!(
        "[JSR-FIX] objects_live={}/{} pending={} checks={} failed={}",
        live1,
        live0,
        pending1,
        CHECKS.load(Ordering::Relaxed),
        failed()
    );
}

/// 1. 接收方已退出 / 已回收：grant、grant_new、transfer 一律被拒，不创建对象、不改所有权、发送方句柄保留。
fn exited_receiver() {
    let (Ok(a), Ok(x)) = (proc::create("fix-sender", SyscallSet::EMPTY), proc::create("fix-exited", SyscallSet::EMPTY)) else {
        check(false, "演练进程创建失败");
        return;
    };
    let Ok(h) = proc::grant_new(a, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT.union(Rights::TRANSFER)) else {
        check(false, "发放句柄失败");
        return;
    };
    check(proc::exit_idle(x, 0), "无线程进程未能退出");
    let owners = |id: ObjId| kobj::with(|t| t.counts(id)).ok().map(|c| c.0);
    let (live_before, _, _) = kobj::stats();
    let a_owners = owners(a);
    let grant = proc::grant(x, a, ObjectType::Process, Rights::WAIT);
    let grant_new = proc::grant_new(x, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT);
    let xfer = proc::transfer(a, h, x);
    let (live_after, _, _) = kobj::stats();
    let exited_ok = grant == Err(ProcError::Exited)
        && grant_new == Err(ProcError::Exited)
        && xfer == Err(ProcError::Exited)
        && live_after == live_before
        && owners(a) == a_owners
        && proc::handle_info(a, h).is_some();
    check(exited_ok, "向已退出进程发放/转移句柄应被拒且无副作用");
    proc::reap(x);
    kobj::run_cleanup(usize::MAX);
    let reaped = proc::grant_new(x, KObject::Event { signaled: false }, ObjectType::Event, Rights::WAIT);
    let xfer2 = proc::transfer(a, h, x);
    let reaped_ok = reaped == Err(ProcError::NoSuchProcess) && xfer2 == Err(ProcError::NoSuchProcess) && proc::handle_info(a, h).is_some();
    check(reaped_ok, "向已回收进程发放/转移句柄应被拒");
    kprintln!(
        "[JSR-FIX] exited_receiver grant={:?} grant_new={:?} transfer={:?} objects_unchanged={} sender_kept={} reaped_receiver={:?}",
        grant.err(),
        grant_new.err(),
        xfer.err(),
        live_after == live_before,
        proc::handle_info(a, h).is_some(),
        reaped.err()
    );
    check(proc::exit_idle(a, 0), "发送方进程未能退出");
    proc::reap(a);
    kobj::run_cleanup(usize::MAX);
}

/// 可注入失败的扩容环境：第 `fail_alloc` 次分配或第 `fail_map` 次映射失败（从 1 计），其余转给真实环境。
struct FaultyGrow {
    allocs: usize,
    maps: usize,
    fail_alloc: usize,
    fail_map: usize,
}

impl GrowEnv for FaultyGrow {
    fn alloc(&mut self) -> Result<PhysFrame, GrowError> {
        self.allocs += 1;
        if self.allocs == self.fail_alloc {
            return Err(GrowError::OutOfFrames);
        }
        KernelGrowEnv.alloc()
    }
    fn map(&mut self, page: VirtPage, f: PhysFrame) -> Result<(), GrowError> {
        self.maps += 1;
        if self.maps == self.fail_map {
            return Err(GrowError::MapFailed);
        }
        KernelGrowEnv.map(page, f)
    }
    fn unmap(&mut self, page: VirtPage) -> Option<PhysFrame> {
        KernelGrowEnv.unmap(page)
    }
    fn free(&mut self, f: PhysFrame) {
        KernelGrowEnv.free(f)
    }
}

/// 拆掉演练窗口 `[start, end)` 内的全部映射并归还帧。
fn teardown(start: u64, end: u64) {
    let mut va = start;
    while va < end {
        if let Ok(f) = map::unmap(VirtPage::containing(va)) {
            let _ = frame::deallocate(f);
        }
        va += FRAME_SIZE;
    }
}

/// 堆回滚演练每次扩容的字节数：至少 16 页（让注入的第 5 次分配、第 3 次映射失败一定落在扩容中途），
/// 且不小于配置档的堆增长步长（扩容至少按步长进行）。
const DRILL_GROW: u64 = if heap::GROW_STEP > 16 * FRAME_SIZE { heap::GROW_STEP } else { 16 * FRAME_SIZE };

/// 2. 内核堆扩容中途失败的回滚。使用独立的演练堆与紧邻真实堆的演练窗口，不影响全局分配器。
fn heap_rollback() {
    let start = heap::HEAP_START + heap::HEAP_MAX;
    let window_end = start + 1024 * 1024;
    let mut h = LinkedListHeap::empty();
    let mut end = start;
    // 预热：第一次扩容会建立中间页表（之后保留复用），先做一次成功扩容 + 拆除，再取基线
    let warm = heap::grow_in(&mut h, &mut end, window_end, heap::GROW_STEP, &mut KernelGrowEnv);
    teardown(start, end);
    let mut h = LinkedListHeap::empty();
    let mut end = start;
    let base = frame::free_frames();

    let mut env = FaultyGrow { allocs: 0, maps: 0, fail_alloc: 5, fail_map: 0 };
    let r1 = heap::grow_in(&mut h, &mut end, window_end, DRILL_GROW, &mut env);
    let after1 = (end == start, h.total_bytes() == 0, frame::free_frames() == base, map::translate(VirtPage::containing(start)).is_none());
    let mut env = FaultyGrow { allocs: 0, maps: 0, fail_alloc: 0, fail_map: 3 };
    let r2 = heap::grow_in(&mut h, &mut end, window_end, DRILL_GROW, &mut env);
    let after2 = (end == start, h.total_bytes() == 0, frame::free_frames() == base, map::translate(VirtPage::containing(start)).is_none());
    let overflow = heap::grow_in(&mut h, &mut end, window_end, u64::MAX, &mut KernelGrowEnv);
    let beyond = heap::grow_in(&mut h, &mut end, window_end, 2 * 1024 * 1024, &mut KernelGrowEnv);
    let ok = heap::grow_in(&mut h, &mut end, window_end, DRILL_GROW, &mut KernelGrowEnv);
    let grown = ok == Ok(DRILL_GROW) && end == start + DRILL_GROW && h.total_bytes() as u64 == DRILL_GROW;
    // SAFETY：演练堆管理的区间刚映射为可写、只由本函数使用；释放的指针正是刚分配的那块。
    let p = unsafe { h.allocate(64, 8) };
    let usable = !p.is_null();
    if usable {
        unsafe { h.deallocate(p, 64) };
    }
    teardown(start, end);
    let back = frame::free_frames() == base;

    check(warm.is_ok(), "演练堆预热扩容失败");
    check(r1 == Err(GrowError::OutOfFrames) && after1 == (true, true, true, true), "分配帧中途失败后未完整回滚");
    check(r2 == Err(GrowError::MapFailed) && after2 == (true, true, true, true), "映射中途失败后未完整回滚");
    check(overflow == Err(GrowError::LimitReached) && beyond == Err(GrowError::LimitReached), "容量溢出或越界未被拒绝");
    check(grown && usable, "回滚后再次扩容失败");
    check(back, "演练堆拆除后页帧未回到基线");
    kprintln!(
        "[JSR-FIX] heap fail_alloc={:?} rolled_back={} fail_map={:?} rolled_back={} overflow={:?} regrow={} reclaimed={}",
        r1.err(),
        after1 == (true, true, true, true),
        r2.err(),
        after2 == (true, true, true, true),
        overflow.err(),
        grown && usable,
        back
    );
}

/// 记录式页帧分配器：转给全局页帧服务，记下尚未归还的帧；`limit` 次分配之后一律失败。
struct CountedFrames {
    limit: usize,
    held: Vec<PhysFrame>,
}

impl FrameAllocator for CountedFrames {
    fn allocate(&mut self) -> Result<PhysFrame, FrameError> {
        if self.limit == 0 {
            return Err(FrameError::OutOfFrames);
        }
        self.limit -= 1;
        let f = frame::allocate()?;
        self.held.push(f);
        Ok(f)
    }
    fn deallocate(&mut self, f: PhysFrame) -> Result<(), FrameError> {
        self.held.retain(|x| *x != f);
        frame::deallocate(f)
    }
    fn free_frames(&self) -> usize {
        frame::free_frames()
    }
    fn usable_frames(&self) -> usize {
        frame::free_frames()
    }
}

/// 3. 内核共享部分预分配：在临时顶级表上演练失败与成功路径；准备失败状态拒绝创建地址空间。
fn kernel_space_prepare() {
    let Some(off) = boot::get().and_then(|b| b.phys_offset) else {
        check(false, "没有物理内存映射偏移");
        return;
    };
    let real_ready = space::init();
    let real_used = unsafe { arch::kernel_part_used(arch::current_space(), off) };
    // 记录用的向量先预留容量：避免演练中途全局堆扩容消耗页帧、干扰帧数比较
    let mut failing = CountedFrames { limit: 100, held: Vec::with_capacity(512) };
    let mut ok_alloc = CountedFrames { limit: usize::MAX, held: Vec::with_capacity(512) };
    let base = frame::free_frames();
    let Ok(scratch) = frame::allocate() else {
        check(false, "无法分配临时顶级表");
        return;
    };
    // SAFETY：scratch 刚分出、由本函数独占，从不被激活。
    let root = unsafe { arch::empty_space_root(scratch, off) };
    // SAFETY：root 是有效的（全空）顶级表，不是活动空间。
    let r_fail = unsafe { arch::prepare_kernel_space(root, off, &mut failing) };
    let untouched = unsafe { arch::kernel_part_used(root, off) } == 0;
    let returned = failing.held.is_empty() && frame::free_frames() == base - 1;
    let r_ok = unsafe { arch::prepare_kernel_space(root, off, &mut ok_alloc) };
    let filled = unsafe { arch::kernel_part_used(root, off) };
    for f in ok_alloc.held.drain(..) {
        let _ = frame::deallocate(f);
    }
    let _ = frame::deallocate(scratch);
    let back = frame::free_frames() == base;
    let refused = space::ready_from(Err(MapError::OutOfFrames));
    let fresh = VmSpace::new().is_ok();

    check(real_ready.is_ok() && real_used == arch::KERNEL_PART_ENTRIES, "内核空间准备结果不正确");
    check(r_fail == Err(MapError::OutOfFrames) && untouched && returned, "预分配失败后顶级表被改动或帧未归还");
    check(r_ok == Ok(arch::KERNEL_PART_ENTRIES) && filled == arch::KERNEL_PART_ENTRIES, "预分配成功路径不完整");
    check(back, "预分配演练后页帧未回到基线");
    check(refused == Err(MapError::OutOfFrames) && fresh, "准备失败状态未拒绝，或正常状态下创建地址空间失败");
    kprintln!(
        "[JSR-FIX] kernel_space ready={} used={} fail={:?} untouched={} frames_returned={} ok={:?} reclaimed={} refuse_when_unready={}",
        real_ready.is_ok(),
        real_used,
        r_fail.err(),
        untouched,
        returned,
        r_ok.ok(),
        back,
        refused.is_err()
    );
}

/// 4. 只读翻译与地址空间自身映射器一致；内核地址在用户空间中不带「用户可访问」。
fn readonly_translate() {
    let Some(off) = boot::get().and_then(|b| b.phys_offset) else {
        return;
    };
    let kobj_box = Box::new(0u64); // 先分配，避免在帧数比较区间内触发全局堆扩容
    let base = frame::free_frames();
    let (Ok(mut s), Ok(f)) = (VmSpace::new(), frame::allocate()) else {
        check(false, "无法建立演练地址空间");
        return;
    };
    let va = arch::USER_WINDOW.0 + DATA_OFF;
    let page = VirtPage::containing(va);
    let mapped = s.map(page, f, MapFlags::USER | MapFlags::WRITE).is_ok();
    // SAFETY：s 在本函数内有效且不被并发修改。
    let raw = unsafe { arch::translate_in(s.root(), off, va + 0x123) };
    let own = s.translate(page);
    let same = matches!((raw, own), (Some((a, fa)), Some((b, _))) if a == b && a == f && fa.contains(MapFlags::USER) && fa.contains(MapFlags::WRITE));
    let unmapped = unsafe { arch::translate_in(s.root(), off, va + FRAME_SIZE) }.is_none();
    let kva = &*kobj_box as *const u64 as u64;
    let kernel = unsafe { arch::translate_in(s.root(), off, kva) };
    let kernel_not_user = matches!(kernel, Some((_, fl)) if !fl.contains(MapFlags::USER));
    let _ = s.unmap(page);
    let _ = frame::deallocate(f);
    drop(s);
    let back = frame::free_frames() == base;
    check(mapped && same && unmapped && kernel_not_user && back, "只读翻译结果不正确或资源未回收");
    kprintln!(
        "[JSR-FIX] translate same_as_mapper={} unmapped_none={} kernel_not_user={} reclaimed={}",
        same,
        unmapped,
        kernel_not_user,
        back
    );
}

/// 5. ID 用尽后拒绝，不回绕。
fn id_exhaustion() {
    let ids = IdAllocator::starting_at(u64::MAX - 1);
    let (a, b, c, d) = (ids.allocate(), ids.allocate(), ids.allocate(), ids.allocate());
    let ok = a == Some(u64::MAX - 1) && b == Some(u64::MAX) && c.is_none() && d.is_none() && ids.exhausted();
    check(ok, "ID 用尽后未拒绝或发生回绕");
    kprintln!("[JSR-FIX] ids last={:?} after_exhausted={:?} again={:?} no_wrap={}", b, c, d, ok);
}

/// 调度器占位任务：什么都不做，直接结束。
// 占位任务：必须**保持存活**直到演练显式放行。
// 若它直接返回，SMP 下会被其他处理器取走并跑完，从而在「槽位已满」的判定之前
// 腾出槽位——这正是 AArch64 上该用例偶发失败的原因（目标线程反而创建成功）。
static FILLER_STOP: AtomicBool = AtomicBool::new(false);

/// 占位任务每次睡眠的 tick 数（被显式唤醒时提前醒来）。
///
/// 为什么不每个 tick 醒一次：占位任务的个数等于启动期任务槽位数（可达数百），每个 tick 全部醒一遍
/// 会让切换次数随容量线性增长，在最慢的模拟平台上拖过验收时限。改为长睡 + 放行时逐个唤醒；
/// 「检查标志之后、入睡之前」被唤醒的竞态由睡眠上限兜底（最多多等这么多 tick，不会卡死）。
const FILLER_NAP: u64 = 50;

fn filler() {
    while !FILLER_STOP.load(Ordering::Relaxed) {
        sched::sleep_until(sched::timer_ticks() + FILLER_NAP);
    }
}

/// 6. 线程创建失败回滚：栈顶为 0、对象表满、调度器槽位满；之后再次创建成功并正常退出。
fn spawn_rollback() {
    let base = arch::USER_WINDOW.0;
    let allowed = SyscallSet::of(&[abi::SYSTEM_TIME_NOW, abi::SYSTEM_TASK_EXIT]);
    let Ok(pid) = proc::create("fix-spawn", allowed) else {
        check(false, "演练进程创建失败");
        return;
    };
    let setup = (|| {
        proc::map_new(pid, base + CODE_OFF, MapFlags::USER | MapFlags::EXECUTE)?;
        proc::write(pid, base + CODE_OFF, arch::user_probe(UserProbe::SyscallSmoke))?;
        proc::map_new(pid, base + DATA_OFF, MapFlags::USER | MapFlags::WRITE)?;
        proc::map_new(pid, base + STACK_OFF - FRAME_SIZE, MapFlags::USER | MapFlags::WRITE)
    })();
    check(setup.is_ok(), "演练进程装载失败");
    let spawn = || proc::spawn_thread(pid, "fix-thread", base + CODE_OFF, base + STACK_OFF, base + DATA_OFF, 0);
    let snapshot = || (proc::thread_counts(pid), proc::registry_len(), kobj::stats().0, kobj::with(|t| t.counts(pid)).ok());
    let before = snapshot();

    // 栈顶为 0：`stack - 1` 不得下溢
    let zero = proc::spawn_thread(pid, "fix-zero", base + CODE_OFF, 0, 0, 0);
    let zero_ok = zero == Err(ProcError::Map(MapError::InvalidAddress)) && snapshot() == before;

    // 对象表满
    let mut fillers: Vec<ObjId> = Vec::new();
    while let Ok(id) = kobj::insert(KObject::Event { signaled: false }, 1, 0) {
        fillers.push(id);
    }
    let full_before = snapshot();
    let objs_full = spawn();
    let objs_ok = objs_full == Err(ProcError::NoTaskSlot) && snapshot() == full_before;
    for id in fillers.drain(..) {
        let _ = kobj::release_owner(id);
    }
    kobj::run_cleanup(usize::MAX);
    let objs_restored = snapshot() == before;

    // 调度器槽位满
    FILLER_STOP.store(false, Ordering::Relaxed);
    let mut slots = 0u64;
    // 记录占位任务创建失败的原因：若先耗尽的是别的资源（例如栈帧），
    // 「槽位满」这个前提就根本没成立，必须能在日志里分辨出来。
    let filler_err = loop {
        match sched::spawn(TaskId(9100 + slots), "fix-filler", filler) {
            Ok(_) => slots += 1,
            Err(e) => break Some(e),
        }
    };
    let sched_full = spawn();
    kobj::run_cleanup(usize::MAX); // 回滚释放的 Task 对象经清理过程销毁
    let sched_ok = sched_full == Err(ProcError::NoTaskSlot) && snapshot() == before;
    FILLER_STOP.store(true, Ordering::Relaxed);
    for i in 0..slots {
        sched::wake(TaskId(9100 + i));
    }
    sched::run(); // 放行后占位任务全部结束，槽位腾空
    kobj::run_cleanup(usize::MAX);

    // 回滚之后再次创建成功，线程正常运行并退出
    let again = spawn();
    sched::run();
    let state = proc::state(pid);
    let ran = again.is_ok() && state == Some(ProcState::Exited { code: 42 }) && proc::thread_counts(pid) == Some((0, 1));
    proc::reap(pid);
    kobj::run_cleanup(usize::MAX);

    check(zero_ok, "栈顶为 0 应被拒且无副作用");
    check(objs_ok && objs_restored, "对象表满时线程创建未完整回滚");
    check(sched_ok && slots > 0, "调度器槽位满时线程创建未完整回滚");
    check(ran, "回滚后再次创建线程失败或未正常退出");
    kprintln!(
        "[JSR-FIX] spawn zero_stack={:?} objects_full={:?} restored={} sched_full={:?} (fillers {} filler_err={:?}) restored={} retry_exit={:?}",
        zero.err(),
        objs_full.err(),
        objs_ok && objs_restored,
        sched_full.err(),
        slots,
        filler_err,
        sched_ok,
        state
    );
}
