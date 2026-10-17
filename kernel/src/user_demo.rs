//! M3.1 演练：真实进入 Ring 3，并证明「用户态异常只终止该任务、内核继续运行」。
//!
//! 每个探针一个独立地址空间（代码页：用户可执行只读；数据页、栈页：用户可写），由一个内核任务
//! 切到该空间后 `enter_user`。三个探针（机器码由 arch 提供，本文件不含 ISA 代码）：
//! 1. 上报特权级：把代码段选择子写进数据页 → 引导线程读出后验证 RPL=3（真的在 Ring 3）
//! 2. 读内核地址：读一个内核堆对象 → 必须在读处缺页被终止，数据页里不得出现泄漏的值
//! 3. 特权指令：执行停机指令 → 保护错误被终止，其后的标记不得出现
//!
//! 每个探针结束后：页帧全部归还，空闲帧数回到探针前；三次故障之后内核继续调度并退出成功。

use core::sync::atomic::{AtomicU32, Ordering};

use alloc::boxed::Box;
use kernel_core::frame::{PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapFlags, VirtPage};

use crate::arch::{self, UserProbe};
use crate::fault::{self, UserFaultKind};
use crate::mm::space::VmSpace;
use crate::mm::{frame, phys_to_virt};
use crate::sync::IrqSpinLock;
use crate::task::TaskId;
use crate::{kprintln, sched};

/// 私有窗口内的布局（相对窗口起点）。
const CODE_OFF: u64 = 0x40_0000;
const DATA_OFF: u64 = 0x80_0000;
const STACK_OFF: u64 = 0xC0_0000;

static CHECKS: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-USER] CHECK FAILED: {}", what);
    }
}

/// 断言失败次数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 交给用户任务的启动参数（引导线程准备，用户任务读取）。
#[derive(Clone, Copy)]
struct Job {
    space: arch::SpaceRoot,
    entry: u64,
    stack: u64,
    arg0: u64,
    arg1: u64,
}

static JOB: IrqSpinLock<Option<Job>> = IrqSpinLock::new(None);

/// 用户任务体：切到探针的地址空间并进入 Ring 3（永不返回；靠用户态异常被终止）。
fn user_task() {
    let Some(job) = *JOB.lock() else {
        return;
    };
    sched::set_current_space(Some(job.space));
    // SAFETY：job 中的地址都已在该空间按用户权限映射；调度器在切入本任务时已设置内核栈顶。
    unsafe { arch::enter_user(job.entry, job.stack, job.arg0, job.arg1) }
}

/// 一个探针的资源：地址空间 + 三个数据帧。
struct Probe {
    space: VmSpace,
    frames: [PhysFrame; 3],
}

/// 为探针建立地址空间并装入机器码。
fn build(probe: UserProbe) -> Option<Probe> {
    let base = arch::USER_WINDOW.0;
    let mut space = VmSpace::new().ok()?;
    let code = frame::allocate().ok()?;
    let data = frame::allocate().ok()?;
    let stack = frame::allocate().ok()?;
    let bytes = arch::user_probe(probe);
    // SAFETY：三帧刚分出、尚未映射给任何人；经全物理内存映射写入。
    unsafe {
        for f in [code, data, stack] {
            core::ptr::write_bytes(phys_to_virt(f.start())?, 0, FRAME_SIZE as usize);
        }
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys_to_virt(code.start())?, bytes.len());
    }
    space.map(VirtPage::containing(base + CODE_OFF), code, MapFlags::USER | MapFlags::EXECUTE).ok()?;
    space.map(VirtPage::containing(base + DATA_OFF), data, MapFlags::USER | MapFlags::WRITE).ok()?;
    space.map(VirtPage::containing(base + STACK_OFF - FRAME_SIZE), stack, MapFlags::USER | MapFlags::WRITE).ok()?;
    Some(Probe { space, frames: [code, data, stack] })
}

/// 读数据页第 `i` 个 64 位字（经全物理内存映射，不依赖用户映射）。
fn data_word(p: &Probe, i: usize) -> u64 {
    match phys_to_virt(p.frames[1].start()) {
        // SAFETY：数据帧仍由本探针持有，8 字节对齐。
        Some(v) => unsafe { (v as *const u64).add(i).read_volatile() },
        None => u64::MAX,
    }
}

/// 运行一个探针：建空间 → 用户任务进入 Ring 3 → 被终止 → 回收；返回 (数据页前三个字, 故障记录)。
fn run_probe(name: &'static str, probe: UserProbe, arg1: u64) -> Option<([u64; 3], Option<fault::UserFault>)> {
    let base = arch::USER_WINDOW.0;
    let p = build(probe)?;
    *JOB.lock() = Some(Job {
        space: p.space.root(),
        entry: base + CODE_OFF,
        stack: base + STACK_OFF,
        arg0: base + DATA_OFF,
        arg1,
    });
    let faults_before = fault::count();
    if sched::spawn(TaskId(30), name, user_task).is_err() {
        check(false, "无法创建用户任务");
        return None;
    }
    sched::run(); // 用户任务被终止后回到这里
    let terminated = fault::count() == faults_before + 1;
    check(terminated, "用户任务未经故障路径终止");
    let words = [data_word(&p, 0), data_word(&p, 1), data_word(&p, 2)];
    let last = fault::last();
    let frames = p.frames;
    drop(p.space); // 销毁地址空间（私有页表帧回收）
    for f in frames {
        check(frame::deallocate(f).is_ok(), "探针数据帧归还失败");
    }
    Some((words, last))
}

/// 运行 M3.1 演练。
pub fn run() {
    let free_before = frame::free_frames();

    // 1. 上报特权级
    if let Some((w, last)) = run_probe("user-cpl", UserProbe::ReportPrivilege, 0) {
        let ring3 = w[0] & 3 == 3 && w[1] == 0x55aa;
        check(ring3, "用户代码未运行在特权级 3");
        check(matches!(last, Some(f) if f.kind == UserFaultKind::InvalidInstruction), "上报探针的终止原因不是无效指令");
        kprintln!("[JSR-USER] probe=report_privilege cs={:#x} cpl={} marker={:#x} ring3={}", w[0], w[0] & 3, w[1], ring3);
    }

    // 2. 读内核地址（一个内核堆对象：内核可读，用户不可读）
    let secret = Box::new(0x5345_4352_4554_u64);
    let secret_addr = &*secret as *const u64 as u64;
    if let Some((w, last)) = run_probe("user-read", UserProbe::ReadAddress, secret_addr) {
        let blocked = w[0] == 0 && w[1] == 0;
        let at_addr = matches!(last, Some(f) if f.kind == UserFaultKind::PageFault && f.addr == secret_addr);
        check(blocked, "用户态读到了内核数据（泄漏）");
        check(at_addr, "读内核地址未在该地址处缺页");
        kprintln!("[JSR-USER] probe=read_kernel addr={:#x} leaked={} fault_at_addr={}", secret_addr, !blocked, at_addr);
    }
    check(*secret == 0x5345_4352_4554, "内核对象被改写");

    // 3. 特权指令
    if let Some((w, last)) = run_probe("user-priv", UserProbe::Privileged, 0) {
        let stopped = w[1] == 0x7e57 && w[2] == 0;
        check(stopped, "特权指令之后用户代码仍继续执行");
        check(matches!(last, Some(f) if f.kind == UserFaultKind::ProtectionFault), "特权指令未触发保护错误");
        kprintln!("[JSR-USER] probe=privileged marker={:#x} after={:#x} stopped={}", w[1], w[2], stopped);
    }

    let free_after = frame::free_frames();
    check(free_after == free_before, "探针结束后页帧未全部回收");
    kprintln!(
        "[JSR-USER] kernel alive after faults={} free_before={} free_after={} reclaimed={}",
        fault::count(),
        free_before,
        free_after,
        free_after == free_before
    );
    kprintln!("[JSR-USER] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}
