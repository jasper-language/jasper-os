//! KRN-0① 的多处理器 TLB 回归：两个钉在不同处理器的任务批量映射、并发读取、击落后撤销。
//! KRN-0 SMP TLB regression with writer and reader pinned to different processors.
//!
//! # 职责
//! * 生成 100,352 个真实页映射访问，分成不超过公告板上限的批次；
//! * 每批只发起一次撤销后的跨核击落，核对读者从未看到批次外的数据；
//! * 另测同一虚拟页从旧帧改到新帧后，其他处理器在击落后读到新值。
//!
//! # 边界
//! 运行于内核映射窗口，不代替用户地址空间的权限检查；所有映射和页帧最终回到基线。

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use kernel_core::paging::{MapFlags, VirtPage};
use kernel_core::smp::CpuSet;

use crate::task::TaskId;
use crate::{arch, kprintln, mm, sched};

const BATCH_PAGES: usize = 512;
const BATCHES: usize = 196;
const TOTAL_PAGES: usize = BATCH_PAGES * BATCHES;
const TASK_ID: u64 = 9900;
const TLB_VA: u64 = arch::KERNEL_PROBE_VA + 0x40_0000;
const PATTERN_A: u64 = 0x4B524E30_544C4241;
const PATTERN_B: u64 = 0x4B524E30_544C4242;

/// 0 = 等待写入者，1 = 本批可读，2 = 读者完成。
static PARTICIPANTS: AtomicU32 = AtomicU32::new(0);
static PHASE: AtomicU32 = AtomicU32::new(0);
static BATCH: AtomicU64 = AtomicU64::new(0);
static READS: AtomicU64 = AtomicU64::new(0);
static MISMATCHES: AtomicU64 = AtomicU64::new(0);
static WRITER_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
static READER_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
static FINISHED: AtomicU32 = AtomicU32::new(0);

fn only(cpu: usize) -> CpuSet {
    let mut set = CpuSet::EMPTY;
    set.insert(cpu);
    set
}

fn pattern(batch: usize, page: usize) -> u64 {
    ((batch as u64) << 32) | page as u64
}

fn write_frame(frame: kernel_core::frame::PhysFrame, value: u64) -> bool {
    let Some(p) = mm::phys_to_virt(frame.start()) else { return false };
    // SAFETY：帧由本任务独占，物理内存映射可写。
    unsafe { (p as *mut u64).write_volatile(value) };
    true
}

fn writer() {
    WRITER_CPU.store(arch::cpu_index() as u32, Ordering::Release);
    // chatgpt: spawn_on can schedule us before the caller creates the reader.
    // The reader is published on CPU1 before this CPU0 writer is published.
    // Yield alone cannot return a CPU0 writer to its boot creator when it is
    // the sole runnable worker. The creation order below closes that gap.
    PARTICIPANTS.fetch_or(1, Ordering::Release);
    while PARTICIPANTS.load(Ordering::Acquire) != 3 { sched::yield_now(); }
    let mut failed = false;
    for batch in 0..BATCHES {
        let pages = BATCH_PAGES.min(TOTAL_PAGES - batch * BATCH_PAGES);
        let mut frames = alloc::vec::Vec::with_capacity(pages);
        for _ in 0..pages {
            let frame = match mm::frame::allocate() {
                Ok(f) => f,
                Err(_) => {
                    failed = true;
                    break;
                }
            };
            if !write_frame(frame, pattern(batch, frames.len())) {
                failed = true;
                break;
            }
            frames.push(frame);
        }
        if failed {
            break;
        }
        for (i, frame) in frames.iter().enumerate() {
            let page = VirtPage::containing(TLB_VA + i as u64 * kernel_core::frame::FRAME_SIZE);
            if mm::map::map(page, *frame, MapFlags::WRITE).is_err() {
                failed = true;
                break;
            }
        }
        if failed {
            break;
        }
        BATCH.store(batch as u64, Ordering::Relaxed);
        PHASE.store(1, Ordering::Release);
        while PHASE.load(Ordering::Acquire) != 2 {
            core::hint::spin_loop();
        }
        let start = VirtPage::containing(TLB_VA);
        if mm::map::unmap_pages(start, pages as u64).is_err() {
            failed = true;
            break;
        }
        for frame in frames {
            if mm::frame::deallocate(frame).is_err() {
                failed = true;
                break;
            }
        }
        PHASE.store(0, Ordering::Release);
    }
    if failed {
        PHASE.store(3, Ordering::Release);
    }
    FINISHED.store(if failed { u32::MAX } else { 1 }, Ordering::Release);
}

fn reader() {
    READER_CPU.store(arch::cpu_index() as u32, Ordering::Release);
    PARTICIPANTS.fetch_or(2, Ordering::Release);
    for _ in 0..BATCHES {
        loop {
            match PHASE.load(Ordering::Acquire) {
                1 => break,
                3 => return,
                _ => core::hint::spin_loop(),
            }
        }
        let batch = BATCH.load(Ordering::Relaxed) as usize;
        let pages = BATCH_PAGES.min(TOTAL_PAGES - batch * BATCH_PAGES);
        for i in 0..pages {
            let at = (TLB_VA + i as u64 * kernel_core::frame::FRAME_SIZE) as *const u64;
            // SAFETY：写入者在本批发布前已完成映射，读者在两方握手完成前不撤销。
            let got = unsafe { at.read_volatile() };
            if got != pattern(batch, i) {
                MISMATCHES.fetch_add(1, Ordering::Relaxed);
            }
            READS.fetch_add(1, Ordering::Relaxed);
        }
        PHASE.store(2, Ordering::Release);
    }
}

fn remote_read(va: u64) -> u64 {
    // SAFETY：调用方保证地址已映射且等待周期内不被撤销。
    unsafe { (va as *const u64).read_volatile() }
}

fn visibility(online: usize) -> bool {
    let page = VirtPage::containing(TLB_VA - 0x1000);
    let (Ok(a), Ok(b)) = (mm::frame::allocate(), mm::frame::allocate()) else { return false };
    let written = write_frame(a, PATTERN_A) && write_frame(b, PATTERN_B);
    let mapped = written && mm::map::map(page, a, MapFlags::WRITE).is_ok();
    // 让另一个处理器先缓存旧映射。
    let cached = mapped && crate::smp::call_on(1, remote_read, page.start()) == Ok(PATTERN_A);
    let switched = cached
        && matches!(mm::map::unmap(page), Ok(frame) if frame == a)
        && mm::map::map(page, b, MapFlags::WRITE).is_ok();
    let fresh = switched && crate::smp::call_on(1, remote_read, page.start()) == Ok(PATTERN_B);
    let unmapped = fresh && matches!(mm::map::unmap(page), Ok(frame) if frame == b);
    let freed = mm::frame::deallocate(a).is_ok() && mm::frame::deallocate(b).is_ok();
    let _ = online;
    fresh && unmapped && freed
}

/// 运行两个处理器的 TLB 回归；单处理器时如实跳过跨核部分。
pub fn run(online: usize) {
    if online < 2 {
        kprintln!("[JSR-KRN0] case=tlb_range batches=0 pages=0 reads=0 mismatches=0 cpus=1 skipped=true");
        return;
    }
    // 先建立并撤销测试窗口的中间页表，使后续基线只衡量数据帧，不把永久页表结构误判为泄漏。
    let preallocated = match mm::frame::allocate() {
        Ok(frame) => {
            let mut ok = true;
            for i in 0..BATCH_PAGES {
                let page = VirtPage::containing(TLB_VA + i as u64 * kernel_core::frame::FRAME_SIZE);
                ok &= mm::map::map(page, frame, MapFlags::WRITE).is_ok();
            }
            ok &= mm::map::unmap_pages(VirtPage::containing(TLB_VA), BATCH_PAGES as u64).is_ok();
            ok &= mm::frame::deallocate(frame).is_ok();
            ok
        }
        Err(_) => false,
    };
    let free0 = mm::frame::free_frames();
    // Author: chatgpt. Publish the AP peer first: if the BSP writer preempts
    // its creator immediately after publication, both participants now exist.
    let spawned = sched::spawn_on(TaskId(TASK_ID + 1), "krn0-tlb-reader", reader, None, only(1)).is_ok()
        && sched::spawn_on(TaskId(TASK_ID), "krn0-tlb-writer", writer, None, only(0)).is_ok();
    if spawned {
        sched::run();
    }
    let reads = READS.load(Ordering::Acquire);
    let mismatches = MISMATCHES.load(Ordering::Acquire);
    let writer_cpu = WRITER_CPU.load(Ordering::Acquire);
    let reader_cpu = READER_CPU.load(Ordering::Acquire);
    let finished = FINISHED.load(Ordering::Acquire) == 1;
    let framed = mm::frame::free_frames() == free0;
    let range_ok = spawned
        && preallocated
        && writer_cpu == 0
        && reader_cpu == 1
        && reads == TOTAL_PAGES as u64
        && mismatches == 0
        && finished
        && framed;
    kprintln!(
        "[JSR-KRN0] case=tlb_range batches={} pages={} reads={} mismatches={} writer_cpu={} reader_cpu={} frames_back={} ok={}",
        BATCHES,
        TOTAL_PAGES,
        reads,
        mismatches,
        writer_cpu,
        reader_cpu,
        framed,
        range_ok
    );
    let visible = visibility(online);
    crate::krn0_demo::tlb_check(range_ok && visible, "TLB 批量并发读或击落后可见性失败");
    kprintln!(
        "[JSR-KRN0] case=tlb_visibility old=A new=B after_shootdown={} frames_back={} ok={}",
        visible,
        visible,
        visible
    );
}
