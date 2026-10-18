//! M2.x 演练：在真机（QEMU）上验证内存管理，打印 `[JSR-FRAME]` / `[JSR-MAP]` 标记并当场断言。
//!
//! M2.1 页帧分配（见下）；M2.2 映射 API 见 [`run_map`]。
//!
//! 演练内容：
//! 1. 内存图规模与可用帧数（应接近 QEMU `-m` 给的内存）
//! 2. 分配 3 帧：互不相同、4 KiB 对齐、非帧 0
//! 3. **真实读写**：经全物理内存映射向每帧写入不同的 64 位图样并读回——证明分到的是可用 RAM
//! 4. 释放中间那帧后再分配，必须拿回同一帧（首次适配 + 复用）
//! 5. 重复释放被拒（`system.memory.error.double_free`），空闲数回到初始值
//!
//! 与机制分离：删掉本文件与 `kmain` 中的调用不影响 `mm::frame`。不含 ISA 代码。

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::frame::{FrameError, PhysFrame, FRAME_SIZE};
use kernel_core::paging::{MapError, MapFlags, VirtPage};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::space::{self, VmSpace};
use super::{frame, heap, map, phys_to_virt};
use crate::arch;
use crate::boot::BootSpec;
use crate::kprintln;

/// 断言失败次数（验收要求为 0）。
static FAILED: AtomicU32 = AtomicU32::new(0);
/// 断言总数。
static CHECKS: AtomicU32 = AtomicU32::new(0);

/// 记录一次断言；失败时打印原因。
fn check(ok: bool, what: &str) {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    if !ok {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-FRAME] CHECK FAILED: {}", what);
    }
}

/// 断言失败次数。
pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 向帧写入图样并读回；返回是否一致。
fn write_read_back(f: PhysFrame, pattern: u64) -> bool {
    let Some(base) = phys_to_virt(f.start()) else {
        return false;
    };
    let words = (FRAME_SIZE / 8) as usize;
    let p = base as *mut u64;
    // SAFETY：该帧刚由分配器分出、尚未被任何人使用；地址经全物理内存映射可访问且 8 字节对齐。
    unsafe {
        for i in 0..words {
            p.add(i).write_volatile(pattern ^ i as u64);
        }
        (0..words).all(|i| p.add(i).read_volatile() == pattern ^ i as u64)
    }
}

/// 运行 M2.1 演练。
pub fn run(boot: &'static BootSpec) {
    let stats = frame::init(boot);
    kprintln!(
        "[JSR-FRAME] regions={} usable_frames={} usable_mib={} ignored={} dropped_regions={} phys_offset={}",
        stats.regions,
        stats.usable,
        stats.usable as u64 * FRAME_SIZE / (1024 * 1024),
        stats.ignored,
        boot.dropped_regions,
        if boot.phys_offset.is_some() { "mapped" } else { "none" }
    );
    check(stats.usable > 0, "没有可用帧");
    check(boot.phys_offset.is_some(), "引导器未映射全部物理内存");
    let free0 = frame::free_frames();

    // 2. 分配 3 帧
    let mut got = [PhysFrame::from_number(0); 3];
    for slot in got.iter_mut() {
        match frame::allocate() {
            Ok(f) => *slot = f,
            Err(e) => check(false, e.name()),
        }
    }
    kprintln!(
        "[JSR-FRAME] alloc frames=3 addrs={:#x},{:#x},{:#x}",
        got[0].start(),
        got[1].start(),
        got[2].start()
    );
    let distinct = got[0] != got[1] && got[1] != got[2] && got[0] != got[2];
    let aligned = got.iter().all(|f| f.start() % FRAME_SIZE == 0 && f.number() != 0);
    check(distinct, "分配到重复的帧");
    check(aligned, "帧未对齐或为帧 0");
    check(frame::free_frames() == free0 - 3, "空闲计数未减 3");

    // 3. 真实读写
    let rw = got.iter().enumerate().all(|(i, f)| write_read_back(*f, 0x4A53_525F_4652_4D00 | i as u64));
    check(rw, "页帧读写校验失败");
    kprintln!("[JSR-FRAME] rw ok={} bytes_per_frame={}", rw, FRAME_SIZE);

    // 4. 释放中间帧再分配，应复用
    let mid = got[1];
    check(frame::deallocate(mid).is_ok(), "释放失败");
    let again = frame::allocate();
    let reused = again == Ok(mid);
    check(reused, "释放后未复用同一帧");
    kprintln!("[JSR-FRAME] free+alloc reuse={} frame={:#x}", reused, mid.start());

    // 5. 重复释放被拒
    for f in got {
        check(frame::deallocate(f).is_ok(), "归还失败");
    }
    let dup = frame::deallocate(got[0]);
    check(dup == Err(FrameError::DoubleFree), "重复释放未被拒绝");
    kprintln!(
        "[JSR-FRAME] double free rejected err={}",
        dup.err().map(|e| e.name()).unwrap_or("none")
    );
    check(frame::free_frames() == free0, "空闲计数未恢复");

    kprintln!(
        "[JSR-FRAME] checks={} failed={} free_frames={}",
        CHECKS.load(Ordering::Relaxed),
        failed(),
        frame::free_frames()
    );
}

/// M2.2 演练用的虚拟地址：由平台给出的内核共享部分中平时不映射的页，远离内核镜像、堆与物理内存映射。
const PROBE_VA: u64 = arch::KERNEL_PROBE_VA;

/// 运行 M2.2 演练：映射 → 经虚拟地址写、经物理映射读回 → 改只读 → 取消映射 → 错误路径。
pub fn run_map(boot: &'static BootSpec) {
    check(map::init(boot), "内核映射器初始化失败（无物理内存映射）");
    let page = VirtPage::from_start(PROBE_VA).unwrap_or(VirtPage::containing(PROBE_VA));
    check(map::translate(page).is_none(), "探针地址事先已被映射");

    let Ok(f) = frame::allocate() else {
        check(false, "无法为映射分配帧");
        return;
    };
    let mapped = map::map(page, f, MapFlags::WRITE);
    check(mapped.is_ok(), mapped.err().map(|e| e.name()).unwrap_or("map"));
    let t = map::translate(page);
    let points_to_frame = matches!(t, Some((pf, fl)) if pf == f && fl.contains(MapFlags::WRITE) && !fl.contains(MapFlags::EXECUTE));
    check(points_to_frame, "translate 结果与映射不符");
    kprintln!(
        "[JSR-MAP] map va={:#x} frame={:#x} flags=write,nx translate_ok={}",
        page.start(),
        f.start(),
        points_to_frame
    );

    // 经新映射的虚拟地址写，再经全物理内存映射读回：两条路径看到同一份数据 ⇒ 映射真实生效
    let pattern: u64 = 0x4A53_525F_4D41_5032;
    let via_phys = phys_to_virt(f.start()).map(|p| p as *mut u64);
    let same = match via_phys {
        Some(pp) => unsafe {
            // SAFETY：page 刚映射到 f，可写；pp 是同一帧经全物理映射的地址。
            (page.start() as *mut u64).write_volatile(pattern);
            pp.read_volatile() == pattern
        },
        None => false,
    };
    check(same, "经虚拟地址写入后物理帧内容不一致");
    kprintln!("[JSR-MAP] write via va, read via phys same={}", same);

    // 改为只读：权限位必须反映出来（实际写入会触发缺页，留到 M3 用户态异常隔离再做负向用例）
    check(map::protect(page, MapFlags::READ_ONLY).is_ok(), "protect 失败");
    let ro = matches!(map::translate(page), Some((_, fl)) if !fl.contains(MapFlags::WRITE));
    check(ro, "改只读后仍可写");
    kprintln!("[JSR-MAP] protect read_only ok={}", ro);

    // 错误路径
    let again = map::map(page, f, MapFlags::WRITE);
    check(again == Err(MapError::AlreadyMapped), "重复映射未被拒绝");
    let bad = map::map(VirtPage::containing(arch::INVALID_VA), f, MapFlags::WRITE);
    check(bad == Err(MapError::InvalidAddress), "非规范地址未被拒绝");
    kprintln!(
        "[JSR-MAP] errors double_map={} invalid_addr={}",
        again.err().map(|e| e.name()).unwrap_or("none"),
        bad.err().map(|e| e.name()).unwrap_or("none")
    );

    // 取消映射：返回原帧，之后查询为空，再取消报 not_mapped
    let un = map::unmap(page);
    check(un == Ok(f), "unmap 未返回原帧");
    check(map::translate(page).is_none(), "取消映射后仍可查到");
    let un2 = map::unmap(page);
    check(un2 == Err(MapError::NotMapped), "重复取消映射未报 not_mapped");
    check(frame::deallocate(f).is_ok(), "归还帧失败");
    kprintln!(
        "[JSR-MAP] unmap returned_frame={} translate_after=none again={}",
        un == Ok(f),
        un2.err().map(|e| e.name()).unwrap_or("none")
    );
    kprintln!("[JSR-MAP] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}

/// 运行 M2.3 演练：Box / Vec / String（含中文）真实使用；大对象触发增长；全部释放后空闲字节回到基线且合并为一块。
pub fn run_heap() {
    let init = heap::init();
    check(init.is_ok(), "堆初始化失败");
    let (total0, free0, blocks0, mapped0) = heap::stats();
    kprintln!("[JSR-HEAP] init total={} free={} blocks={} mapped={}", total0, free0, blocks0, mapped0);

    {
        let b = Box::new(0x4A53_525F_4845_4150u64);
        check(*b == 0x4A53_525F_4845_4150, "Box 读回不一致");
        let mut v: Vec<u64> = Vec::new();
        for i in 0..10_000u64 {
            v.push(i * 3);
        }
        let sum: u64 = v.iter().sum();
        check(sum == 3 * (9_999 * 10_000 / 2), "Vec 求和不一致");
        let mut s = String::from("内核堆可用：");
        s.push_str("中文 UTF-8 ✓");
        check(s.chars().count() == 16 && s.len() > 16, "String 字符数/字节数不符");
        kprintln!("[JSR-HEAP] box ok vec_len={} vec_sum={} string=\"{}\" chars={} bytes={}", v.len(), sum, s, s.chars().count(), s.len());

        // 大对象：超过初始容量，必须触发按需增长
        let big: Vec<u8> = alloc::vec![0xA5; 512 * 1024];
        let (_, _, _, mapped1) = heap::stats();
        check(big.iter().all(|&x| x == 0xA5), "大对象内容错误");
        check(mapped1 > mapped0, "大对象未触发堆增长");
        kprintln!("[JSR-HEAP] grow big_bytes={} mapped_before={} mapped_after={}", big.len(), mapped0, mapped1);
    }

    // 全部离开作用域后：空闲字节 = 总字节，且所有空闲块合并成一个
    let (total2, free2, blocks2, mapped2) = heap::stats();
    let back = free2 == total2;
    check(back, "释放后空闲字节未回到总量（泄漏或记账错误）");
    check(blocks2 == 1, "释放后空闲块未合并为一个");
    kprintln!("[JSR-HEAP] after free total={} free={} blocks={} mapped={} baseline_ok={}", total2, free2, blocks2, mapped2, back && blocks2 == 1);
    kprintln!("[JSR-HEAP] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}

/// 运行 M2.4 演练：两个地址空间在**同一虚拟地址**映射不同物理帧，真实切换后读到各自的图样；
/// 内核堆对象在两边都可见（共享）；该地址在内核空间不可见（私有）；销毁后页表帧全部回收。
pub fn run_space() {
    if let Err(e) = space::init() {
        check(false, "内核空间准备失败");
        kprintln!("[JSR-SPACE] kernel space not ready: {:?}", e);
        return;
    }
    let va = arch::USER_WINDOW.0 + 0x1000_0000;
    let page = VirtPage::containing(va);
    let shared = Box::new(0x5348_4152_4544_u64); // 内核堆对象：两个空间都应能读到
    let free_before = frame::free_frames();

    let (Ok(fa), Ok(fb)) = (frame::allocate(), frame::allocate()) else {
        check(false, "无法分配数据帧");
        return;
    };
    let pat_a: u64 = 0xAAAA_0000_0000_000A;
    let pat_b: u64 = 0xBBBB_0000_0000_000B;
    // 经全物理内存映射预先写入两帧，不依赖任何用户映射
    unsafe {
        if let (Some(pa), Some(pb)) = (phys_to_virt(fa.start()), phys_to_virt(fb.start())) {
            (pa as *mut u64).write_volatile(pat_a);
            (pb as *mut u64).write_volatile(pat_b);
        }
    }

    {
        let (Ok(mut a), Ok(mut b)) = (VmSpace::new(), VmSpace::new()) else {
            check(false, "创建地址空间失败");
            return;
        };
        check(a.root() != b.root(), "两个空间的根相同");
        check(a.map(page, fa, MapFlags::READ_ONLY).is_ok(), "空间 A 映射失败");
        check(b.map(page, fb, MapFlags::READ_ONLY).is_ok(), "空间 B 映射失败");
        let outside = a.map(VirtPage::containing(arch::KERNEL_PROBE_VA), fa, MapFlags::READ_ONLY);
        check(outside == Err(MapError::InvalidAddress), "私有窗口外的映射未被拒绝");
        kprintln!(
            "[JSR-AS] created a={:?} b={:?} va={:#x} window={:#x}..{:#x} outside_window={}",
            a.root(),
            b.root(),
            va,
            arch::USER_WINDOW.0,
            arch::USER_WINDOW.1,
            outside.err().map(|e| e.name()).unwrap_or("none")
        );

        // 真实切换：关中断，保证读取期间不会被调度到别处
        let (read_a, shared_a, read_b, shared_b, read_a2) = arch::without_irq(|| unsafe {
            a.activate();
            let ra = (va as *const u64).read_volatile();
            let sa = *shared;
            b.activate();
            let rb = (va as *const u64).read_volatile();
            let sb = *shared;
            a.activate();
            let ra2 = (va as *const u64).read_volatile();
            space::activate_kernel();
            (ra, sa, rb, sb, ra2)
        });
        let isolated = read_a == pat_a && read_b == pat_b && read_a2 == pat_a;
        let kernel_shared = shared_a == *shared && shared_b == *shared;
        check(isolated, "同一虚拟地址在两个空间读到的内容不符");
        check(kernel_shared, "内核堆对象在用户空间中不可见");
        kprintln!(
            "[JSR-AS] switch read a={:#x} b={:#x} a_again={:#x} isolated={} kernel_shared={}",
            read_a,
            read_b,
            read_a2,
            isolated,
            kernel_shared
        );
        let private = map::translate(page).is_none();
        check(private, "私有映射泄漏到了内核空间");
        kprintln!("[JSR-AS] kernel space sees va={}", if private { "unmapped" } else { "MAPPED" });
        check(a.unmap(page) == Ok(fa), "A 取消映射未返回原帧");
        check(b.unmap(page) == Ok(fb), "B 取消映射未返回原帧");
    } // a、b 在此 Drop：销毁并回收页表帧

    check(frame::deallocate(fa).is_ok() && frame::deallocate(fb).is_ok(), "数据帧归还失败");
    let free_after = frame::free_frames();
    let reclaimed = free_after == free_before;
    check(reclaimed, "销毁地址空间后页帧未全部回收");
    kprintln!("[JSR-AS] destroyed free_before={} free_after={} reclaimed={}", free_before, free_after, reclaimed);
    kprintln!("[JSR-AS] checks={} failed={}", CHECKS.load(Ordering::Relaxed), failed());
}
