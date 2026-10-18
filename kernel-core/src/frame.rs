//! 物理页帧分配（M2.1）：把引导器报告的物理内存图变成「可分配的 4 KiB 页帧」。
//!
//! # 职责
//! * [`PhysRegion`] / [`RegionKind`]：与引导协议无关的物理内存区域描述
//!   （引导适配层负责把 `bootloader_api`、UEFI、设备树等格式转换成它）
//! * [`FrameAllocator`]：页帧分配契约（Strategy 模式，可替换为伙伴系统等）
//! * [`BitmapFrameAllocator`]：位图实现——每帧 1 位，1 = 已占用/不可用，0 = 空闲
//!
//! # 设计取舍
//! * **不需要堆**：位图存储由调用者以 `&mut [u64]` 提供（内核用 `.bss` 中的静态数组），
//!   因此可以在内核堆（M2.2）建立之前使用，堆本身也正是从这里拿页。
//! * **释放必须可验证**：只接受「落在可用区域内、且当前处于已分配状态」的帧；
//!   重复释放、释放保留内存、释放未对齐地址都返回带规范名的错误，而不是悄悄破坏位图。
//! * **帧 0 永不分配**：物理地址 0 常被当作「空」，分出去会让空指针错误变得隐蔽。
//! * 只做记账，不访问物理内存本身（清零、写入需要映射，属于内核的职责）——因此可宿主测试。
//!
//! # 命名
//! 错误名属于 `system.memory` 领域：`system.memory.error.{out_of_frames,double_free,not_usable,misaligned}`。

/// 页帧大小（4 KiB）。
pub const FRAME_SIZE: u64 = 4096;

/// 一个物理页帧（以 4 KiB 对齐的起始物理地址表示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysFrame(u64);

impl PhysFrame {
    /// 由对齐的起始地址构造；未对齐返回 `None`。
    pub const fn from_start(addr: u64) -> Option<Self> {
        if addr % FRAME_SIZE == 0 {
            Some(PhysFrame(addr))
        } else {
            None
        }
    }

    /// 由帧号构造。
    pub const fn from_number(n: u64) -> Self {
        PhysFrame(n * FRAME_SIZE)
    }

    /// 起始物理地址。
    pub const fn start(self) -> u64 {
        self.0
    }

    /// 帧号（起始地址 / 4 KiB）。
    pub const fn number(self) -> u64 {
        self.0 / FRAME_SIZE
    }
}

/// 物理区域种类（只区分「内核可自由使用」与「不可用」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// 可用的普通内存。
    Usable,
    /// 保留：固件、引导器自身的页表与数据、MMIO、内核镜像等。
    Reserved,
}

/// 一段物理内存 `[start, end)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysRegion {
    /// 起始物理地址（含）。
    pub start: u64,
    /// 结束物理地址（不含）。
    pub end: u64,
    /// 种类。
    pub kind: RegionKind,
}

impl PhysRegion {
    /// 空区域（静态数组初始化用）。
    pub const EMPTY: PhysRegion = PhysRegion { start: 0, end: 0, kind: RegionKind::Reserved };

    /// 区域内**完整**包含的第一个与最后一个（不含）帧号；起点向上、终点向下对齐到 4 KiB。
    pub const fn frame_range(&self) -> (u64, u64) {
        let first = self.start.div_ceil(FRAME_SIZE);
        let last = self.end / FRAME_SIZE;
        if last > first {
            (first, last)
        } else {
            (first, first)
        }
    }
}

/// 页帧分配错误（`system.memory.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// 没有空闲帧了。
    OutOfFrames,
    /// 释放一个当前并未分配的帧（重复释放）。
    DoubleFree,
    /// 释放一个不在可用区域内（或超出管理范围）的帧。
    NotUsable,
    /// 地址未按 4 KiB 对齐。
    Misaligned,
}

impl FrameError {
    /// 规范错误名（命名约定）。
    pub const fn name(self) -> &'static str {
        match self {
            FrameError::OutOfFrames => "system.memory.error.out_of_frames",
            FrameError::DoubleFree => "system.memory.error.double_free",
            FrameError::NotUsable => "system.memory.error.not_usable",
            FrameError::Misaligned => "system.memory.error.misaligned",
        }
    }
}

/// 页帧分配契约（Strategy）：位图、伙伴系统、按 NUMA 节点分区等实现都满足它。
pub trait FrameAllocator {
    /// 分配一个空闲帧。
    fn allocate(&mut self) -> Result<PhysFrame, FrameError>;
    /// 释放一个此前由本分配器分出的帧。
    fn deallocate(&mut self, frame: PhysFrame) -> Result<(), FrameError>;
    /// 当前空闲帧数。
    fn free_frames(&self) -> usize;
    /// 可管理的可用帧总数（初始化时的空闲帧数）。
    fn usable_frames(&self) -> usize;
}

/// 位图页帧分配器。位 i 对应帧号 i（物理地址 `i * 4 KiB`）；1 = 占用/不可用，0 = 空闲。
///
/// 管理范围 = `bits.len() * 64` 个帧；超出范围的可用内存被计入 [`ignored_frames`](Self::ignored_frames)
/// 而不是静默丢弃，便于诊断「位图开小了」。
pub struct BitmapFrameAllocator<'a> {
    bits: &'a mut [u64],
    regions: &'a [PhysRegion],
    usable: usize,
    free: usize,
    ignored: usize,
    /// 下一次从哪个字开始找（循环首次适配，避免每次都从头扫描）。
    hint: usize,
}

impl<'a> BitmapFrameAllocator<'a> {
    /// 用调用者提供的位图存储与物理内存图建立分配器。
    ///
    /// `regions` 中重叠的区域以「保留优先」处理：先把所有帧标为占用，只清除可用区域里的帧，
    /// 再把保留区域重新标为占用——因此固件报告重叠时也不会把保留内存分出去。
    pub fn new(bits: &'a mut [u64], regions: &'a [PhysRegion]) -> Self {
        for w in bits.iter_mut() {
            *w = u64::MAX;
        }
        let capacity = (bits.len() as u64) * 64;
        let mut ignored = 0usize;
        for r in regions.iter().filter(|r| r.kind == RegionKind::Usable) {
            let (first, last) = r.frame_range();
            for n in first..last {
                if n == 0 {
                    continue; // 帧 0 永不分配
                }
                if n >= capacity {
                    ignored += 1;
                    continue;
                }
                // n < capacity = bits.len() * 64 ⇒ 下标必在 usize 与位图范围内
                bits[(n / 64) as usize] &= !(1u64 << (n % 64));
            }
        }
        for r in regions.iter().filter(|r| r.kind == RegionKind::Reserved) {
            let (first, last) = r.frame_range();
            for n in first..last.min(capacity) {
                bits[(n / 64) as usize] |= 1u64 << (n % 64);
            }
        }
        let free = bits.iter().map(|w| w.count_zeros() as usize).sum();
        BitmapFrameAllocator { bits, regions, usable: free, free, ignored, hint: 0 }
    }

    /// 因超出位图管理范围而未纳入的可用帧数。
    pub fn ignored_frames(&self) -> usize {
        self.ignored
    }

    /// 帧号在位图中的字下标；超出位图（或在 32 位目标上超出 `usize` 表示范围）返回 `None`。
    /// 不用 `as usize`：32 位目标上截断会把一个很大的帧号映射到错误的位上。
    /// Bitmap word index of frame `n`, without truncating casts.
    fn word_index(&self, n: u64) -> Option<usize> {
        usize::try_from(n / 64).ok().filter(|&i| i < self.bits.len())
    }

    /// 该帧当前是否已分配（或不可用）。
    pub fn is_used(&self, frame: PhysFrame) -> bool {
        let n = frame.number();
        match self.word_index(n).map(|i| self.bits[i]) {
            Some(w) => w & (1u64 << (n % 64)) != 0,
            None => true,
        }
    }

    /// 帧是否落在某个可用区域内且不在任何保留区域内（释放合法性检查）。
    fn is_usable(&self, frame: PhysFrame) -> bool {
        let n = frame.number();
        let inside = |kind: RegionKind| {
            self.regions.iter().filter(|r| r.kind == kind).any(|r| {
                let (first, last) = r.frame_range();
                n >= first && n < last
            })
        };
        n != 0 && inside(RegionKind::Usable) && !inside(RegionKind::Reserved)
    }
}

impl FrameAllocator for BitmapFrameAllocator<'_> {
    fn allocate(&mut self) -> Result<PhysFrame, FrameError> {
        if self.free == 0 {
            return Err(FrameError::OutOfFrames);
        }
        let words = self.bits.len();
        for k in 0..words {
            let i = (self.hint + k) % words;
            let w = self.bits[i];
            if w != u64::MAX {
                let bit = (!w).trailing_zeros() as u64;
                self.bits[i] = w | (1u64 << bit);
                self.free -= 1;
                self.hint = i;
                return Ok(PhysFrame::from_number(i as u64 * 64 + bit));
            }
        }
        Err(FrameError::OutOfFrames)
    }

    fn deallocate(&mut self, frame: PhysFrame) -> Result<(), FrameError> {
        if frame.start() % FRAME_SIZE != 0 {
            return Err(FrameError::Misaligned);
        }
        let n = frame.number();
        let Some(i) = self.word_index(n).filter(|_| self.is_usable(frame)) else {
            return Err(FrameError::NotUsable);
        };
        if !self.is_used(frame) {
            return Err(FrameError::DoubleFree);
        }
        self.bits[i] &= !(1u64 << (n % 64));
        self.free += 1;
        Ok(())
    }

    fn free_frames(&self) -> usize {
        self.free
    }

    fn usable_frames(&self) -> usize {
        self.usable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn regions() -> [PhysRegion; 3] {
        [
            // 0..640 KiB 可用（含帧 0，帧 0 必须被排除）
            PhysRegion { start: 0, end: 640 * 1024, kind: RegionKind::Usable },
            // 1 MiB..2 MiB 可用，但起点不对齐：应向上对齐
            PhysRegion { start: MIB + 100, end: 2 * MIB, kind: RegionKind::Usable },
            // 1.5 MiB..1.5 MiB+8 KiB 保留（与可用区重叠，保留优先）
            PhysRegion { start: MIB + MIB / 2, end: MIB + MIB / 2 + 8192, kind: RegionKind::Reserved },
        ]
    }

    #[test]
    fn counts_usable_frames_excluding_frame_zero_and_reserved() {
        let regs = regions();
        let mut bits = [0u64; 16]; // 1024 帧 = 4 MiB 管理范围
        let a = BitmapFrameAllocator::new(&mut bits, &regs);
        // 160 帧（0..640K）- 帧0 = 159；1M+100 向上对齐 → 帧 257..512 = 255；减保留 2 帧 = 253
        assert_eq!(a.usable_frames(), 159 + 255 - 2);
        assert_eq!(a.free_frames(), a.usable_frames());
        assert_eq!(a.ignored_frames(), 0);
    }

    #[test]
    fn allocations_are_distinct_aligned_and_never_reserved() {
        let regs = regions();
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let total = a.usable_frames();
        let mut seen = [false; 1024];
        for _ in 0..total {
            let f = a.allocate().unwrap();
            assert_eq!(f.start() % FRAME_SIZE, 0);
            assert_ne!(f.number(), 0, "帧 0 不得分配");
            assert!(!seen[f.number() as usize], "重复分配 {:?}", f);
            seen[f.number() as usize] = true;
            let reserved = (MIB + MIB / 2) / FRAME_SIZE;
            assert!(f.number() != reserved && f.number() != reserved + 1, "分出了保留帧");
        }
        assert_eq!(a.allocate(), Err(FrameError::OutOfFrames));
        assert_eq!(a.free_frames(), 0);
    }

    #[test]
    fn free_then_reuse() {
        let regs = regions();
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let f1 = a.allocate().unwrap();
        let f2 = a.allocate().unwrap();
        assert_ne!(f1, f2);
        a.deallocate(f1).unwrap();
        assert_eq!(a.free_frames(), a.usable_frames() - 1);
        // 释放后可以再次分到（位图首次适配会先找到它）
        let mut again = a.allocate().unwrap();
        while again != f1 {
            again = a.allocate().unwrap();
        }
        assert!(a.is_used(f1));
    }

    #[test]
    fn rejects_double_free_reserved_and_misaligned() {
        let regs = regions();
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let f = a.allocate().unwrap();
        a.deallocate(f).unwrap();
        assert_eq!(a.deallocate(f), Err(FrameError::DoubleFree));
        let reserved = PhysFrame::from_start(MIB + MIB / 2).unwrap();
        assert_eq!(a.deallocate(reserved), Err(FrameError::NotUsable));
        assert_eq!(a.deallocate(PhysFrame::from_number(0)), Err(FrameError::NotUsable));
        assert_eq!(a.deallocate(PhysFrame(4097)), Err(FrameError::Misaligned));
        assert_eq!(PhysFrame::from_start(4097), None);
        assert_eq!(FrameError::DoubleFree.name(), "system.memory.error.double_free");
    }

    #[test]
    fn frames_beyond_capacity_are_reported_not_lost_silently() {
        let regs = [PhysRegion { start: 0, end: 8 * MIB, kind: RegionKind::Usable }];
        let mut bits = [0u64; 16]; // 只管 4 MiB
        let a = BitmapFrameAllocator::new(&mut bits, &regs);
        assert_eq!(a.usable_frames(), 1024 - 1);
        assert_eq!(a.ignored_frames(), 1024);
    }
}
