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

    /// 分配一个起始地址低于 `limit` 的空闲帧（从低地址找起）；没有则返回错误且位图不变。
    ///
    /// 用于硬件只能寻址低端物理内存的场合（例如处理器启动代码必须位于 1 MiB 以下）。
    /// Allocate a free frame whose start address is below `limit`; on failure nothing changes.
    pub fn allocate_below(&mut self, limit: u64) -> Result<PhysFrame, FrameError> {
        let last = limit / FRAME_SIZE;
        for n in 1..last {
            let Some(i) = self.word_index(n) else { break };
            let bit = 1u64 << (n % 64);
            if self.bits[i] & bit == 0 {
                self.bits[i] |= bit;
                self.free -= 1;
                return Ok(PhysFrame::from_number(n));
            }
        }
        Err(FrameError::OutOfFrames)
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

impl BitmapFrameAllocator<'_> {
    /// 分配 `count` 个物理相邻的空闲帧，返回首帧；失败时位图与空闲计数完全不变。
    ///
    /// 扫描从帧 1 开始，只接受整段都空闲的地址区间；保留区域与超出管理范围的帧在位图中
    /// 恒为已占用，因此结果不会跨越不可用空洞。`count` 为 0 或超过当前空闲帧数时直接拒绝。
    /// Allocates `count` physically adjacent free frames and returns the first one.
    pub fn allocate_contiguous(&mut self, count: usize) -> Result<PhysFrame, FrameError> {
        if count == 0 || count > self.free {
            return Err(FrameError::OutOfFrames);
        }
        let capacity = self.bits.len() as u64 * 64;
        let wanted = count as u64;
        let mut run_start = 1u64;
        let mut run = 0u64;
        let mut n = 1u64;
        while n < capacity {
            let Some(i) = self.word_index(n) else { break };
            let bit = 1u64 << (n % 64);
            if self.bits[i] & bit == 0 {
                if run == 0 {
                    run_start = n;
                }
                run += 1;
                if run == wanted {
                    for m in run_start..run_start + wanted {
                        // 已确认整段落在位图内且空闲，此处下标与位掩码必然有效。
                        let w = (m / 64) as usize;
                        self.bits[w] |= 1u64 << (m % 64);
                    }
                    self.free -= count;
                    return Ok(PhysFrame::from_number(run_start));
                }
            } else {
                run = 0;
            }
            n += 1;
        }
        Err(FrameError::OutOfFrames)
    }

    /// 归还 [`allocate_contiguous`](Self::allocate_contiguous) 取得的整段帧。
    ///
    /// 先校验整段的每一帧都可释放（在管理范围内、位于可用区域、当前已占用），全部通过后才修改位图；
    /// 任一帧不合法即整体拒绝且不留残留改动。`count` 为 0 同样拒绝。
    /// Releases a whole contiguous run after validating every frame.
    pub fn deallocate_contiguous(&mut self, first: PhysFrame, count: usize) -> Result<(), FrameError> {
        if first.start() % FRAME_SIZE != 0 {
            return Err(FrameError::Misaligned);
        }
        if count == 0 {
            return Err(FrameError::NotUsable);
        }
        let start = first.number();
        let end = start.checked_add(count as u64).ok_or(FrameError::NotUsable)?;
        for n in start..end {
            let frame = PhysFrame::from_number(n);
            if self.word_index(n).is_none() || !self.is_usable(frame) {
                return Err(FrameError::NotUsable);
            }
            if !self.is_used(frame) {
                return Err(FrameError::DoubleFree);
            }
        }
        for n in start..end {
            // 校验阶段已确认每一帧都可写；这里只做记账。
            let w = (n / 64) as usize;
            self.bits[w] &= !(1u64 << (n % 64));
        }
        self.free += count;
        Ok(())
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
    fn allocate_below_limit_succeeds_or_refuses_without_change() {
        let mut bits = [0u64; 64];
        let r = regions();
        let mut a = BitmapFrameAllocator::new(&mut bits, &r);
        let before = a.free_frames();
        // 低于 1 MiB 的第一个可用帧：帧 0 永不分配
        let f = a.allocate_below(MIB).expect("低端有可用帧");
        assert!(f.start() < MIB && f.number() != 0);
        assert!(a.is_used(f));
        assert_eq!(a.free_frames(), before - 1);
        // 极限低于第一个可用帧 ⇒ 拒绝，空闲数不变
        let free = a.free_frames();
        assert_eq!(a.allocate_below(FRAME_SIZE), Err(FrameError::OutOfFrames));
        assert_eq!(a.free_frames(), free);
        a.deallocate(f).unwrap();
        assert_eq!(a.free_frames(), before);
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

    #[test]
    fn contiguous_allocation_returns_adjacent_run() {
        let regs = regions();
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let before = a.free_frames();
        let base = a.allocate_contiguous(4).expect("有足够的连续空闲帧");
        for i in 0..4 {
            let frame = PhysFrame::from_number(base.number() + i);
            assert_eq!(frame.start(), base.start() + i * FRAME_SIZE);
            assert!(a.is_used(frame), "整段帧都应标记为已占用");
        }
        assert_eq!(a.free_frames(), before - 4);
        assert_eq!(base.start() % FRAME_SIZE, 0);
    }

    #[test]
    fn contiguous_deallocation_restores_baseline() {
        let regs = regions();
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let before = a.free_frames();
        let base = a.allocate_contiguous(3).expect("有足够的连续空闲帧");
        a.deallocate_contiguous(base, 3).expect("整段可归还");
        assert_eq!(a.free_frames(), before);
        for i in 0..3 {
            assert!(!a.is_used(PhysFrame::from_number(base.number() + i)));
        }
        // 归还后同样的区间应能再次分配。
        assert_eq!(a.allocate_contiguous(3), Ok(base));
    }

    #[test]
    fn contiguous_allocation_skips_fragmented_holes() {
        // 16 帧可用区域，帧 0 永不分配：1..16 共 15 帧。
        let regs = [PhysRegion { start: 0, end: 16 * FRAME_SIZE, kind: RegionKind::Usable }];
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        for _ in 0..15 {
            a.allocate().expect("整段可分配");
        }
        assert_eq!(a.free_frames(), 0);
        // 制造交替空洞：单个空闲帧无法组成两个连续帧。
        for n in [2u64, 4, 6, 8] {
            a.deallocate(PhysFrame::from_number(n)).unwrap();
        }
        let free = a.free_frames();
        let before_bits = a.bits.to_vec();
        assert_eq!(a.allocate_contiguous(2), Err(FrameError::OutOfFrames));
        assert_eq!(a.free_frames(), free, "失败不得改变空闲计数");
        assert_eq!(a.bits, before_bits.as_slice(), "失败不得改动位图");
        // 释放一对相邻帧后，首次适配应跳过所有单帧空洞找到它们。
        a.deallocate(PhysFrame::from_number(10)).unwrap();
        a.deallocate(PhysFrame::from_number(11)).unwrap();
        let base = a.allocate_contiguous(2).expect("存在相邻空洞");
        assert_eq!(base, PhysFrame::from_number(10));
    }

    #[test]
    fn contiguous_allocation_rejects_zero_and_oversized_without_change() {
        let regs = regions();
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let free = a.free_frames();
        let before_bits = a.bits.to_vec();
        assert_eq!(a.allocate_contiguous(0), Err(FrameError::OutOfFrames));
        assert_eq!(a.allocate_contiguous(free + 1), Err(FrameError::OutOfFrames));
        assert_eq!(a.allocate_contiguous(usize::MAX), Err(FrameError::OutOfFrames));
        assert_eq!(a.free_frames(), free);
        assert_eq!(a.bits, before_bits.as_slice());
    }

    #[test]
    fn contiguous_deallocation_rejects_invalid_runs_without_change() {
        let regs = regions();
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let before = a.free_frames();
        let base = a.allocate_contiguous(3).unwrap();
        a.deallocate_contiguous(base, 3).unwrap();
        assert_eq!(a.free_frames(), before);
        assert_eq!(a.deallocate_contiguous(base, 3), Err(FrameError::DoubleFree));
        assert_eq!(a.free_frames(), before);

        let base = a.allocate_contiguous(2).unwrap();
        let free = a.free_frames();
        let before_bits = a.bits.to_vec();
        // 第三帧仍空闲：整段校验失败，前两帧也必须保持已占用。
        assert_eq!(a.deallocate_contiguous(base, 3), Err(FrameError::DoubleFree));
        assert_eq!(a.free_frames(), free);
        assert_eq!(a.bits, before_bits.as_slice());
        assert!(a.is_used(base) && a.is_used(PhysFrame::from_number(base.number() + 1)));

        assert_eq!(a.deallocate_contiguous(PhysFrame::from_number(900), 2), Err(FrameError::NotUsable));
        assert_eq!(a.deallocate_contiguous(base, 0), Err(FrameError::NotUsable));
        assert_eq!(a.deallocate_contiguous(PhysFrame(4097), 1), Err(FrameError::Misaligned));
        assert_eq!(a.free_frames(), free);
        assert_eq!(a.bits, before_bits.as_slice());
    }

    #[test]
    fn contiguous_allocation_never_spans_reserved_hole() {
        // 可用 0..8 帧、保留 8..12 帧、可用 12..20 帧，两段之间是不可用空洞。
        let regs = [
            PhysRegion { start: 0, end: 8 * FRAME_SIZE, kind: RegionKind::Usable },
            PhysRegion { start: 8 * FRAME_SIZE, end: 12 * FRAME_SIZE, kind: RegionKind::Reserved },
            PhysRegion { start: 12 * FRAME_SIZE, end: 20 * FRAME_SIZE, kind: RegionKind::Usable },
        ];
        let mut bits = [0u64; 16];
        let mut a = BitmapFrameAllocator::new(&mut bits, &regs);
        let free = a.free_frames();
        let before_bits = a.bits.to_vec();
        // 单段最多 8 帧，9 帧必然跨越空洞 ⇒ 拒绝且无改动。
        assert_eq!(a.allocate_contiguous(9), Err(FrameError::OutOfFrames));
        assert_eq!(a.free_frames(), free);
        assert_eq!(a.bits, before_bits.as_slice());
        // 第二段恰好 8 帧，应整段分自帧 12，而不是跨过保留区。
        let base = a.allocate_contiguous(8).expect("第二段足够 8 帧");
        assert_eq!(base, PhysFrame::from_number(12));
        for n in 8..12 {
            assert!(a.is_used(PhysFrame::from_number(n)));
        }
        // 第一段只剩 7 帧，分配 7 帧应从帧 1 开始。
        assert_eq!(a.allocate_contiguous(7), Ok(PhysFrame::from_number(1)));
    }
}
