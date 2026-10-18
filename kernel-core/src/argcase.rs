//! 系统调用参数用例生成：确定性伪随机数 + 偏向边界值的整数 + 不触碰受保护区间的地址规划。
//! Deterministic argument-case generation for system-call robustness tests.
//!
//! # 职责
//! 健壮性回归测试要用大量「坏参数」反复调用系统接口，检查每次都被干净地拒绝（或合法地完成）、
//! 内核不崩溃、资源回到基线。本模块只负责**产生参数**，不发起调用：
//! * [`Prng`] —— xorshift64* 伪随机数发生器，固定种子即可复现整条序列（不是密码学用途）
//! * [`BOUNDARY_VALUES`] / [`Prng::boundary_biased`] —— 溢出、截断、对齐类缺陷集中出现的边界值
//! * [`AddressPlan`] —— 给出地址与区间时避开调用方声明的受保护区间（自身代码、栈、堆、校验页），
//!   让测试程序不会因为**正确**的内核照办了一个合法请求而毁掉自己
//!
//! # 边界
//! 只依赖 `core`，宿主测试、内核与用户程序共用同一份实现。地址的含义（哪里是用户窗口、页多大）
//! 全部由调用方给出，本模块不含任何指令集或内存布局常量。
//!
//! # 「安全」的确切含义
//! 区间 `[addr, addr + len)` 的算术不溢出时，它必须与每个受保护区间都不相交；算术溢出（回绕）的区间
//! 本身就是非法请求，正确的内核必然拒绝，因此视为安全——若内核错误地照办了，测试程序会因自身内存
//! 被破坏而失败，这正是测试要发现的缺陷。

/// xorshift64* 伪随机数发生器（确定性、可复现；非密码学用途）。
/// Deterministic xorshift64* generator.
#[derive(Debug, Clone)]
pub struct Prng(u64);

impl Prng {
    /// 由种子创建；种子 0 会被替换为 1（xorshift 的状态不能为 0）。
    /// Creates a generator from a seed (0 is mapped to 1).
    pub const fn new(seed: u64) -> Self {
        Prng(if seed == 0 { 1 } else { seed })
    }

    /// 下一个 64 位数。
    /// Next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// `[0, n)` 内的数；`n == 0` 时按 1 处理（恒为 0）。
    /// A value in `[0, n)`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }

    /// 以 `percent`% 的概率返回 `true`（≥100 恒为真）。
    /// Returns `true` with the given percentage.
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    /// 从非空切片中等概率取一个元素；空切片返回 `None`。
    /// Picks one element uniformly.
    pub fn pick<T: Copy>(&mut self, items: &[T]) -> Option<T> {
        if items.is_empty() {
            return None;
        }
        Some(items[self.below(items.len() as u64) as usize])
    }

    /// 偏向边界值的 64 位数：一半取 [`BOUNDARY_VALUES`]，一半取完全随机的数。
    /// A 64-bit value biased toward boundary values.
    pub fn boundary_biased(&mut self) -> u64 {
        if self.chance(50) {
            BOUNDARY_VALUES[self.below(BOUNDARY_VALUES.len() as u64) as usize]
        } else {
            self.next_u64()
        }
    }
}

/// 边界值：零与一、页边界两侧、32 位上限两侧（截断）、符号位、64 位上限附近（溢出）、
/// 48 位规范地址分界两侧（高半区 / 非规范地址）。
/// Boundary values where overflow, truncation and alignment defects cluster.
pub const BOUNDARY_VALUES: [u64; 16] = [
    0,
    1,
    0xfff,
    0x1000,
    0x1001,
    0x7fff_ffff,
    0xffff_ffff,
    0x1_0000_0000,
    0x1_0000_0001,
    0x0000_7fff_ffff_f000,
    0x0000_8000_0000_0000,
    0xffff_8000_0000_0000,
    1 << 63,
    u64::MAX - 0x1000,
    u64::MAX - 0xfff,
    u64::MAX,
];

/// 一段地址区间 `[start, start + len)`。
/// An address span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// 起点。
    pub start: u64,
    /// 长度（字节）。
    pub len: u64,
}

impl Span {
    /// 构造区间。
    /// Creates a span.
    pub const fn new(start: u64, len: u64) -> Self {
        Span { start, len }
    }

    /// 终点（不含）；算术溢出时为 `None`。
    /// Exclusive end, or `None` on overflow.
    pub const fn end(&self) -> Option<u64> {
        self.start.checked_add(self.len)
    }

    /// 与 `[addr, addr + len)` 是否相交（两者都不溢出时才有意义；空区间与任何区间都不相交）。
    /// Whether the span intersects `[addr, addr + len)`.
    pub fn intersects(&self, addr: u64, len: u64) -> bool {
        match (self.end(), addr.checked_add(len)) {
            (Some(e), Some(end)) => len != 0 && self.len != 0 && addr < e && self.start < end,
            _ => false,
        }
    }

    /// 是否完整包含 `[addr, addr + len)`。
    /// Whether the span contains `[addr, addr + len)`.
    pub fn contains(&self, addr: u64, len: u64) -> bool {
        match (self.end(), addr.checked_add(len)) {
            (Some(e), Some(end)) => addr >= self.start && end <= e,
            _ => false,
        }
    }
}

/// [`AddressPlan`] 的配置错误（被拒时不构造任何规划）。
/// Configuration errors of an [`AddressPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// 页大小不是 2 的幂。
    BadPageSize,
    /// 没有给出任何目标区间。
    NoTargets,
    /// 某个区间为空或终点溢出。
    BadSpan,
    /// 目标区间未按页对齐。
    UnalignedTarget,
    /// 目标区间与受保护区间相交。
    TargetProtected,
}

/// 地址规划：在「目标区间」（测试程序专门准备的区域）与边界值之间挑选地址，保证结果不会让正确的内核
/// 改动受保护区间。
/// Picks addresses for test cases while keeping protected spans untouched.
#[derive(Debug, Clone, Copy)]
pub struct AddressPlan<'a> {
    protected: &'a [Span],
    targets: &'a [Span],
    page: u64,
}

impl<'a> AddressPlan<'a> {
    /// 校验并创建规划：页大小为 2 的幂；至少一个目标区间；全部区间非空且终点不溢出；
    /// 目标区间按页对齐且不与任何受保护区间相交。
    /// Validates and creates a plan.
    pub fn new(protected: &'a [Span], targets: &'a [Span], page: u64) -> Result<Self, PlanError> {
        if !page.is_power_of_two() {
            return Err(PlanError::BadPageSize);
        }
        if targets.is_empty() {
            return Err(PlanError::NoTargets);
        }
        if protected.iter().chain(targets).any(|s| s.len == 0 || s.end().is_none()) {
            return Err(PlanError::BadSpan);
        }
        if targets.iter().any(|t| t.start % page != 0 || t.len % page != 0) {
            return Err(PlanError::UnalignedTarget);
        }
        if targets.iter().any(|t| protected.iter().any(|p| p.intersects(t.start, t.len))) {
            return Err(PlanError::TargetProtected);
        }
        Ok(AddressPlan { protected, targets, page })
    }

    /// 页大小。
    /// Page size.
    pub fn page(&self) -> u64 {
        self.page
    }

    /// 字节区间 `[addr, addr + len)` 对正确的内核是否安全（见模块文档：溢出的区间视为安全）。
    /// Whether a byte range is safe to hand to a correct kernel.
    pub fn is_safe(&self, addr: u64, len: u64) -> bool {
        if addr.checked_add(len).is_none() {
            return true;
        }
        !self.protected.iter().any(|p| p.intersects(addr, len))
    }

    /// 页区间 `[addr, addr + pages 页)` 是否安全（页数乘法溢出同样视为安全）。
    /// Whether a page range is safe.
    pub fn is_safe_pages(&self, addr: u64, pages: u64) -> bool {
        match pages.checked_mul(self.page) {
            Some(len) => self.is_safe(addr, len),
            None => true,
        }
    }

    /// 挑一个指针，供长度为 `len` 的读写使用：目标区间内（含跨越末尾、未对齐）、边界值或完全随机；
    /// 结果不安全时退回第一个目标区间的起点。
    /// Picks a pointer for an access of `len` bytes.
    pub fn pick_ptr(&self, rng: &mut Prng, len: u64) -> u64 {
        let p = match rng.below(4) {
            0 | 1 => {
                let t = self.target(rng);
                // 区间内任意偏移；有一半机会贴着末尾，让访问越过区间终点
                if rng.chance(50) {
                    t.start + rng.below(t.len)
                } else {
                    (t.start + t.len).saturating_sub(rng.below(len.max(1) + 1))
                }
            }
            2 => rng.boundary_biased(),
            _ => rng.next_u64(),
        };
        if self.is_safe(p, len) {
            p
        } else {
            self.targets[0].start
        }
    }

    /// 挑一个页区间 `(起点, 页数)`：目标区间内的整页、未对齐的起点、边界页数或边界地址；
    /// 结果不安全时退回第一个目标区间的第一页。
    /// Picks a page range `(addr, pages)`.
    pub fn pick_pages(&self, rng: &mut Prng) -> (u64, u64) {
        let t = self.target(rng);
        let in_target = t.len / self.page;
        let addr = match rng.below(4) {
            0 | 1 => t.start + rng.below(in_target) * self.page,
            2 => t.start + rng.below(t.len),
            _ => rng.boundary_biased(),
        };
        let pages = match rng.below(3) {
            0 | 1 => 1 + rng.below(in_target),
            _ => rng.boundary_biased(),
        };
        if self.is_safe_pages(addr, pages) {
            (addr, pages)
        } else {
            (self.targets[0].start, 1)
        }
    }

    fn target(&self, rng: &mut Prng) -> Span {
        self.targets[rng.below(self.targets.len() as u64) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 0x1000;
    const PROTECTED: [Span; 2] = [Span::new(0x40_0000, 0x10_0000), Span::new(0x80_0000, PAGE)];
    const TARGETS: [Span; 2] = [Span::new(0x100_0000, 16 * PAGE), Span::new(0x200_0000, 2 * PAGE)];

    #[test]
    fn same_seed_same_sequence_and_seed_zero_is_usable() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut z = Prng::new(0);
        assert_ne!(z.next_u64(), 0, "种子 0 不得卡死在全零状态");
        let mut c = Prng::new(43);
        assert_ne!(Prng::new(42).next_u64(), c.next_u64());
    }

    #[test]
    fn below_chance_pick_stay_in_range() {
        let mut r = Prng::new(7);
        for n in [1u64, 2, 3, 10, 1000] {
            for _ in 0..200 {
                assert!(r.below(n) < n);
            }
        }
        assert_eq!(r.below(0), 0, "n = 0 按 1 处理");
        assert!((0..100).all(|_| !r.chance(0)));
        assert!((0..100).all(|_| r.chance(100)));
        assert_eq!(r.pick::<u8>(&[]), None);
        assert!((0..100).all(|_| [3u8, 5].contains(&r.pick(&[3u8, 5]).unwrap())));
    }

    #[test]
    fn boundary_bias_reaches_every_boundary_value() {
        let mut r = Prng::new(9);
        let mut seen = [false; BOUNDARY_VALUES.len()];
        for _ in 0..20_000 {
            let v = r.boundary_biased();
            if let Some(i) = BOUNDARY_VALUES.iter().position(|&b| b == v) {
                seen[i] = true;
            }
        }
        assert!(seen.iter().all(|&s| s), "每个边界值都应被取到：{:?}", seen);
    }

    #[test]
    fn span_intersection_and_containment() {
        let s = Span::new(0x1000, 0x1000);
        assert!(s.intersects(0x1fff, 1));
        assert!(!s.intersects(0x2000, 1));
        assert!(!s.intersects(0x0, 0x1000));
        assert!(!s.intersects(0x1800, 0), "空区间与任何区间都不相交");
        assert!(!s.intersects(u64::MAX, 2), "溢出的区间不参与相交判断");
        assert!(s.contains(0x1000, 0x1000));
        assert!(!s.contains(0x1000, 0x1001));
        assert_eq!(Span::new(u64::MAX, 2).end(), None);
    }

    #[test]
    fn invalid_plans_are_refused() {
        assert_eq!(AddressPlan::new(&PROTECTED, &TARGETS, 3000).err(), Some(PlanError::BadPageSize));
        assert_eq!(AddressPlan::new(&PROTECTED, &[], PAGE).err(), Some(PlanError::NoTargets));
        assert_eq!(AddressPlan::new(&[Span::new(5, 0)], &TARGETS, PAGE).err(), Some(PlanError::BadSpan));
        assert_eq!(AddressPlan::new(&PROTECTED, &[Span::new(u64::MAX - PAGE + 1, 2 * PAGE)], PAGE).err(), Some(PlanError::BadSpan));
        assert_eq!(AddressPlan::new(&PROTECTED, &[Span::new(0x100_0800, PAGE)], PAGE).err(), Some(PlanError::UnalignedTarget));
        assert_eq!(AddressPlan::new(&PROTECTED, &[Span::new(0x7f_f000, 2 * PAGE)], PAGE).err(), Some(PlanError::TargetProtected));
        assert!(AddressPlan::new(&PROTECTED, &TARGETS, PAGE).is_ok());
    }

    #[test]
    fn safety_rules() {
        let plan = AddressPlan::new(&PROTECTED, &TARGETS, PAGE).unwrap();
        assert!(!plan.is_safe(0x40_0000, 1));
        assert!(!plan.is_safe(0x3f_ffff, 2), "跨入受保护区间");
        assert!(plan.is_safe(0x3f_f000, PAGE), "紧贴受保护区间之前");
        assert!(plan.is_safe(u64::MAX, 2), "回绕的区间必被正确的内核拒绝");
        assert!(plan.is_safe_pages(0x40_0000, u64::MAX), "页数乘法溢出");
        assert!(!plan.is_safe_pages(0x3f_f000, 2));
    }

    #[test]
    fn generated_cases_never_touch_protected_spans() {
        let plan = AddressPlan::new(&PROTECTED, &TARGETS, PAGE).unwrap();
        let mut r = Prng::new(0x5eed);
        let (mut in_target, mut crossing, mut boundary_pages) = (0, 0, 0);
        for _ in 0..50_000 {
            let len = r.pick(&[1u64, 8, 32, 56, 4096, 4097]).unwrap();
            let p = plan.pick_ptr(&mut r, len);
            assert!(plan.is_safe(p, len), "指针 {:#x}+{} 触及受保护区间", p, len);
            if TARGETS.iter().any(|t| t.contains(p, len)) {
                in_target += 1;
            } else if TARGETS.iter().any(|t| t.intersects(p, len)) {
                crossing += 1;
            }
            let (a, n) = plan.pick_pages(&mut r);
            assert!(plan.is_safe_pages(a, n), "页区间 {:#x}×{} 触及受保护区间", a, n);
            if BOUNDARY_VALUES.contains(&n) {
                boundary_pages += 1;
            }
        }
        // 分布：多数落在目标区间、确有越过末尾的访问、确有边界页数
        assert!(in_target > 10_000 && crossing > 1_000 && boundary_pages > 1_000, "{} {} {}", in_target, crossing, boundary_pages);
    }

    #[test]
    fn unsafe_picks_fall_back_to_first_target() {
        // 受保护区间覆盖了除目标外的全部低地址：随机指针多数不安全，必须退回目标起点
        let protected = [Span::new(0, 0x100_0000), Span::new(0x101_0000, u64::MAX - 0x101_0000)];
        let targets = [Span::new(0x100_0000, 16 * PAGE)];
        let plan = AddressPlan::new(&protected, &targets, PAGE).unwrap();
        let mut r = Prng::new(3);
        let mut fallbacks = 0;
        for _ in 0..5_000 {
            let p = plan.pick_ptr(&mut r, 8);
            assert!(plan.is_safe(p, 8));
            if p == targets[0].start {
                fallbacks += 1;
            }
        }
        assert!(fallbacks > 0);
    }
}
