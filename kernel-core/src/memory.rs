//! 虚拟内存抽象与记账（`system.memory` 领域）。
//!
//! # 职责
//! * [`VmProtection`]：区域保护位（读/写/执行）
//! * [`VmRegion`]：一段映射：基址、大小、保护
//! * [`AddressSpace`]：地址空间契约——`map_anonymous` / `unmap` / `protect` / `regions`
//! * [`SimpleAddressSpace`]：纯记账实现，匿名映射从 `0x1000_0000` 起按 4 KiB 对齐递增分配
//!
//! # 边界（为什么这里没有页表）
//! 页表格式是 ISA 相关的（x86_64 四级页表、RISC-V Sv48、AArch64 TTBR……），属于 `arch/`。
//! Core 只维护「哪些虚拟区间、以什么权限存在」的账本；M2.2/M2.3 会提供第二个
//! [`AddressSpace`] 实现，在记账的同时调用 arch 的页表接口做真实映射——契约不变。
//!
//! `SimpleAddressSpace` 的地址只增不回收（区间被 `unmap` 后不再复用），这让「释放后访问」
//! 必然落在未映射区；代价是虚拟地址空间单调消耗，对记账实现可以接受。

use core::fmt;

/// 页大小（4 KiB；各 ISA 的最小页都不小于它）。
pub const PAGE_SIZE: u64 = 0x1000;
/// 匿名映射的起始地址（沿用原型）。
pub const ANON_BASE: u64 = 0x1000_0000;

/// 区域保护位掩码。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VmProtection(u8);

impl VmProtection {
    /// 不可访问。
    pub const NONE: VmProtection = VmProtection(0);
    /// 可读。
    pub const READ: VmProtection = VmProtection(1 << 0);
    /// 可写。
    pub const WRITE: VmProtection = VmProtection(1 << 1);
    /// 可执行。
    pub const EXECUTE: VmProtection = VmProtection(1 << 2);
    /// 读写（匿名映射的默认值）。
    pub const READ_WRITE: VmProtection = VmProtection(0b011);

    /// 是否包含 `other` 的全部位。
    pub const fn contains(self, other: VmProtection) -> bool {
        self.0 & other.0 == other.0
    }

    /// 并集。
    pub const fn union(self, other: VmProtection) -> VmProtection {
        VmProtection(self.0 | other.0)
    }

    /// 是否同时可写又可执行（W^X 策略据此拒绝；策略本身由上层决定）。
    pub const fn is_writable_executable(self) -> bool {
        self.contains(VmProtection::WRITE.union(VmProtection::EXECUTE))
    }
}

/// 输出形如 `rw-`。
impl fmt::Display for VmProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = |p, ch| if self.contains(p) { ch } else { '-' };
        write!(
            f,
            "{}{}{}",
            c(VmProtection::READ, 'r'),
            c(VmProtection::WRITE, 'w'),
            c(VmProtection::EXECUTE, 'x')
        )
    }
}

impl fmt::Debug for VmProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VmProtection({})", self)
    }
}

/// 一段虚拟内存映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmRegion {
    /// 起始地址（页对齐）。
    pub base: u64,
    /// 大小（页对齐，> 0）。
    pub size: u64,
    /// 保护位。
    pub protection: VmProtection,
}

impl VmRegion {
    /// 结束地址（不含）。
    pub const fn end(&self) -> u64 {
        self.base + self.size
    }

    /// 地址是否落在区域内。
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

/// 地址空间错误（`system.memory.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// 大小为 0 或对齐后溢出。
    InvalidSize,
    /// 没有以该地址为基址的区域。
    NotFound,
    /// 区域表已满或地址空间耗尽。
    NoSpace,
}

impl VmError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            VmError::InvalidSize => "system.memory.error.invalid_size",
            VmError::NotFound => "system.memory.error.not_found",
            VmError::NoSpace => "system.memory.error.no_space",
        }
    }
}

/// 地址空间契约。
pub trait AddressSpace {
    /// 映射一段匿名内存，大小向上对齐到页（`system.memory.map`）。
    fn map_anonymous(&mut self, size: u64, protection: VmProtection) -> Result<VmRegion, VmError>;
    /// 解除以 `base` 为基址的映射（`system.memory.unmap`）。
    fn unmap(&mut self, base: u64) -> Result<VmRegion, VmError>;
    /// 修改以 `base` 为基址的区域的保护位（`system.memory.protect`）。
    fn protect(&mut self, base: u64, protection: VmProtection) -> Result<VmRegion, VmError>;
    /// 当前全部区域（按基址升序）。
    fn regions(&self) -> &[VmRegion];

    /// 查找包含 `addr` 的区域。
    fn find(&self, addr: u64) -> Option<VmRegion> {
        self.regions().iter().copied().find(|r| r.contains(addr))
    }
}

/// 向上对齐到页；0 或溢出返回 `None`。
pub const fn page_align_up(size: u64) -> Option<u64> {
    if size == 0 {
        return None;
    }
    match size.checked_add(PAGE_SIZE - 1) {
        Some(s) => Some(s & !(PAGE_SIZE - 1)),
        None => None,
    }
}

/// 纯记账的地址空间，最多 `N` 个区域，不使用堆。
pub struct SimpleAddressSpace<const N: usize> {
    next_base: u64,
    regions: [VmRegion; N],
    len: usize,
}

impl<const N: usize> SimpleAddressSpace<N> {
    const EMPTY: VmRegion = VmRegion { base: 0, size: 0, protection: VmProtection::NONE };

    /// 新建空地址空间。
    pub const fn new() -> Self {
        SimpleAddressSpace { next_base: ANON_BASE, regions: [Self::EMPTY; N], len: 0 }
    }

    /// 已映射总字节数。
    pub fn mapped_bytes(&self) -> u64 {
        self.regions().iter().map(|r| r.size).sum()
    }

    fn index_of(&self, base: u64) -> Result<usize, VmError> {
        self.regions().iter().position(|r| r.base == base).ok_or(VmError::NotFound)
    }
}

impl<const N: usize> Default for SimpleAddressSpace<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AddressSpace for SimpleAddressSpace<N> {
    fn map_anonymous(&mut self, size: u64, protection: VmProtection) -> Result<VmRegion, VmError> {
        let size = page_align_up(size).ok_or(VmError::InvalidSize)?;
        if self.len == N {
            return Err(VmError::NoSpace);
        }
        let end = self.next_base.checked_add(size).ok_or(VmError::NoSpace)?;
        let region = VmRegion { base: self.next_base, size, protection };
        // 基址单调递增 ⇒ 追加到末尾即保持升序。
        self.regions[self.len] = region;
        self.len += 1;
        self.next_base = end;
        Ok(region)
    }

    fn unmap(&mut self, base: u64) -> Result<VmRegion, VmError> {
        let i = self.index_of(base)?;
        let removed = self.regions[i];
        self.regions.copy_within(i + 1..self.len, i);
        self.len -= 1;
        Ok(removed)
    }

    fn protect(&mut self, base: u64, protection: VmProtection) -> Result<VmRegion, VmError> {
        let i = self.index_of(base)?;
        self.regions[i].protection = protection;
        Ok(self.regions[i])
    }

    fn regions(&self) -> &[VmRegion] {
        &self.regions[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_aligns_to_pages_from_anon_base() {
        let mut a: SimpleAddressSpace<4> = SimpleAddressSpace::new();
        let r1 = a.map_anonymous(64, VmProtection::READ_WRITE).unwrap();
        assert_eq!((r1.base, r1.size), (ANON_BASE, PAGE_SIZE));
        let r2 = a.map_anonymous(PAGE_SIZE + 1, VmProtection::READ).unwrap();
        assert_eq!((r2.base, r2.size), (ANON_BASE + PAGE_SIZE, 2 * PAGE_SIZE));
        assert_eq!(a.mapped_bytes(), 3 * PAGE_SIZE);
        assert_eq!(a.find(ANON_BASE + 0x1800), Some(r2));
        assert!(r1.contains(ANON_BASE + 63) && !r1.contains(r1.end()));
    }

    #[test]
    fn invalid_sizes_rejected() {
        let mut a: SimpleAddressSpace<1> = SimpleAddressSpace::new();
        assert_eq!(a.map_anonymous(0, VmProtection::READ), Err(VmError::InvalidSize));
        assert_eq!(a.map_anonymous(u64::MAX, VmProtection::READ), Err(VmError::InvalidSize));
        a.map_anonymous(1, VmProtection::READ).unwrap();
        assert_eq!(a.map_anonymous(1, VmProtection::READ), Err(VmError::NoSpace));
    }

    #[test]
    fn unmap_and_protect() {
        let mut a: SimpleAddressSpace<4> = SimpleAddressSpace::new();
        let r1 = a.map_anonymous(1, VmProtection::READ_WRITE).unwrap();
        let r2 = a.map_anonymous(1, VmProtection::READ_WRITE).unwrap();
        let p = a.protect(r2.base, VmProtection::READ.union(VmProtection::EXECUTE)).unwrap();
        assert_eq!(format!("{}", p.protection), "r-x");
        assert_eq!(a.unmap(r1.base), Ok(r1));
        assert_eq!(a.unmap(r1.base), Err(VmError::NotFound));
        assert_eq!(a.regions(), &[p]);
        let r3 = a.map_anonymous(1, VmProtection::READ).unwrap();
        assert!(r3.base > r2.base, "释放的地址不复用");
        assert_eq!(a.find(r1.base), None);
    }

    #[test]
    fn wx_detection() {
        assert!(VmProtection::WRITE.union(VmProtection::EXECUTE).is_writable_executable());
        assert!(!VmProtection::READ_WRITE.is_writable_executable());
    }
}
