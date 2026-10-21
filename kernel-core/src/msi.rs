//! 每核 MSI 向量池：每个处理器一张独立位图，分配与释放互不影响。
//! Per-processor MSI vector pools: one independent bitmap per processor.
//!
//! # 职责
//! * 把调用者给出的连续向量范围切成每个处理器各自的一份资源：同一向量号在多个处理器上
//!   可以同时被分配（MSI 的目标处理器决定实际投递到哪一核，向量号本身是每核私有的）。
//! * [`VectorPool::alloc`] 从低位起找第一个空闲向量；[`VectorPool::free`] 只释放该处理器
//!   自己分配过的向量。成功路径返回向量号，失败路径返回结构化错误且**位图保持不变**。
//!
//! # 边界与原因
//! * 范围内不出现任何具体向量号：范围（起点与个数）由指令集层给出，本模块只做记账。
//! * 每个处理器一把锁、一张位图，没有全局锁：不同处理器同时分配时不会互相等待。
//! * 处理器是否存在 / 是否在线由调用者在构造时以集合给出；不在线处理器的分配与释放一律被拒。
//! * 只依赖 `core`，因此成功与失败路径都能在宿主上确定性测试。

use crate::smp::{CpuSet, MAX_CPUS};
use crate::sync::SpinLock;

/// 向量编号的取值上限（`u8` 的全部取值）。
/// Number of representable vector numbers.
pub const MAX_SLOTS: usize = 256;

/// 每核位图的 64 位字数。
/// Number of 64-bit words per CPU bitmap.
const WORDS: usize = MAX_SLOTS / 64;

/// 向量池错误。
/// Vector-pool error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsiError {
    /// 处理器下标超出容量。
    /// The processor index is outside the supported capacity.
    NoSuchCpu,
    /// 处理器存在但不在线。
    /// The processor exists but is not online.
    NotOnline,
    /// 该处理器的向量已用尽。
    /// Every vector of this processor is already allocated.
    Exhausted,
    /// 向量号不在本池的范围内。
    /// The vector is outside this pool's range.
    OutOfRange,
    /// 向量在该处理器上没有分配（含重复释放与释放别核的向量）。
    /// The vector is not allocated on this processor.
    NotAllocated,
    /// 构造参数非法（空范围或越过 256 个向量）。
    /// The requested range is empty or exceeds 256 vectors.
    BadRange,
    /// 平台没有提供 MSI 向量范围。
    /// The platform provides no MSI vector range.
    Unsupported,
    /// 平台投递 MSI 超时（消息未送达）。
    /// The platform timed out while delivering an MSI message.
    Timeout,
}

impl MsiError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            MsiError::NoSuchCpu => "system.cpu.error.no_such_cpu",
            MsiError::NotOnline => "system.cpu.error.not_online",
            MsiError::Exhausted => "system.irq.error.msi_exhausted",
            MsiError::OutOfRange => "system.irq.error.msi_vector_out_of_range",
            MsiError::NotAllocated => "system.irq.error.msi_not_allocated",
            MsiError::BadRange => "system.irq.error.msi_bad_range",
            MsiError::Unsupported => "system.irq.error.msi_unsupported",
            MsiError::Timeout => "system.irq.error.msi_timeout",
        }
    }
}

/// 一个 MSI 向量号（构造时不校验范围；范围由所属向量池判定）。
/// One MSI vector number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vector(u8);

impl Vector {
    /// 由原始编号构造。
    /// Builds a vector from its raw number.
    pub const fn new(value: u8) -> Vector {
        Vector(value)
    }

    /// 原始编号。
    /// Raw vector number.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// 每核一张位图的向量池。
/// A pool with one bitmap per processor.
pub struct VectorPool {
    first: u8,
    count: u8,
    online: CpuSet,
    bits: [SpinLock<[u64; WORDS]>; MAX_CPUS],
}

impl VectorPool {
    /// 构造向量池：`[first, first + count)` 是每核可用的向量范围，`online` 是参与分配的处理器。
    ///
    /// `count == 0` 或范围越过 256 个向量时返回 [`MsiError::BadRange`]，不产生对象。
    /// Builds a pool over `[first, first + count)` for the processors in `online`.
    pub fn new(first: u8, count: u8, online: CpuSet) -> Result<VectorPool, MsiError> {
        if count == 0 || first as u16 + count as u16 > MAX_SLOTS as u16 {
            return Err(MsiError::BadRange);
        }
        Ok(VectorPool {
            first,
            count,
            online,
            bits: [const { SpinLock::new([0u64; WORDS]) }; MAX_CPUS],
        })
    }

    /// 范围起点。
    /// First vector of the range.
    pub const fn first(&self) -> u8 {
        self.first
    }

    /// 每核的向量个数。
    /// Number of vectors per processor.
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// 参与分配的处理器集合（构造后不变）。
    /// Processor set taking part in allocation.
    pub const fn online(&self) -> CpuSet {
        self.online
    }

    /// 处理器 `cpu` 是否可参与分配。
    /// Whether `cpu` may allocate from this pool.
    pub fn available(&self, cpu: usize) -> bool {
        cpu < MAX_CPUS && self.online.contains(cpu)
    }

    /// 处理器 `cpu` 已分配的向量个数；处理器无效时返回 0（诊断用）。
    /// Number of vectors allocated on `cpu`, or 0 when the CPU is invalid.
    pub fn allocated(&self, cpu: usize) -> usize {
        if !self.available(cpu) {
            return 0;
        }
        self.bits[cpu].lock().iter().map(|w| w.count_ones() as usize).sum()
    }

    /// 向量 `vector` 是否在处理器 `cpu` 上已分配。
    /// Whether `vector` is allocated on `cpu`.
    pub fn is_allocated(&self, cpu: usize, vector: Vector) -> Result<bool, MsiError> {
        self.check_cpu(cpu)?;
        let index = self.index(vector)?;
        let (word, bit) = (index / 64, index % 64);
        Ok(self.bits[cpu].lock()[word] & (1u64 << bit) != 0)
    }

    /// 在处理器 `cpu` 上分配一个向量；用尽返回 [`MsiError::Exhausted`]，位图不变。
    ///
    /// 只锁该处理器自己的位图，其他处理器的分配不受影响。
    /// Allocates the lowest free vector on `cpu`.
    pub fn alloc(&self, cpu: usize) -> Result<Vector, MsiError> {
        self.check_cpu(cpu)?;
        let mut bits = self.bits[cpu].lock();
        for index in 0..self.count as usize {
            let (word, bit) = (index / 64, index % 64);
            if bits[word] & (1u64 << bit) == 0 {
                bits[word] |= 1u64 << bit;
                return Ok(Vector::new(self.first + index as u8));
            }
        }
        Err(MsiError::Exhausted)
    }

    /// 释放处理器 `cpu` 上的向量 `vector`。
    ///
    /// 未分配、重复释放、或该向量属于别的处理器时返回 [`MsiError::NotAllocated`] 且位图不变。
    /// Frees an allocated vector of `cpu`.
    pub fn free(&self, cpu: usize, vector: Vector) -> Result<(), MsiError> {
        self.check_cpu(cpu)?;
        let index = self.index(vector)?;
        let (word, bit) = (index / 64, index % 64);
        let mut bits = self.bits[cpu].lock();
        if bits[word] & (1u64 << bit) == 0 {
            return Err(MsiError::NotAllocated);
        }
        bits[word] &= !(1u64 << bit);
        Ok(())
    }

    /// 释放处理器 `cpu` 的全部向量，返回释放个数。
    /// Frees every vector of `cpu` and returns how many were allocated.
    pub fn free_all(&self, cpu: usize) -> Result<usize, MsiError> {
        self.check_cpu(cpu)?;
        let mut bits = self.bits[cpu].lock();
        let freed = bits.iter().map(|w| w.count_ones() as usize).sum();
        *bits = [0u64; WORDS];
        Ok(freed)
    }

    fn check_cpu(&self, cpu: usize) -> Result<(), MsiError> {
        if cpu >= MAX_CPUS {
            Err(MsiError::NoSuchCpu)
        } else if !self.online.contains(cpu) {
            Err(MsiError::NotOnline)
        } else {
            Ok(())
        }
    }

    /// 向量在范围中的下标。
    fn index(&self, vector: Vector) -> Result<usize, MsiError> {
        match (vector.get() as u16).checked_sub(self.first as u16) {
            Some(delta) if delta < self.count as u16 => Ok(delta as usize),
            _ => Err(MsiError::OutOfRange),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpus(list: &[usize]) -> CpuSet {
        let mut set = CpuSet::EMPTY;
        for &cpu in list {
            set.insert(cpu);
        }
        set
    }

    fn pool(first: u8, count: u8, online: &[usize]) -> VectorPool {
        VectorPool::new(first, count, cpus(online)).unwrap()
    }

    #[test]
    fn allocates_lowest_free_vector_and_each_cpu_has_its_own_bitmap() {
        let p = pool(0x60, 4, &[0, 1]);
        assert_eq!(p.alloc(0), Ok(Vector::new(0x60)));
        assert_eq!(p.alloc(0), Ok(Vector::new(0x61)));
        assert_eq!(p.alloc(1), Ok(Vector::new(0x60)), "同一向量号在另一核上独立");
        assert_eq!(p.allocated(0), 2);
        assert_eq!(p.allocated(1), 1);
        assert_eq!(p.free(0, Vector::new(0x60)), Ok(()));
        assert_eq!(p.alloc(0), Ok(Vector::new(0x60)), "释放后的最低位重新可用");
        assert!(p.is_allocated(1, Vector::new(0x60)).unwrap());
        assert_eq!(p.count(), 4);
        assert_eq!(p.first(), 0x60);
        assert_eq!(p.online(), cpus(&[0, 1]));
    }

    #[test]
    fn exhaustion_is_per_cpu_and_leaves_bitmap_unchanged() {
        let p = pool(0x80, 2, &[0, 1]);
        assert_eq!(p.alloc(0), Ok(Vector::new(0x80)));
        assert_eq!(p.alloc(0), Ok(Vector::new(0x81)));
        assert_eq!(p.alloc(0), Err(MsiError::Exhausted));
        assert_eq!(p.alloc(0), Err(MsiError::Exhausted), "重复尝试仍被拒");
        assert_eq!(p.allocated(0), 2, "拒绝时位图不变");
        assert_eq!(p.alloc(1), Ok(Vector::new(0x80)), "其他核不受影响");
        assert_eq!(MsiError::Exhausted.name(), "system.irq.error.msi_exhausted");
    }

    #[test]
    fn unknown_and_offline_cpus_are_rejected_without_change() {
        let p = pool(0x60, 2, &[0]);
        assert_eq!(p.alloc(MAX_CPUS), Err(MsiError::NoSuchCpu));
        assert_eq!(p.free(MAX_CPUS, Vector::new(0x60)), Err(MsiError::NoSuchCpu));
        assert_eq!(p.alloc(1), Err(MsiError::NotOnline));
        assert_eq!(p.free(1, Vector::new(0x60)), Err(MsiError::NotOnline));
        assert_eq!(p.allocated(MAX_CPUS), 0);
        assert_eq!(p.allocated(1), 0);
        assert_eq!(p.allocated(0), 0);
        assert_eq!(MsiError::NoSuchCpu.name(), "system.cpu.error.no_such_cpu");
        assert_eq!(MsiError::NotOnline.name(), "system.cpu.error.not_online");
    }

    #[test]
    fn invalid_and_foreign_frees_are_rejected_without_change() {
        let p = pool(0x60, 4, &[0, 1]);
        let owned = p.alloc(0).unwrap();
        let extra = p.alloc(0).unwrap();
        assert_eq!(p.free(1, extra), Err(MsiError::NotAllocated), "释放别核的向量");
        assert_eq!(p.allocated(0), 2, "被拒后本核位图不变");
        assert_eq!(p.allocated(1), 0, "另一核位图不变");
        assert_eq!(p.free(0, Vector::new(0x5F)), Err(MsiError::OutOfRange));
        assert_eq!(p.free(0, Vector::new(0x64)), Err(MsiError::OutOfRange));
        assert_eq!(p.free(0, owned), Ok(()));
        assert_eq!(p.free(0, owned), Err(MsiError::NotAllocated), "重复释放");
        assert_eq!(p.allocated(0), 1);
        assert_eq!(MsiError::NotAllocated.name(), "system.irq.error.msi_not_allocated");
        assert_eq!(MsiError::OutOfRange.name(), "system.irq.error.msi_vector_out_of_range");
    }

    #[test]
    fn each_cpu_has_its_own_lock() {
        let p = pool(0x60, 2, &[0, 1]);
        let held = p.bits[0].lock();
        assert_eq!(p.alloc(1), Ok(Vector::new(0x60)), "锁住 0 号核不阻塞 1 号核");
        drop(held);
        assert_eq!(p.alloc(0), Ok(Vector::new(0x60)));
    }

    #[test]
    fn constructors_reject_bad_ranges() {
        assert_eq!(VectorPool::new(0x60, 0, cpus(&[0])).err(), Some(MsiError::BadRange));
        assert_eq!(VectorPool::new(0xF0, 0x11, cpus(&[0])).err(), Some(MsiError::BadRange));
        assert_eq!(VectorPool::new(0xFF, 1, cpus(&[0])).is_ok(), true);
        assert_eq!(MsiError::BadRange.name(), "system.irq.error.msi_bad_range");
    }

    #[test]
    fn free_all_returns_to_baseline() {
        let p = pool(0x60, 4, &[0, 1]);
        p.alloc(0).unwrap();
        p.alloc(0).unwrap();
        p.alloc(1).unwrap();
        assert_eq!(p.free_all(0), Ok(2));
        assert_eq!(p.allocated(0), 0);
        assert_eq!(p.allocated(1), 1);
        assert_eq!(p.free_all(0), Ok(0));
        assert_eq!(p.free_all(1), Ok(1));
        assert_eq!(p.allocated(1), 0);
        assert_eq!(p.alloc(0), Ok(Vector::new(0x60)), "清空后重新可用");
        assert_eq!(p.alloc(1), Ok(Vector::new(0x60)));
        assert_eq!(MsiError::Unsupported.name(), "system.irq.error.msi_unsupported");
    }
}
