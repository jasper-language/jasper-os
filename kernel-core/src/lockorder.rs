//! 锁顺序登记与检查：全局锁按「级别」排成一条链，同一执行流只能按级别递增的顺序加锁。
//! Lock-order registry and checking: global locks form one ranked chain; nesting must ascend.
//!
//! # 职责
//! * [`LockClass`] —— 一类锁的登记项（级别 + 稳定名称）
//! * [`validate_registry`] —— 校验登记表：级别严格递增、不超上限、名称非空且不重复
//! * [`HeldRanks`] —— 一个执行流（一个处理器）当前持有的锁级别集合；加锁前检查顺序，
//!   违反顺序或重复加同级锁时**拒绝且不改动**，释放未持有的级别同样拒绝
//!
//! # 边界
//! 只是纯机制：不碰中断、不知道「当前处理器」是谁。内核把 [`HeldRanks`] 放进每核数据，
//! 在关中断的自旋锁加锁 / 解锁处调用它；持锁期间本处理器不被中断，因此「每核一份」就等于「每个执行流一份」。
//!
//! # 为什么需要
//! 多处理器下两个处理器以相反顺序获取两把锁就会互相等待（死锁）。把全部全局锁登记在一条链上，
//! 并在每次加锁时检查，违反顺序的代码第一次运行就会被发现，而不是在罕见的交错下才卡死。

use core::sync::atomic::{AtomicU32, Ordering};

/// 可登记的最大级别（[`HeldRanks`] 的位宽减一）。
/// Highest registrable rank.
pub const MAX_RANK: u8 = 31;

/// 一类锁的登记项：级别越小越「外层」，持有级别 r 时只能再获取级别大于 r 的锁。
/// Registry entry of one lock class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockClass {
    /// 级别（0..=[`MAX_RANK`]）。
    pub rank: u8,
    /// 稳定名称（点分小写，用于诊断输出）。
    pub name: &'static str,
}

impl LockClass {
    /// 新建登记项。
    /// Create a registry entry.
    pub const fn new(rank: u8, name: &'static str) -> Self {
        LockClass { rank, name }
    }
}

/// 锁顺序错误。
/// Lock-order error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockOrderError {
    /// 要获取的级别不大于已持有的最高级别（逆序或重复加同级锁）。
    OutOfOrder {
        /// 要获取的级别。
        acquiring: u8,
        /// 已持有的最高级别。
        highest_held: u8,
    },
    /// 释放一个并未持有的级别。
    NotHeld(u8),
    /// 级别超出上限。
    BadRank(u8),
}

impl LockOrderError {
    /// 稳定的错误名称。
    /// Stable error name.
    pub fn name(&self) -> &'static str {
        match self {
            LockOrderError::OutOfOrder { .. } => "system.lock.error.out_of_order",
            LockOrderError::NotHeld(_) => "system.lock.error.not_held",
            LockOrderError::BadRank(_) => "system.lock.error.bad_rank",
        }
    }
}

/// 登记表错误。
/// Registry validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// 第 `index` 项的级别不大于前一项（链必须严格递增）。
    NotAscending { index: usize },
    /// 第 `index` 项的级别超出上限。
    RankTooHigh { index: usize },
    /// 第 `index` 项的名称为空。
    EmptyName { index: usize },
    /// 第 `index` 项的名称与之前某项重复。
    DuplicateName { index: usize },
}

/// 两个字符串是否相等（`const` 上下文可用）。
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// 校验登记表（`const` 可用，内核据此在编译期拒绝错误的登记表）。
/// Validate a registry; usable in `const` context.
pub const fn validate_registry(reg: &[LockClass]) -> Result<(), RegistryError> {
    let mut i = 0;
    while i < reg.len() {
        if reg[i].rank > MAX_RANK {
            return Err(RegistryError::RankTooHigh { index: i });
        }
        if reg[i].name.is_empty() {
            return Err(RegistryError::EmptyName { index: i });
        }
        if i > 0 && reg[i].rank <= reg[i - 1].rank {
            return Err(RegistryError::NotAscending { index: i });
        }
        let mut j = 0;
        while j < i {
            if str_eq(reg[i].name, reg[j].name) {
                return Err(RegistryError::DuplicateName { index: i });
            }
            j += 1;
        }
        i += 1;
    }
    Ok(())
}

/// 一个执行流当前持有的锁级别集合（位 r = 持有级别 r）。
///
/// 只应由所属执行流修改（内核里是本处理器、关中断时）；读取可来自任何处理器（诊断）。
/// Set of lock ranks currently held by one execution flow.
pub struct HeldRanks(AtomicU32);

impl HeldRanks {
    /// 新建（什么也不持有）。
    /// Create an empty set.
    pub const fn new() -> Self {
        HeldRanks(AtomicU32::new(0))
    }

    /// 当前位图。
    /// Current bitmap.
    pub fn bits(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }

    /// 已持有的最高级别（什么也不持有时 `None`）。
    /// Highest held rank.
    pub fn highest(&self) -> Option<u8> {
        let b = self.bits();
        if b == 0 {
            None
        } else {
            Some(31 - b.leading_zeros() as u8)
        }
    }

    /// 能否获取级别 `rank`（不改动）。
    /// Check whether `rank` may be acquired now, without recording it.
    pub fn check(&self, rank: u8) -> Result<(), LockOrderError> {
        if rank > MAX_RANK {
            return Err(LockOrderError::BadRank(rank));
        }
        match self.highest() {
            Some(h) if h >= rank => Err(LockOrderError::OutOfOrder { acquiring: rank, highest_held: h }),
            _ => Ok(()),
        }
    }

    /// 登记获取级别 `rank`：顺序合法才记录；否则返回错误且位图不变。
    /// Record acquisition of `rank` if the order is legal.
    pub fn acquire(&self, rank: u8) -> Result<(), LockOrderError> {
        self.check(rank)?;
        self.0.fetch_or(1 << rank, Ordering::Relaxed);
        Ok(())
    }

    /// 登记释放级别 `rank`（释放顺序不限）；未持有时返回错误且位图不变。
    /// Record release of `rank`.
    pub fn release(&self, rank: u8) -> Result<(), LockOrderError> {
        if rank > MAX_RANK {
            return Err(LockOrderError::BadRank(rank));
        }
        let bit = 1u32 << rank;
        if self.bits() & bit == 0 {
            return Err(LockOrderError::NotHeld(rank));
        }
        self.0.fetch_and(!bit, Ordering::Relaxed);
        Ok(())
    }
}

impl Default for HeldRanks {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: LockClass = LockClass::new(2, "a.outer");
    const B: LockClass = LockClass::new(5, "b.middle");
    const C: LockClass = LockClass::new(9, "c.leaf");

    #[test]
    fn registry_accepts_ascending_unique_chain() {
        assert_eq!(validate_registry(&[A, B, C]), Ok(()));
        assert_eq!(validate_registry(&[]), Ok(()));
        // 编译期也可校验
        const OK: () = assert!(validate_registry(&[A, B, C]).is_ok());
        let _ = OK;
    }

    #[test]
    fn registry_rejects_bad_tables() {
        assert_eq!(validate_registry(&[B, A]), Err(RegistryError::NotAscending { index: 1 }));
        assert_eq!(validate_registry(&[A, A]), Err(RegistryError::NotAscending { index: 1 }));
        assert_eq!(validate_registry(&[A, LockClass::new(32, "x")]), Err(RegistryError::RankTooHigh { index: 1 }));
        assert_eq!(validate_registry(&[A, LockClass::new(3, "")]), Err(RegistryError::EmptyName { index: 1 }));
        assert_eq!(validate_registry(&[A, LockClass::new(3, "a.outer")]), Err(RegistryError::DuplicateName { index: 1 }));
    }

    #[test]
    fn ascending_acquire_and_any_order_release() {
        let h = HeldRanks::new();
        assert_eq!(h.highest(), None);
        assert_eq!(h.acquire(A.rank), Ok(()));
        assert_eq!(h.acquire(B.rank), Ok(()));
        assert_eq!(h.acquire(C.rank), Ok(()));
        assert_eq!(h.highest(), Some(9));
        // 释放顺序不限
        assert_eq!(h.release(A.rank), Ok(()));
        assert_eq!(h.highest(), Some(9));
        assert_eq!(h.release(C.rank), Ok(()));
        assert_eq!(h.release(B.rank), Ok(()));
        assert_eq!(h.bits(), 0);
        // 全部释放后可从任意级别重新开始
        assert_eq!(h.acquire(C.rank), Ok(()));
        assert_eq!(h.release(C.rank), Ok(()));
    }

    #[test]
    fn out_of_order_and_recursive_acquire_rejected_without_change() {
        let h = HeldRanks::new();
        h.acquire(B.rank).unwrap();
        let before = h.bits();
        assert_eq!(h.acquire(A.rank), Err(LockOrderError::OutOfOrder { acquiring: 2, highest_held: 5 }));
        assert_eq!(h.bits(), before);
        assert_eq!(h.acquire(B.rank), Err(LockOrderError::OutOfOrder { acquiring: 5, highest_held: 5 }));
        assert_eq!(h.bits(), before);
        assert_eq!(h.check(C.rank), Ok(()));
        assert_eq!(h.bits(), before, "check 不得改动");
        assert_eq!(h.acquire(MAX_RANK + 1), Err(LockOrderError::BadRank(32)));
        assert_eq!(h.bits(), before);
        assert_eq!(LockOrderError::OutOfOrder { acquiring: 0, highest_held: 0 }.name(), "system.lock.error.out_of_order");
    }

    #[test]
    fn releasing_unheld_rank_rejected_without_change() {
        let h = HeldRanks::new();
        h.acquire(A.rank).unwrap();
        let before = h.bits();
        assert_eq!(h.release(B.rank), Err(LockOrderError::NotHeld(5)));
        assert_eq!(h.release(40), Err(LockOrderError::BadRank(40)));
        assert_eq!(h.bits(), before);
        assert_eq!(LockOrderError::NotHeld(5).name(), "system.lock.error.not_held");
    }

    #[test]
    fn per_thread_sets_are_independent() {
        // 每个执行流一份：一个线程持有高级别不影响另一个线程获取低级别
        let sets: std::sync::Arc<[HeldRanks; 4]> = std::sync::Arc::new([const { HeldRanks::new() }; 4]);
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let s = sets.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        let mine = &s[t];
                        mine.acquire(C.rank - t as u8).unwrap();
                        assert!(mine.acquire(A.rank).is_err());
                        mine.release(C.rank - t as u8).unwrap();
                        mine.acquire(A.rank).unwrap();
                        mine.release(A.rank).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(sets.iter().all(|s| s.bits() == 0));
    }
}
