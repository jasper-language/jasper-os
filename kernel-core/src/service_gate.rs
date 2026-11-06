//! 可撤回能力发布门：读者持有租约，写者先撤位并等待已进入的读者退出，再停用服务。
//! Revocable capability publication gate: readers hold leases while writers withdraw first.
//!
//! # 协议
//! 读者先观察没有写者，登记活动租约，再复核写者标记；写者先置写者标记，再清位并等待活动租约
//! 归零。顺序一致序使两边至少有一方看见对方的握手：读者复核失败会撤销登记，已成功返回的租约
//! 必然在写者等待集合内。因此 [`Gate::withdraw`] 返回后不再产生该能力的租约，而
//! [`Gate::wait_quiescent`] 返回后停用函数才可以运行。
//!
//! # 边界
//! 本模块只管理发布位、代次和租约计数，不执行模块代码。等待函数由调用者注入，使多核内核可以
//! 让出 CPU，而宿主测试可以用确定性的推进函数。位图只有 32 位，对应既有 Profile 能力上限。

use core::sync::atomic::{AtomicU32, Ordering};

// Acquire/Release 只能为数据建立 happens-before，不能单独证明排空检查看见并发写者刚登记的租约。
// 本协议的三枚原子量使用顺序一致序，使“读者确认旧代次”与“写者开始撤位”进入同一全序。
const ORDER: Ordering = Ordering::SeqCst;
const WRITER: u32 = 1 << 31;
const GENERATION: u32 = 1 << 30;
const READERS: u32 = GENERATION - 1;

/// 一次已获准进入服务的租约；最后一个租约退出后等待撤回的写者才能继续。
/// A lease held for exactly as long as a caller may use the published service.
pub struct Lease<'a> {
    gate: &'a Gate,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.gate.state.fetch_sub(1, ORDER);
    }
}

/// 能力位发布门。
/// Publication gate for up to 32 capability bits.
pub struct Gate {
    epoch: AtomicU32,
    published: AtomicU32,
    /// 最高位是写者，次高位是撤回代次，其余位是活动读者数。
    state: AtomicU32,
}

impl Gate {
    /// 建立空发布门。
    /// Create an empty publication gate.
    pub const fn new() -> Self {
        Self {
            epoch: AtomicU32::new(0),
            published: AtomicU32::new(0),
            state: AtomicU32::new(0),
        }
    }

    /// 当前发布位（只能用于报告，不能作为服务入口的完整同步协议）。
    /// Current publication bits, for reporting only.
    pub fn mask(&self) -> u32 {
        self.published.load(ORDER)
    }

    /// 当前代次；奇数表示撤回 / 发布事务正在进行。
    /// Current generation; an odd value means a publication transaction is in progress.
    pub fn epoch(&self) -> u32 {
        self.epoch.load(ORDER)
    }

    /// 当前活动租约数。
    /// Number of active reader leases.
    pub fn readers(&self) -> u32 {
        self.state.load(ORDER) & READERS
    }

    /// 尝试取得一项已发布能力的租约。撤回事务进行中、位未发布或握手期间状态变化都返回 `None`。
    /// Try to acquire one published capability; `None` means the caller must not enter the service.
    pub fn acquire(&self, bit: u32) -> Option<Lease<'_>> {
        if bit >= 32 {
            return None;
        }
        let flag = 1u32 << bit;
        loop {
            let state = self.state.load(ORDER);
            if state & WRITER != 0 || state & READERS == READERS {
                return None;
            }
            match self.state.compare_exchange_weak(state, state + 1, ORDER, ORDER) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        if self.published.load(ORDER) & flag == 0 {
            self.state.fetch_sub(1, ORDER);
            return None;
        }
        Some(Lease { gate: self })
    }

    /// 发布位图，返回发布前的掩码。调用者必须保证该位对应的服务已经完成初始化。
    /// Publish bits and return the previous mask; the service must already be initialised.
    pub fn publish(&self, bits: u32) -> u32 {
        self.published.fetch_or(bits, ORDER)
    }

    /// 在一个事务内撤掉给定发布位，返回撤位后的掩码。返回后新读者不能再取得这些位。
    /// Withdraw bits atomically with respect to readers and return the remaining mask.
    pub fn withdraw(&self, bits: u32) -> u32 {
        loop {
            let state = self.state.load(ORDER);
            if state & WRITER != 0 {
                core::hint::spin_loop();
                continue;
            }
            let writer = (state ^ GENERATION) | WRITER;
            match self.state.compare_exchange_weak(state, writer, ORDER, ORDER) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        self.epoch.fetch_add(1, ORDER);
        let left = self.published.fetch_and(!bits, ORDER) & !bits;
        self.epoch.fetch_add(1, ORDER);
        left
    }

    /// 等待所有在撤回前已取得租约的读者退出；`wait` 在每次轮询之间执行。
    /// Wait until every lease acquired before withdrawal has gone; `wait` runs between polls.
    pub fn wait_quiescent(&self, mut wait: impl FnMut()) {
        while self.state.load(ORDER) & READERS != 0 {
            wait();
        }
        self.state.fetch_and(!WRITER, ORDER);
    }

    /// 撤位并等待读者排空，返回撤位后的掩码。
    /// Withdraw and wait for reader quiescence.
    pub fn withdraw_and_wait(&self, bits: u32, wait: impl FnMut()) -> u32 {
        let left = self.withdraw(bits);
        self.wait_quiescent(wait);
        left
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdraw_blocks_new_leases_and_waits_for_existing_reader() {
        let gate = Gate::new();
        gate.publish(0b11);
        let mut lease = Some(gate.acquire(0).expect("published bit"));
        assert!(gate.acquire(1).is_some());
        assert_eq!(gate.withdraw(0b1), 0b10);
        assert!(gate.acquire(0).is_none());
        assert!(gate.acquire(1).is_none(), "withdrawal excludes every new service entry until drain completes");
        let mut polls = 0;
        let mut released = false;
        gate.wait_quiescent(|| {
            polls += 1;
            if !released {
                drop(lease.take());
                released = true;
            }
        });
        assert!(released);
        assert!(polls > 0);
        assert_eq!(gate.readers(), 0);
        assert!(gate.acquire(1).is_some());
    }

    #[test]
    fn publish_and_withdraw_boundaries_do_not_change_unrelated_bits() {
        let gate = Gate::new();
        assert!(gate.acquire(32).is_none());
        assert_eq!(gate.publish(0x8000_0001), 0);
        assert!(gate.acquire(31).is_some());
        assert_eq!(gate.withdraw(1), 0x8000_0000);
        assert_eq!(gate.mask(), 0x8000_0000);
    }
}
