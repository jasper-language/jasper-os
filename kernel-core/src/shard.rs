//! 系统服务的分片模式（可复用组件的纯部分）：按处理器 / 队列 / 流把请求路由到分片，固定容量的分片队列，
//! 以及衡量各分片负载是否均衡的指标。
//! Sharding pattern for system services: key-to-shard routing, fixed-capacity shard queues and balance metrics.
//!
//! # 职责
//! * [`ShardRouter`]：把 [`ShardKey`] 映射到分片下标。按处理器 = 直接对应（每核一个分片，不跨核）；
//!   按队列 = 取模（设备的多队列各归一个分片）；按流 = 混合后用跳跃一致性哈希
//!   （同一个流永远落在同一分片，保证流内顺序；分片数变化时只有约 1/(n+1) 的流换分片）。
//! * [`ShardRing`]：一个分片的固定容量先进先出队列（无堆，满时拒绝而不覆盖）。
//! * [`imbalance_permille`]：(最大 − 最小) / 最大，用来判定各分片负载是否均衡。
//!
//! # 边界与原因
//! 不含锁与线程：每个分片由内核侧各自一把锁保护，分片之间互不等待——这是服务多核化的关键，
//! 没有全局串行点。路由是纯函数，因此在宿主上可做确定性测试。

use crate::smp::MAX_CPUS;

/// 分片数上限。
/// Maximum number of shards.
pub const MAX_SHARDS: usize = MAX_CPUS * 4;

/// 分片键。
/// Shard key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardKey {
    /// 按处理器：请求属于某个处理器本地（如每核统计、每核缓存）。
    Cpu(usize),
    /// 按队列：设备的第 q 个硬件队列。
    Queue(u32),
    /// 按流：同一个流的请求必须按序处理（如一条连接）。
    Flow(u64),
}

/// 分片错误。
/// Sharding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardError {
    /// 分片数为 0 或超过 [`MAX_SHARDS`]。
    BadCount,
    /// 按处理器路由时该处理器没有分片。
    NoCpuShard,
    /// 分片队列已满（调用者应退避或在源头施加反压）。
    Full,
}

impl ShardError {
    /// 规范名。
    /// Canonical name.
    pub const fn name(self) -> &'static str {
        match self {
            ShardError::BadCount => "system.service.shard.error.bad_count",
            ShardError::NoCpuShard => "system.service.shard.error.no_cpu_shard",
            ShardError::Full => "system.service.shard.error.full",
        }
    }
}

/// 64 位混合函数（SplitMix64 的终结步骤）：让相邻的流标识也散得开。
/// 64-bit finaliser so that adjacent flow ids spread.
pub const fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// 跳跃一致性哈希：把 `key` 映射到 `[0, buckets)`；`buckets` 为 0 时返回 0。
/// 只用整数运算（内核不使用浮点寄存器）：跳跃距离 = (b + 1) × 2^31 / (随机数 + 1)，向下取整。
/// Jump consistent hash of `key` into `buckets` buckets (integer-only).
pub fn jump_hash(mut key: u64, buckets: u32) -> u32 {
    let (mut b, mut j) = (0u64, 0u64);
    while j < buckets as u64 {
        b = j;
        key = key.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(1);
        j = (b + 1) * (1u64 << 31) / ((key >> 33) + 1);
    }
    b as u32
}

/// 分片路由（不可变，可在各处理器间共享）。
/// Shard router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardRouter {
    shards: u32,
}

impl ShardRouter {
    /// 建立 `shards` 个分片的路由；数量非法返回 [`ShardError::BadCount`]。
    /// Create a router over `shards` shards.
    pub const fn new(shards: usize) -> Result<ShardRouter, ShardError> {
        if shards == 0 || shards > MAX_SHARDS {
            Err(ShardError::BadCount)
        } else {
            Ok(ShardRouter { shards: shards as u32 })
        }
    }

    /// 分片数。
    /// Number of shards.
    pub const fn shards(&self) -> usize {
        self.shards as usize
    }

    /// 键所属的分片。
    /// Shard of `key`.
    pub fn route(&self, key: ShardKey) -> Result<usize, ShardError> {
        match key {
            ShardKey::Cpu(c) if c < self.shards as usize => Ok(c),
            ShardKey::Cpu(_) => Err(ShardError::NoCpuShard),
            ShardKey::Queue(q) => Ok((q % self.shards) as usize),
            ShardKey::Flow(f) => Ok(jump_hash(mix64(f), self.shards) as usize),
        }
    }
}

/// 一个分片的固定容量先进先出队列。
/// Fixed-capacity FIFO of one shard.
#[derive(Debug, Clone, Copy)]
pub struct ShardRing<T: Copy, const CAP: usize> {
    buf: [Option<T>; CAP],
    head: usize,
    len: usize,
    /// 因已满被拒绝的次数。
    rejected: u64,
}

impl<T: Copy, const CAP: usize> ShardRing<T, CAP> {
    /// 空队列。
    /// Empty queue.
    pub const fn new() -> Self {
        ShardRing { buf: [None; CAP], head: 0, len: 0, rejected: 0 }
    }

    /// 入队；已满返回 [`ShardError::Full`]，队列不变（只累计拒绝次数）。
    /// Push `item`; refuses when full.
    pub fn push(&mut self, item: T) -> Result<(), ShardError> {
        if self.len == CAP {
            self.rejected += 1;
            return Err(ShardError::Full);
        }
        self.buf[(self.head + self.len) % CAP] = Some(item);
        self.len += 1;
        Ok(())
    }

    /// 出队（最早入队的）。
    /// Pop the oldest item.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let v = self.buf[self.head].take();
        self.head = (self.head + 1) % CAP;
        self.len -= 1;
        v
    }

    /// 当前长度。
    /// Current length.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    /// Whether empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 被拒绝的次数。
    /// Number of refused pushes.
    pub const fn rejected(&self) -> u64 {
        self.rejected
    }
}

impl<T: Copy, const CAP: usize> Default for ShardRing<T, CAP> {
    fn default() -> Self {
        Self::new()
    }
}

/// 负载不均衡度：(最大 − 最小) × 1000 / 最大；全为 0 或为空时为 0。
/// Imbalance of `loads` in permille.
pub fn imbalance_permille(loads: &[u64]) -> u32 {
    let max = loads.iter().copied().max().unwrap_or(0);
    let min = loads.iter().copied().min().unwrap_or(0);
    if max == 0 {
        0
    } else {
        ((max - min) as u128 * 1000 / max as u128) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_rejects_bad_counts() {
        assert_eq!(ShardRouter::new(0), Err(ShardError::BadCount));
        assert_eq!(ShardRouter::new(MAX_SHARDS + 1), Err(ShardError::BadCount));
        assert_eq!(ShardRouter::new(MAX_SHARDS).map(|r| r.shards()), Ok(MAX_SHARDS));
        assert_eq!(ShardError::Full.name(), "system.service.shard.error.full");
    }

    #[test]
    fn cpu_keys_map_directly_and_refuse_missing_cpu() {
        let r = ShardRouter::new(4).unwrap();
        for c in 0..4 {
            assert_eq!(r.route(ShardKey::Cpu(c)), Ok(c));
        }
        assert_eq!(r.route(ShardKey::Cpu(4)), Err(ShardError::NoCpuShard));
    }

    #[test]
    fn queue_keys_wrap() {
        let r = ShardRouter::new(3).unwrap();
        let got: Vec<usize> = (0..6).map(|q| r.route(ShardKey::Queue(q)).unwrap()).collect();
        assert_eq!(got, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn flows_are_stable_and_spread_evenly() {
        let r = ShardRouter::new(4).unwrap();
        let mut counts = [0u64; 4];
        for f in 0..4096u64 {
            let s = r.route(ShardKey::Flow(f)).unwrap();
            assert_eq!(r.route(ShardKey::Flow(f)), Ok(s));
            counts[s] += 1;
        }
        // 4096 个流分到 4 片：每片 1024 左右，不均衡度不超过 15%
        assert!(imbalance_permille(&counts) <= 150, "{counts:?}");
    }

    #[test]
    fn jump_hash_moves_few_flows_on_growth() {
        let (mut moved, total) = (0u32, 10_000u64);
        for f in 0..total {
            let k = mix64(f);
            let a = jump_hash(k, 4);
            let b = jump_hash(k, 5);
            assert!(a < 4 && b < 5);
            if a != b {
                assert_eq!(b, 4, "增加分片时流只应搬到新分片");
                moved += 1;
            }
        }
        // 理论值 1/5；允许统计误差
        assert!((1500..=2500).contains(&moved), "moved={moved}");
        assert_eq!(jump_hash(123, 0), 0);
        assert_eq!(jump_hash(123, 1), 0);
    }

    #[test]
    fn ring_fifo_full_refusal_leaves_contents() {
        let mut q: ShardRing<u32, 3> = ShardRing::new();
        assert!(q.is_empty());
        for i in 0..3 {
            q.push(i).unwrap();
        }
        assert_eq!(q.push(99), Err(ShardError::Full));
        assert_eq!((q.len(), q.rejected()), (3, 1));
        assert_eq!(q.pop(), Some(0));
        q.push(3).unwrap();
        assert_eq!([q.pop(), q.pop(), q.pop(), q.pop()], [Some(1), Some(2), Some(3), None]);
    }

    #[test]
    fn imbalance_metric() {
        assert_eq!(imbalance_permille(&[]), 0);
        assert_eq!(imbalance_permille(&[0, 0]), 0);
        assert_eq!(imbalance_permille(&[100, 100, 100]), 0);
        assert_eq!(imbalance_permille(&[100, 50]), 500);
        assert_eq!(imbalance_permille(&[10, 0]), 1000);
    }
}
