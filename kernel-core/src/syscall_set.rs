//! 系统调用能力集合：有界、可增长、内核与用户运行时共用的唯一权威表示。
//! Bounded and growable syscall-capability set shared by the kernel and user runtime.
//!
//! # 为什么不用单个 `u64`
//! 早期实现把「可用操作集合」写成 `u64`：位 i = 操作 ID i。操作 ID 由
//! `abi/system-ids.txt` 单调追加，超过 63 后 `of()` 会把高编号静默丢掉、`contains()`
//! 恒返回 false —— 权限表承认、实现却看不见，属于不可接受的安全缺口。
//!
//! # 权威语义
//! * 集合是 256 位的定长位图（4 个 `u64`，32 字节），有效 ID 范围为 `0..=255`。
//! * 位 i 为 1 当且仅当操作 ID i 被授予；不存在「未知位」「影子通道」或按调用点
//!   另算的第二种解释。
//! * 超出容量的 ID 不会被静默忽略：构造时显式拒绝（[`SyscallSet::try_of`] /
//!   [`SyscallSet::from_id`]），受信任的静态表用 [`SyscallSet::of`]（越界即编译期或
//!   运行期 panic，表示程序错误而不是权限降级）。
//! * 查表是一次数组下标 + 移位：`contains` 的时间上界与集合大小无关（常数 1 次
//!   边界比较、1 次下标、1 次位测试）。
//!
//! # 容量与增长
//! 256 位 = 当前最高操作 ID（69）的 3 倍余量；结构大小 32 字节，可随任务控制块
//! 直接复制。若将来登记表突破 255，只需把 [`MAX_IDS`] / [`WORDS`] 一起提高并同步
//! 重新生成 ABI（`SpawnDesc` 的大小由 [`WORDS`] 决定），语义不变；不保留旧宽度
//! 的影子通道。

/// 可表示的操作 ID 上限（ID 取值 `0..MAX_IDS`）。
pub const MAX_IDS: usize = 256;
/// 位图字数。
pub const WORDS: usize = MAX_IDS / 64;
/// 序列化字节数（小端，逐字）。
pub const BYTES: usize = WORDS * 8;

const _: () = assert!(MAX_IDS % 64 == 0);

/// 严格构造能力集合时的拒绝原因。
/// Why a strict capability-set construction was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallIdError {
    /// 操作 ID 超出 [`MAX_IDS`]，不能进入 256 位集合。
    OutOfRange(u64),
    /// 操作 ID 尚未登记，不能作为能力授予。
    Unknown(u64),
    /// 同一个操作 ID 在输入中出现超过一次。
    Duplicate(u64),
}

/// 任务/进程可发起的系统调用集合。
///
/// `Copy` 且大小固定，可放进任务控制块；比较按 4 个字整体进行。
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct SyscallSet {
    words: [u64; WORDS],
}

impl SyscallSet {
    /// 空集合（内核任务默认：内核任务不经系统调用入口）。
    pub const EMPTY: SyscallSet = SyscallSet { words: [0; WORDS] };

    /// 全 1 集合（测试与「全部已登记操作」的边界用）。
    pub const FULL: SyscallSet = SyscallSet { words: [u64::MAX; WORDS] };

    /// 由若干**受信任**的操作 ID 构造。
    ///
    /// 只用于编译期常量或内核内静态列表。ID 超出 [`MAX_IDS`] 时立即 panic：
    /// 宁可启动失败，也不能把越界权限静默丢掉。来自用户或可增长数据的 ID 必须走
    /// [`SyscallSet::try_of`] / [`SyscallSet::from_id`]。
    pub const fn of(ids: &[u32]) -> SyscallSet {
        let mut set = SyscallSet::EMPTY;
        let mut i = 0;
        while i < ids.len() {
            let id = ids[i];
            assert!(id < MAX_IDS as u32, "syscall id exceeds SyscallSet capacity");
            set.words[(id as usize) / 64] |= 1u64 << (id % 64);
            i += 1;
        }
        set
    }

    /// 由若干操作 ID 构造；任一 ID 超出容量时返回 `None`（不截断、不忽略）。
    pub fn try_of(ids: &[u32]) -> Option<SyscallSet> {
        let mut set = SyscallSet::EMPTY;
        for &id in ids {
            set = set.union(SyscallSet::from_id(id)?);
        }
        Some(set)
    }

    /// 严格由用户提供的操作 ID 构造集合：越界、未登记或重复任一项即整体拒绝。
    ///
    /// 与 [`SyscallSet::try_of`] 不同，此函数按原始寄存器宽度接收 ID，不截断超过 `u32`
    /// 的值，也不把重复项静默合并。`registered` 必须来自同一份系统接口登记表。
    /// Strictly builds a set from caller-provided IDs; any bad or duplicate ID rejects all input.
    pub fn try_from_ids(ids: &[u64], registered: SyscallSet) -> Result<SyscallSet, CallIdError> {
        let mut set = SyscallSet::EMPTY;
        for &id in ids {
            set = set.try_with_id(id, registered)?;
        }
        Ok(set)
    }

    /// 在不修改原集合的前提下加入一个已登记 ID；失败时原集合保持不变。
    /// Returns a set with one registered ID added, rejecting bad or duplicate input without mutation.
    pub fn try_with_id(self, id: u64, registered: SyscallSet) -> Result<SyscallSet, CallIdError> {
        if id >= MAX_IDS as u64 {
            return Err(CallIdError::OutOfRange(id));
        }
        if !registered.contains(id) {
            return Err(CallIdError::Unknown(id));
        }
        if self.contains(id) {
            return Err(CallIdError::Duplicate(id));
        }
        match SyscallSet::from_id(id as u32) {
            Some(one) => Ok(self.union(one)),
            None => Err(CallIdError::OutOfRange(id)),
        }
    }

    /// 只含一个操作 ID 的集合；ID 超出容量时返回 `None`。
    pub const fn from_id(id: u32) -> Option<SyscallSet> {
        if id >= MAX_IDS as u32 {
            return None;
        }
        let mut words = [0u64; WORDS];
        words[(id as usize) / 64] = 1u64 << (id % 64);
        Some(SyscallSet { words })
    }

    /// 由原始位图字构造（小端序列化、生成代码与测试用）。
    pub const fn from_words(words: [u64; WORDS]) -> SyscallSet {
        SyscallSet { words }
    }

    /// 原始位图字（诊断与序列化用）。
    pub const fn words(self) -> [u64; WORDS] {
        self.words
    }

    /// 两个集合的并集。
    pub const fn union(self, other: SyscallSet) -> SyscallSet {
        let mut words = [0u64; WORDS];
        let mut i = 0;
        while i < WORDS {
            words[i] = self.words[i] | other.words[i];
            i += 1;
        }
        SyscallSet { words }
    }

    /// 两个集合的交集。
    pub const fn intersection(self, other: SyscallSet) -> SyscallSet {
        let mut words = [0u64; WORDS];
        let mut i = 0;
        while i < WORDS {
            words[i] = self.words[i] & other.words[i];
            i += 1;
        }
        SyscallSet { words }
    }

    /// 差集：`self \ other`（撤权语义：结果永远不会多出 `self` 没有的位）。
    pub const fn difference(self, other: SyscallSet) -> SyscallSet {
        let mut words = [0u64; WORDS];
        let mut i = 0;
        while i < WORDS {
            words[i] = self.words[i] & !other.words[i];
            i += 1;
        }
        SyscallSet { words }
    }

    /// `self ⊆ other`。spawn 授权与撤权检查的权威判据。
    pub const fn is_subset_of(self, other: SyscallSet) -> bool {
        let mut i = 0;
        while i < WORDS {
            if self.words[i] & !other.words[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// 是否为空集。
    pub const fn is_empty(self) -> bool {
        let mut i = 0;
        while i < WORDS {
            if self.words[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// 置位个数（唯一操作数）。
    pub const fn count(self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < WORDS {
            n += self.words[i].count_ones() as usize;
            i += 1;
        }
        n
    }

    /// 是否包含某个操作 ID。
    ///
    /// `id` 用 `u64` 接收（系统调用的寄存器宽度）；超出 [`MAX_IDS`] 的 ID 明确返回
    /// `false`，调用方（登记表查表）会先把它判为未登记，因此不会与「已授权」混淆。
    pub const fn contains(self, id: u64) -> bool {
        if id >= MAX_IDS as u64 {
            return false;
        }
        let i = id as usize;
        self.words[i / 64] & (1u64 << (i % 64)) != 0
    }

    /// 逐个小端写入固定长度缓冲区。
    pub fn encode(self, out: &mut [u8; BYTES]) {
        for (i, word) in self.words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
    }

    /// 从固定长度小端缓冲区读出（布局唯一，不解释任何「保留位」）。
    pub fn decode(input: &[u8; BYTES]) -> SyscallSet {
        let mut words = [0u64; WORDS];
        for (i, word) in words.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&input[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(b);
        }
        SyscallSet { words }
    }

    /// 按 ID 升序列出所有被授予的操作（诊断与测试用，不用于热路径）。
    pub fn ids(self) -> impl Iterator<Item = u32> {
        (0..MAX_IDS as u32).filter(move |&id| self.contains(id as u64))
    }
}

impl core::fmt::Debug for SyscallSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SyscallSet{")?;
        let mut first = true;
        for id in self.ids() {
            if !first {
                f.write_str(",")?;
            }
            write!(f, "{}", id)?;
            first = false;
        }
        f.write_str("}")
    }
}

#[cfg(kani)]
mod proofs {
    //! 生产 `SyscallSet` 的实现级有界证明：位图字取任意值，ID 取整个 `u32`/`u64` 范围。
    //! Implementation-level Kani proofs over arbitrary words and ids.
    use super::*;

    fn any_set() -> SyscallSet {
        SyscallSet::from_words(kani::any())
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn contains_matches_word_bit_for_every_id() {
        let s = any_set();
        let id: u64 = kani::any();
        let expect = id < MAX_IDS as u64 && (s.words()[(id / 64) as usize % WORDS] >> (id % 64)) & 1 == 1;
        assert_eq!(s.contains(id), expect);
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn from_id_is_exact_singleton_or_explicit_none() {
        let id: u32 = kani::any();
        let probe: u64 = kani::any();
        match SyscallSet::from_id(id) {
            None => assert!(id as usize >= MAX_IDS),
            Some(one) => {
                assert!((id as usize) < MAX_IDS);
                assert_eq!(one.count(), 1);
                assert_eq!(one.contains(probe), probe == id as u64);
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn set_algebra_is_pointwise() {
        let a = any_set();
        let b = any_set();
        let id: u64 = kani::any();
        assert_eq!(a.union(b).contains(id), a.contains(id) || b.contains(id));
        assert_eq!(a.intersection(b).contains(id), a.contains(id) && b.contains(id));
        assert_eq!(a.difference(b).contains(id), a.contains(id) && !b.contains(id));
        // 撤权不可提升：差集永远是原集合的子集。
        assert!(a.difference(b).is_subset_of(a));
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn subset_is_sound_and_complete() {
        let a = any_set();
        let b = any_set();
        let id: u64 = kani::any();
        // 完备：不是子集 ⇔ 差集非空（差集逐位语义已由上一个 harness 证明）。
        assert_eq!(a.is_subset_of(b), a.difference(b).is_empty());
        // 可靠：子集 ⇒ 任意 ID 的授权都被保留。
        if a.is_subset_of(b) && a.contains(id) {
            assert!(b.contains(id));
        }
    }

    #[kani::proof]
    #[kani::unwind(33)]
    fn encode_decode_roundtrip() {
        let s = any_set();
        let mut buf = [0u8; BYTES];
        s.encode(&mut buf);
        assert_eq!(SyscallSet::decode(&buf), s);
        let raw: [u8; BYTES] = kani::any();
        let mut again = [0u8; BYTES];
        SyscallSet::decode(&raw).encode(&mut again);
        assert_eq!(again, raw);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_63_64_127_are_distinct_and_visible() {
        assert_eq!(core::mem::size_of::<SyscallSet>(), 32);
        assert_eq!(BYTES, 32);
        // ID 63 是旧实现的最后一位；64/127 在旧实现里被静默忽略。
        let a = SyscallSet::of(&[63]);
        let b = SyscallSet::of(&[64]);
        let c = SyscallSet::of(&[127]);
        let all = SyscallSet::of(&[63, 64, 127]);
        for (set, id) in [(a, 63u64), (b, 64), (c, 127)] {
            assert!(set.contains(id), "id={} 必须可见", id);
            assert_eq!(set.count(), 1);
        }
        assert!(all.contains(63) && all.contains(64) && all.contains(127));
        assert_eq!(all.count(), 3);
        assert_eq!(all.ids().collect::<std::vec::Vec<_>>(), std::vec![63, 64, 127]);
        // 三个位分属不同字，互不串位。
        assert!(!a.contains(64) && !b.contains(63) && !c.contains(64));
    }

    #[test]
    fn capacity_boundary_is_explicit() {
        assert!(SyscallSet::from_id(255).is_some());
        assert!(SyscallSet::from_id(256).is_none());
        assert_eq!(SyscallSet::try_of(&[255]), SyscallSet::from_id(255));
        assert_eq!(SyscallSet::try_of(&[0, 255]), Some(SyscallSet::of(&[0, 255])));
        assert_eq!(SyscallSet::try_of(&[0, 256]), None);
        // 越界 ID 不被静默截断：单 ID 构造失败，集合也不会「看起来包含 0」。
        assert!(!SyscallSet::of(&[255]).contains(256));
        assert!(!SyscallSet::EMPTY.contains(256));
    }

    #[test]
    fn strict_construction_rejects_bad_or_duplicate_ids() {
        let registered = SyscallSet::of(&[0, 1, 63, 64]);
        assert_eq!(
            SyscallSet::try_from_ids(&[0, 63, 64], registered),
            Ok(SyscallSet::of(&[0, 63, 64]))
        );
        assert_eq!(
            SyscallSet::try_from_ids(&[0, 1, 1], registered),
            Err(CallIdError::Duplicate(1))
        );
        assert_eq!(
            SyscallSet::try_from_ids(&[0, 2], registered),
            Err(CallIdError::Unknown(2))
        );
        assert_eq!(
            SyscallSet::try_from_ids(&[0, 256], registered),
            Err(CallIdError::OutOfRange(256))
        );
        assert_eq!(
            SyscallSet::try_from_ids(&[u64::MAX], registered),
            Err(CallIdError::OutOfRange(u64::MAX))
        );
        let original = SyscallSet::of(&[0]);
        assert_eq!(original.try_with_id(0, registered), Err(CallIdError::Duplicate(0)));
        assert_eq!(original.try_with_id(2, registered), Err(CallIdError::Unknown(2)));
        assert_eq!(original.try_with_id(256, registered), Err(CallIdError::OutOfRange(256)));
        assert_eq!(original, SyscallSet::of(&[0]));
    }

    #[test]
    #[should_panic(expected = "SyscallSet capacity")]
    fn trusted_constructor_panics_instead_of_dropping_overflow() {
        let _ = SyscallSet::of(&[256]);
    }

    #[test]
    fn subset_union_difference_semantics() {
        let a = SyscallSet::of(&[1, 63, 64, 127, 255]);
        let b = SyscallSet::of(&[63, 64, 200]);
        assert_eq!(b.difference(a), SyscallSet::of(&[200]));
        assert_eq!(a.intersection(b), SyscallSet::of(&[63, 64]));
        assert!(b.intersection(a).is_subset_of(a));
        assert!(a.union(b).is_subset_of(SyscallSet::FULL));
        assert!(!a.is_subset_of(b));
        assert!(a.difference(b).is_subset_of(a));
        // 差集不会提权：结果与 other 的并集不含 A 之外的位。
        let removed = a.difference(b);
        assert_eq!(removed.union(a.intersection(b)), a);
        assert_eq!(a.union(b).difference(b), a.difference(b));
    }

    #[test]
    fn exhaustive_small_subset_matches_set_semantics() {
        // 在 4 个位上穷举：位图语义与朴素集合完全一致。
        for caller in 0u64..16 {
            for calls in 0u64..16 {
                let c = SyscallSet::from_words([caller, 0, 0, 0]);
                let d = SyscallSet::from_words([calls, 0, 0, 0]);
                assert_eq!(d.is_subset_of(c), calls & !caller == 0, "caller={caller:04b} calls={calls:04b}");
                assert_eq!(c.union(d).words()[0], caller | calls);
                assert_eq!(c.intersection(d).words()[0], caller & calls);
                assert_eq!(c.difference(d).words()[0], caller & !calls);
            }
        }
    }

    #[test]
    fn fixed_seed_roundtrip_and_membership_across_all_words() {
        // 固定种子的确定性伪随机（xorshift64*）：不依赖外部 crate，失败可复现。
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for round in 0..512 {
            let words = [next(), next(), next(), next()];
            let set = SyscallSet::from_words(words);
            let mut encoded = [0u8; BYTES];
            set.encode(&mut encoded);
            assert_eq!(SyscallSet::decode(&encoded), set, "round={round}");
            for id in 0..MAX_IDS {
                let expected = words[id / 64] & (1u64 << (id % 64)) != 0;
                assert_eq!(set.contains(id as u64), expected, "round={round} id={id}");
            }
            assert!(!set.contains(MAX_IDS as u64));
            assert_eq!(set.count(), set.ids().count());
            // 补集 + 差集 = 全集；差集不会产生原集合没有的位。
            let inv = SyscallSet::FULL.difference(set);
            assert_eq!(set.union(inv), SyscallSet::FULL);
            assert_eq!(set.intersection(inv), SyscallSet::EMPTY);
            assert!(set.difference(set).is_empty());
        }
    }

    #[test]
    fn encoded_layout_is_fixed_little_endian() {
        let set = SyscallSet::of(&[0, 63, 64, 127, 255]);
        let mut bytes = [0u8; BYTES];
        set.encode(&mut bytes);
        assert_eq!(bytes.len(), 32);
        assert_eq!(&bytes[0..8], &(1u64 | 1u64 << 63).to_le_bytes());
        assert_eq!(&bytes[8..16], &(1u64 | 1u64 << 63).to_le_bytes());
        assert_eq!(&bytes[16..24], &[0u8; 8]);
        assert_eq!(&bytes[24..32], &(1u64 << 63).to_le_bytes());
        assert_eq!(SyscallSet::decode(&bytes), set);
        // 单字边界不会被相邻字「借位」。
        for word in 0..WORDS {
            let mut w = [0u64; WORDS];
            w[word] = 1;
            let s = SyscallSet::from_words(w);
            assert_eq!(s.count(), 1);
            assert!(s.contains((word * 64) as u64));
            assert!(!s.contains((word * 64 + 1) as u64));
        }
    }

    #[test]
    fn high_id_64_serialization_is_target_width_independent() {
        #[cfg(target_pointer_width = "32")]
        assert_eq!(core::mem::size_of::<usize>(), 4);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(core::mem::size_of::<usize>(), 8);

        let mut bytes = [0u8; BYTES];
        SyscallSet::of(&[64]).encode(&mut bytes);
        assert_eq!(&bytes[0..8], &[0u8; 8]);
        assert_eq!(&bytes[8..16], &1u64.to_le_bytes());
        assert_eq!(&bytes[16..24], &[0u8; 8]);
        assert_eq!(&bytes[24..32], &[0u8; 8]);
        assert_eq!(SyscallSet::decode(&bytes), SyscallSet::of(&[64]));
    }
}
