//! 每核运行列表：把「哪些槽位在第 q 个运行队列上」按槽位号有序串成侵入式双向链表，
//! 让选择、等待档位、窃取候选只遍历相关队列上的任务，而不是扫描整张任务表。
//! Per-CPU run lists: intrusive, slot-ordered doubly linked lists of the slots queued on each run queue.
//!
//! # 职责边界
//! * 只记录成员关系与顺序，不看任务状态、档位或策略；调用者（调度机制）在每次运行队列成员关系改变后
//!   用 [`RunLists::place`] 让列表与实体的队列字段一致。
//! * 链接存放在调用者提供的切片里（每个槽位一个 [`Link`]），本类型只保存每个队列的表头与长度，
//!   因此槽位数可以在启动期决定、不需要编译期常量，也不在持锁路径上分配内存。
//! * 列表按槽位号升序：遍历顺序与「按槽位扫描任务表」一致，策略的同键取先者规则因此不受影响。
//!   插入代价是该队列的长度（与整张表的槽位数无关）。
//! * 非法操作（重复插入、移除不在任何列表上的槽位、下标越界）一律拒绝且不改动任何状态。

/// 链表结束标记。
const NIL: u32 = u32::MAX;
/// 「不在任何列表上」标记。
const NONE: u8 = u8::MAX;

/// 一个槽位的链接（由调用者按槽位数分配，初值为 [`Link::EMPTY`]）。
/// Per-slot link storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    prev: u32,
    next: u32,
    queue: u8,
}

impl Link {
    /// 不在任何列表上的链接。
    /// A link that is on no list.
    pub const EMPTY: Link = Link { prev: NIL, next: NIL, queue: NONE };

    /// 所在队列（不在任何列表上为 `None`）。
    /// The queue this slot is listed on.
    pub const fn queue(&self) -> Option<usize> {
        if self.queue == NONE {
            None
        } else {
            Some(self.queue as usize)
        }
    }
}

/// 列表操作被拒绝的原因（被拒绝时什么都不改）。
/// Why a run-list operation was refused (nothing changed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunListError {
    /// 槽位已在某个列表上。
    AlreadyListed(usize),
    /// 槽位不在任何列表上。
    NotListed,
    /// 队列下标越界。
    NoSuchQueue,
    /// 槽位下标越界（超出链接切片或无法用 32 位表示）。
    NoSuchSlot,
}

/// `M` 个队列的表头与长度。
/// Heads and lengths of `M` run lists.
#[derive(Debug, Clone, Copy)]
pub struct RunLists<const M: usize> {
    head: [u32; M],
    len: [u32; M],
}

impl<const M: usize> Default for RunLists<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const M: usize> RunLists<M> {
    /// 全部为空（`const`，可放进 `static`）。
    /// All lists empty.
    pub const fn new() -> Self {
        RunLists { head: [NIL; M], len: [0; M] }
    }

    /// 队列 `q` 上的槽位数（越界为 0）。
    /// Number of slots on list `q`.
    pub fn len(&self, q: usize) -> usize {
        self.len.get(q).map_or(0, |&n| n as usize)
    }

    /// 队列 `q` 是否为空。
    /// Whether list `q` is empty.
    pub fn is_empty(&self, q: usize) -> bool {
        self.len(q) == 0
    }

    /// 全部列表上的槽位总数。
    /// Total slots over all lists.
    pub fn total(&self) -> usize {
        self.len.iter().map(|&n| n as usize).sum()
    }

    /// 按槽位号升序插入队列 `q`。已在任何列表上、或下标越界时拒绝。
    /// Insert `slot` into list `q`, keeping slot order.
    pub fn insert(&mut self, links: &mut [Link], q: usize, slot: usize) -> Result<(), RunListError> {
        if q >= M || q >= NONE as usize {
            return Err(RunListError::NoSuchQueue);
        }
        if slot >= links.len() || slot >= NIL as usize {
            return Err(RunListError::NoSuchSlot);
        }
        if let Some(on) = links[slot].queue() {
            return Err(RunListError::AlreadyListed(on));
        }
        let s = slot as u32;
        // 找到第一个槽位号大于 slot 的结点，插在它前面
        let mut prev = NIL;
        let mut at = self.head[q];
        while at != NIL && at < s {
            prev = at;
            at = links[at as usize].next;
        }
        links[slot] = Link { prev, next: at, queue: q as u8 };
        if prev == NIL {
            self.head[q] = s;
        } else {
            links[prev as usize].next = s;
        }
        if at != NIL {
            links[at as usize].prev = s;
        }
        self.len[q] += 1;
        Ok(())
    }

    /// 把槽位从它所在的列表上摘下，返回原来的队列。不在任何列表上或越界时拒绝。
    /// Unlink `slot`; returns the list it was on.
    pub fn remove(&mut self, links: &mut [Link], slot: usize) -> Result<usize, RunListError> {
        let l = *links.get(slot).ok_or(RunListError::NoSuchSlot)?;
        let q = l.queue().ok_or(RunListError::NotListed)?;
        if q >= M {
            return Err(RunListError::NoSuchQueue);
        }
        if l.prev == NIL {
            self.head[q] = l.next;
        } else {
            links[l.prev as usize].next = l.next;
        }
        if l.next != NIL {
            links[l.next as usize].prev = l.prev;
        }
        links[slot] = Link::EMPTY;
        self.len[q] -= 1;
        Ok(q)
    }

    /// 让槽位的列表成员关系等于 `want`（`None` = 不在任何列表上）：已一致时不动，否则先摘下再插入。
    /// 返回是否有改动。`want` 越界时拒绝且不改动（不会先摘下）。
    /// Make `slot`'s membership equal to `want`.
    pub fn place(&mut self, links: &mut [Link], slot: usize, want: Option<usize>) -> Result<bool, RunListError> {
        let have = links.get(slot).ok_or(RunListError::NoSuchSlot)?.queue();
        if have == want {
            return Ok(false);
        }
        if let Some(q) = want {
            if q >= M || q >= NONE as usize {
                return Err(RunListError::NoSuchQueue);
            }
            if slot >= NIL as usize {
                return Err(RunListError::NoSuchSlot);
            }
        }
        if have.is_some() {
            self.remove(links, slot)?;
        }
        if let Some(q) = want {
            self.insert(links, q, slot)?;
        }
        Ok(true)
    }

    /// 按槽位号升序遍历队列 `q`（越界为空）。
    /// Iterate list `q` in slot order.
    pub fn iter<'a>(&self, links: &'a [Link], q: usize) -> Iter<'a> {
        Iter { links, at: self.head.get(q).copied().unwrap_or(NIL) }
    }

    /// First slot on queue `q`, for callers that keep link storage behind a
    /// lock and therefore cannot let [`Iter`] borrow it across lock releases.
    pub fn first(&self, q: usize) -> Option<usize> {
        match self.head.get(q) {
            Some(&NIL) | None => None,
            Some(&slot) => Some(slot as usize),
        }
    }

    /// Successor of `slot` in its current list.  The caller must serialize
    /// this lookup with list mutation.
    pub fn next(&self, links: &[Link], slot: usize) -> Option<usize> {
        let next = links.get(slot)?.next;
        (next != NIL).then_some(next as usize)
    }
}

/// 一个列表的遍历器（产出槽位号）。
/// Iterator over one list's slots.
#[derive(Clone)]
pub struct Iter<'a> {
    links: &'a [Link],
    at: u32,
}

impl Iterator for Iter<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        if self.at == NIL {
            return None;
        }
        let s = self.at as usize;
        self.at = self.links.get(s).map_or(NIL, |l| l.next);
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    fn items<const M: usize>(r: &RunLists<M>, l: &[Link], q: usize) -> Vec<usize> {
        r.iter(l, q).collect()
    }

    #[test]
    fn insert_keeps_slot_order_and_counts() {
        let mut l = vec![Link::EMPTY; 16];
        let mut r = RunLists::<4>::new();
        for s in [7, 3, 11, 1, 5] {
            r.insert(&mut l, 2, s).unwrap();
        }
        assert_eq!(items(&r, &l, 2), [1, 3, 5, 7, 11]);
        assert_eq!(r.len(2), 5);
        assert_eq!(r.total(), 5);
        assert!(r.is_empty(0));
        assert_eq!(l[5].queue(), Some(2));
    }

    #[test]
    fn remove_head_middle_tail() {
        let mut l = vec![Link::EMPTY; 8];
        let mut r = RunLists::<2>::new();
        for s in 1..6 {
            r.insert(&mut l, 0, s).unwrap();
        }
        assert_eq!(r.remove(&mut l, 1), Ok(0));
        assert_eq!(r.remove(&mut l, 3), Ok(0));
        assert_eq!(r.remove(&mut l, 5), Ok(0));
        assert_eq!(items(&r, &l, 0), [2, 4]);
        assert_eq!(l[3], Link::EMPTY);
        r.insert(&mut l, 0, 3).unwrap();
        assert_eq!(items(&r, &l, 0), [2, 3, 4]);
    }

    #[test]
    fn refusals_change_nothing() {
        let mut l = vec![Link::EMPTY; 4];
        let mut r = RunLists::<2>::new();
        r.insert(&mut l, 1, 2).unwrap();
        let (l0, r0) = (l.clone(), r);
        assert_eq!(r.insert(&mut l, 0, 2), Err(RunListError::AlreadyListed(1)));
        assert_eq!(r.insert(&mut l, 2, 1), Err(RunListError::NoSuchQueue));
        assert_eq!(r.insert(&mut l, 0, 4), Err(RunListError::NoSuchSlot));
        assert_eq!(r.remove(&mut l, 1), Err(RunListError::NotListed));
        assert_eq!(r.remove(&mut l, 9), Err(RunListError::NoSuchSlot));
        assert_eq!(r.place(&mut l, 2, Some(5)), Err(RunListError::NoSuchQueue));
        assert_eq!(l, l0);
        assert_eq!((r.head, r.len), (r0.head, r0.len));
    }

    #[test]
    fn place_moves_between_lists_and_is_idempotent() {
        let mut l = vec![Link::EMPTY; 8];
        let mut r = RunLists::<3>::new();
        assert_eq!(r.place(&mut l, 4, Some(0)), Ok(true));
        assert_eq!(r.place(&mut l, 4, Some(0)), Ok(false));
        assert_eq!(r.place(&mut l, 4, Some(2)), Ok(true));
        assert_eq!(items(&r, &l, 0), [] as [usize; 0]);
        assert_eq!(items(&r, &l, 2), [4]);
        assert_eq!(r.place(&mut l, 4, None), Ok(true));
        assert_eq!(r.place(&mut l, 4, None), Ok(false));
        assert_eq!(r.total(), 0);
    }

    /// 64 个队列、4096 个槽位、每队 1 个可运行任务：遍历一个队列只看到它自己的成员。
    #[test]
    fn many_queues_iterate_only_their_members() {
        const Q: usize = 64;
        let mut l = vec![Link::EMPTY; 4096];
        let mut r = RunLists::<Q>::new();
        for q in 0..Q {
            r.insert(&mut l, q, 4095 - q * 7).unwrap();
        }
        for q in 0..Q {
            assert_eq!(items(&r, &l, q), [4095 - q * 7]);
        }
        assert_eq!(r.total(), Q);
    }

    /// 与朴素模型逐步对拍：随机插入 / 移除 / 搬动后，每个列表等于按槽位排序的成员集合。
    #[test]
    fn matches_reference_model() {
        let mut l = vec![Link::EMPTY; 64];
        let mut r = RunLists::<5>::new();
        let mut model: Vec<Option<usize>> = vec![None; 64];
        let mut x: u32 = 0x1234_5678;
        for _ in 0..5000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let slot = (x % 64) as usize;
            let want = match (x >> 8) % 7 {
                0..=4 => Some(((x >> 12) % 5) as usize),
                _ => None,
            };
            r.place(&mut l, slot, want).unwrap();
            model[slot] = want;
        }
        for q in 0..5 {
            let expect: Vec<usize> = (0..64).filter(|&s| model[s] == Some(q)).collect();
            assert_eq!(items(&r, &l, q), expect);
            assert_eq!(r.len(q), expect.len());
        }
    }
}
