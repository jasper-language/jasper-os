//! 内核对象表（M4.1）：对象生命周期的唯一记账处。
//! Kernel object table: the single source of truth for object lifetimes.
//!
//! # 依据（M4.0 规范 v0.6，第 1 节）
//! 每个对象分开计数两种强引用：
//! * **有效外部所有权**（owners）：进程句柄表中的句柄、队列中尚未交付的消息。归零 ⇒ 对象进入 closing
//!   （调用者据 [`Released::became_unowned`] 执行该类型的 closing 动作，例如取消在飞 recv）
//! * **内部引用**（internal）：在飞请求、执行上下文、进程线程表等为完成工作而持有的引用。只保证内存安全，不阻止 closing
//!
//! 两者之和归零 ⇒ 对象「死亡」：**不在这里就地销毁**，而是放进清理队列；由清理过程（[`drain`]）在锁外取出并执行
//! 该类型的销毁动作。销毁动作本身可以释放其他对象的引用（级联），被级联释放的对象同样只是入队——
//! 因此清理永远是迭代而不是递归，也不会在持锁或中断上下文里执行复杂回调（INV-09 的执行侧保证）。
//!
//! # 标识
//! [`ObjId`] = 槽位下标 + 世代：槽位复用时世代加一，旧标识必然失效；世代耗尽的槽位永久退役，标识永不复用。
//!
//! # 容量（启动期决定）
//! 本 crate 不使用堆：表本身不分配内存，存储（槽位与清理队列两个切片）由内核在**启动期**按配置容量
//! 从堆上分配后经 [`ObjectTable::install`] 一次性交给表，此后容量不变。安装之前表的容量为 0，
//! 任何插入都返回 [`ObjError::Full`]（安全失败，而不是越界）。
//! Storage is supplied once at boot (`install`), so the capacity is a boot-time setting, not a const generic.

pub use crate::capacity::InstallError;

/// 对象标识（槽位下标 + 世代，打包为 64 位跨边界传递）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjId {
    index: u32,
    generation: u32,
}

impl ObjId {
    /// 打包成 64 位（高 32 位世代，低 32 位下标 + 1；0 表示空标识）。
    pub const fn raw(self) -> u64 {
        ((self.generation as u64) << 32) | (self.index as u64 + 1)
    }

    /// 由 64 位原始值还原（校验发生在查表时）。
    pub const fn from_raw(raw: u64) -> Option<ObjId> {
        let low = (raw & 0xFFFF_FFFF) as u32;
        if low == 0 {
            None
        } else {
            Some(ObjId { index: low - 1, generation: (raw >> 32) as u32 })
        }
    }
}

/// 对象表错误（`system.object.error.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjError {
    /// 标识不存在、已死亡或世代不匹配。
    Invalid,
    /// 释放了一个计数已经为 0 的引用（调用方记账错误）。
    Underflow,
    /// 表已满（配额：系统内核对象总数），或某个引用计数已到上限（拒绝而不是回绕）。
    Full,
}

impl ObjError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            ObjError::Invalid => "system.object.error.invalid",
            ObjError::Underflow => "system.object.error.underflow",
            ObjError::Full => "system.error.quota_exceeded",
        }
    }
}

/// 一次释放的后果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Released {
    /// 有效外部所有权刚刚降为 0（调用者应执行该对象的 closing 动作）。
    pub became_unowned: bool,
    /// 全部强引用刚刚降为 0（对象已进入清理队列）。
    pub dead: bool,
}

/// 生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    /// 有外部所有者。
    Live,
    /// 没有外部所有者，但仍有内部引用（在飞操作等）。
    Closing,
    /// 已死亡，等待清理过程销毁。
    Dead,
}

struct Entry<T> {
    value: T,
    owners: u32,
    internal: u32,
    state: Lifecycle,
}

/// 对象表的一个槽位（内部状态不公开；调用者只用 [`Slot::VACANT`] 准备存储）。
/// One slot of the object table (opaque; callers only use [`Slot::VACANT`] to prepare storage).
pub struct Slot<T> {
    generation: u32,
    retired: bool,
    entry: Option<Entry<T>>,
}

impl<T> Slot<T> {
    /// 空槽位：世代 0、未退役、无对象。启动期准备存储时用它填满切片。
    pub const VACANT: Slot<T> = Slot { generation: 0, retired: false, entry: None };

    fn is_vacant(&self) -> bool {
        self.generation == 0 && !self.retired && self.entry.is_none()
    }
}

/// 对象表：容量在启动期由 [`ObjectTable::install`] 决定。清理队列与表同容量，因此永不溢出。
/// Object table whose capacity is fixed at boot by [`ObjectTable::install`].
pub struct ObjectTable<T: 'static> {
    slots: &'static mut [Slot<T>],
    /// 清理队列（环形，存死亡对象的下标）。
    pending: &'static mut [u32],
    head: usize,
    len: usize,
    live: usize,
    destroyed: u64,
}

impl<T: 'static> ObjectTable<T> {
    /// 尚未安装存储的空表（容量 0）。可以放进 `static`，启动期再 [`install`](Self::install)。
    pub const fn empty() -> Self {
        ObjectTable { slots: &mut [], pending: &mut [], head: 0, len: 0, live: 0, destroyed: 0 }
    }

    /// 安装存储（只能一次）：`slots` 必须全部是 [`Slot::VACANT`]，`pending` 与它等长。
    /// 被拒时返回原因并且表保持为空（调用者据此拒绝启动）。
    /// Install the boot-time storage (once). On refusal the table stays empty.
    pub fn install(&mut self, slots: &'static mut [Slot<T>], pending: &'static mut [u32]) -> Result<usize, InstallError> {
        if !self.slots.is_empty() {
            return Err(InstallError::AlreadyInstalled);
        }
        if slots.is_empty() {
            return Err(InstallError::Empty);
        }
        if slots.len() != pending.len() {
            return Err(InstallError::LengthMismatch);
        }
        if slots.len() > MAX_CAPACITY {
            return Err(InstallError::TooLarge);
        }
        if !slots.iter().all(Slot::is_vacant) {
            return Err(InstallError::NotVacant);
        }
        self.slots = slots;
        self.pending = pending;
        Ok(self.slots.len())
    }

    /// 容量（安装之前为 0）。
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// 因世代用尽而永久退役的槽位数（长期运行审计用：它增长意味着可用容量在下降）。
    /// Slots permanently retired because their generation was exhausted.
    pub fn retired_slots(&self) -> usize {
        self.slots.iter().filter(|s| s.retired).count()
    }

    /// 宿主测试用：从测试堆上泄漏出一份容量为 `n` 的存储并安装。
    #[cfg(test)]
    pub(crate) fn for_test(n: usize) -> Self {
        let mut t = Self::empty();
        let slots: &'static mut [Slot<T>] = Box::leak((0..n).map(|_| Slot::VACANT).collect::<Vec<_>>().into_boxed_slice());
        let pending: &'static mut [u32] = Box::leak(vec![0u32; n].into_boxed_slice());
        t.install(slots, pending).expect("测试存储应可安装");
        t
    }

    /// 放入新对象，初始持有 `owners` 个外部所有权与 `internal` 个内部引用（两者之和须 ≥ 1）。
    pub fn insert(&mut self, value: T, owners: u32, internal: u32) -> Result<ObjId, ObjError> {
        match owners.checked_add(internal) {
            None => return Err(ObjError::Full),
            Some(0) => return Err(ObjError::Underflow),
            Some(_) => {}
        }
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, s)| s.entry.is_none() && !s.retired)
            .ok_or(ObjError::Full)?;
        // 新对象一律从 Live 开始：closing 只在外部所有权「从有降到零」的那一刻触发（release_owner），
        // 刚创建、尚未发放任何句柄的对象（例如新线程对象）必须仍能获得第一个所有者。
        slot.entry = Some(Entry { value, owners, internal, state: Lifecycle::Live });
        self.live += 1;
        Ok(ObjId { index: index as u32, generation: slot.generation })
    }

    fn entry(&self, id: ObjId) -> Result<&Entry<T>, ObjError> {
        let slot = self.slots.get(id.index as usize).ok_or(ObjError::Invalid)?;
        match &slot.entry {
            Some(e) if slot.generation == id.generation && e.state != Lifecycle::Dead => Ok(e),
            _ => Err(ObjError::Invalid),
        }
    }

    fn entry_mut(&mut self, id: ObjId) -> Result<&mut Entry<T>, ObjError> {
        let slot = self.slots.get_mut(id.index as usize).ok_or(ObjError::Invalid)?;
        match &mut slot.entry {
            Some(e) if slot.generation == id.generation && e.state != Lifecycle::Dead => Ok(e),
            _ => Err(ObjError::Invalid),
        }
    }

    /// 借用对象值（死亡后不可再借）。
    pub fn get(&self, id: ObjId) -> Result<&T, ObjError> {
        self.entry(id).map(|e| &e.value)
    }

    /// 可变借用对象值。
    pub fn get_mut(&mut self, id: ObjId) -> Result<&mut T, ObjError> {
        self.entry_mut(id).map(|e| &mut e.value)
    }

    /// （外部所有权, 内部引用, 状态）。
    pub fn counts(&self, id: ObjId) -> Result<(u32, u32, Lifecycle), ObjError> {
        self.entry(id).map(|e| (e.owners, e.internal, e.state))
    }

    /// Borrow two distinct live object values without aliasing. Author: chatgpt.
    /// Validation is read-only; on error no object or reference count changes.
    pub fn get_pair_mut(&mut self, a: ObjId, b: ObjId) -> Result<(&mut T, &mut T), ObjError> {
        if a.index == b.index { return Err(ObjError::Invalid); }
        self.entry(a)?;
        self.entry(b)?;
        let (low, high, reversed) = if a.index < b.index {
            (a.index as usize, b.index as usize, false)
        } else { (b.index as usize, a.index as usize, true) };
        let (left, right) = self.slots.split_at_mut(high);
        let x = &mut left[low].entry.as_mut().expect("validated low entry").value;
        let y = &mut right[0].entry.as_mut().expect("validated high entry").value;
        if reversed { Ok((y, x)) } else { Ok((x, y)) }
    }

    /// 增加一个外部所有权。closing 的对象不能再获得所有者（它已无人可再使用）。
    pub fn acquire_owner(&mut self, id: ObjId) -> Result<(), ObjError> {
        let e = self.entry_mut(id)?;
        if e.state != Lifecycle::Live {
            return Err(ObjError::Invalid);
        }
        // 检查式加法：计数回绕到 0 会让仍在使用的对象被提前销毁（释放后使用），因此到上限即拒绝
        e.owners = e.owners.checked_add(1).ok_or(ObjError::Full)?;
        Ok(())
    }

    /// 增加一个内部引用（closing 的对象也可以，例如清理期间仍需访问）。计数到上限即拒绝（不回绕）。
    pub fn acquire_internal(&mut self, id: ObjId) -> Result<(), ObjError> {
        let e = self.entry_mut(id)?;
        e.internal = e.internal.checked_add(1).ok_or(ObjError::Full)?;
        Ok(())
    }

    /// 释放一个外部所有权。
    pub fn release_owner(&mut self, id: ObjId) -> Result<Released, ObjError> {
        let e = self.entry_mut(id)?;
        if e.owners == 0 {
            return Err(ObjError::Underflow);
        }
        e.owners -= 1;
        let became_unowned = e.owners == 0;
        if became_unowned {
            e.state = Lifecycle::Closing;
        }
        Ok(Released { became_unowned, dead: self.maybe_die(id) })
    }

    /// 释放一个内部引用。
    pub fn release_internal(&mut self, id: ObjId) -> Result<Released, ObjError> {
        let e = self.entry_mut(id)?;
        if e.internal == 0 {
            return Err(ObjError::Underflow);
        }
        e.internal -= 1;
        Ok(Released { became_unowned: false, dead: self.maybe_die(id) })
    }

    /// 两种计数都为 0 ⇒ 标记死亡并入清理队列。
    fn maybe_die(&mut self, id: ObjId) -> bool {
        let Some(slot) = self.slots.get_mut(id.index as usize) else {
            return false;
        };
        let Some(e) = slot.entry.as_mut() else {
            return false;
        };
        if e.owners == 0 && e.internal == 0 && e.state != Lifecycle::Dead {
            e.state = Lifecycle::Dead;
            let tail = (self.head + self.len) % self.pending.len();
            self.pending[tail] = id.index;
            self.len += 1;
            return true;
        }
        false
    }

    /// 取出一个死亡对象（从表中移除、槽位世代加一），交给调用者执行销毁动作。
    pub fn take_dead(&mut self) -> Option<(ObjId, T)> {
        if self.len == 0 {
            return None;
        }
        let index = self.pending[self.head];
        self.head = (self.head + 1) % self.pending.len();
        self.len -= 1;
        let slot = &mut self.slots[index as usize];
        let generation = slot.generation;
        let entry = slot.entry.take()?;
        match slot.generation.checked_add(1) {
            Some(g) => slot.generation = g,
            None => slot.retired = true,
        }
        self.live -= 1;
        self.destroyed += 1;
        Some((ObjId { index, generation }, entry.value))
    }

    /// 仍在表中的对象数（含 closing 与等待清理的）。
    pub fn live(&self) -> usize {
        self.live
    }

    /// 清理队列长度（规范 6.2：可观测，负载结束后应归零）。
    pub fn pending(&self) -> usize {
        self.len
    }

    /// 累计已销毁的对象数。
    pub fn destroyed(&self) -> u64 {
        self.destroyed
    }
}

impl<T: 'static> Default for ObjectTable<T> {
    fn default() -> Self {
        Self::empty()
    }
}

/// 容量上限：下标存成 `u32`，标识里存「下标 + 1」，所以最多 `u32::MAX` 个槽位。
pub const MAX_CAPACITY: usize = u32::MAX as usize;

/// 清理过程：最多处理 `limit` 个死亡对象。`destroy` 收到对象值后执行销毁动作，可以经传入的表释放其他对象
/// 的引用（级联）；被级联释放的对象只会入队，在本轮剩余预算或下一轮被处理——迭代、不递归。返回本轮处理数。
pub fn drain<T: 'static>(
    table: &mut ObjectTable<T>,
    limit: usize,
    mut destroy: impl FnMut(&mut ObjectTable<T>, ObjId, T),
) -> usize {
    let mut n = 0;
    while n < limit {
        let Some((id, value)) = table.take_dead() else {
            break;
        };
        destroy(table, id, value);
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    enum Obj {
        Leaf(u32),
        /// 持有另一个对象内部引用的容器（模拟 Process → Task）。
        Holder(ObjId),
    }

    #[test]
    fn closing_handle_does_not_destroy_while_internal_refs_remain() {
        let mut t: ObjectTable<Obj> = ObjectTable::for_test(8);
        let id = t.insert(Obj::Leaf(1), 1, 1).unwrap(); // 一个句柄 + 一个在飞请求
        let r = t.release_owner(id).unwrap();
        assert_eq!(r, Released { became_unowned: true, dead: false }, "句柄关闭 ⇒ closing，但未死亡（INV-01）");
        assert_eq!(t.counts(id).unwrap(), (0, 1, Lifecycle::Closing));
        assert_eq!(t.acquire_owner(id), Err(ObjError::Invalid), "closing 对象不能再获得所有者");
        assert!(t.get(id).is_ok(), "在飞请求仍可访问对象");
        let r = t.release_internal(id).unwrap();
        assert!(r.dead && !r.became_unowned);
        assert_eq!(t.pending(), 1);
        assert_eq!(t.get(id), Err(ObjError::Invalid), "死亡后不可再借用");
        let (gone, v) = t.take_dead().unwrap();
        assert_eq!((gone, v), (id, Obj::Leaf(1)));
        assert_eq!(t.live(), 0);
    }

    #[test]
    fn double_release_and_stale_ids_are_rejected() {
        let mut t: ObjectTable<Obj> = ObjectTable::for_test(4);
        let id = t.insert(Obj::Leaf(7), 1, 0).unwrap();
        assert!(t.release_owner(id).unwrap().dead);
        assert_eq!(t.release_owner(id), Err(ObjError::Invalid), "重复关闭");
        t.take_dead().unwrap();
        let id2 = t.insert(Obj::Leaf(8), 1, 0).unwrap();
        assert_eq!(id2.raw() & 0xFFFF_FFFF, id.raw() & 0xFFFF_FFFF, "复用同一槽位");
        assert_ne!(id2, id, "但世代不同");
        assert_eq!(t.get(id), Err(ObjError::Invalid), "旧标识必然失效");
        assert_eq!(ObjId::from_raw(id2.raw()), Some(id2));
        assert_eq!(ObjId::from_raw(0), None);
        let id3 = t.insert(Obj::Leaf(9), 0, 1).unwrap();
        assert_eq!(t.release_owner(id3), Err(ObjError::Underflow));
        assert_eq!(t.insert(Obj::Leaf(0), 0, 0), Err(ObjError::Underflow));
    }

    #[test]
    fn cascade_cleanup_is_iterative_and_reentrant() {
        let mut t: ObjectTable<Obj> = ObjectTable::for_test(8);
        // 链：H1 → H2 → leaf（每个容器持有下一个的内部引用）
        let leaf = t.insert(Obj::Leaf(3), 0, 1).unwrap();
        let h2 = t.insert(Obj::Holder(leaf), 0, 1).unwrap();
        let h1 = t.insert(Obj::Holder(h2), 1, 0).unwrap();
        assert!(t.release_owner(h1).unwrap().dead);
        let mut order = Vec::new();
        // 预算 1：每轮只销毁一个；销毁动作里释放下一个（重入表），被释放者入队而不是递归销毁
        for _ in 0..5 {
            drain(&mut t, 1, |tab, id, v| {
                order.push(id);
                if let Obj::Holder(next) = v {
                    let r = tab.release_internal(next).unwrap();
                    assert!(r.dead);
                }
            });
        }
        assert_eq!(order, vec![h1, h2, leaf]);
        assert_eq!((t.live(), t.pending(), t.destroyed()), (0, 0, 3));
    }

    #[test]
    fn object_created_without_owner_can_still_gain_its_first_owner() {
        let mut t: ObjectTable<Obj> = ObjectTable::for_test(4);
        let id = t.insert(Obj::Leaf(5), 0, 2).unwrap(); // 新线程对象：只有内部引用
        assert_eq!(t.counts(id).unwrap(), (0, 2, Lifecycle::Live), "新对象不是 closing");
        t.acquire_owner(id).unwrap(); // 发放第一个句柄
        let r = t.release_owner(id).unwrap();
        assert!(r.became_unowned && !r.dead, "句柄关闭后才进入 closing");
        assert_eq!(t.counts(id).unwrap().2, Lifecycle::Closing);
    }

    #[test]
    fn table_full_is_reported() {
        let mut t: ObjectTable<Obj> = ObjectTable::for_test(2);
        t.insert(Obj::Leaf(1), 1, 0).unwrap();
        t.insert(Obj::Leaf(2), 1, 0).unwrap();
        assert_eq!(t.insert(Obj::Leaf(3), 1, 0), Err(ObjError::Full));
    }

    #[test]
    fn reference_counts_refuse_to_wrap() {
        let mut t: ObjectTable<u8> = ObjectTable::for_test(2);
        assert_eq!(t.insert(1, u32::MAX, 1), Err(ObjError::Full), "初始计数之和溢出被拒");
        let id = t.insert(1, u32::MAX, 0).unwrap();
        assert_eq!(t.acquire_owner(id), Err(ObjError::Full), "外部所有权到上限被拒，而不是回绕到 0");
        let id2 = t.insert(2, 0, u32::MAX).unwrap();
        assert_eq!(t.acquire_internal(id2), Err(ObjError::Full));
        assert_eq!(t.counts(id2).map(|c| (c.0, c.1)), Ok((0, u32::MAX)), "被拒后计数不变");
    }

    #[test]
    fn empty_table_refuses_inserts_until_storage_is_installed() {
        let mut t: ObjectTable<u8> = ObjectTable::empty();
        assert_eq!(t.capacity(), 0);
        assert_eq!(t.insert(1, 1, 0), Err(ObjError::Full), "未安装存储 ⇒ 安全失败而不是越界");
        assert_eq!(t.take_dead(), None);
    }

    #[test]
    fn install_rejects_bad_storage_and_leaves_table_unchanged() {
        fn leak_slots(n: usize) -> &'static mut [Slot<u8>] {
            Box::leak((0..n).map(|_| Slot::VACANT).collect::<Vec<_>>().into_boxed_slice())
        }
        fn leak_pending(n: usize) -> &'static mut [u32] {
            Box::leak(vec![0u32; n].into_boxed_slice())
        }
        let mut t: ObjectTable<u8> = ObjectTable::empty();
        assert_eq!(t.install(leak_slots(0), leak_pending(0)), Err(InstallError::Empty));
        assert_eq!(t.install(leak_slots(4), leak_pending(3)), Err(InstallError::LengthMismatch));
        let dirty = leak_slots(2);
        dirty[1].generation = 5;
        assert_eq!(t.install(dirty, leak_pending(2)), Err(InstallError::NotVacant));
        assert_eq!(t.capacity(), 0, "被拒后表保持为空");
        assert_eq!(t.install(leak_slots(3), leak_pending(3)), Ok(3));
        assert_eq!(t.install(leak_slots(3), leak_pending(3)), Err(InstallError::AlreadyInstalled), "容量只能决定一次");
        assert_eq!(t.capacity(), 3);
    }

    #[test]
    fn large_boot_capacity_works_end_to_end() {
        // 容量远大于编译期旧上限（1024）。插入目前是线性找空槽（装满为 O(n²)），去掉它属于 HARDEN-1D，
        // 因此这里取 8192 控制测试时长，而不是以此衡量规模化性能。
        let n = 8192;
        let mut t: ObjectTable<u32> = ObjectTable::for_test(n);
        let ids: Vec<_> = (0..n as u32).map(|i| t.insert(i, 1, 0).unwrap()).collect();
        assert_eq!(t.insert(0, 1, 0), Err(ObjError::Full), "装满后安全失败");
        for id in &ids {
            assert!(t.release_owner(*id).unwrap().dead);
        }
        assert_eq!(t.pending(), n, "清理队列与表同容量，装满也不溢出");
        let mut gone = 0;
        while t.take_dead().is_some() {
            gone += 1;
        }
        assert_eq!((gone, t.live(), t.pending()), (n, 0, 0));
    }
}

#[cfg(kani)]
mod fv1_objects {
    extern crate std;
    use super::*;
    use self::std::boxed::Box;
    fn table() -> ObjectTable<u8> {
        let mut t = ObjectTable::empty();
        t.install(Box::leak(Box::new([Slot::VACANT])),
            Box::leak(Box::new([0]))).unwrap();
        t
    }
    #[kani::proof]
    #[kani::unwind(4)]
    fn object_generation_and_internal_reference_lifetime() {
        let mut t = table();
        let generation: u32 = kani::any();
        t.slots[0].generation = generation;
        let old = t.insert(7, 1, 1).unwrap();
        assert!(!t.release_owner(old).unwrap().dead);
        assert_eq!(t.acquire_owner(old), Err(ObjError::Invalid));
        assert_eq!(t.get(old), Ok(&7));
        assert!(t.release_internal(old).unwrap().dead);
        assert_eq!(t.get(old), Err(ObjError::Invalid));
        assert_eq!(t.pending(), 1);
        assert_eq!(t.take_dead(), Some((old, 7)));
        assert_eq!(t.take_dead(), None);
        if generation == u32::MAX {
            assert_eq!(t.retired_slots(), 1);
            assert_eq!(t.insert(8, 1, 0), Err(ObjError::Full));
        } else {
            let new = t.insert(8, 1, 0).unwrap();
            assert_ne!(old, new);
            assert_eq!(t.get(old), Err(ObjError::Invalid));
        }
    }
    #[kani::proof]
    #[kani::unwind(4)]
    fn object_reference_increment_rejects_overflow_atomically() {
        let mut t = table();
        let owners: u32 = kani::any();
        if owners == 0 {
            assert_eq!(t.insert(7, owners, 0), Err(ObjError::Underflow));
            assert_eq!(t.live(), 0);
            return;
        }
        let id = t.insert(7, owners, 0).unwrap();
        let result = t.acquire_owner(id);
        if owners == u32::MAX {
            assert_eq!(result, Err(ObjError::Full));
            assert_eq!(t.counts(id).unwrap().0, owners);
        } else {
            assert!(result.is_ok());
            assert_eq!(t.counts(id).unwrap().0, owners + 1);
            t.release_owner(id).unwrap();
            assert_eq!(t.counts(id).unwrap().0, owners);
        }
        assert_eq!(t.pending(), 0);
    }
    #[kani::proof]
    #[kani::unwind(4)]
    fn two_object_borrows_are_distinct_and_validate_indices() {
        let mut t = ObjectTable::empty();
        t.install(Box::leak(Box::new([Slot::VACANT, Slot::VACANT])),
            Box::leak(Box::new([0, 0]))).unwrap();
        let first = t.insert(7u8, 1, 0).unwrap();
        let second = t.insert(9u8, 1, 0).unwrap();
        let raw: u64 = kani::any();
        if let Some(candidate) = ObjId::from_raw(raw) {
            if candidate == second {
                let (a, b) = t.get_pair_mut(first, candidate).unwrap();
                *a = 11; *b = 13;
                assert_eq!(t.get(first), Ok(&11));
                assert_eq!(t.get(second), Ok(&13));
            } else {
                assert!(t.get_pair_mut(first, candidate).is_err());
                assert_eq!(t.get(first), Ok(&7));
                assert_eq!(t.get(second), Ok(&9));
            }
        }
        let (b, a) = t.get_pair_mut(second, first).unwrap();
        *a = 17; *b = 19;
        assert_eq!(t.get(first), Ok(&17));
        assert_eq!(t.get(second), Ok(&19));
        assert_eq!(t.counts(first).unwrap(), (1, 0, Lifecycle::Live));
    }

    #[kani::proof]
    #[kani::unwind(4)]
    fn internal_reference_increment_rejects_overflow_atomically() {
        let mut t = table();
        let internal: u32 = kani::any();
        if internal == 0 {
            assert_eq!(t.insert(7, 0, internal), Err(ObjError::Underflow));
            return;
        }
        let id = t.insert(7, 0, internal).unwrap();
        let result = t.acquire_internal(id);
        if internal == u32::MAX {
            assert_eq!(result, Err(ObjError::Full));
        } else {
            assert!(result.is_ok());
            assert_eq!(t.counts(id).unwrap().1, internal + 1);
            t.release_internal(id).unwrap();
        }
        assert_eq!(t.counts(id).unwrap().1, internal);
        assert_eq!(t.release_owner(id), Err(ObjError::Underflow));
        assert_eq!(t.pending(), 0);
    }

}

#[cfg(test)]
mod subscription_publisher_contract {
 use super::*;
 #[test]
 fn publisher_anchor_keeps_source_regrantable_until_publisher_finishes() {
  let mut table=ObjectTable::for_test(2);
  let broken=table.insert(1u8,0,1).unwrap();
  table.acquire_owner(broken).unwrap();table.release_owner(broken).unwrap();
  assert_eq!(table.acquire_owner(broken),Err(ObjError::Invalid));
  table.release_internal(broken).unwrap();table.take_dead().unwrap();
  let source=table.insert(2u8,1,0).unwrap();
  for _ in 0..32 {table.acquire_owner(source).unwrap();let released=table.release_owner(source).unwrap();assert!(!released.became_unowned);assert!(!released.dead);}
  table.acquire_internal(source).unwrap();let released=table.release_owner(source).unwrap();assert!(released.became_unowned);assert!(!released.dead);
  assert_eq!(table.acquire_owner(source),Err(ObjError::Invalid));
  assert!(table.release_internal(source).unwrap().dead);
 }
}
