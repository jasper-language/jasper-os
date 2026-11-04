//! 启动期定容的槽位存储：堆就绪前用一小块内联存储，堆就绪后在启动期一次性扩到配置容量。
//! Boot-sized slot storage: a small inline array before the heap exists, one boot-time grow afterwards.
//!
//! # 为什么需要两段
//! 调度器在内核堆初始化之前就要运行（协作式 / 抢占式 / 机制演练），那时只能用 `.bss` 里的存储；
//! 而任务槽位数属于启动期容量（由启动容量记录决定），不能写成编译期常量。
//! 因此：先用 `I` 项内联存储（与静态内核栈数一致，堆就绪前本来也只有这么多槽位有栈），
//! 堆就绪后由 [`BootSlots::prepare`] + [`BootSlots::commit`] 扩到启动期容量，**下标保持不变**。
//!
//! # 全有或全无
//! 扩容分两步：`prepare` 只分配（失败时什么也不改），`commit` 只搬运（不会失败）。
//! 调度器先为全部字段 `prepare`，都成功后才逐个 `commit`，所以要么全部扩容、要么全部保持原样。

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

/// 槽位存储：内联 `I` 项，或启动期扩容后的堆存储。
pub enum BootSlots<T, const I: usize> {
    /// 堆就绪之前的内联存储。
    Inline([T; I]),
    /// 启动期扩容后的存储（之后容量不再变化）。
    Heap(Box<[T]>),
}

impl<T, const I: usize> BootSlots<T, I> {
    /// 为扩到 `n` 项准备新存储（每项用 `fill` 填充）。内核堆不足返回 `None`，原存储不受影响。
    pub fn prepare(&self, n: usize, mut fill: impl FnMut() -> T) -> Option<Box<[T]>> {
        let mut v = Vec::new();
        v.try_reserve_exact(n).ok()?;
        for _ in 0..n {
            v.push(fill());
        }
        Some(v.into_boxed_slice())
    }

    /// 把已有各项按原下标搬进 `new`（`new` 必须不短于现有存储），然后改用 `new`。不会失败。
    pub fn commit(&mut self, mut new: Box<[T]>) {
        assert!(new.len() >= self.len(), "扩容后的存储不得比原来短");
        for (dst, src) in new.iter_mut().zip(self.iter_mut()) {
            core::mem::swap(dst, src);
        }
        *self = BootSlots::Heap(new);
    }
}

impl<T, const I: usize> Deref for BootSlots<T, I> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        match self {
            BootSlots::Inline(a) => a,
            BootSlots::Heap(b) => b,
        }
    }
}

impl<T, const I: usize> DerefMut for BootSlots<T, I> {
    fn deref_mut(&mut self) -> &mut [T] {
        match self {
            BootSlots::Inline(a) => a,
            BootSlots::Heap(b) => b,
        }
    }
}

/// 记录「谁被改过」的槽位存储（issue #2）：可变访问一律先标脏，没有绕开标记的可变入口
/// （不实现 `DerefMut`，只读访问经 `Deref` 到切片），所以不可能漏登记；代价只是偶尔多同步一个
/// 其实没变的槽位，而同步对未变化的槽位不写堆。
/// Slot storage where every mutable access marks the slot dirty; there is no
/// unmarked mutable path, so a state transition cannot forget to register.
pub struct TrackedSlots<T, const I: usize, const W: usize> {
    slots: BootSlots<T, I>,
    dirty: BootSlots<u64, W>,
}

impl<T, const I: usize, const W: usize> TrackedSlots<T, I, W> {
    /// 内联存储上的新表，初始全部未标记。
    pub const fn new(slots: [T; I]) -> Self {
        Self { slots: BootSlots::Inline(slots), dirty: BootSlots::Inline([0; W]) }
    }

    /// 可变访问一个槽位并标脏；越界返回 `None`。
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut T> {
        kernel_core::dirty_slots::mark(&mut self.dirty, slot);
        self.slots.get_mut(slot)
    }

    /// 可变遍历满足条件的槽位，只标脏这些槽位。
    pub fn iter_mut_where<'a>(&'a mut self, mut wanted: impl FnMut(usize, &T) -> bool + 'a)
        -> impl Iterator<Item = (usize, &'a mut T)> + 'a
    where T: 'a {
        let (slots, dirty) = (&mut *self.slots, &mut *self.dirty);
        slots.iter_mut().enumerate().filter_map(move |(i, t)| {
            if !wanted(i, t) { return None; }
            kernel_core::dirty_slots::mark(dirty, i);
            Some((i, t))
        })
    }

    /// 不改内容地标脏（内容之外的输入变了时用）；越界是空操作。
    pub fn mark_dirty(&mut self, slot: usize) {
        kernel_core::dirty_slots::mark(&mut self.dirty, slot);
    }

    /// 全部标脏。
    pub fn mark_all_dirty(&mut self) {
        let n = self.slots.len();
        kernel_core::dirty_slots::mark_first(&mut self.dirty, n);
    }

    /// 槽位是否有待同步标记。
    pub fn is_dirty(&self, slot: usize) -> bool {
        kernel_core::dirty_slots::is_marked(&self.dirty, slot)
    }

    /// 取走不小于 `from` 的最小脏槽位。
    pub fn take_dirty(&mut self, from: usize) -> Option<usize> {
        kernel_core::dirty_slots::take_next(&mut self.dirty, from)
    }

    /// 为扩到 `n` 项准备新存储，语义同 [`BootSlots::prepare`]。
    pub fn prepare(&self, n: usize, fill: impl FnMut() -> T) -> Option<(Box<[T]>, Box<[u64]>)> {
        let slots = self.slots.prepare(n, fill)?;
        let dirty = self.dirty.prepare(kernel_core::dirty_slots::words_for(n), || 0)?;
        Some((slots, dirty))
    }

    /// 按原下标搬进新存储，不会失败。扩容后全部标脏。
    pub fn commit(&mut self, (slots, dirty): (Box<[T]>, Box<[u64]>)) {
        self.slots.commit(slots);
        self.dirty.commit(dirty);
        self.mark_all_dirty();
    }
}

impl<T, const I: usize, const W: usize> Deref for TrackedSlots<T, I, W> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.slots
    }
}

impl<T, const I: usize, const W: usize> core::ops::Index<usize> for TrackedSlots<T, I, W> {
    type Output = T;
    fn index(&self, slot: usize) -> &T {
        &self.slots[slot]
    }
}

impl<T, const I: usize, const W: usize> core::ops::IndexMut<usize> for TrackedSlots<T, I, W> {
    fn index_mut(&mut self, slot: usize) -> &mut T {
        kernel_core::dirty_slots::mark(&mut self.dirty, slot);
        &mut self.slots[slot]
    }
}
