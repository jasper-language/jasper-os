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
