//! Linux-facing adapters backed by Jasper-native event, synchronization, memory and Ring
//! mechanisms.
//!
//! 职责：在系统服务层保存 Linux 兼容状态，并把 epoll、futex、mmap 与 io_uring
//! 请求映射到 Jasper 原生对象、Rights、等待登记、Memory capability、配额和异步 Ring。
//! 边界：本模块不定义内核 Core 语义，不直接进入用户态，也不把 Linux 概念放入原生 ABI。
//! Responsibility: keep Linux compatibility state outside the native ABI and adapt operations
//! to reusable Jasper mechanisms with bounded, failure-atomic resource accounting.

use core::sync::atomic::{AtomicBool, Ordering};

use kernel_core::async_ring::{
    AsyncRing, CancelError, Cancelled, Completion, Exec, ProgressError, Submission, SubmitError,
    Terminal,
};
use kernel_core::event_wait::{Enroll, Key, Registration};
use kernel_core::inherited_mutex::{Claim, ReleaseError, State};
use kernel_core::memory::{AddressSpace, SimpleAddressSpace, VmProtection, VmRegion, PAGE_SIZE};
use kernel_core::memory_capability::{
    BackingIdentity, MemoryCapabilityError, MemoryCapabilityTable, MemoryKind, MemoryRights,
};
use kernel_core::memory_object;
use kernel_core::object::Rights;
use kernel_core::task_index::Token;
use kernel_core::wait::{Event, Waitable};

/// Maximum number of event records returned by one compatibility wait.
///
/// 单次 epoll 等待最多写回的记录数。
pub const MAX_EPOLL_EVENTS: usize = 16;
/// Maximum number of futex waiters on one native synchronization word.
///
/// 单个 futex 同步字可登记的最大等待者数。
pub const MAX_FUTEX_WAITERS: usize = 8;

/// Stable reference to one compatibility resource generation.
///
/// 指向兼容资源特定世代的稳定标识；槽位复用后旧标识永久失效。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeHandle {
    slot: u32,
    generation: u32,
}
impl NativeHandle {
    /// Builds a non-zero generation-checked handle.
    ///
    /// 构造带非零世代的资源标识。
    pub const fn new(slot: u32, generation: u32) -> Option<Self> {
        if generation == 0 {
            None
        } else {
            Some(Self { slot, generation })
        }
    }

    /// Returns the resource-table slot.
    ///
    /// 返回资源表中的槽位。
    pub const fn slot(self) -> u32 {
        self.slot
    }

    /// Returns the generation that makes stale references detectable.
    ///
    /// 返回用于拒绝陈旧引用的世代。
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

/// Compatibility-layer error before conversion to a Linux errno.
///
/// 转换到 Linux errno 前的兼容层错误；原生 ABI 不直接暴露这些值。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeError {
    /// The resource slot is not active.
    /// 资源槽位不存在或已关闭。
    InvalidHandle,
    /// The handle generation no longer identifies the active resource.
    /// 句柄世代已失效。
    Stale,
    /// Native Rights do not permit the requested operation.
    /// 原生 Rights 不允许该操作。
    RightsDenied,
    /// A Linux-facing field or flag is malformed.
    /// Linux 描述符或标志非法。
    InvalidArgument,
    /// The operation is not implemented for the declared compatibility profile.
    /// 当前兼容配置尚不支持该操作。
    Unsupported,
    /// A bounded table or wait queue is full.
    /// 有界表或等待队列已满。
    Capacity,
    /// A resource is already registered or waited on.
    /// 资源已登记或已有等待者。
    Busy,
    /// A signal interrupted a blocking compatibility operation.
    /// 信号打断了阻塞兼容操作。
    Interrupted,
    /// The observed value changed before a conditional operation could commit.
    /// 条件操作提交前观测值已变化。
    TryAgain,
    /// The absolute deadline elapsed.
    /// 绝对截止期已到。
    TimedOut,
    /// A native object or capability was revoked.
    /// 原生对象或能力已被撤销。
    Revoked,
    /// A quota refused the operation without partial effects.
    /// 配额拒绝操作且没有部分副作用。
    Quota,
    /// Resource accounting failed internally.
    /// 内部资源记账失败。
    Accounting,
    /// A sequence or state transition was not valid.
    /// 序列或状态迁移非法。
    State,
}

impl NativeError {
    /// Converts an adapter failure to the Linux errno used at the compatibility boundary.
    ///
    /// 把适配器失败转换为兼容边界使用的 Linux errno。
    pub const fn errno(self) -> crate::syscall::CompatErrno {
        use crate::syscall::CompatErrno;
        match self {
            Self::InvalidHandle | Self::Stale | Self::Revoked => CompatErrno::BadFd,
            Self::RightsDenied => CompatErrno::Perm,
            Self::InvalidArgument | Self::State => CompatErrno::Invalid,
            Self::Unsupported => CompatErrno::NoSys,
            Self::Capacity => CompatErrno::NoSpace,
            Self::Quota | Self::Accounting => CompatErrno::NoMemory,
            Self::Busy => CompatErrno::Busy,
            Self::Interrupted => CompatErrno::Interrupted,
            Self::TryAgain => CompatErrno::TryAgain,
            Self::TimedOut => CompatErrno::TimedOut,
        }
    }
}

/// Result of an epoll-compatible wait.
///
/// epoll 兼容等待结果。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeWait {
    /// At least one readiness record was written.
    /// 已写回至少一条就绪记录。
    Ready(usize),
    /// The deadline elapsed before readiness.
    /// 在就绪前达到截止期。
    TimedOut,
    /// A signal interrupted the wait.
    /// 等待被信号打断。
    Interrupted,
}

/// Linux epoll interest bits implemented by this adapter.
///
/// 本适配器实现的 Linux epoll 关注位。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollInterest(u32);

impl EpollInterest {
    /// None of the supported readiness bits.
    /// 没有受支持的就绪位。
    pub const NONE: Self = Self(0);
    /// Readable.
    /// 可读。
    pub const READ: Self = Self(0x001);
    /// Writable.
    /// 可写。
    pub const WRITE: Self = Self(0x004);
    /// Error pending.
    /// 有错误待处理。
    pub const ERROR: Self = Self(0x008);
    /// Hang-up.
    /// 对端挂断。
    pub const HANGUP: Self = Self(0x010);
    /// Peer half-close.
    /// 对端半关闭。
    pub const READ_HANGUP: Self = Self(0x2000);
    /// Disable the entry after one delivery.
    /// 一次交付后禁用该条目。
    pub const ONESHOT: Self = Self(1 << 30);
    /// Report only readiness edges.
    /// 仅报告就绪边沿。
    pub const EDGE: Self = Self(1 << 31);

    /// Accepted mask for control operations.
    ///
    /// 控制操作允许的完整位掩码。
    pub const SUPPORTED: Self = Self(
        Self::READ.0
            | Self::WRITE.0
            | Self::ERROR.0
            | Self::HANGUP.0
            | Self::READ_HANGUP.0
            | Self::ONESHOT.0
            | Self::EDGE.0,
    );
    const LEVEL_MASK: u32 =
        Self::READ.0 | Self::WRITE.0 | Self::ERROR.0 | Self::HANGUP.0 | Self::READ_HANGUP.0;

    /// Decodes a Linux interest mask.
    ///
    /// 解码 Linux 关注位；未知位失败关闭。
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::SUPPORTED.0 == 0 && bits & Self::LEVEL_MASK != 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns the raw interest bits.
    ///
    /// 返回原始关注位。
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns true when every bit in `other` is selected.
    ///
    /// 判断是否包含 `other` 的全部关注位。
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn level(self) -> u32 {
        self.0 & Self::LEVEL_MASK
    }
}

/// One event record returned through the Linux-facing epoll ABI.
///
/// 经 Linux 兼容 ABI 返回的一条 epoll 记录。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpollEvent {
    /// Caller-provided identity returned unchanged.
    /// 原样返回的调用者标识。
    pub data: u64,
    /// Native readiness translated to Linux interest bits.
    /// 转换后的 Linux 就绪位。
    pub events: EpollInterest,
}

/// Native event source with generation, Rights and terminal closure state.
///
/// 原生事件源在兼容层中的客观引用与生命周期状态。
struct EventSlot {
    handle: NativeHandle,
    event: Event,
    rights: Rights,
    active: bool,
    closed: bool,
    leases: u32,
}

impl EventSlot {
    const fn empty() -> Self {
        Self {
            handle: NativeHandle {
                slot: 0,
                generation: 0,
            },
            event: Event::new(),
            rights: Rights::NONE,
            active: false,
            closed: false,
            leases: 0,
        }
    }
}

/// Bounded table of native events exposed to the compatibility service.
///
/// 兼容服务可见的有界原生事件表；每次发布使用真实的 Jasper `Event`。
pub struct EventSourceTable<const N: usize> {
    slots: [EventSlot; N],
    next_generation: u32,
}

impl<const N: usize> EventSourceTable<N> {
    /// Creates an empty native event table.
    ///
    /// 创建空的原生事件表。
    pub const fn new() -> Self {
        assert!(N > 0, "event source capacity must be non-zero");
        Self {
            slots: [const { EventSlot::empty() }; N],
            next_generation: 1,
        }
    }

    /// Registers one native event with its delegated Rights.
    ///
    /// 登记一个原生事件及其获准 Rights；句柄世代绝不回绕。
    pub fn register(&mut self, rights: Rights) -> Result<NativeHandle, NativeError> {
        if !rights.contains(Rights::SUBSCRIBE) {
            return Err(NativeError::RightsDenied);
        }
        let slot = self
            .slots
            .iter()
            .position(|entry| !entry.active)
            .ok_or(NativeError::Capacity)?;
        let generation = self.next_generation;
        self.next_generation = generation.checked_add(1).ok_or(NativeError::Capacity)?;
        let handle =
            NativeHandle::new(slot as u32, generation).ok_or(NativeError::InvalidArgument)?;
        self.slots[slot] = EventSlot {
            handle,
            event: Event::new(),
            rights,
            active: true,
            closed: false,
            leases: 0,
        };
        Ok(handle)
    }

    /// Publishes a readiness edge on a source.
    ///
    /// 在事件源上发布一个就绪事件；关闭或陈旧句柄失败关闭。
    pub fn signal(&mut self, handle: NativeHandle) -> Result<(), NativeError> {
        let slot = self.resolve_mut(handle)?;
        slot.event.signal();
        Ok(())
    }

    /// Closes a source and makes all new registrations fail.
    ///
    /// 关闭事件源，后续登记和发布均失败。
    pub fn close(&mut self, handle: NativeHandle) -> Result<(), NativeError> {
        let slot = self.resolve_mut(handle)?;
        if slot.closed {
            return Err(NativeError::InvalidHandle);
        }
        slot.closed = true;
        slot.event.signal();
        Ok(())
    }

    /// Retains a source for one epoll-style registration.
    ///
    /// 为 epoll 类登记保留事件源；已关闭源不能获得新租约。
    pub fn retain(&mut self, handle: NativeHandle) -> Result<(), NativeError> {
        let slot = self.resolve_mut(handle)?;
        if slot.closed {
            return Err(NativeError::Revoked);
        }
        slot.leases = slot.leases.checked_add(1).ok_or(NativeError::Capacity)?;
        Ok(())
    }

    /// Releases one registration lease.
    ///
    /// 释放一个登记租约；计数下溢失败关闭。
    pub fn release_lease(&mut self, handle: NativeHandle) -> Result<(), NativeError> {
        let slot = self.resolve_mut(handle)?;
        slot.leases = slot.leases.checked_sub(1).ok_or(NativeError::Accounting)?;
        Ok(())
    }

    /// Releases a source slot only after close.
    ///
    /// 仅在关闭后回收事件源槽位。
    pub fn release(&mut self, handle: NativeHandle) -> Result<(), NativeError> {
        let slot = self.resolve_mut(handle)?;
        if !slot.closed || slot.leases != 0 {
            return Err(NativeError::Busy);
        }
        slot.active = false;
        slot.rights = Rights::NONE;
        Ok(())
    }

    /// Returns whether a source has been closed.
    ///
    /// 返回事件源是否已关闭。
    pub fn is_closed(&self, handle: NativeHandle) -> Result<bool, NativeError> {
        Ok(self.resolve(handle)?.closed)
    }

    fn resolve(&self, handle: NativeHandle) -> Result<&EventSlot, NativeError> {
        let slot = self
            .slots
            .get(handle.slot as usize)
            .ok_or(NativeError::InvalidHandle)?;
        if !slot.active {
            return Err(NativeError::InvalidHandle);
        }
        if slot.handle.generation != handle.generation {
            return Err(NativeError::Stale);
        }
        Ok(slot)
    }

    fn resolve_mut(&mut self, handle: NativeHandle) -> Result<&mut EventSlot, NativeError> {
        let slot = self
            .slots
            .get_mut(handle.slot as usize)
            .ok_or(NativeError::InvalidHandle)?;
        if !slot.active {
            return Err(NativeError::InvalidHandle);
        }
        if slot.handle.generation != handle.generation {
            return Err(NativeError::Stale);
        }
        Ok(slot)
    }

    fn readiness(&self, handle: NativeHandle, now: u64) -> Result<(u32, bool), NativeError> {
        let source = self.resolve(handle)?;
        let mut bits = 0;
        if source.event.is_signaled(now) {
            bits |= EpollInterest::READ.0;
        }
        if source.closed {
            bits |= EpollInterest::HANGUP.0;
        }
        Ok((bits, source.closed))
    }
}

impl<const N: usize> Default for EventSourceTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
struct EpollSlot {
    source: NativeHandle,
    interest: EpollInterest,
    data: u64,
    armed: bool,
    edge_seen: u32,
}

impl EpollSlot {
    const fn empty() -> Self {
        Self {
            source: NativeHandle {
                slot: 0,
                generation: 0,
            },
            interest: EpollInterest::NONE,
            data: 0,
            armed: false,
            edge_seen: 0,
        }
    }
}

/// Bounded epoll-compatible set over Jasper event sources.
///
/// 建立在 Jasper 事件源上的有界 epoll 兼容集合；它只保存兼容状态，
/// 等待和发布仍由原生事件对象完成。
pub struct Epoll<const N: usize> {
    entries: [EpollSlot; N],
    active: usize,
}

impl<const N: usize> Epoll<N> {
    /// Creates an empty epoll-compatible set.
    ///
    /// 创建空 epoll 兼容集合。
    pub const fn new() -> Self {
        assert!(N > 0, "epoll capacity must be non-zero");
        Self {
            entries: [const { EpollSlot::empty() }; N],
            active: 0,
        }
    }

    /// Adds one source, data token and interest mask.
    ///
    /// 添加事件源、数据标识和关注位；重复源或容量不足不会改变状态。
    pub fn add(
        &mut self,
        sources: &mut EventSourceTable<N>,
        source: NativeHandle,
        data: u64,
        interest: EpollInterest,
    ) -> Result<(), NativeError> {
        let source_slot = sources.resolve(source)?;
        if source_slot.closed
            || !source_slot
                .rights
                .contains(Rights::SUBSCRIBE.union(Rights::WAIT))
        {
            return Err(NativeError::RightsDenied);
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.source.generation != 0 && entry.source == source)
        {
            return Err(NativeError::Busy);
        }
        sources.retain(source)?;
        let slot = self
            .entries
            .iter()
            .position(|entry| !entry.armed)
            .ok_or_else(|| {
                let _ = sources.release_lease(source);
                NativeError::Capacity
            })?;
        self.entries[slot] = EpollSlot {
            source,
            interest,
            data,
            armed: true,
            edge_seen: 0,
        };
        self.active += 1;
        Ok(())
    }

    /// Removes one source.
    ///
    /// 删除一个事件源；不存在时失败且不改变集合。
    pub fn delete(
        &mut self,
        sources: &mut EventSourceTable<N>,
        source: NativeHandle,
    ) -> Result<u64, NativeError> {
        let slot = self
            .entries
            .iter()
            .position(|entry| entry.source.generation != 0 && entry.source == source)
            .ok_or(NativeError::InvalidHandle)?;
        let data = self.entries[slot].data;
        sources.release_lease(source)?;
        let was_armed = self.entries[slot].armed;
        self.entries[slot] = EpollSlot::empty();
        if was_armed {
            self.active -= 1;
        }
        Ok(data)
    }

    /// Replaces interest and data for one source.
    ///
    /// 更新一个事件源的关注位与数据标识；源不存在时失败且无部分更新。
    pub fn modify(
        &mut self,
        sources: &EventSourceTable<N>,
        source: NativeHandle,
        data: u64,
        interest: EpollInterest,
    ) -> Result<(), NativeError> {
        let source_slot = sources.resolve(source)?;
        if source_slot.closed {
            return Err(NativeError::Revoked);
        }
        if !source_slot
            .rights
            .contains(Rights::SUBSCRIBE.union(Rights::WAIT))
        {
            return Err(NativeError::RightsDenied);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.source.generation != 0 && entry.source == source)
            .ok_or(NativeError::InvalidHandle)?;
        if !entry.armed {
            self.active += 1;
        }
        entry.interest = interest;
        entry.data = data;
        entry.armed = true;
        entry.edge_seen = 0;
        Ok(())
    }

    /// Polls one batch with signal and deadline semantics.
    ///
    /// 按就绪优先、信号次之、截止期最后的顺序轮询；一次只返回一个有界批次。
    pub fn wait(
        &mut self,
        sources: &EventSourceTable<N>,
        now: u64,
        deadline: Option<u64>,
        signal_pending: bool,
        output: &mut [EpollEvent],
    ) -> Result<NativeWait, NativeError> {
        if output.is_empty() {
            return Err(NativeError::InvalidArgument);
        }
        let mut count = 0;
        for entry in &mut self.entries {
            if !entry.armed || count == output.len() {
                continue;
            }
            let (native_bits, closed) = sources.readiness(entry.source, now)?;
            let always_reported = EpollInterest::ERROR.0 | EpollInterest::HANGUP.0;
            let selected = (native_bits & entry.interest.level()) | (native_bits & always_reported);
            let newly_ready = selected & !entry.edge_seen;
            if selected != 0 {
                let deliver = if entry.interest.contains(EpollInterest::EDGE) {
                    newly_ready != 0
                } else {
                    true
                };
                if deliver {
                    output[count] = EpollEvent {
                        data: entry.data,
                        events: EpollInterest(selected),
                    };
                    count += 1;
                    entry.edge_seen |= selected;
                    if entry.interest.contains(EpollInterest::ONESHOT) {
                        entry.armed = false;
                        self.active -= 1;
                    }
                }
            } else {
                entry.edge_seen = 0;
            }
            if entry.armed && closed && entry.interest.contains(EpollInterest::ONESHOT) {
                entry.armed = false;
                self.active -= 1;
            }
        }
        if count != 0 {
            return Ok(NativeWait::Ready(count));
        }
        if signal_pending {
            return Ok(NativeWait::Interrupted);
        }
        if deadline.is_some_and(|at| now >= at) {
            return Ok(NativeWait::TimedOut);
        }
        Ok(NativeWait::Ready(0))
    }

    /// Closes all Linux-facing registrations.
    ///
    /// 关闭全部兼容登记，不触碰事件源所有权。所有租约先统一预检，任何一项不匹配时
    /// 集合保持不变。
    pub fn close(&mut self, sources: &mut EventSourceTable<N>) -> Result<usize, NativeError> {
        let count = self.active;
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.source.generation != 0)
        {
            let source = sources.resolve(entry.source)?;
            if source.leases == 0 {
                return Err(NativeError::Accounting);
            }
        }
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.source.generation != 0)
        {
            sources.release_lease(entry.source)?;
        }
        self.entries.fill(EpollSlot::empty());
        self.active = 0;
        Ok(count)
    }

    /// Returns the active registration count.
    ///
    /// 返回当前有效登记数。
    pub const fn active(&self) -> usize {
        self.active
    }
}

impl<const N: usize> Default for Epoll<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug)]
struct FutexWaiter {
    task: u64,
    priority: u8,
    sequence: u64,
    key: Key,
    registration: Registration,
    active: bool,
}

impl FutexWaiter {
    const fn empty() -> Self {
        Self {
            task: 0,
            priority: 0,
            sequence: 0,
            key: Key {
                task: Token {
                    slot: 0,
                    generation: 0,
                },
                round: 0,
            },
            registration: Registration::new(),
            active: false,
        }
    }
}

#[derive(Clone, Copy)]
struct FutexWord<const W: usize> {
    handle: NativeHandle,
    value: u64,
    waiters: [FutexWaiter; W],
    waiter_count: usize,
    sequence: u64,
    state: State<u64>,
    active: bool,
}

/// Number of waiters made runnable by a futex wake.
///
/// 一次 futex 唤醒使可运行的任务数。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FutexWake {
    /// Number of waiters removed from the queue.
    /// 从等待队列移除的等待者数。
    pub woken: usize,
    /// Effective priority donated to the owner after the wake.
    /// 唤醒后捐赠给所有者的有效优先级；数值越小优先级越高。
    pub owner_priority: Option<u8>,
}

/// Bounded futex-compatible wait and priority-inheritance adapter.
///
/// 有界 futex 兼容等待与优先级继承适配器；等待登记、截止期与终态消费复用
/// Jasper event-wait 和 inherited-mutex 状态机。
pub struct Futex<const N: usize, const W: usize = MAX_FUTEX_WAITERS> {
    words: [Option<FutexWord<W>>; N],
    generations: [u32; N],
}

impl<const N: usize, const W: usize> Futex<N, W> {
    /// Creates an empty futex word table.
    ///
    /// 创建空 futex 同步字表。
    pub const fn new() -> Self {
        assert!(N > 0 && W > 0, "futex capacities must be non-zero");
        Self {
            words: [None; N],
            generations: [0; N],
        }
    }

    /// Creates a native synchronization word initialized from user memory.
    ///
    /// 用用户内存值创建原生同步字。
    pub fn create(&mut self, initial: u64) -> Result<NativeHandle, NativeError> {
        let slot = self
            .words
            .iter()
            .position(|word| word.is_none_or(|word| !word.active))
            .ok_or(NativeError::Capacity)?;
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(NativeError::Capacity)?;
        self.generations[slot] = generation;
        let handle =
            NativeHandle::new(slot as u32, generation).ok_or(NativeError::InvalidArgument)?;
        self.words[slot] = Some(FutexWord {
            handle,
            value: initial,
            waiters: [const { FutexWaiter::empty() }; W],
            waiter_count: 0,
            sequence: 0,
            state: State::new(),
            active: true,
        });
        Ok(handle)
    }

    /// Reads the current native synchronization value.
    ///
    /// 读取当前原生同步值。
    pub fn value(&self, handle: NativeHandle) -> Result<u64, NativeError> {
        Ok(self.resolve(handle)?.value)
    }

    /// Stores a futex wake value.
    ///
    /// 更新 futex 唤醒值。
    pub fn store(&mut self, handle: NativeHandle, value: u64) -> Result<(), NativeError> {
        self.resolve_mut(handle)?.value = value;
        Ok(())
    }

    /// Registers one wait if the observed value still matches.
    ///
    /// 观测值仍匹配时登记等待；值已改变、信号、截止期、重复任务和容量失败均无部分登记。
    pub fn wait(
        &mut self,
        handle: NativeHandle,
        expected: u64,
        task: u64,
        priority: u8,
        now: u64,
        deadline: Option<u64>,
        signal_pending: bool,
    ) -> Result<u64, NativeError> {
        let word = self.resolve_mut(handle)?;
        if word.value != expected {
            return Err(NativeError::TryAgain);
        }
        if signal_pending {
            return Err(NativeError::Interrupted);
        }
        if word
            .waiters
            .iter()
            .any(|waiter| waiter.active && waiter.task == task)
        {
            return Err(NativeError::Busy);
        }
        if word.waiter_count == W {
            return Err(NativeError::Capacity);
        }
        let token = Token {
            slot: (task & usize::MAX as u64) as usize,
            generation: task >> 32,
        };
        let mut registration = Registration::new();
        let key = match registration.enroll(token, false, now, deadline) {
            Enroll::TimedOut => return Err(NativeError::TimedOut),
            Enroll::Exhausted => return Err(NativeError::Capacity),
            Enroll::Busy | Enroll::Ready => return Err(NativeError::State),
            Enroll::Armed(key) => key,
        };
        word.sequence = word.sequence.checked_add(1).ok_or(NativeError::Capacity)?;
        let slot = word
            .waiters
            .iter()
            .position(|waiter| !waiter.active)
            .ok_or(NativeError::Capacity)?;
        word.waiters[slot] = FutexWaiter {
            task,
            priority,
            sequence: word.sequence,
            key,
            registration,
            active: true,
        };
        word.waiter_count += 1;
        Ok(word.sequence)
    }

    /// Wakes up to `count` highest-priority waiters.
    ///
    /// 按有效优先级、再按等待顺序唤醒至多 `count` 个等待者。
    pub fn wake(&mut self, handle: NativeHandle, count: usize) -> Result<FutexWake, NativeError> {
        if count == 0 {
            return Ok(FutexWake::default());
        }
        let word = self.resolve_mut(handle)?;
        let mut output = FutexWake::default();
        while output.woken < count && output.woken < word.waiter_count {
            let Some(slot) = candidate_waiter(&word.waiters, |_| true) else {
                break;
            };
            assert!(word.waiters[slot]
                .registration
                .finish(word.waiters[slot].key));
            word.waiters[slot].active = false;
            word.waiter_count -= 1;
            output.woken += 1;
        }
        output.owner_priority = word
            .waiters
            .iter()
            .filter(|waiter| waiter.active)
            .map(|waiter| waiter.priority)
            .min();
        Ok(output)
    }

    /// Cancels one exact waiter identity.
    ///
    /// 精确取消一个等待者；陈旧轮次或错误任务不会移除其他等待。
    pub fn cancel(
        &mut self,
        handle: NativeHandle,
        task: u64,
        wait_id: u64,
    ) -> Result<bool, NativeError> {
        let word = self.resolve_mut(handle)?;
        let Some(slot) = word
            .waiters
            .iter()
            .position(|waiter| waiter.active && waiter.task == task && waiter.sequence == wait_id)
        else {
            return Ok(false);
        };
        assert!(word.waiters[slot]
            .registration
            .finish(word.waiters[slot].key));
        word.waiters[slot].active = false;
        word.waiter_count -= 1;
        Ok(true)
    }

    /// Expires all waiters whose exact absolute deadlines elapsed.
    ///
    /// 使所有精确截止期已到的等待者结束，并返回结束数量。
    pub fn expire(&mut self, handle: NativeHandle, now: u64) -> Result<usize, NativeError> {
        let word = self.resolve_mut(handle)?;
        let mut expired = 0;
        for waiter in word.waiters.iter_mut().filter(|waiter| waiter.active) {
            if waiter.registration.expire(waiter.key, now) {
                waiter.active = false;
                word.waiter_count -= 1;
                expired += 1;
            }
        }
        Ok(expired)
    }

    /// Acquires a PI futex or returns the task that currently owns it.
    ///
    /// 获取 PI futex；冲突时返回当前所有者，真实阻塞与跨核捐赠由调度器完成。
    pub fn lock_pi(
        &mut self,
        handle: NativeHandle,
        task: u64,
        priority: u8,
        owner_live: bool,
    ) -> Result<Option<u64>, NativeError> {
        let word = self.resolve_mut(handle)?;
        match word.state.claim(task, owner_live) {
            Claim::Acquired { .. } => Ok(None),
            Claim::Recursive => Err(NativeError::Busy),
            Claim::Closed => Err(NativeError::Revoked),
            Claim::WaitFor(owner) => {
                if word
                    .waiters
                    .iter()
                    .any(|waiter| waiter.active && waiter.task == task)
                {
                    return Err(NativeError::Busy);
                }
                if word.waiter_count == W {
                    return Err(NativeError::Capacity);
                }
                let token = Token {
                    slot: (task & usize::MAX as u64) as usize,
                    generation: task >> 32,
                };
                let mut registration = Registration::new();
                let key = match registration.enroll(token, false, 0, None) {
                    Enroll::Armed(key) => key,
                    _ => return Err(NativeError::State),
                };
                word.sequence = word.sequence.checked_add(1).ok_or(NativeError::Capacity)?;
                let slot = word
                    .waiters
                    .iter()
                    .position(|waiter| !waiter.active)
                    .ok_or(NativeError::Capacity)?;
                word.waiters[slot] = FutexWaiter {
                    task,
                    priority,
                    sequence: word.sequence,
                    key,
                    registration,
                    active: true,
                };
                word.waiter_count += 1;
                Ok(Some(owner))
            }
        }
    }

    /// Releases a PI futex and hands it to the highest-priority waiter.
    ///
    /// 释放 PI futex，并把所有权直接交接给优先级最高的等待者。
    pub fn unlock_pi(
        &mut self,
        handle: NativeHandle,
        task: u64,
    ) -> Result<Option<u64>, NativeError> {
        let word = self.resolve_mut(handle)?;
        if word.state.is_closed() {
            return Err(NativeError::Revoked);
        }
        if word.state.owner() != Some(task) {
            return Err(NativeError::RightsDenied);
        }
        let Some(slot) = candidate_waiter(&word.waiters, |_| true) else {
            return word
                .state
                .release(task, None)
                .map(|_| None)
                .map_err(|error| match error {
                    ReleaseError::Closed => NativeError::Revoked,
                    ReleaseError::NotOwner => NativeError::RightsDenied,
                });
        };
        let mut next = word.waiters[slot];
        assert!(next.registration.finish(next.key));
        word.waiters[slot].active = false;
        word.waiter_count -= 1;
        word.state
            .release(task, Some(next.task))
            .map(|_| Some(next.task))
            .map_err(|error| match error {
                ReleaseError::Closed => NativeError::Revoked,
                ReleaseError::NotOwner => NativeError::RightsDenied,
            })
    }

    /// Revokes one synchronization word and all wait registrations.
    ///
    /// 撤销一个同步字及其全部等待登记，旧句柄不能再复活。
    pub fn revoke(&mut self, handle: NativeHandle) -> Result<usize, NativeError> {
        let word = self.resolve_mut(handle)?;
        let count = word.waiter_count;
        if word
            .waiters
            .iter()
            .any(|waiter| waiter.active && waiter.registration.pending() != Some(waiter.key))
        {
            return Err(NativeError::Accounting);
        }
        for waiter in word.waiters.iter_mut().filter(|waiter| waiter.active) {
            debug_assert!(waiter.registration.finish(waiter.key));
            waiter.active = false;
        }
        word.state.close();
        word.waiters.fill(FutexWaiter::empty());
        word.waiter_count = 0;
        word.active = false;
        Ok(count)
    }

    fn resolve(&self, handle: NativeHandle) -> Result<&FutexWord<W>, NativeError> {
        let word = self
            .words
            .get(handle.slot as usize)
            .and_then(Option::as_ref)
            .ok_or(NativeError::InvalidHandle)?;
        if word.handle.generation != handle.generation {
            return Err(NativeError::Stale);
        }
        if !word.active {
            return Err(NativeError::Revoked);
        }
        Ok(word)
    }

    fn resolve_mut(&mut self, handle: NativeHandle) -> Result<&mut FutexWord<W>, NativeError> {
        let word = self
            .words
            .get_mut(handle.slot as usize)
            .and_then(Option::as_mut)
            .ok_or(NativeError::InvalidHandle)?;
        if word.handle.generation != handle.generation {
            return Err(NativeError::Stale);
        }
        if !word.active {
            return Err(NativeError::Revoked);
        }
        Ok(word)
    }
}

fn candidate_waiter<const W: usize>(
    waiters: &[FutexWaiter; W],
    accept: impl Fn(&FutexWaiter) -> bool,
) -> Option<usize> {
    waiters
        .iter()
        .enumerate()
        .filter(|(_, waiter)| waiter.active && accept(waiter))
        .min_by_key(|(_, waiter)| (waiter.priority, waiter.sequence))
        .map(|(slot, _)| slot)
}

impl<const N: usize, const W: usize> Default for Futex<N, W> {
    fn default() -> Self {
        Self::new()
    }
}

/// One anonymous or object-backed mapping created through the compatibility layer.
///
/// 兼容层创建的一段匿名或对象支撑映射。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMapping {
    /// Final virtual range.
    /// 最终虚拟地址范围。
    pub region: VmRegion,
    /// Stable native backing identity.
    /// 稳定原生后备对象身份。
    pub backing: BackingIdentity,
    /// Native memory Rights granted to the mapping.
    /// 映射获准的原生内存 Rights。
    pub rights: MemoryRights,
    /// Memory capability identifier.
    /// 内存能力标识。
    pub capability: u64,
}

/// Bounded mmap-compatible adapter over native Memory and capability accounting.
///
/// 基于 Jasper Memory 区域、capability 与 quota 的有界 mmap 兼容适配器。
pub struct NativeMemory<const N: usize> {
    space: SimpleAddressSpace<N>,
    capabilities: MemoryCapabilityTable<N>,
    usage: memory_object::Usage,
    limits: memory_object::Usage,
    next_backing: u32,
    revoked: u64,
}

impl<const N: usize> NativeMemory<N> {
    /// Creates an empty map with explicit page-reference quotas.
    ///
    /// 以显式页引用配额创建空映射。
    pub const fn new(limits: memory_object::Usage) -> Self {
        Self {
            space: SimpleAddressSpace::new(),
            capabilities: MemoryCapabilityTable::new(),
            usage: memory_object::Usage {
                mapped: 0,
                pinned: 0,
            },
            limits,
            next_backing: 1,
            revoked: 0,
        }
    }

    /// Maps an object-backed range at the next native anonymous address.
    ///
    /// 在下一个原生匿名地址映射对象范围；W^X、Rights、容量和配额在发布前全部预检，
    /// 失败不留下区域、capability 或配额残留。
    pub fn map(
        &mut self,
        pages: u64,
        protection: VmProtection,
        rights: MemoryRights,
        kind: MemoryKind,
    ) -> Result<MemoryMapping, NativeError> {
        if pages == 0 || protection.is_writable_executable() {
            return Err(NativeError::InvalidArgument);
        }
        let mut required = MemoryRights::MAP;
        if protection.contains(VmProtection::READ) {
            required = required.union(MemoryRights::READ);
        }
        if protection.contains(VmProtection::WRITE) {
            required = required.union(MemoryRights::WRITE);
        }
        if protection.contains(VmProtection::EXECUTE) {
            required = required.union(MemoryRights::EXECUTE);
        }
        if !rights.contains(required) {
            return Err(NativeError::RightsDenied);
        }
        let bytes = pages
            .checked_mul(memory_object::PAGE_BYTES)
            .ok_or(NativeError::InvalidArgument)?;
        self.usage
            .reserve(pages, 0, self.limits)
            .map_err(|_| NativeError::Quota)?;
        let region = match self.space.map_anonymous(bytes, protection) {
            Ok(region) => region,
            Err(_) => {
                let _ = self.usage.release(pages, 0);
                return Err(NativeError::Capacity);
            }
        };
        let generation = self.next_backing;
        self.next_backing = match generation.checked_add(1) {
            Some(next) => next,
            None => {
                let _ = self.space.unmap(region.base);
                let _ = self.usage.release(pages, 0);
                return Err(NativeError::Capacity);
            }
        };
        let backing = BackingIdentity::new(0, generation).ok_or(NativeError::Accounting)?;
        let capability = match self
            .capabilities
            .grant(region.base, pages, rights, kind, backing)
        {
            Ok(capability) => capability,
            Err(error) => {
                let _ = self.space.unmap(region.base);
                let _ = self.usage.release(pages, 0);
                return Err(map_memory_error(error));
            }
        };
        Ok(MemoryMapping {
            region,
            backing,
            rights,
            capability,
        })
    }

    /// Changes protection only when the capability still proves the full range.
    ///
    /// 仅当 capability 仍完整证明范围时修改保护位；拒绝不会改变原映射。
    pub fn protect(
        &mut self,
        mapping: MemoryMapping,
        protection: VmProtection,
    ) -> Result<MemoryMapping, NativeError> {
        if protection.is_writable_executable() {
            return Err(NativeError::InvalidArgument);
        }
        let mut required = MemoryRights::MAP;
        if protection.contains(VmProtection::READ) {
            required = required.union(MemoryRights::READ);
        }
        if protection.contains(VmProtection::WRITE) {
            required = required.union(MemoryRights::WRITE);
        }
        if protection.contains(VmProtection::EXECUTE) {
            required = required.union(MemoryRights::EXECUTE);
        }
        self.capabilities
            .check(
                mapping.region.base,
                mapping.region.size,
                required,
                Some(mapping.backing),
            )
            .map_err(map_memory_error)?;
        let region = self
            .space
            .protect(mapping.region.base, protection)
            .map_err(|_| NativeError::InvalidHandle)?;
        Ok(MemoryMapping {
            region,
            rights: required,
            ..mapping
        })
    }

    /// Unmaps and revokes one complete compatibility range.
    ///
    /// 解除映射并撤销完整兼容范围，归还映射配额。
    pub fn unmap(&mut self, mapping: MemoryMapping) -> Result<VmRegion, NativeError> {
        self.capabilities
            .check(
                mapping.region.base,
                mapping.region.size,
                MemoryRights::NONE,
                Some(mapping.backing),
            )
            .map_err(map_memory_error)?;
        if !self
            .space
            .regions()
            .iter()
            .any(|region| *region == mapping.region)
        {
            return Err(NativeError::Stale);
        }
        let pages = mapping.region.size / PAGE_SIZE;
        if pages == 0 || mapping.region.size % PAGE_SIZE != 0 || self.usage.mapped < pages {
            return Err(NativeError::Accounting);
        }
        let removed = self
            .space
            .unmap(mapping.region.base)
            .map_err(|_| NativeError::InvalidHandle)?;
        debug_assert_eq!(removed, mapping.region);
        // 完整范围与用量预检已完成后，撤销不需要拆分且释放不会下溢，剩余步骤都是提交。
        // After exact-range and usage preflights, revocation needs no split and release cannot
        // underflow; the remaining steps are invariant commits after every refusal path.
        let revoked = self
            .capabilities
            .revoke_range(removed.base, pages)
            .map_err(map_memory_error)?;
        debug_assert!(revoked != 0);
        self.revoked = self.revoked.saturating_add(revoked as u64);
        self.usage
            .release(pages, 0)
            .map_err(|_| NativeError::Accounting)?;
        Ok(removed)
    }

    /// Validates a capability use token for an actual memory access.
    ///
    /// 为实际内存访问校验 capability 使用凭据。
    pub fn validate(
        &self,
        token: kernel_core::memory_capability::MemoryCapabilityUse,
    ) -> Result<(), NativeError> {
        self.capabilities.validate(token).map_err(map_memory_error)
    }

    /// Returns current mapped-page usage.
    ///
    /// 返回当前已映射页数与 pin 页数。
    pub const fn usage(&self) -> memory_object::Usage {
        self.usage
    }

    /// Returns the cumulative revoked capability count.
    ///
    /// 返回累计撤销的 capability 数。
    pub const fn revoked(&self) -> u64 {
        self.revoked
    }
}

fn map_memory_error(error: MemoryCapabilityError) -> NativeError {
    match error {
        MemoryCapabilityError::InvalidRange
        | MemoryCapabilityError::InvalidIdentity
        | MemoryCapabilityError::InvalidCapability => NativeError::InvalidArgument,
        MemoryCapabilityError::NoSpace | MemoryCapabilityError::Overlap => NativeError::Capacity,
        MemoryCapabilityError::Revoked => NativeError::Revoked,
        MemoryCapabilityError::RightsDenied | MemoryCapabilityError::Unmapped => {
            NativeError::RightsDenied
        }
        MemoryCapabilityError::StaleIdentity => NativeError::Stale,
        MemoryCapabilityError::HardwareUnavailable => NativeError::Unsupported,
    }
}

#[derive(Clone, Copy)]
struct RequestMeta {
    id: u64,
    context: u64,
    deadline: Option<u64>,
    active: bool,
}

impl RequestMeta {
    const fn empty() -> Self {
        Self {
            id: 0,
            context: 0,
            deadline: None,
            active: false,
        }
    }
}

/// Bounded io_uring-compatible adapter over the Jasper asynchronous Ring state machine.
///
/// 基于 Jasper 异步 Ring 状态机的有界 io_uring 兼容适配器。
pub struct Uring<const C: usize, const N: usize> {
    ring: AsyncRing<C, N>,
    rights: Rights,
    metadata: [RequestMeta; N],
    revoked: AtomicBool,
    aborted: [u64; N],
    aborted_len: usize,
}

impl<const C: usize, const N: usize> Uring<C, N> {
    /// Creates a Ring only when the caller holds native Ring Rights.
    ///
    /// 仅在调用者持有原生 Ring Rights 时创建异步环。
    pub fn new(capacity: usize, rights: Rights) -> Result<Self, NativeError> {
        let required = Rights::WRITE.union(Rights::WAIT).union(Rights::CONTROL);
        if !rights.contains(required) {
            return Err(NativeError::RightsDenied);
        }
        let ring = AsyncRing::new(capacity).ok_or(NativeError::InvalidArgument)?;
        Ok(Self {
            ring,
            rights,
            metadata: [RequestMeta::empty(); N],
            revoked: AtomicBool::new(false),
            aborted: [0; N],
            aborted_len: 0,
        })
    }

    /// Submits and starts one abortable compatibility request.
    ///
    /// 提交并启动一个可中止兼容请求；配额、信用、Rights 和 ID 拒绝均保持状态不变。
    pub fn submit(
        &mut self,
        op: u32,
        user_tag: u64,
        context: u64,
        uses_buffer: bool,
        deadline: Option<u64>,
        required: Rights,
    ) -> Result<u64, NativeError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(NativeError::Revoked);
        }
        if !self.rights.contains(required) {
            return Err(NativeError::RightsDenied);
        }
        if self
            .metadata
            .iter()
            .any(|meta| meta.active && meta.context == context)
        {
            return Err(NativeError::InvalidArgument);
        }
        let slot = self
            .metadata
            .iter()
            .position(|entry| !entry.active)
            .ok_or(NativeError::Capacity)?;
        let id = self
            .ring
            .submit(Submission {
                op,
                user_tag,
                context,
                uses_buffer,
            })
            .map_err(map_submit_error)?;
        if self.ring.start(id, Exec::Abortable).is_err() {
            let _ = self.ring.cancel(id);
            return Err(NativeError::State);
        }
        self.metadata[slot] = RequestMeta {
            id,
            context,
            deadline,
            active: true,
        };
        Ok(id)
    }

    /// Completes a request with its native operation result.
    ///
    /// 以原生操作结果完成请求；重复或错误状态被拒绝。
    pub fn complete(&mut self, id: u64, value: i64) -> Result<Terminal, NativeError> {
        self.ring.finish(id, value).map_err(map_progress_error)
    }

    /// Cancels one request and reports whether its backend must quiesce.
    ///
    /// 取消请求并返回后端是否必须先静止；已完成或不存在时区分错误。
    pub fn cancel(&mut self, id: u64) -> Result<bool, NativeError> {
        match self.ring.cancel(id) {
            Ok(Cancelled::NotStarted) => Ok(false),
            Ok(Cancelled::AbortBackend { .. }) => Ok(true),
            Err(CancelError::AlreadyCompleted) => Err(NativeError::State),
            Err(CancelError::NotFound) => Err(NativeError::InvalidHandle),
            Err(CancelError::InProgress) => Err(NativeError::Busy),
        }
    }

    /// Reports that an aborted backend no longer touches user buffers or objects.
    ///
    /// 报告被中止后端已静止；此后完成记录才可发布并销毁控制块。
    pub fn quiesce(&mut self, id: u64) -> Result<(), NativeError> {
        self.ring.quiesce(id).map_err(map_progress_error)
    }

    /// Cancels every request whose absolute deadline elapsed.
    ///
    /// 对截止期已到的请求执行取消，并把需要后端静止的请求标识写回有界输出。
    pub fn expire(&mut self, now: u64, aborts: &mut [u64]) -> Result<usize, NativeError> {
        let expired = self
            .metadata
            .iter()
            .filter(|meta| meta.active && meta.deadline.is_some_and(|deadline| now >= deadline))
            .count();
        if aborts.len() < expired {
            return Err(NativeError::Capacity);
        }
        let mut count = 0;
        for meta in self
            .metadata
            .iter()
            .filter(|meta| meta.active && meta.deadline.is_some_and(|deadline| now >= deadline))
        {
            match self.ring.cancel(meta.id) {
                Ok(Cancelled::NotStarted) => {}
                Ok(Cancelled::AbortBackend { context }) => {
                    if count == aborts.len() {
                        return Err(NativeError::Capacity);
                    }
                    aborts[count] = context;
                    count += 1;
                }
                Err(CancelError::AlreadyCompleted | CancelError::NotFound) => {}
                Err(CancelError::InProgress) => {}
            }
        }
        Ok(count)
    }

    /// Pops one completion while preserving signal and native readiness ordering.
    ///
    /// 弹出一条完成记录；信号仅在没有完成记录时产生 EINTR 语义。
    pub fn reap(&mut self, signal_pending: bool) -> Result<Option<Completion>, NativeError> {
        if self.revoked.load(Ordering::Acquire) && self.ring.ready() == 0 {
            return Err(NativeError::Revoked);
        }
        let completion = self.ring.peek(0);
        if completion.is_some() {
            assert_eq!(self.ring.consume(1), 1);
            return Ok(completion);
        }
        if signal_pending {
            return Err(NativeError::Interrupted);
        }
        Ok(None)
    }

    /// Recovers the context of every destroyed request control block.
    ///
    /// 取出已销毁控制块的上下文，供调用者释放对象引用。
    pub fn reclaim(&mut self) -> Option<u64> {
        let context = self.ring.take_reclaimed()?;
        if let Some(meta) = self
            .metadata
            .iter_mut()
            .find(|meta| meta.active && meta.context == context)
        {
            meta.active = false;
        }
        Some(context)
    }

    /// Returns the number of requests that have not yet destroyed their control blocks.
    ///
    /// 返回尚未销毁控制块的请求数。
    pub fn in_flight(&self) -> usize {
        self.ring.in_flight()
    }

    /// Closes the Ring and records backend contexts that must be aborted.
    ///
    /// 关闭 Ring 并记录必须中止的后端上下文；已发布的完成记录被原生 closing 语义丢弃。
    pub fn close(&mut self) -> usize {
        self.revoked.store(true, Ordering::Release);
        self.aborted_len = 0;
        let aborted = &mut self.aborted;
        let mut length = 0;
        let cancelled = self.ring.close(|context, _id| {
            debug_assert!(length < aborted.len());
            aborted[length] = context;
            length += 1;
        });
        debug_assert!(length <= aborted.len());
        self.aborted_len = length;
        cancelled
    }

    /// Pops one backend context that must observe quiescence.
    ///
    /// 取出一条等待后端静止的上下文。
    pub fn take_abort(&mut self) -> Option<u64> {
        if self.aborted_len == 0 {
            return None;
        }
        self.aborted_len -= 1;
        Some(self.aborted[self.aborted_len])
    }

    /// Returns whether the native Ring is fully drained after close.
    ///
    /// 返回关闭后原生 Ring 是否已经完全排空。
    pub fn is_drained(&self) -> bool {
        self.ring.is_drained()
    }
}

fn map_submit_error(error: SubmitError) -> NativeError {
    match error {
        SubmitError::CqFull | SubmitError::IdExhausted | SubmitError::QuotaExceeded => {
            NativeError::Capacity
        }
        SubmitError::Closing => NativeError::InvalidHandle,
    }
}

fn map_progress_error(_error: ProgressError) -> NativeError {
    NativeError::State
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoll_readiness_edge_oneshot_deadline_signal_and_rights() {
        let mut sources = EventSourceTable::<4>::new();
        let source = sources
            .register(Rights::SUBSCRIBE.union(Rights::WAIT))
            .unwrap();
        let denied = sources.register(Rights::READ).unwrap_err();
        assert_eq!(denied, NativeError::RightsDenied);
        let mut epoll = Epoll::<4>::new();
        epoll
            .add(
                &mut sources,
                source,
                11,
                EpollInterest::from_bits(
                    EpollInterest::READ.bits() | EpollInterest::ONESHOT.bits(),
                )
                .unwrap(),
            )
            .unwrap();
        let mut output = [EpollEvent {
            data: 0,
            events: EpollInterest::NONE,
        }; 2];
        assert_eq!(
            epoll.wait(&sources, 1, Some(1), true, &mut output),
            Ok(NativeWait::Interrupted)
        );
        assert_eq!(
            epoll.wait(&sources, 1, Some(1), false, &mut output),
            Ok(NativeWait::TimedOut)
        );
        sources.signal(source).unwrap();
        assert_eq!(
            epoll.wait(&sources, 2, None, false, &mut output),
            Ok(NativeWait::Ready(1))
        );
        assert_eq!(output[0].data, 11);
        assert_eq!(
            epoll.wait(&sources, 2, None, false, &mut output),
            Ok(NativeWait::Ready(0)),
            "oneshot entry must disarm after delivery"
        );
        assert_eq!(epoll.active(), 0);
        sources.close(source).unwrap();
        assert_eq!(sources.release(source), Err(NativeError::Busy));
        epoll.delete(&mut sources, source).unwrap();
        sources.release(source).unwrap();
    }

    #[test]
    fn epoll_generation_and_close_revoke_old_registrations() {
        let mut sources = EventSourceTable::<2>::new();
        let source = sources
            .register(Rights::SUBSCRIBE.union(Rights::WAIT))
            .unwrap();
        sources.close(source).unwrap();
        sources.release(source).unwrap();
        let replacement = sources
            .register(Rights::SUBSCRIBE.union(Rights::WAIT))
            .unwrap();
        assert_eq!(replacement.slot(), source.slot());
        assert_ne!(replacement.generation(), source.generation());
        let mut epoll = Epoll::<2>::new();
        assert_eq!(
            epoll.add(
                &mut sources,
                source,
                1,
                EpollInterest::from_bits(EpollInterest::READ.bits()).unwrap()
            ),
            Err(NativeError::Stale)
        );
    }

    #[test]
    fn epoll_reports_hangup_even_without_requesting_it() {
        let mut sources = EventSourceTable::<1>::new();
        let source = sources
            .register(Rights::SUBSCRIBE.union(Rights::WAIT))
            .unwrap();
        let mut epoll = Epoll::<1>::new();
        epoll
            .add(
                &mut sources,
                source,
                7,
                EpollInterest::from_bits(EpollInterest::READ.bits()).unwrap(),
            )
            .unwrap();
        sources.close(source).unwrap();
        let mut output = [EpollEvent {
            data: 0,
            events: EpollInterest::NONE,
        }; 1];
        assert_eq!(
            epoll.wait(&sources, 1, None, false, &mut output),
            Ok(NativeWait::Ready(1))
        );
        assert!(output[0].events.contains(EpollInterest::HANGUP));
        assert_eq!(epoll.close(&mut sources), Ok(1));
        sources.release(source).unwrap();
    }

    #[test]
    fn epoll_modify_rejects_revoked_source_without_changing_entry() {
        let mut sources = EventSourceTable::<1>::new();
        let source = sources
            .register(Rights::SUBSCRIBE.union(Rights::WAIT))
            .unwrap();
        let mut epoll = Epoll::<1>::new();
        epoll
            .add(
                &mut sources,
                source,
                0x41,
                EpollInterest::from_bits(EpollInterest::READ.bits()).unwrap(),
            )
            .unwrap();
        sources.close(source).unwrap();
        assert_eq!(
            epoll.modify(
                &sources,
                source,
                0x99,
                EpollInterest::from_bits(EpollInterest::WRITE.bits()).unwrap(),
            ),
            Err(NativeError::Revoked)
        );
        assert_eq!(epoll.active(), 1);
        let mut output = [EpollEvent {
            data: 0,
            events: EpollInterest::NONE,
        }; 1];
        assert_eq!(
            epoll.wait(&sources, 1, None, false, &mut output),
            Ok(NativeWait::Ready(1))
        );
        assert_eq!(output[0].data, 0x41);
        assert!(output[0].events.contains(EpollInterest::HANGUP));
    }

    #[test]
    fn epoll_delete_and_close_keep_registration_on_lease_accounting_failure() {
        let mut sources = EventSourceTable::<1>::new();
        let source = sources
            .register(Rights::SUBSCRIBE.union(Rights::WAIT))
            .unwrap();
        let mut epoll = Epoll::<1>::new();
        epoll
            .add(
                &mut sources,
                source,
                0x77,
                EpollInterest::from_bits(EpollInterest::READ.bits()).unwrap(),
            )
            .unwrap();
        sources.slots[0].leases = 0;
        assert_eq!(
            epoll.delete(&mut sources, source),
            Err(NativeError::Accounting)
        );
        assert_eq!(epoll.active(), 1);
        assert_eq!(epoll.close(&mut sources), Err(NativeError::Accounting));
        assert_eq!(epoll.active(), 1);
        let mut output = [EpollEvent {
            data: 0,
            events: EpollInterest::NONE,
        }; 1];
        sources.signal(source).unwrap();
        assert_eq!(
            epoll.wait(&sources, 1, None, false, &mut output),
            Ok(NativeWait::Ready(1))
        );
        assert_eq!(output[0].data, 0x77);
    }

    #[test]
    fn futex_wait_value_signal_cancel_expiry_and_priority_handoff() {
        let mut futex = Futex::<2, 4>::new();
        let word = futex.create(7).unwrap();
        assert_eq!(
            futex.wait(word, 8, 1, 3, 10, Some(20), false),
            Err(NativeError::TryAgain)
        );
        assert_eq!(
            futex.wait(word, 7, 1, 3, 10, Some(20), true),
            Err(NativeError::Interrupted)
        );
        assert_eq!(futex.wait(word, 7, 1, 3, 10, Some(20), false), Ok(1));
        assert_eq!(
            futex.wait(word, 7, 1, 3, 10, Some(20), false),
            Err(NativeError::Busy)
        );
        assert_eq!(futex.wait(word, 7, 2, 1, 10, Some(20), false), Ok(2));
        futex.wait(word, 7, 3, 2, 10, Some(20), false).unwrap();
        assert_eq!(futex.cancel(word, 3, 3), Ok(true));
        assert_eq!(futex.cancel(word, 3, 3), Ok(false));
        let wake = futex.wake(word, 1).unwrap();
        assert_eq!(wake.woken, 1);
        assert_eq!(wake.owner_priority, Some(3));
        assert_eq!(futex.revoke(word), Ok(1));
        assert_eq!(futex.value(word), Err(NativeError::Revoked));
    }

    #[test]
    fn futex_revoke_finishes_every_armed_registration_before_retiring() {
        let mut futex = Futex::<1, 4>::new();
        let word = futex.create(9).unwrap();
        futex.wait(word, 9, 1, 3, 0, None, false).unwrap();
        futex.wait(word, 9, 2, 2, 0, None, false).unwrap();
        futex.wait(word, 9, 3, 1, 0, None, false).unwrap();
        assert_eq!(futex.revoke(word), Ok(3));
        assert_eq!(futex.revoke(word), Err(NativeError::Revoked));
        let replacement = futex.create(10).unwrap();
        assert_eq!(replacement.slot(), word.slot());
        assert_ne!(replacement.generation(), word.generation());
        assert_eq!(
            futex.wait(word, 10, 4, 1, 0, None, false),
            Err(NativeError::Stale)
        );
    }

    #[test]
    fn futex_deadline_removes_only_the_expired_registration() {
        let mut futex = Futex::<1, 3>::new();
        let word = futex.create(1).unwrap();
        futex.wait(word, 1, 1, 2, 10, Some(20), false).unwrap();
        futex.wait(word, 1, 2, 1, 10, None, false).unwrap();
        assert_eq!(futex.expire(word, 19), Ok(0));
        assert_eq!(futex.expire(word, 20), Ok(1));
        let wake = futex.wake(word, 2).unwrap();
        assert_eq!(wake.woken, 1);
        assert_eq!(wake.owner_priority, None);
    }

    #[test]
    fn pi_futex_owner_handoff_and_refusal_are_atomic() {
        let mut futex = Futex::<2, 4>::new();
        let word = futex.create(0).unwrap();
        assert_eq!(futex.lock_pi(word, 10, 3, false), Ok(None));
        assert_eq!(futex.lock_pi(word, 10, 3, true), Err(NativeError::Busy));
        assert_eq!(futex.lock_pi(word, 20, 2, true), Ok(Some(10)));
        assert_eq!(futex.lock_pi(word, 30, 1, true), Ok(Some(10)));
        assert_eq!(futex.unlock_pi(word, 10), Ok(Some(30)));
        assert_eq!(futex.unlock_pi(word, 30), Ok(Some(20)));
        assert_eq!(futex.unlock_pi(word, 10), Err(NativeError::RightsDenied));
    }

    #[test]
    fn memory_map_protect_quota_revoke_and_wx_are_failure_atomic() {
        let limits = memory_object::Usage {
            mapped: 3,
            pinned: 0,
        };
        let mut memory = NativeMemory::<4>::new(limits);
        let rw = MemoryRights::READ
            .union(MemoryRights::WRITE)
            .union(MemoryRights::MAP);
        let mapping = memory
            .map(1, VmProtection::READ_WRITE, rw, MemoryKind::Shared)
            .unwrap();
        assert_eq!(memory.usage().mapped, 1);
        assert_eq!(
            memory.map(
                1,
                VmProtection::WRITE.union(VmProtection::EXECUTE),
                rw,
                MemoryKind::Anonymous
            ),
            Err(NativeError::InvalidArgument)
        );
        assert_eq!(
            memory.protect(mapping, VmProtection::READ.union(VmProtection::EXECUTE)),
            Err(NativeError::RightsDenied)
        );
        let ro = memory.protect(mapping, VmProtection::READ).unwrap();
        assert_eq!(ro.region.protection, VmProtection::READ);
        memory.unmap(ro).unwrap();
        assert_eq!(memory.usage().mapped, 0);
        assert_eq!(memory.revoked(), 1);
    }

    #[test]
    fn forged_unmap_metadata_fails_before_mapping_or_quota_changes() {
        let limits = memory_object::Usage {
            mapped: 2,
            pinned: 0,
        };
        let mut memory = NativeMemory::<4>::new(limits);
        let rights = MemoryRights::READ
            .union(MemoryRights::WRITE)
            .union(MemoryRights::MAP);
        let mapping = memory
            .map(2, VmProtection::READ_WRITE, rights, MemoryKind::Anonymous)
            .unwrap();
        let mut forged = mapping;
        forged.region.size = PAGE_SIZE;
        assert_eq!(memory.unmap(forged), Err(NativeError::Stale));
        assert_eq!(memory.usage().mapped, 2);
        assert_eq!(memory.revoked(), 0);
        memory.unmap(mapping).unwrap();
        assert_eq!(memory.usage().mapped, 0);
    }

    #[test]
    fn memory_quota_and_stale_mapping_fail_without_partial_state() {
        let limits = memory_object::Usage {
            mapped: 1,
            pinned: 0,
        };
        let mut memory = NativeMemory::<4>::new(limits);
        let rights = MemoryRights::READ
            .union(MemoryRights::WRITE)
            .union(MemoryRights::MAP);
        let mapping = memory
            .map(1, VmProtection::READ_WRITE, rights, MemoryKind::Anonymous)
            .unwrap();
        assert_eq!(
            memory.map(1, VmProtection::READ, rights, MemoryKind::Anonymous),
            Err(NativeError::Quota)
        );
        assert_eq!(memory.usage().mapped, 1);
        memory.unmap(mapping).unwrap();
        assert_eq!(
            memory.protect(mapping, VmProtection::READ),
            Err(NativeError::RightsDenied)
        );
        assert_eq!(memory.usage().mapped, 0);
    }

    #[test]
    fn adapter_errors_use_specific_linux_errno_values() {
        use crate::syscall::CompatErrno;
        assert_eq!(NativeError::Interrupted.errno(), CompatErrno::Interrupted);
        assert_eq!(NativeError::TryAgain.errno(), CompatErrno::TryAgain);
        assert_eq!(NativeError::TimedOut.errno(), CompatErrno::TimedOut);
        assert_eq!(NativeError::RightsDenied.errno(), CompatErrno::Perm);
        assert_eq!(NativeError::Capacity.errno(), CompatErrno::NoSpace);
        assert_eq!(NativeError::Unsupported.errno(), CompatErrno::NoSys);
    }

    #[test]
    fn uring_completion_cancellation_deadline_signal_and_reclaim() {
        let rights = Rights::WRITE.union(Rights::WAIT).union(Rights::CONTROL);
        let mut ring = Uring::<4, 4>::new(2, rights).unwrap();
        let a = ring
            .submit(1, 11, 101, false, Some(20), Rights::WRITE)
            .unwrap();
        let b = ring
            .submit(2, 12, 102, true, Some(20), Rights::WRITE)
            .unwrap();
        assert_eq!(
            ring.reap(true),
            Err(NativeError::Interrupted),
            "a pending signal must produce EINTR when no completion is ready"
        );
        ring.complete(a, 7).unwrap();
        assert_eq!(
            ring.reap(false).unwrap().unwrap().terminal,
            Terminal::Done(7)
        );
        assert_eq!(ring.reclaim(), Some(101));
        let mut aborts = [0; 2];
        assert_eq!(ring.expire(20, &mut aborts), Ok(1));
        assert_eq!(aborts[0], 102);
        ring.quiesce(b).unwrap();
        assert_eq!(
            ring.reap(false).unwrap().unwrap().terminal,
            Terminal::Cancelled
        );
        assert_eq!(ring.reclaim(), Some(102));
        assert_eq!(ring.in_flight(), 0);
    }

    #[test]
    fn uring_close_drops_completions_and_requires_quiescence() {
        let rights = Rights::WRITE.union(Rights::WAIT).union(Rights::CONTROL);
        let mut ring = Uring::<2, 2>::new(2, rights).unwrap();
        let id = ring.submit(1, 1, 55, false, None, Rights::WRITE).unwrap();
        assert_eq!(ring.close(), 1);
        assert!(!ring.is_drained());
        assert_eq!(ring.take_abort(), Some(55));
        ring.quiesce(id).unwrap();
        assert!(ring.is_drained());
        assert_eq!(ring.reap(false), Err(NativeError::Revoked));
    }

    #[test]
    fn uring_close_reports_every_backend_context_without_truncation() {
        let rights = Rights::WRITE.union(Rights::WAIT).union(Rights::CONTROL);
        let mut ring = Uring::<3, 3>::new(3, rights).unwrap();
        for context in 201..=203 {
            ring.submit(1, context, context, true, None, Rights::WRITE)
                .unwrap();
        }
        assert_eq!(ring.close(), 3);
        let mut contexts = [ring.take_abort(), ring.take_abort(), ring.take_abort()];
        contexts.sort_unstable();
        assert_eq!(contexts, [Some(201), Some(202), Some(203)]);
        assert_eq!(ring.take_abort(), None);
        assert!(!ring.is_drained());
    }

    #[test]
    fn uring_context_and_expiry_preflight_fail_without_cancellation() {
        let rights = Rights::WRITE.union(Rights::WAIT).union(Rights::CONTROL);
        let mut ring = Uring::<2, 2>::new(2, rights).unwrap();
        ring.submit(1, 1, 9, false, Some(10), Rights::WRITE)
            .unwrap();
        assert_eq!(
            ring.submit(2, 2, 9, false, None, Rights::WRITE),
            Err(NativeError::InvalidArgument)
        );
        assert_eq!(ring.in_flight(), 1);
        assert_eq!(ring.expire(10, &mut []), Err(NativeError::Capacity));
        let mut aborts = [0; 1];
        assert_eq!(ring.expire(10, &mut aborts), Ok(1));
    }
}
