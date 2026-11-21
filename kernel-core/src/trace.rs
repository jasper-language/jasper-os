//! 观测性：无堆环形缓冲 + 结构化事件追踪器。
//!
//! # 职责
//! * [`RingBuffer`]：固定容量、零堆分配的环形缓冲。**满时行为由调用者显式选择**：
//!   [`RingBuffer::push`] 拒绝（把值还给调用者），[`RingBuffer::push_overwrite`] 覆盖最旧的元素
//!   （并把被挤出的值还给调用者）。两种语义都不会静默丢失信息。
//! * [`TraceEvent`]：结构化事件 = 规范事件名 + 若干键值标签（设计约束「原生 AI」：日志/trace
//!   必须机器可读，而不是自由文本）。
//! * [`Tracer`]：把事件写进覆盖式环形缓冲，并可选地通知一个观察者（Observer 模式，内核用它
//!   把事件打印到串口；宿主测试里不装观察者）。
//!
//! # 边界
//! 不做格式化输出、不碰串口：怎么呈现由观察者决定。事件名应遵守命名约定（过去分词）。

use core::fmt;

pub use crate::object::IdAllocator;

/// 固定容量 `N` 的环形缓冲（FIFO）。
pub struct RingBuffer<T, const N: usize> {
    slots: [Option<T>; N],
    head: usize,
    len: usize,
}

impl<T, const N: usize> RingBuffer<T, N> {
    /// 新建空缓冲。
    pub const fn new() -> Self {
        assert!(N > 0, "环形缓冲容量必须大于 0");
        RingBuffer {
            slots: [const { None }; N],
            head: 0,
            len: 0,
        }
    }

    /// 元素个数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 是否已满。
    pub fn is_full(&self) -> bool {
        self.len == N
    }

    /// 容量。
    pub const fn capacity(&self) -> usize {
        N
    }

    /// 尾部追加；**满时拒绝**，原值经 `Err` 返回。适合不允许丢数据的队列（如异步完成队列）。
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.is_full() {
            return Err(value);
        }
        let tail = (self.head + self.len) % N;
        self.slots[tail] = Some(value);
        self.len += 1;
        Ok(())
    }

    /// 尾部追加；**满时覆盖最旧的元素**并返回它。适合「只关心最近 N 条」的追踪缓冲。
    pub fn push_overwrite(&mut self, value: T) -> Option<T> {
        let evicted = if self.is_full() { self.pop() } else { None };
        // 刚腾出空间，必然成功。
        let _ = self.push(value);
        evicted
    }

    /// 取出最旧的元素。
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let v = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        v
    }

    /// 从最旧到最新遍历（不取出）。
    pub fn iter(&self) -> impl Iterator<Item = &T> + '_ {
        (0..self.len).filter_map(move |i| self.slots[(self.head + i) % N].as_ref())
    }

    /// 按条件移除第一个匹配的元素并返回它，其余元素保持原有顺序。
    pub fn remove_first(&mut self, mut pred: impl FnMut(&T) -> bool) -> Option<T> {
        let pos = self.iter().position(|v| pred(v))?;
        let idx = (self.head + pos) % N;
        let found = self.slots[idx].take();
        // 把后面的元素逐个前移，填上空洞。
        for i in pos..self.len - 1 {
            let from = (self.head + i + 1) % N;
            let to = (self.head + i) % N;
            self.slots[to] = self.slots[from].take();
        }
        self.len -= 1;
        found
    }
}

impl<T, const N: usize> Default for RingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// 事件标签的值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagValue {
    /// 无符号整数。
    U64(u64),
    /// 静态字符串（UTF-8，可含中文）。
    Str(&'static str),
}

/// 一个键值标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// 键（ASCII 小写 + 下划线）。
    pub key: &'static str,
    /// 值。
    pub value: TagValue,
}

impl Tag {
    /// 整数标签。
    pub const fn u64(key: &'static str, v: u64) -> Tag {
        Tag {
            key,
            value: TagValue::U64(v),
        }
    }
    /// 字符串标签。
    pub const fn str(key: &'static str, v: &'static str) -> Tag {
        Tag {
            key,
            value: TagValue::Str(v),
        }
    }
}

/// 单个事件最多携带的标签数（超出部分被截断，并在 `truncated` 中注明）。
pub const MAX_TAGS: usize = 4; // JASPER-HARDCODE-REVIEW: issue=35 source=trace-tag-envelope-policy reason=fixed-event-envelope-marks-visible-truncation-instead-of-silent-overwrite

/// Non-zero correlation identity for one causally related trace group.
///
/// This is a native diagnostic fact, not an execution capability. It never
/// grants access and must not be accepted as a substitute for security audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: u64,
    pub span_id: u64,
    pub parent_span_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceContextError {
    ZeroTrace,
    ZeroSpan,
    SelfParent,
}

impl TraceContext {
    pub fn new(
        trace_id: u64,
        span_id: u64,
        parent_span_id: Option<u64>,
    ) -> Result<Self, TraceContextError> {
        if trace_id == 0 {
            return Err(TraceContextError::ZeroTrace);
        }
        if span_id == 0 || parent_span_id == Some(0) {
            return Err(TraceContextError::ZeroSpan);
        }
        if parent_span_id == Some(span_id) {
            return Err(TraceContextError::SelfParent);
        }
        Ok(Self {
            trace_id,
            span_id,
            parent_span_id,
        })
    }
}

/// 结构化事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceEvent {
    /// 全局序号（从 1 开始，单调递增）。
    pub seq: u64,
    /// 规范事件名，如 `system.module.loaded`。
    pub name: &'static str,
    tags: [Option<Tag>; MAX_TAGS],
    /// 是否有标签因超过 [`MAX_TAGS`] 被截断。
    pub truncated: bool,
    /// Optional native causal context. Security audit remains separate.
    pub context: Option<TraceContext>,
}

impl TraceEvent {
    /// 标签列表。
    pub fn tags(&self) -> impl Iterator<Item = &Tag> {
        self.tags.iter().flatten()
    }
}

/// 输出形如 `seq=3 system.module.loaded module=hello_syscall`。
impl fmt::Display for TraceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seq={} {}", self.seq, self.name)?;
        for t in self.tags() {
            match t.value {
                TagValue::U64(v) => write!(f, " {}={}", t.key, v)?,
                TagValue::Str(s) => write!(f, " {}={}", t.key, s)?,
            }
        }
        if let Some(context) = self.context {
            write!(f, " trace={} span={}", context.trace_id, context.span_id)?;
            if let Some(parent) = context.parent_span_id {
                write!(f, " parent_span={}", parent)?;
            }
        }
        if self.truncated {
            f.write_str(" …")?;
        }
        Ok(())
    }
}

/// 事件观察者（例如内核的串口输出）。
pub type TraceSink = fn(&TraceEvent);

/// Explicit cumulative losses from the best-effort retained-event ring.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TraceLossStats {
    pub ring_overwrites: u64,
    pub sequence_exhausted: u64,
}

/// 结构化事件追踪器：保留最近 `N` 条事件。
pub struct Tracer<const N: usize> {
    events: RingBuffer<TraceEvent, N>,
    seq: IdAllocator,
    sink: Option<TraceSink>,
    losses: TraceLossStats,
}

impl<const N: usize> Tracer<N> {
    /// 新建（无观察者）。
    pub const fn new() -> Self {
        Tracer {
            events: RingBuffer::new(),
            seq: IdAllocator::new(),
            sink: None,
            losses: TraceLossStats {
                ring_overwrites: 0,
                sequence_exhausted: 0,
            },
        }
    }

    /// 安装观察者；每条事件记录后同步回调一次。
    pub fn set_sink(&mut self, sink: TraceSink) {
        self.sink = Some(sink);
    }

    /// 记录一条事件，返回其序号；序号用尽时丢弃该事件并返回 `None`（不回绕、不复用序号）。
    pub fn emit(&mut self, name: &'static str, tags: &[Tag]) -> Option<u64> {
        self.emit_with_context(name, tags, None)
    }

    /// Record one event with explicit native causal context.
    pub fn emit_correlated(
        &mut self,
        name: &'static str,
        tags: &[Tag],
        context: TraceContext,
    ) -> Option<u64> {
        self.emit_with_context(name, tags, Some(context))
    }

    fn emit_with_context(
        &mut self,
        name: &'static str,
        tags: &[Tag],
        context: Option<TraceContext>,
    ) -> Option<u64> {
        let seq = match self.seq.allocate() {
            Some(seq) => seq,
            None => {
                self.losses.sequence_exhausted = self.losses.sequence_exhausted.saturating_add(1);
                return None;
            }
        };
        let mut slot = [None; MAX_TAGS];
        for (dst, src) in slot.iter_mut().zip(tags) {
            *dst = Some(*src);
        }
        let ev = TraceEvent {
            seq,
            name,
            tags: slot,
            truncated: tags.len() > MAX_TAGS,
            context,
        };
        if let Some(sink) = self.sink {
            sink(&ev);
        }
        if self.events.push_overwrite(ev).is_some() {
            self.losses.ring_overwrites = self.losses.ring_overwrites.saturating_add(1);
        }
        Some(ev.seq)
    }

    /// 缓冲中当前保留的事件数（≤ N）。
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// 缓冲是否为空。
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// 迄今记录过的事件总数（含已被覆盖的）。
    pub fn total(&self) -> u64 {
        self.seq.allocated()
    }

    /// Cumulative best-effort trace losses. These counters never replace the
    /// reliable security audit stream.
    pub const fn losses(&self) -> TraceLossStats {
        self.losses
    }

    /// 从旧到新遍历保留的事件。
    pub fn iter(&self) -> impl Iterator<Item = &TraceEvent> + '_ {
        self.events.iter()
    }
}

impl<const N: usize> Default for Tracer<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_rejects_when_full() {
        let mut r: RingBuffer<u8, 2> = RingBuffer::new();
        assert_eq!(r.push(1), Ok(()));
        assert_eq!(r.push(2), Ok(()));
        assert_eq!(r.push(3), Err(3), "满时拒绝并原样退回");
        assert_eq!(r.pop(), Some(1));
        assert_eq!(r.push(3), Ok(()));
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn ring_overwrite_evicts_oldest() {
        let mut r: RingBuffer<u8, 3> = RingBuffer::new();
        for v in 1..=3 {
            assert_eq!(r.push_overwrite(v), None);
        }
        assert_eq!(r.push_overwrite(4), Some(1));
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![2, 3, 4]);
        assert!(r.is_full());
    }

    #[test]
    fn ring_remove_first_keeps_order_across_wrap() {
        let mut r: RingBuffer<u8, 4> = RingBuffer::new();
        for v in 1..=4 {
            r.push(v).unwrap();
        }
        r.pop();
        r.pop();
        r.push(5).unwrap();
        r.push(6).unwrap(); // 内部已回绕：3 4 5 6
        assert_eq!(r.remove_first(|&v| v == 4), Some(4));
        assert_eq!(r.remove_first(|&v| v == 9), None);
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![3, 5, 6]);
        r.push(7).unwrap();
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![3, 5, 6, 7]);
    }

    #[test]
    fn tracer_keeps_recent_and_counts_total() {
        let mut t: Tracer<2> = Tracer::new();
        t.emit("system.module.loaded", &[Tag::str("module", "a")]);
        t.emit("system.module.loaded", &[Tag::str("module", "b")]);
        let s = t.emit(
            "system.module.unloaded",
            &[Tag::str("module", "b"), Tag::u64("n", 1)],
        );
        assert_eq!(s, Some(3));
        assert_eq!(t.len(), 2);
        assert_eq!(t.total(), 3);
        let last = t.iter().last().unwrap();
        assert_eq!(
            format!("{}", last),
            "seq=3 system.module.unloaded module=b n=1"
        );
    }

    #[test]
    fn tracer_truncates_extra_tags_visibly() {
        let mut t: Tracer<2> = Tracer::new();
        let exact = [Tag::u64("a", 1); MAX_TAGS];
        t.emit("x.test.exact", &exact);
        let tags = [Tag::u64("a", 1); MAX_TAGS + 1];
        t.emit("x.test.happened", &tags);
        assert_eq!(t.iter().next().unwrap().tags().count(), MAX_TAGS);
        let ev = t.iter().nth(1).unwrap();
        assert_eq!(ev.name, "x.test.happened");
        assert!(ev.truncated);
        assert_eq!(ev.tags().count(), MAX_TAGS);
    }

    #[test]
    fn tracer_notifies_sink() {
        use core::sync::atomic::{AtomicU64, Ordering};
        static SEEN: AtomicU64 = AtomicU64::new(0);
        fn sink(e: &TraceEvent) {
            SEEN.store(e.seq, Ordering::Relaxed);
        }
        let mut t: Tracer<4> = Tracer::new();
        t.set_sink(sink);
        t.emit("x.test.happened", &[]);
        assert_eq!(SEEN.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn correlated_events_keep_trace_and_parent_identity() {
        let root = TraceContext::new(17, 1, None).unwrap();
        let child = TraceContext::new(17, 2, Some(1)).unwrap();
        let mut t: Tracer<2> = Tracer::new();
        assert_eq!(
            t.emit_correlated("system.request.started", &[], root),
            Some(1)
        );
        assert_eq!(
            t.emit_correlated("system.request.completed", &[Tag::u64("status", 0)], child),
            Some(2)
        );
        assert_eq!(
            format!("{}", t.iter().last().unwrap()),
            "seq=2 system.request.completed status=0 trace=17 span=2 parent_span=1"
        );
    }

    #[test]
    fn trace_context_rejects_zero_and_self_parent() {
        assert_eq!(
            TraceContext::new(0, 1, None),
            Err(TraceContextError::ZeroTrace)
        );
        assert_eq!(
            TraceContext::new(1, 0, None),
            Err(TraceContextError::ZeroSpan)
        );
        assert_eq!(
            TraceContext::new(1, 1, Some(0)),
            Err(TraceContextError::ZeroSpan)
        );
        assert_eq!(
            TraceContext::new(1, 1, Some(1)),
            Err(TraceContextError::SelfParent)
        );
    }

    #[test]
    fn ring_overwrites_are_accounted_without_hiding_sequence_progress() {
        let mut t: Tracer<2> = Tracer::new();
        for value in 0..5 {
            assert_eq!(
                t.emit("x.test.happened", &[Tag::u64("n", value)]),
                Some(value + 1)
            );
        }
        assert_eq!(t.total(), 5);
        assert_eq!(t.len(), 2);
        assert_eq!(
            t.losses(),
            TraceLossStats {
                ring_overwrites: 3,
                sequence_exhausted: 0,
            }
        );
        assert_eq!(
            t.iter().map(|event| event.seq).collect::<Vec<_>>(),
            vec![4, 5]
        );
    }
}
