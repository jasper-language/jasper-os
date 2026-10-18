//! 异步环的请求状态机（`system.async.ring` 后端的纯机制部分）。
//! Request state machine of the asynchronous ring: credits, identities, cancellation and closing.
//!
//! # 职责
//! 本模块只做**记账与裁决**，不执行任何操作、不碰用户内存、不持有对象：
//! * 请求身份：64 位单调递增、永不复用、到上限拒绝（不回绕）；用户标签只原样带回，**从不参与匹配**
//! * 完成信用：每个被接受的请求在提交时预留 1 份信用，发布完成时转为「占据完成队列」，
//!   用户消费完成记录时归还——同一请求从接受到被消费始终只占一份信用；信用为 0 时提交原子失败
//! * 请求事件：D 终态裁决（只一次）、Q 后端静止、P 完成发布、C 用户消费、X 控制块销毁，
//!   并强制其先后依赖：D → P；访问用户缓冲区的请求另需 Q → P；X 需要 Q 且需要 P 已发生或 Ring 已 closing
//! * 取消：同步取消直接返回结果、不占信用；按请求所处状态给出唯一正确的结果（见 [`AsyncRing::cancel`]）
//! * 完成历史窗口：已发布的终态按先进先出保留最近 C 个，供取消查询区分「已完成」与「不存在」
//! * closing：拒绝新提交；排队中的与可中止的立即裁决为取消；不可中止的继续到自然结束；完成记录全部丢弃
//!
//! # 边界（为什么这样分）
//! * 「谁来执行」是后端（内核里的具体对象，例如事件等待）的事；后端只通过 [`AsyncRing::start`]、
//!   [`AsyncRing::finish`]、[`AsyncRing::quiesce`] 三个入口向本状态机报告进展，因此任何后端都复用同一套裁决。
//! * 在飞配额（每进程跨所有 Ring 的上限）与完成信用是**两种独立资源**：本模块报告「尚未 X 的控制块数」
//!   （[`AsyncRing::in_flight`]），由调用者在同一把锁内做配额检查与记账。
//! * 控制块被销毁（X）时，它的不透明上下文（例如对目标对象的引用标识）进入回收队列，
//!   调用者用 [`AsyncRing::take_reclaimed`] 取出并释放相应引用——本模块不知道引用是什么。
//! * 不使用堆：所有容量都是常量参数，`cargo test -p kernel-core` 可在宿主上运行全部测试。

use crate::meta::{Effects, InterfaceMeta};
use crate::object::Rights;
use crate::trace::RingBuffer;

/// Ring 自身的接口元数据（L2 后端级 + L1 契约级的取消）。
pub const RING_INTERFACE: [InterfaceMeta; 3] = [
    InterfaceMeta::op("system.async.ring.create", Rights::NONE, Effects::Write, "异步环·创建"),
    InterfaceMeta::op("system.async.ring.enter", Rights::WRITE.union(Rights::WAIT), Effects::Write, "异步环·提交并收取完成"),
    InterfaceMeta::op("system.async.cancel", Rights::CONTROL, Effects::Write, "异步·同步取消请求"),
];

/// 请求的终态。具体操作的结果值由操作自己定义（这里只是不透明的 64 位有符号数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// 操作按其语义执行完毕，结果值由操作定义。
    Done(i64),
    /// 操作被取消，不会再产生任何正常副作用（`system.async.error.cancelled`）。
    Cancelled,
}

/// 一条完成记录（拷贝给用户；内核回收不依赖用户何时读取它）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    /// 内核分配的请求 ID。
    pub request_id: u64,
    /// 提交时的用户标签（原样带回）。
    pub user_tag: u64,
    /// 操作编号（登记表中的操作 ID）。
    pub op: u32,
    /// 终态。
    pub terminal: Terminal,
}

/// 后端开始执行时声明的可中止性。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exec {
    /// 尚无不可撤销副作用，后端可以中止：取消立即裁决为 `cancelled`，可见性仍受 Q → P 约束。
    Abortable,
    /// 已有不可撤销副作用或后端不可中止：取消返回 `in_progress`，请求按实际执行结果结束。
    NonAbortable,
}

/// 提交的可信快照（调用者已从用户描述符复制并校验；执行阶段不再读用户内存）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Submission {
    /// 操作编号。
    pub op: u32,
    /// 用户标签。
    pub user_tag: u64,
    /// 不透明上下文（例如目标对象的引用标识）；X 时进入回收队列。
    pub context: u64,
    /// 是否访问用户缓冲区（是 ⇒ 完成必须等后端静止后才发布）。
    pub uses_buffer: bool,
}

/// 提交被拒绝的原因（拒绝路径不扣除任何信用与配额，不产生请求）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// 完成信用耗尽（`system.async.error.cq_full`）。
    CqFull,
    /// 请求 ID 已到上限（`system.async.error.id_exhausted`）。
    IdExhausted,
    /// 本 Ring 的控制块容量用尽（`system.error.quota_exceeded`）。
    QuotaExceeded,
    /// Ring 已 closing，不再接受提交（有效外部所有权已归零，或所属进程已在退出）。
    /// 对提交方而言等同于句柄已失效，因此报告 `system.handle.error.invalid`。
    Closing,
}

impl SubmitError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            SubmitError::CqFull => "system.async.error.cq_full",
            SubmitError::IdExhausted => "system.async.error.id_exhausted",
            SubmitError::QuotaExceeded => "system.error.quota_exceeded",
            SubmitError::Closing => "system.handle.error.invalid",
        }
    }
}

/// 同步取消的失败结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelError {
    /// 原请求已裁决（已发布并在历史窗口内，或已裁决尚未发布）（`system.async.error.already_completed`）。
    AlreadyCompleted,
    /// 窗口外，或本 Ring 中从未存在此 ID（`system.async.error.not_found`）。
    NotFound,
    /// 原请求已有不可撤销副作用或后端不可中止（`system.async.error.in_progress`）。
    InProgress,
}

impl CancelError {
    /// 规范错误名。
    pub const fn name(self) -> &'static str {
        match self {
            CancelError::AlreadyCompleted => "system.async.error.already_completed",
            CancelError::NotFound => "system.async.error.not_found",
            CancelError::InProgress => "system.async.error.in_progress",
        }
    }
}

/// 同步取消成功时，调用者还须做的事。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancelled {
    /// 请求尚未开始执行，已直接收尾。
    NotStarted,
    /// 请求正在可中止地执行：调用者须通知后端中止，后端静止后调用 [`AsyncRing::quiesce`]。
    AbortBackend {
        /// 请求的上下文（供调用者找到后端）。
        context: u64,
    },
}

/// 后端进展报告的错误（调用者记账错误，不是用户错误）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressError {
    /// 没有这个在飞请求，或请求不处于该报告所要求的状态。
    NoSuchRequest,
}

/// 请求执行阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// 已接受，后端尚未开始（天然处于静止）。
    Queued,
    /// 后端正在执行。
    Running(Exec),
}

/// 请求控制块（X 之前一直存在）。
#[derive(Debug, Clone, Copy)]
struct Block {
    id: u64,
    sub: Submission,
    phase: Phase,
    /// D：终态（只写一次）。
    decided: Option<Terminal>,
    /// Q：后端不再访问请求的任何对象与内存。
    quiesced: bool,
    /// P：完成已发布（或因 closing 被丢弃）。
    published: bool,
    /// Ring closing 时完成被丢弃（不进入完成队列）。
    dropped: bool,
}

/// 状态机统计（可观测性：验收要求负载结束后各「在途」数归零）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RingStats {
    /// 累计接受的请求数。
    pub accepted: u64,
    /// 累计被拒绝的提交数。
    pub rejected: u64,
    /// 累计发布进完成队列的记录数。
    pub published: u64,
    /// 累计被用户消费的记录数。
    pub consumed: u64,
    /// 累计因 closing 丢弃的完成记录数。
    pub dropped: u64,
    /// 累计销毁（X）的控制块数。
    pub destroyed: u64,
}

/// 异步环的请求状态机：完成队列容量上限 `C`，控制块容量 `N`。
///
/// 运行时容量 `capacity`（1..=C）由创建者给出：它就是规范里的 CQ 容量 C（也是历史窗口长度）。
pub struct AsyncRing<const C: usize, const N: usize> {
    capacity: usize,
    cq: RingBuffer<Completion, C>,
    /// 已发布终态的历史窗口（最近 `capacity` 个，与是否已消费无关；不持有任何引用）。
    window: RingBuffer<(u64, Terminal), C>,
    blocks: [Option<Block>; N],
    /// 已预留、尚未发布（也未丢弃）的信用数。
    reserved: usize,
    next_id: u64,
    id_limit: u64,
    closing: bool,
    /// 已 X 的控制块的上下文，等调用者释放引用。
    reclaimed: RingBuffer<u64, N>,
    stats: RingStats,
}

impl<const C: usize, const N: usize> AsyncRing<C, N> {
    /// 新建（`system.async.ring.create`）。`capacity` 超出 1..=C 时返回 `None`。
    pub const fn new(capacity: usize) -> Option<Self> {
        if capacity == 0 || capacity > C {
            return None;
        }
        Some(AsyncRing {
            capacity,
            cq: RingBuffer::new(),
            window: RingBuffer::new(),
            blocks: [const { None }; N],
            reserved: 0,
            next_id: 1,
            id_limit: u64::MAX,
            closing: false,
            reclaimed: RingBuffer::new(),
            stats: RingStats { accepted: 0, rejected: 0, published: 0, consumed: 0, dropped: 0, destroyed: 0 },
        })
    }

    /// 设定请求 ID 上限（最后一个可分配的 ID）。用于把「ID 耗尽」这条拒绝路径变得可测；只能调低。
    /// 默认上限为 `u64::MAX - 1`（`next_id` 自身不得溢出），到达后永久拒绝、绝不回绕。
    /// Lower the last assignable request ID (makes exhaustion testable); never raises it.
    pub fn limit_ids(&mut self, last_id: u64) {
        self.id_limit = self.id_limit.min(last_id);
    }

    /// CQ 容量 C。
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// 可用完成信用 = C − 已预留未发布数 − 已发布未消费数。
    pub fn credits(&self) -> usize {
        self.capacity - self.reserved - self.cq.len()
    }

    /// 已预留、尚未发布的请求数（≤ C）。
    pub fn reserved(&self) -> usize {
        self.reserved
    }

    /// 已发布、尚未消费的完成记录数。
    pub fn ready(&self) -> usize {
        self.cq.len()
    }

    /// 尚未 X 的控制块数（计入调用者的在飞配额）。
    pub fn in_flight(&self) -> usize {
        self.blocks.iter().filter(|b| b.is_some()).count()
    }

    /// 已裁决但尚未发布（在等后端静止）的请求数。
    pub fn decided_unpublished(&self) -> usize {
        self.blocks.iter().flatten().filter(|b| b.decided.is_some() && !b.published).count()
    }

    /// 是否已 closing。
    pub fn is_closing(&self) -> bool {
        self.closing
    }

    /// closing 且全部控制块已销毁（收尾完成，调用者可以释放 Ring 本身）。
    pub fn is_drained(&self) -> bool {
        self.closing && self.in_flight() == 0
    }

    /// 统计。
    pub fn stats(&self) -> RingStats {
        self.stats
    }

    /// 下一个将要分配的请求 ID（诊断用）。
    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    fn slot_of(&self, id: u64) -> Option<usize> {
        self.blocks.iter().position(|b| matches!(b, Some(b) if b.id == id))
    }

    /// 提交一个请求（INV-11 / INV-12）：要么全部成功（分配 ID、预留 1 份信用、建立控制块），要么什么都不改。
    ///
    /// 检查顺序：closing → ID 是否耗尽 → 信用 → 控制块容量。调用者须在**同一把锁内**先完成自己的检查
    /// （对象引用、每进程在飞配额、进程是否 exiting），再调用本方法。
    pub fn submit(&mut self, sub: Submission) -> Result<u64, SubmitError> {
        let r = self.check_submit();
        let slot = match r {
            Ok(slot) => slot,
            Err(e) => {
                self.stats.rejected += 1;
                return Err(e);
            }
        };
        let id = self.next_id;
        self.next_id += 1; // id ≤ id_limit ≤ u64::MAX 已检查；到 u64::MAX 之后 check_submit 必然拒绝
        self.reserved += 1;
        self.blocks[slot] =
            Some(Block { id, sub, phase: Phase::Queued, decided: None, quiesced: true, published: false, dropped: false });
        self.stats.accepted += 1;
        Ok(id)
    }

    fn check_submit(&self) -> Result<usize, SubmitError> {
        if self.closing {
            return Err(SubmitError::Closing);
        }
        if self.next_id > self.id_limit || self.next_id == u64::MAX {
            return Err(SubmitError::IdExhausted);
        }
        if self.credits() == 0 {
            return Err(SubmitError::CqFull);
        }
        self.blocks.iter().position(|b| b.is_none()).ok_or(SubmitError::QuotaExceeded)
    }

    /// 请求的裁决状态：`None` = 不存在（或已销毁）；`Some(None)` = 在飞且尚未裁决；`Some(Some(t))` = 已裁决为 `t`。
    /// 后端在执行**不可撤销的副作用之前**用它确认请求仍未被取消（与取消在同一把锁内，因此二者以先到者为准）。
    /// Decision state of a live request: not found / undecided / decided.
    pub fn decision(&self, id: u64) -> Option<Option<Terminal>> {
        self.slot_of(id).and_then(|i| self.blocks[i].as_ref()).map(|b| b.decided)
    }

    /// 后端开始执行请求（Queued → Running）。此后在 Q 之前，后端可能访问请求引用的对象与内存。
    pub fn start(&mut self, id: u64, exec: Exec) -> Result<(), ProgressError> {
        let i = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let b = self.blocks[i].as_mut().ok_or(ProgressError::NoSuchRequest)?;
        if b.phase != Phase::Queued || b.decided.is_some() {
            return Err(ProgressError::NoSuchRequest);
        }
        b.phase = Phase::Running(exec);
        b.quiesced = false;
        Ok(())
    }

    /// 后端自然结束（结果为 `value`）并已静止：若尚未裁决则裁决为 `Done(value)`；随后按依赖发布与销毁。
    ///
    /// 已被裁决为取消的可中止请求也可能「自然结束」（中止与完成竞争）：终态仍是先裁决的那一个（D 只一次）。
    pub fn finish(&mut self, id: u64, value: i64) -> Result<Terminal, ProgressError> {
        let i = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let b = self.blocks[i].as_mut().ok_or(ProgressError::NoSuchRequest)?;
        if !matches!(b.phase, Phase::Running(_)) || b.quiesced {
            return Err(ProgressError::NoSuchRequest);
        }
        let t = *b.decided.get_or_insert(Terminal::Done(value));
        b.quiesced = true;
        self.advance(i);
        Ok(t)
    }

    /// 后端在被要求中止后报告静止（Q）。请求必须已被裁决（取消时裁决）。
    pub fn quiesce(&mut self, id: u64) -> Result<(), ProgressError> {
        let i = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let b = self.blocks[i].as_mut().ok_or(ProgressError::NoSuchRequest)?;
        if b.decided.is_none() || b.quiesced {
            return Err(ProgressError::NoSuchRequest);
        }
        b.quiesced = true;
        self.advance(i);
        Ok(())
    }

    /// 同步取消（`system.async.cancel`）：直接返回结果，**不占完成信用**——信用耗尽时也可用。
    ///
    /// | 原请求状态 | 原请求终态 | 本调用结果 |
    /// |---|---|---|
    /// | 尚未开始 | `cancelled`（立即发布） | `Ok(NotStarted)` |
    /// | 可中止地执行中 | `cancelled`（访问缓冲区的请求等后端静止后才发布） | `Ok(AbortBackend)` |
    /// | 不可中止地执行中 | 按实际执行结果 | `Err(InProgress)` |
    /// | 已裁决（未发布，或已发布且在窗口内） | 原终态 | `Err(AlreadyCompleted)` |
    /// | 窗口外 / 从未存在 | — | `Err(NotFound)` |
    pub fn cancel(&mut self, id: u64) -> Result<Cancelled, CancelError> {
        let Some(i) = self.slot_of(id) else {
            return if self.window.iter().any(|(wid, _)| *wid == id) {
                Err(CancelError::AlreadyCompleted)
            } else {
                Err(CancelError::NotFound)
            };
        };
        let Some(b) = self.blocks[i].as_mut() else {
            return Err(CancelError::NotFound);
        };
        if b.decided.is_some() {
            return Err(CancelError::AlreadyCompleted);
        }
        let out = match b.phase {
            Phase::Queued => Cancelled::NotStarted,
            Phase::Running(Exec::Abortable) => Cancelled::AbortBackend { context: b.sub.context },
            Phase::Running(Exec::NonAbortable) => return Err(CancelError::InProgress),
        };
        b.decided = Some(Terminal::Cancelled);
        self.advance(i);
        Ok(out)
    }

    /// 按依赖推进一个控制块：能发布就发布（D → P；访问缓冲区另需 Q → P），能销毁就销毁（X 需要 Q 且 P 或丢弃）。
    fn advance(&mut self, i: usize) {
        let Some(b) = self.blocks[i] else { return };
        let mut b = b;
        if let Some(t) = b.decided {
            if !b.published && (b.quiesced || !b.sub.uses_buffer) {
                b.published = true;
                self.reserved -= 1; // 预留 → 占据（或随丢弃释放）：总数不变或减少，从不重复计数
                if self.closing {
                    b.dropped = true;
                    self.stats.dropped += 1;
                } else {
                    let c = Completion { request_id: b.id, user_tag: b.sub.user_tag, op: b.sub.op, terminal: t };
                    let pushed = self.cq.push(c);
                    debug_assert!(pushed.is_ok(), "完成信用预留失效");
                    if self.window.len() == self.capacity {
                        self.window.pop();
                    }
                    let _ = self.window.push((b.id, t));
                    self.stats.published += 1;
                }
            }
        }
        if b.quiesced && (b.published || b.dropped) {
            self.blocks[i] = None;
            let _ = self.reclaimed.push(b.sub.context); // 与控制块同容量，必然成功
            self.stats.destroyed += 1;
        } else {
            self.blocks[i] = Some(b);
        }
    }

    /// 查看第 `i` 条尚未消费的完成记录（不消费；配合 [`consume`](Self::consume) 实现「复制成功才消费」）。
    pub fn peek(&self, i: usize) -> Option<Completion> {
        self.cq.iter().nth(i).copied()
    }

    /// 消费最早的 `n` 条完成记录（C）：每条归还 1 份信用。返回实际消费数。
    pub fn consume(&mut self, n: usize) -> usize {
        let mut k = 0;
        while k < n && self.cq.pop().is_some() {
            k += 1;
        }
        self.stats.consumed += k as u64;
        k
    }

    /// 进入 closing（Ring 有效外部所有权归零或所属进程 exiting）。
    ///
    /// * 拒绝此后的一切提交；已发布未消费的记录全部丢弃（信用随之释放）
    /// * 排队中的请求裁决为 `cancelled` 并立即收尾
    /// * 可中止地执行中的请求裁决为 `cancelled`：对每个这样的请求调用 `abort(上下文, 请求 ID)`，
    ///   调用者通知后端中止，后端静止后调用 [`quiesce`](Self::quiesce)
    /// * 不可中止的请求继续到自然结束（裁决仍只一次，完成被丢弃）
    ///
    /// 内核强制取消走这条控制路径，不需要任何完成槽位。返回此刻被裁决为取消的请求数。
    pub fn close(&mut self, mut abort: impl FnMut(u64, u64)) -> usize {
        if self.closing {
            return 0;
        }
        self.closing = true;
        let dropped = self.cq.len();
        while self.cq.pop().is_some() {}
        self.stats.dropped += dropped as u64;
        let mut cancelled = 0;
        for i in 0..N {
            let Some(b) = self.blocks[i].as_mut() else { continue };
            if b.decided.is_none() {
                match b.phase {
                    Phase::Queued => {
                        b.decided = Some(Terminal::Cancelled);
                        cancelled += 1;
                    }
                    Phase::Running(Exec::Abortable) => {
                        b.decided = Some(Terminal::Cancelled);
                        cancelled += 1;
                        abort(b.sub.context, b.id);
                    }
                    Phase::Running(Exec::NonAbortable) => {}
                }
            }
            self.advance(i);
        }
        cancelled
    }

    /// 取出一个已销毁控制块的上下文（调用者据此释放请求持有的对象引用）。
    pub fn take_reclaimed(&mut self) -> Option<u64> {
        self.reclaimed.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = AsyncRing<8, 16>;

    fn sub(tag: u64) -> Submission {
        Submission { op: 12, user_tag: tag, context: 100 + tag, uses_buffer: false }
    }

    fn buf_sub(tag: u64) -> Submission {
        Submission { op: 12, user_tag: tag, context: 100 + tag, uses_buffer: true }
    }

    fn snapshot(r: &R) -> (usize, usize, usize, usize, u64) {
        (r.credits(), r.reserved(), r.ready(), r.in_flight(), r.next_id())
    }

    #[test]
    fn ids_are_monotonic_and_tags_never_match() {
        let mut r = R::new(4).unwrap();
        let a = r.submit(sub(7)).unwrap();
        let b = r.submit(sub(7)).unwrap();
        let c = r.submit(sub(7)).unwrap();
        assert!(a < b && b < c, "请求 ID 单调递增");
        // 三个请求同一标签：取消只按 ID 匹配
        assert_eq!(r.cancel(b), Ok(Cancelled::NotStarted));
        assert_eq!(r.peek(0).map(|x| (x.request_id, x.user_tag, x.terminal)), Some((b, 7, Terminal::Cancelled)));
        assert_eq!(r.in_flight(), 2, "其余两个同标签请求不受影响");
        // ID 永不复用：消费、销毁后新 ID 仍大于旧 ID
        r.consume(1);
        assert!(r.submit(sub(7)).unwrap() > c);
    }

    #[test]
    fn credits_exhausted_rejects_atomically_and_sync_cancel_still_works() {
        let mut r = R::new(2).unwrap();
        let a = r.submit(sub(1)).unwrap();
        r.start(a, Exec::Abortable).unwrap();
        let b = r.submit(sub(2)).unwrap();
        let before = (snapshot(&r), r.stats().accepted);
        assert_eq!(r.submit(sub(3)), Err(SubmitError::CqFull));
        assert_eq!((snapshot(&r), r.stats().accepted), before, "拒绝路径不改任何计数（不分配 ID、不扣信用、不建控制块）");
        // 信用耗尽时同步取消仍可用
        assert_eq!(r.cancel(a), Ok(Cancelled::AbortBackend { context: 101 }));
        assert_eq!(r.cancel(b), Ok(Cancelled::NotStarted));
        // 已发布未消费仍占信用
        assert_eq!(r.credits(), 0);
        assert_eq!(r.submit(sub(3)), Err(SubmitError::CqFull), "信用只在消费时归还");
        assert_eq!(r.consume(1), 1);
        assert_eq!(r.credits(), 1);
        assert!(r.submit(sub(3)).is_ok());
    }

    #[test]
    fn published_before_destroy_holds_one_credit_and_quota_outlives_credit() {
        // 不访问缓冲区的可中止请求：取消后 D → P 立即发生，X 等后端静止
        let mut r = R::new(4).unwrap();
        let a = r.submit(sub(1)).unwrap();
        r.start(a, Exec::Abortable).unwrap();
        assert_eq!(r.credits(), 3);
        r.cancel(a).unwrap();
        assert_eq!((r.ready(), r.reserved(), r.credits(), r.in_flight()), (1, 0, 3, 1), "P 之后、X 之前只占一份信用");
        r.consume(1);
        assert_eq!((r.credits(), r.in_flight()), (4, 1), "消费后信用归还，但控制块未 X，在飞配额仍占用");
        assert_eq!(r.take_reclaimed(), None);
        r.quiesce(a).unwrap();
        assert_eq!((r.in_flight(), r.take_reclaimed()), (0, Some(101)), "后端静止后 X，上下文进入回收");
        // 已 X 的重复报告被拒
        assert_eq!(r.quiesce(a), Err(ProgressError::NoSuchRequest));
    }

    #[test]
    fn buffer_request_completion_waits_for_quiesce() {
        let mut r = R::new(4).unwrap();
        let a = r.submit(buf_sub(1)).unwrap();
        r.start(a, Exec::Abortable).unwrap();
        r.cancel(a).unwrap();
        assert_eq!((r.ready(), r.decided_unpublished()), (0, 1), "访问缓冲区：静止前完成不可见");
        assert_eq!(r.cancel(a), Err(CancelError::AlreadyCompleted), "已裁决未发布 ⇒ already_completed");
        // 后端与取消竞争地自然结束：终态仍是先裁决的取消（D 只一次）
        assert_eq!(r.finish(a, 5), Ok(Terminal::Cancelled));
        assert_eq!(r.peek(0).map(|c| c.terminal), Some(Terminal::Cancelled));
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn cancel_results_follow_state_table() {
        let mut r = R::new(4).unwrap();
        let q = r.submit(sub(1)).unwrap();
        let ab = r.submit(sub(2)).unwrap();
        let na = r.submit(sub(3)).unwrap();
        r.start(ab, Exec::Abortable).unwrap();
        r.start(na, Exec::NonAbortable).unwrap();
        assert_eq!(r.cancel(q), Ok(Cancelled::NotStarted));
        assert_eq!(r.cancel(ab), Ok(Cancelled::AbortBackend { context: 102 }));
        assert_eq!(r.cancel(na), Err(CancelError::InProgress));
        assert_eq!(r.finish(na, 9), Ok(Terminal::Done(9)), "不可中止请求按实际结果结束");
        assert_eq!(r.cancel(na), Err(CancelError::AlreadyCompleted));
        assert_eq!(r.cancel(9999), Err(CancelError::NotFound), "从未存在");
        assert_eq!(CancelError::InProgress.name(), "system.async.error.in_progress");
    }

    #[test]
    fn history_window_evicts_fifo() {
        let mut r = R::new(2).unwrap();
        let mut ids = [0u64; 3];
        for (k, id) in ids.iter_mut().enumerate() {
            *id = r.submit(sub(k as u64)).unwrap();
            r.start(*id, Exec::NonAbortable).unwrap();
            r.finish(*id, 0).unwrap();
            r.consume(1);
        }
        assert_eq!(r.cancel(ids[0]), Err(CancelError::NotFound), "窗口只保留最近 C 个，最早的被淘汰");
        assert_eq!(r.cancel(ids[1]), Err(CancelError::AlreadyCompleted));
        assert_eq!(r.cancel(ids[2]), Err(CancelError::AlreadyCompleted), "窗口与是否已消费无关");
    }

    #[test]
    fn id_exhaustion_never_wraps() {
        let mut r = R::new(4).unwrap();
        r.limit_ids(2);
        assert_eq!(r.submit(sub(1)), Ok(1));
        assert_eq!(r.submit(sub(2)), Ok(2));
        let before = snapshot(&r);
        assert_eq!(r.submit(sub(3)), Err(SubmitError::IdExhausted));
        assert_eq!(snapshot(&r), before, "ID 耗尽拒绝无副作用");
        r.cancel(1).unwrap();
        r.consume(1);
        assert_eq!(r.submit(sub(3)), Err(SubmitError::IdExhausted), "释放后也不回绕");
    }

    #[test]
    fn closing_finishes_each_kind_and_drops_completions() {
        let mut r = R::new(4).unwrap();
        let queued = r.submit(sub(1)).unwrap();
        let ab = r.submit(buf_sub(2)).unwrap();
        let na = r.submit(sub(3)).unwrap();
        let done = r.submit(sub(4)).unwrap();
        r.start(ab, Exec::Abortable).unwrap();
        r.start(na, Exec::NonAbortable).unwrap();
        r.start(done, Exec::NonAbortable).unwrap();
        r.finish(done, 1).unwrap(); // 已发布、未消费
        let _ = queued;
        let mut aborted = [0u64; 4];
        let mut n = 0;
        let cancelled = r.close(|ctx, id| {
            aborted[n] = ctx * 1000 + id;
            n += 1;
        });
        assert_eq!(cancelled, 2, "排队中的与可中止的立即裁决为取消");
        assert_eq!(&aborted[..n], &[102 * 1000 + ab], "只对可中止的执行中请求要求后端中止");
        assert_eq!(r.ready(), 0, "closing 丢弃全部完成记录");
        assert_eq!(r.submit(sub(5)), Err(SubmitError::Closing));
        assert_eq!(r.in_flight(), 2, "可中止的等后端静止，不可中止的继续执行");
        assert!(!r.is_drained());
        r.quiesce(ab).unwrap();
        assert_eq!(r.finish(na, 7), Ok(Terminal::Done(7)), "不可中止请求自然结束，裁决仍只一次");
        assert!(r.is_drained(), "全部控制块 X 后收尾完成");
        assert_eq!((r.reserved(), r.credits()), (0, 4));
        let mut reclaimed = 0;
        while r.take_reclaimed().is_some() {
            reclaimed += 1;
        }
        assert_eq!(reclaimed, 4, "每个请求的上下文恰好回收一次");
        let s = r.stats();
        assert_eq!((s.accepted, s.published, s.dropped, s.destroyed), (4, 1, 4, 4));
    }

    #[test]
    fn decision_reports_undecided_then_terminal() {
        let mut r = R::new(4).unwrap();
        let a = r.submit(buf_sub(1)).unwrap();
        assert_eq!(r.decision(a), Some(None));
        r.start(a, Exec::Abortable).unwrap();
        r.cancel(a).unwrap();
        assert_eq!(r.decision(a), Some(Some(Terminal::Cancelled)), "已裁决、尚未静止：控制块仍在");
        r.quiesce(a).unwrap();
        assert_eq!(r.decision(a), None, "销毁后查不到");
        assert_eq!(r.decision(999), None);
    }

    #[test]
    fn capacity_bounds_and_interface_names() {
        assert!(R::new(0).is_none() && R::new(9).is_none() && R::new(8).is_some());
        assert!(RING_INTERFACE.iter().all(|m| m.name.starts_with("system.async.")));
        assert_eq!(SubmitError::CqFull.name(), "system.async.error.cq_full");
    }
}
