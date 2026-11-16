//! Runtime-capacity async-ring state machine for the production kernel.
//!
//! The ABI-only `AsyncRing<C, N>` remains allocation-free for user-side checks
//! and Kani. The kernel uses this heap-backed state machine so completion,
//! control-block and history capacities come from the ring creation request
//! and admitted resource budget instead of a compiled shape.
//! 生产内核使用运行时容量的异步环状态机；ABI-only 的固定形状实现继续供
//! 无分配器用户侧检查和 Kani 使用。

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::async_ring::{
    Cancelled, CancelError, Completion, Exec, ProgressError, RingStats, Submission, SubmitError,
    Terminal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    Running(Exec),
}

#[derive(Debug, Clone, Copy)]
struct Block {
    id: u64,
    sub: Submission,
    phase: Phase,
    decided: Option<Terminal>,
    quiesced: bool,
    published: bool,
    dropped: bool,
}

/// Allocation-backed async-ring state machine.
/// 堆后备、容量由创建请求决定的异步环状态机。
pub struct RuntimeAsyncRing {
    capacity: usize,
    blocks_capacity: usize,
    cq: VecDeque<Completion>,
    window: VecDeque<(u64, Terminal)>,
    blocks: Vec<Option<Block>>,
    reserved: usize,
    next_id: u64,
    id_limit: u64,
    closing: bool,
    reclaimed: VecDeque<u64>,
    stats: RingStats,
}

impl RuntimeAsyncRing {
    /// Allocate every runtime table before publishing the ring. Any allocation
    /// failure returns `None` without a partially initialized state machine.
    /// 发布环之前完成全部运行时表分配；任一失败都不留下部分初始化状态。
    pub fn new(capacity: usize, blocks_capacity: usize) -> Option<Self> {
        if capacity == 0 || blocks_capacity == 0 || capacity > blocks_capacity {
            return None;
        }

        let mut cq = VecDeque::new();
        cq.try_reserve_exact(capacity).ok()?;
        let mut window = VecDeque::new();
        window.try_reserve_exact(capacity).ok()?;
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(blocks_capacity).ok()?;
        blocks.resize_with(blocks_capacity, || None);
        let mut reclaimed = VecDeque::new();
        reclaimed.try_reserve_exact(blocks_capacity).ok()?;

        Some(Self {
            capacity,
            blocks_capacity,
            cq,
            window,
            blocks,
            reserved: 0,
            next_id: 1,
            id_limit: u64::MAX,
            closing: false,
            reclaimed,
            stats: RingStats::default(),
        })
    }

    /// Lower the last assignable request ID; never raises it.
    pub fn limit_ids(&mut self, last_id: u64) {
        self.id_limit = self.id_limit.min(last_id);
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn blocks_capacity(&self) -> usize {
        self.blocks_capacity
    }

    pub fn credits(&self) -> usize {
        self.capacity - self.reserved - self.cq.len()
    }

    pub fn reserved(&self) -> usize {
        self.reserved
    }

    pub fn ready(&self) -> usize {
        self.cq.len()
    }

    pub fn in_flight(&self) -> usize {
        self.blocks.iter().filter(|block| block.is_some()).count()
    }

    pub fn decided_unpublished(&self) -> usize {
        self.blocks
            .iter()
            .flatten()
            .filter(|block| block.decided.is_some() && !block.published)
            .count()
    }

    pub fn is_closing(&self) -> bool {
        self.closing
    }

    pub fn is_drained(&self) -> bool {
        self.closing && self.in_flight() == 0
    }

    pub fn stats(&self) -> RingStats {
        self.stats
    }

    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    fn slot_of(&self, id: u64) -> Option<usize> {
        self.blocks
            .iter()
            .position(|block| matches!(block, Some(block) if block.id == id))
    }

    pub fn submit(&mut self, sub: Submission) -> Result<u64, SubmitError> {
        let slot = match self.check_submit() {
            Ok(slot) => slot,
            Err(error) => {
                self.stats.rejected += 1;
                return Err(error);
            }
        };
        let id = self.next_id;
        self.next_id += 1;
        self.reserved += 1;
        self.blocks[slot] = Some(Block {
            id,
            sub,
            phase: Phase::Queued,
            decided: None,
            quiesced: true,
            published: false,
            dropped: false,
        });
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
        self.blocks
            .iter()
            .position(Option::is_none)
            .ok_or(SubmitError::QuotaExceeded)
    }

    pub fn decision(&self, id: u64) -> Option<Option<Terminal>> {
        self.slot_of(id)
            .and_then(|slot| self.blocks[slot].as_ref())
            .map(|block| block.decided)
    }

    pub fn start(&mut self, id: u64, exec: Exec) -> Result<(), ProgressError> {
        let slot = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(ProgressError::NoSuchRequest)?;
        if block.phase != Phase::Queued || block.decided.is_some() {
            return Err(ProgressError::NoSuchRequest);
        }
        block.phase = Phase::Running(exec);
        block.quiesced = false;
        Ok(())
    }

    pub fn finish(&mut self, id: u64, value: i64) -> Result<Terminal, ProgressError> {
        let slot = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(ProgressError::NoSuchRequest)?;
        if !matches!(block.phase, Phase::Running(_)) || block.quiesced {
            return Err(ProgressError::NoSuchRequest);
        }
        let terminal = *block.decided.get_or_insert(Terminal::Done(value));
        block.quiesced = true;
        self.advance(slot);
        Ok(terminal)
    }

    pub fn quiesce(&mut self, id: u64) -> Result<(), ProgressError> {
        let slot = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(ProgressError::NoSuchRequest)?;
        if block.decided.is_none() || block.quiesced {
            return Err(ProgressError::NoSuchRequest);
        }
        block.quiesced = true;
        self.advance(slot);
        Ok(())
    }

    pub fn cancel(&mut self, id: u64) -> Result<Cancelled, CancelError> {
        let Some(slot) = self.slot_of(id) else {
            return if self.window.iter().any(|(request_id, _)| *request_id == id) {
                Err(CancelError::AlreadyCompleted)
            } else {
                Err(CancelError::NotFound)
            };
        };
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(CancelError::NotFound)?;
        if block.decided.is_some() {
            return Err(CancelError::AlreadyCompleted);
        }
        let cancelled = match block.phase {
            Phase::Queued => Cancelled::NotStarted,
            Phase::Running(Exec::Abortable) => {
                Cancelled::AbortBackend { context: block.sub.context }
            }
            Phase::Running(Exec::NonAbortable) => return Err(CancelError::InProgress),
        };
        block.decided = Some(Terminal::Cancelled);
        self.advance(slot);
        Ok(cancelled)
    }

    fn advance(&mut self, slot: usize) {
        let Some(mut block) = self.blocks[slot] else {
            return;
        };
        if let Some(terminal) = block.decided {
            if !block.published && (block.quiesced || !block.sub.uses_buffer) {
                block.published = true;
                self.reserved -= 1;
                if self.closing {
                    block.dropped = true;
                    self.stats.dropped += 1;
                } else {
                    self.cq.push_back(Completion {
                        request_id: block.id,
                        user_tag: block.sub.user_tag,
                        op: block.sub.op,
                        terminal,
                    });
                    if self.window.len() == self.capacity {
                        self.window.pop_front();
                    }
                    self.window.push_back((block.id, terminal));
                    self.stats.published += 1;
                }
            }
        }
        if block.quiesced && (block.published || block.dropped) {
            self.blocks[slot] = None;
            self.reclaimed.push_back(block.sub.context);
            self.stats.destroyed += 1;
        } else {
            self.blocks[slot] = Some(block);
        }
    }

    pub fn peek(&self, index: usize) -> Option<Completion> {
        self.cq.iter().nth(index).copied()
    }

    pub fn consume(&mut self, count: usize) -> usize {
        let mut consumed = 0;
        while consumed < count && self.cq.pop_front().is_some() {
            consumed += 1;
        }
        self.stats.consumed += consumed as u64;
        consumed
    }

    pub fn close(&mut self, mut abort: impl FnMut(u64, u64)) -> usize {
        if self.closing {
            return 0;
        }
        self.closing = true;
        let dropped = self.cq.len();
        self.cq.clear();
        self.stats.dropped += dropped as u64;

        let mut cancelled = 0;
        for slot in 0..self.blocks.len() {
            let Some(block) = self.blocks[slot].as_mut() else {
                continue;
            };
            if block.decided.is_none() {
                match block.phase {
                    Phase::Queued => {
                        block.decided = Some(Terminal::Cancelled);
                        cancelled += 1;
                    }
                    Phase::Running(Exec::Abortable) => {
                        block.decided = Some(Terminal::Cancelled);
                        cancelled += 1;
                        abort(block.sub.context, block.id);
                    }
                    Phase::Running(Exec::NonAbortable) => {}
                }
            }
            self.advance(slot);
        }
        cancelled
    }

    pub fn take_reclaimed(&mut self) -> Option<u64> {
        self.reclaimed.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submission(tag: u64) -> Submission {
        Submission {
            op: 1,
            user_tag: tag,
            context: 100 + tag,
            uses_buffer: false,
        }
    }

    #[test]
    fn runtime_capacity_grows_past_previous_sixty_four_envelope() {
        let mut ring = RuntimeAsyncRing::new(128, 128).unwrap();
        for tag in 0..128 {
            ring.submit(submission(tag)).unwrap();
        }
        assert_eq!(ring.in_flight(), 128);
        assert_eq!(ring.credits(), 0);
        assert_eq!(ring.close(|_, _| {}), 128);
        assert!(ring.is_drained());
        assert_eq!(ring.reclaimed.len(), 128);
    }

    #[test]
    fn capacity_rejection_is_failure_atomic() {
        assert!(RuntimeAsyncRing::new(0, 4).is_none());
        assert!(RuntimeAsyncRing::new(5, 4).is_none());

        let mut ring = RuntimeAsyncRing::new(2, 8).unwrap();
        ring.submit(submission(1)).unwrap();
        ring.submit(submission(2)).unwrap();
        let before = (ring.credits(), ring.in_flight(), ring.next_id());
        let stats_before = ring.stats();
        assert_eq!(ring.submit(submission(3)), Err(SubmitError::CqFull));
        assert_eq!((ring.credits(), ring.in_flight(), ring.next_id()), before);
        let stats_after = ring.stats();
        assert_eq!(stats_after.rejected, stats_before.rejected + 1);
        assert_eq!(stats_after.accepted, stats_before.accepted);
        assert_eq!(stats_after.published, stats_before.published);
        assert_eq!(stats_after.consumed, stats_before.consumed);
        assert_eq!(stats_after.dropped, stats_before.dropped);
        assert_eq!(stats_after.destroyed, stats_before.destroyed);
    }
}
