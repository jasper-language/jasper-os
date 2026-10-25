//! 事件等待登记凭据：由外层对象锁与调度器锁串行调用，不自行加锁或切换。
//! Author: chatgpt. 防止旧任务代次、旧等待轮次与重复通知消费新的等待。
use crate::task_index::Token;

/// 一次等待的完整身份；通知方必须携带原凭据，不可只用任务槽号。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key { pub task: Token, pub round: u64 }
/// 登记结果：就绪优先于同一观察点的超时；已有登记不得被覆盖。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enroll { Ready, TimedOut, Busy, Exhausted, Armed(Key) }
/// 单任务的等待登记状态。外层必须原子完成条件检查、登记和调度阻塞。
/// 单独调用本对象不能解决检查到睡眠的竞态，也不提供IPI送达保证。
#[derive(Clone, Copy, Debug)]
pub struct Registration { round: u64, pending: Option<(Key, Option<u64>)> }
impl Registration {
    /// 新任务代次的空登记。复用对象前旧登记须完成清理，任务代次不能复用。
    pub const fn new() -> Self { Self { round: 0, pending: None } }
    /// 在同一临界区检查就绪与绝对截止时刻并登记；失败不改变状态。
    pub fn enroll(&mut self, task: Token, ready: bool, now: u64, deadline: Option<u64>) -> Enroll {
        if self.pending.is_some() { return Enroll::Busy; }
        if ready { return Enroll::Ready; }
        if deadline.is_some_and(|at| now >= at) { return Enroll::TimedOut; }
        let Some(round) = self.round.checked_add(1) else { return Enroll::Exhausted; };
        let key = Key { task, round };
        self.round = round; self.pending = Some((key, deadline));
        Enroll::Armed(key)
    }
    /// 当前登记，只供外层等待队列与清理核对，不会消费。
    pub fn pending(&self) -> Option<Key> { self.pending.map(|(key, _)| key) }
    /// 完成、关闭或取消赢得本轮消费；旧凭据和重复消费均无副作用。
    pub fn finish(&mut self, key: Key) -> bool {
        if self.pending() != Some(key) { return false; }
        self.pending = None; true
    }
    /// 截止时刻已到且凭据仍匹配才消费；无期限的等待不会被周期唤醒。
    pub fn expire(&mut self, key: Key, now: u64) -> bool {
        if !self.pending.is_some_and(|(k, at)| k == key && at.is_some_and(|at| now >= at)) { return false; }
        self.finish(key)
    }
}
impl Default for Registration { fn default() -> Self { Self::new() } }
/// Ring广播等待集合的登记错误；拒绝时原集合保持不变。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetError { Full, DuplicateTask }
/// 有界、无分配的等待集合；不承诺FIFO，只用于全部通知或精确撤销。
/// N由接入层按实际任务容量确定；容量不足必须在阻塞前显式拒绝。
#[derive(Clone, Debug)]
pub struct WaitSet<const N: usize> { entries: [Option<Key>; N], len: usize }
impl<const N: usize> WaitSet<N> {
    /// 空集合，不分配内存。
    pub const fn new() -> Self { Self { entries: [None; N], len: 0 } }
    /// 当前有效登记数。
    pub fn len(&self) -> usize { self.len }
    /// 检查同一任务是否已有登记；旧轮次须先清理，不能覆盖。
    pub fn insert(&mut self, key: Key) -> Result<(), SetError> {
        if self.entries[..self.len].iter().flatten().any(|k| k.task == key.task) { return Err(SetError::DuplicateTask); }
        if self.len == N { return Err(SetError::Full); }
        self.entries[self.len] = Some(key); self.len += 1; Ok(())
    }
    /// 精确撤销；旧轮次不影响当前项。交换末项填洞，不保证顺序。
    pub fn remove(&mut self, key: Key) -> bool {
        let Some(i) = self.entries[..self.len].iter().position(|k| *k == Some(key)) else { return false; };
        self.len -= 1; self.entries.swap(i, self.len); self.entries[self.len] = None; true
    }
    /// 取走末项；重复调用可O(N)排空后广播，不持久保留任何已取走的凭据。
    pub fn pop(&mut self) -> Option<Key> {
        if self.len == 0 { return None; }
        self.len -= 1; self.entries[self.len].take()
    }
}
impl<const N: usize> Default for WaitSet<N> { fn default() -> Self { Self::new() } }
#[cfg(test)]
mod tests {
    use super::*;
    fn token(generation: u64) -> Token { Token { slot: 3, generation } }
    fn arm(r: &mut Registration, task: Token, deadline: Option<u64>) -> Key {
        match r.enroll(task, false, 0, deadline) { Enroll::Armed(k) => k, other => panic!("{other:?}") }
    }
    #[test]
    fn old_generation_round_duplicate_and_busy_are_rejected() {
        let mut r = Registration::new();
        let mut previous = None;
        for i in 0..20_000 {
            let task = token(i / 17 + 1); let key = arm(&mut r, task, None);
            assert_eq!(key.round, i + 1);
            assert_eq!(r.enroll(task, true, 1, Some(0)), Enroll::Busy);
            assert!(!r.finish(Key { task: token(task.generation + 1), ..key }));
            if let Some(old) = previous { assert!(!r.finish(old)); }
            assert!(!r.expire(key, u64::MAX)); assert_eq!(r.pending(), Some(key));
            assert!(r.finish(key)); assert!(!r.finish(key)); previous = Some(key);
        }
    }
    #[test]
    fn deadlines_ready_priority_and_single_terminal_consumer() {
        let mut r = Registration::new(); let task = token(1);
        assert_eq!(r.enroll(task, true, 5, Some(5)), Enroll::Ready);
        assert_eq!(r.enroll(task, false, 5, Some(5)), Enroll::TimedOut);
        assert_eq!(r.pending(), None);
        let k = arm(&mut r, task, Some(5)); assert_eq!(k.round, 1);
        assert!(!r.expire(k, 4)); assert!(r.expire(k, 5)); assert!(!r.finish(k));
        let k = arm(&mut r, task, Some(5)); assert!(r.finish(k)); assert!(!r.expire(k, 5));
    }
    #[test]
    fn round_exhaustion_never_wraps() {
        let mut r = Registration { round: u64::MAX - 1, pending: None };
        let k = arm(&mut r, token(1), None); assert_eq!(k.round, u64::MAX);
        assert!(r.finish(k)); assert_eq!(r.enroll(token(1), false, 0, None), Enroll::Exhausted);
        assert_eq!(r.pending(), None);
    }
}
