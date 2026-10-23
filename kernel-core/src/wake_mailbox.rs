//! Author: chatgpt. Bounded FIFO of generation-tagged wakes. Caller serializes
//! producers/consumer; this is not a lock-free queue. Full means caller must
//! apply synchronously or retry, never overwrite/drop the requested wake.
use crate::task_index::Token;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueue { Queued, Coalesced, Full }
pub struct WakeMailbox<const N: usize> { entries: [Option<Token>; N], head: usize, len: usize }
impl<const N: usize> WakeMailbox<N> {
    pub const fn new() -> Self { Self { entries: [None; N], head: 0, len: 0 } }
    pub fn len(&self) -> usize { self.len }
    pub fn push(&mut self, token: Token) -> Enqueue {
        for i in 0..self.len {
            if self.entries[(self.head + i) % N] == Some(token) { return Enqueue::Coalesced; }
        }
        if self.len == N { return Enqueue::Full; }
        self.entries[(self.head + self.len) % N] = Some(token);
        self.len += 1;
        Enqueue::Queued
    }
    pub fn pop(&mut self) -> Option<Token> {
        if self.len == 0 { return None; }
        let t = self.entries[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        t
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn t(n: u64) -> Token { Token { slot: 1, generation: n } }
    #[test]
    fn full_is_not_overwrite_and_generations_do_not_coalesce() {
        let mut q = WakeMailbox::<2>::new();
        assert_eq!(q.push(t(1)), Enqueue::Queued);
        assert_eq!(q.push(t(1)), Enqueue::Coalesced);
        assert_eq!(q.push(t(2)), Enqueue::Queued);
        assert_eq!(q.push(t(3)), Enqueue::Full);
        assert_eq!(q.pop(), Some(t(1)));
        assert_eq!(q.push(t(3)), Enqueue::Queued);
        assert_eq!(q.pop(), Some(t(2)));
        assert_eq!(q.pop(), Some(t(3)));
        assert_eq!(q.pop(), None);
        let mut empty = WakeMailbox::<0>::new();
        assert_eq!(empty.push(t(1)), Enqueue::Full);
        assert_eq!(empty.pop(), None);
    }
    #[derive(Clone, Copy, Debug)]
    enum Op { Push(u64), Pop }
    fn replay(ops: &[Op]) -> Result<(), &'static str> {
        let mut q = WakeMailbox::<3>::new();
        let mut reference = std::collections::VecDeque::new();
        for op in ops {
            match *op {
                Op::Push(generation) => {
                    let token = t(generation);
                    let expected = if reference.contains(&token) { Enqueue::Coalesced }
                        else if reference.len() == 3 { Enqueue::Full } else { reference.push_back(token); Enqueue::Queued };
                    if q.push(token) != expected { return Err("enqueue result"); }
                }
                Op::Pop => if q.pop() != reference.pop_front() { return Err("FIFO value"); },
            }
            if q.len() != reference.len() { return Err("length"); }
        }
        while let Some(expected) = reference.pop_front() {
            if q.pop() != Some(expected) { return Err("final drain"); }
        }
        if q.pop().is_some() { return Err("extra entry"); }
        Ok(())
    }
    #[test]
    fn repeated_fifo_wrap_matches_reference() {
        const SEED: u64 = 0x57414b454d534731;
        let mut seed = SEED;
        let mut ops = std::vec::Vec::new();
        for _ in 0..20_000 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            ops.push(if seed & 1 == 0 { Op::Push(seed % 8) } else { Op::Pop });
        }
        if let Err(error) = replay(&ops) {
            let mut chunk = ops.len() / 2;
            while chunk > 0 {
                let mut start = 0;
                while start < ops.len() {
                    let mut candidate = ops.clone();
                    candidate.drain(start..(start+chunk).min(candidate.len()));
                    if replay(&candidate).is_err() { ops = candidate; } else { start += chunk; }
                }
                chunk /= 2;
            }
            panic!("seed={SEED:#x}, {error}, reduced={ops:?}");
        }
    }
}
