//! Author: chatgpt. Fixed-capacity full-u64 label index (compressed binary trie).
//!
//! Every branch consumes a strictly increasing MSB-first bit position. Lookup
//! visits at most 64 branches plus one leaf, independent of task capacity.
//! This is a bounded word-width lookup, not a claim about physical timing.
//! The caller supplies storage and serializes access. Owned slice containers
//! can be moved with the index; borrowed slices are also supported. Slot generations are opaque
//! values: reservation, publication, retirement and validation belong to caller.

const NONE: usize = usize::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub slot: usize,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    Free(usize),
    Leaf { key: u64, token: Token },
    Branch { bit: u32, children: [usize; 2] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError { Duplicate, Full }

/// Storage is retained for the entire index lifetime; no hot-path
/// allocation or unsafe code. N labels need at most 2*N-1 nodes.
pub struct TaskIndex<S> {
    nodes: S,
    root: usize,
    free: usize,
    available: usize,
    len: usize,
}

fn direction(key: u64, bit: u32) -> usize { ((key >> (63 - bit)) & 1) as usize }

impl<S: core::ops::Deref<Target = [Node]> + core::ops::DerefMut> TaskIndex<S> {
    pub fn new(mut nodes: S) -> Self {
        let n = nodes.len();
        for (i, node) in nodes.iter_mut().enumerate() {
            *node = Node::Free(if i + 1 < n { i + 1 } else { NONE });
        }
        Self { nodes, root: NONE, free: if n == 0 { NONE } else { 0 }, available: n, len: 0 }
    }

    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }

    fn leaf(&self, key: u64) -> Option<usize> {
        let mut at = self.root;
        if at == NONE { return None; }
        loop {
            match self.nodes[at] {
                Node::Branch { bit, children } => at = children[direction(key, bit)],
                Node::Leaf { .. } => return Some(at),
                Node::Free(_) => unreachable!("reachable free task index node"),
            }
        }
    }

    pub fn get(&self, key: u64) -> Option<Token> {
        match self.nodes[*self.leaf(key).as_ref()?] {
            Node::Leaf { key: found, token } if found == key => Some(token),
            _ => None,
        }
    }

    fn allocate(&mut self, node: Node) -> usize {
        let at = self.free;
        let Node::Free(next) = self.nodes[at] else { unreachable!() };
        self.free = next;
        self.available -= 1;
        self.nodes[at] = node;
        at
    }

    fn release(&mut self, at: usize) {
        self.nodes[at] = Node::Free(self.free);
        self.free = at;
        self.available += 1;
    }

    /// Duplicate/full failures leave the whole tree and free list unchanged.
    pub fn insert(&mut self, key: u64, token: Token) -> Result<(), InsertError> {
        let Some(leaf) = self.leaf(key) else {
            if self.available == 0 { return Err(InsertError::Full); }
            self.root = self.allocate(Node::Leaf { key, token });
            self.len = 1;
            return Ok(());
        };
        let Node::Leaf { key: old, .. } = self.nodes[leaf] else { unreachable!() };
        if old == key { return Err(InsertError::Duplicate); }
        if self.available < 2 { return Err(InsertError::Full); }
        let bit = (old ^ key).leading_zeros(); // 0..63, since unequal
        let (mut at, mut parent) = (self.root, None);
        while let Node::Branch { bit: here, children } = self.nodes[at] {
            if here >= bit { break; }
            let side = direction(key, here);
            parent = Some((at, side));
            at = children[side];
        }
        let new_leaf = self.allocate(Node::Leaf { key, token });
        let mut children = [at; 2];
        children[direction(key, bit)] = new_leaf;
        let branch = self.allocate(Node::Branch { bit, children });
        if let Some((p, side)) = parent {
            let Node::Branch { ref mut children, .. } = self.nodes[p] else { unreachable!() };
            children[side] = branch;
        } else { self.root = branch; }
        self.len += 1;
        Ok(())
    }

    /// Removing a leaf also removes its parent, so repeated churn cannot
    /// exhaust capacity with unreachable nodes. Missing keys change nothing.
    pub fn remove(&mut self, key: u64) -> Option<Token> {
        if self.root == NONE { return None; }
        let (mut at, mut parent, mut grand) = (self.root, None, None);
        while let Node::Branch { bit, children } = self.nodes[at] {
            grand = parent;
            let side = direction(key, bit);
            parent = Some((at, side));
            at = children[side];
        }
        let Node::Leaf { key: found, token } = self.nodes[at] else { unreachable!() };
        if found != key { return None; }
        if let Some((p, side)) = parent {
            let Node::Branch { children, .. } = self.nodes[p] else { unreachable!() };
            let sibling = children[1 - side];
            if let Some((g, gs)) = grand {
                let Node::Branch { ref mut children, .. } = self.nodes[g] else { unreachable!() };
                children[gs] = sibling;
            } else { self.root = sibling; }
            self.release(p);
        } else { self.root = NONE; }
        self.release(at);
        self.len -= 1;
        Some(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    fn token(n: u64) -> Token { Token { slot: (n % 8) as usize, generation: n } }

    fn audit(index: &TaskIndex<&mut [Node]>) -> Result<(), &'static str> {
        fn walk(i: &TaskIndex<&mut [Node]>, at: usize, prev: Option<u32>, seen: &mut [bool], depth: usize) -> Result<usize, &'static str> {
            if at >= seen.len() || seen[at] || depth > 64 { return Err("cycle/bound"); }
            seen[at] = true;
            match i.nodes[at] {
                Node::Leaf { key, token } => {
                    if i.get(key) != Some(token) { return Err("routing"); }
                    Ok(1)
                }
                Node::Branch { bit, children } => {
                    if bit >= 64 || prev.is_some_and(|b| bit <= b) { return Err("bit order"); }
                    Ok(walk(i, children[0], Some(bit), seen, depth+1)? + walk(i, children[1], Some(bit), seen, depth+1)?)
                }
                _ => Err("reachable free"),
            }
        }
        let mut seen = std::vec![false; index.nodes.len()];
        let leaves = if index.root == NONE { 0 } else { walk(index, index.root, None, &mut seen, 0)? };
        if leaves != index.len { return Err("length"); }
        let mut at = index.free;
        let mut free = 0;
        while at != NONE {
            if at >= seen.len() || seen[at] { return Err("free overlap/cycle"); }
            seen[at] = true;
            let Node::Free(next) = index.nodes[at] else { return Err("free type"); };
            at = next;
            free += 1;
        }
        if free != index.available || seen.iter().any(|b| !b) { return Err("lost storage"); }
        Ok(())
    }

    #[test]
    fn boundaries_and_failure_atomicity() {
        let mut empty = [];
        let mut index = TaskIndex::new(&mut empty[..]);
        assert_eq!(index.insert(0, token(0)), Err(InsertError::Full));
        assert_eq!(index.get(0), None);
        assert_eq!(index.remove(0), None);
        let mut nodes = [Node::Free(NONE); 3];
        let mut i = TaskIndex::new(&mut nodes[..]);
        i.insert(0, token(u64::MAX)).unwrap();
        i.insert(u64::MAX, token(1)).unwrap();
        let before = i.nodes.to_vec();
        assert_eq!(i.insert(0, token(2)), Err(InsertError::Duplicate));
        assert_eq!(i.insert(1, token(3)), Err(InsertError::Full));
        assert_eq!(i.remove(2), None);
        assert_eq!(i.nodes, before.as_slice());
        assert_eq!(i.remove(0), Some(token(u64::MAX)));
        i.insert(1, token(4)).unwrap();
        audit(&i).unwrap();
    }

    #[test]
    fn all_64_branch_positions_and_reuse() {
        let mut nodes = [Node::Free(NONE); 129];
        let mut i = TaskIndex::new(&mut nodes[..]);
        i.insert(0, token(0)).unwrap();
        for bit in 0..64 { i.insert(1u64 << bit, token(bit+1)).unwrap(); }
        audit(&i).unwrap(); // includes an actual depth-64 lookup path
        for bit in (0..64).rev() {
            assert_eq!(i.remove(1u64 << bit), Some(token(bit+1)));
            audit(&i).unwrap();
        }
        assert_eq!(i.remove(0), Some(token(0)));
        assert!(i.is_empty());
        audit(&i).unwrap();
    }

    #[derive(Clone, Copy, Debug)]
    enum Op { Insert(u64, u64), Remove(u64), Get(u64) }

    fn replay(ops: &[Op]) -> Result<(), &'static str> {
        let mut nodes = [Node::Free(NONE); 31]; // 16 labels
        let mut i = TaskIndex::new(&mut nodes[..]);
        let mut reference = BTreeMap::new();
        for op in ops {
            match *op {
                Op::Insert(k, g) => {
                    let expected = if reference.contains_key(&k) { Err(InsertError::Duplicate) }
                        else if reference.len() == 16 { Err(InsertError::Full) } else { Ok(()) };
                    let snapshot = i.nodes.to_vec();
                    if i.insert(k, token(g)) != expected { return Err("insert result"); }
                    if expected.is_ok() { reference.insert(k, token(g)); }
                    else if i.nodes != snapshot.as_slice() { return Err("failure mutation"); }
                }
                Op::Remove(k) => if i.remove(k) != reference.remove(&k) { return Err("remove result"); },
                Op::Get(k) => if i.get(k) != reference.get(&k).copied() { return Err("get result"); },
            }
            if i.len() != reference.len() { return Err("reference length"); }
            for (&k, &v) in &reference { if i.get(k) != Some(v) { return Err("reference value"); } }
            audit(&i)?;
        }
        Ok(())
    }

    #[test]
    fn seeded_reference_campaign_with_deletion_shrink() {
        const SEED: u64 = 0x4b524e3249445831;
        let mut state = SEED;
        let mut ops = Vec::new();
        for step in 0..20_000u64 {
            state ^= state << 13; state ^= state >> 7; state ^= state << 17;
            let label = state % 64;
            let key = match label % 4 { 0 => label / 4, 1 => 1u64 << label,
                2 => u64::MAX - label / 4, _ => label.wrapping_mul(0x9e3779b97f4a7c15) };
            ops.push(match (state >> 8) % 3 { 0 => Op::Insert(key, step), 1 => Op::Remove(key), _ => Op::Get(key) });
        }
        if let Err(error) = replay(&ops) {
            // Delete chunks, then individual operations; preserve a failing
            // executable sequence, rather than merely shrinking input numbers.
            let mut chunk = ops.len().max(1) / 2;
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
