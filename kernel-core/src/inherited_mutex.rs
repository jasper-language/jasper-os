//! Pure ownership state for a priority-inheriting mutex.
//!
//! Wait-graph mutation remains a scheduler responsibility. This state decides
//! only whether a caller acquires, waits, is recursive, or observes closure,
//! and whether an existing ownership reference is transferred or a new one is
//! required.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim<T> {
    Acquired { reused_owner_ref: bool },
    WaitFor(T),
    Recursive,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseError { Closed, NotOwner }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State<T> {
    owner: Option<T>,
    closed: bool,
}

impl<T: Copy + Eq> State<T> {
    pub const fn new() -> Self { Self { owner: None, closed: false } }
    pub const fn owner(&self) -> Option<T> { self.owner }
    pub const fn is_closed(&self) -> bool { self.closed }

    pub fn claim(&mut self, caller: T, owner_live: bool) -> Claim<T> {
        if self.closed { return Claim::Closed; }
        match self.owner {
            None => {
                self.owner = Some(caller);
                Claim::Acquired { reused_owner_ref: false }
            }
            Some(owner) if owner == caller => Claim::Recursive,
            Some(_) if !owner_live => {
                self.owner = Some(caller);
                Claim::Acquired { reused_owner_ref: true }
            }
            Some(owner) => Claim::WaitFor(owner),
        }
    }

    pub fn release(&mut self, caller: T, successor: Option<T>) -> Result<bool, ReleaseError> {
        if self.closed { return Err(ReleaseError::Closed); }
        if self.owner != Some(caller) { return Err(ReleaseError::NotOwner); }
        self.owner = successor;
        Ok(successor.is_none()) // true => caller releases the ownership reference
    }

    /// Marks the object terminal and returns the former owner, whose ownership
    /// reference must be released by the caller.
    pub fn close(&mut self) -> Option<T> {
        if self.closed { return None; }
        self.closed = true;
        self.owner.take()
    }
}

impl<T: Copy + Eq> Default for State<T> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_wait_handoff_close() {
        let mut s = State::new();
        assert_eq!(s.claim(1, false), Claim::Acquired { reused_owner_ref: false });
        assert_eq!(s.claim(2, true), Claim::WaitFor(1));
        assert_eq!(s.release(1, Some(2)), Ok(false));
        assert_eq!(s.owner(), Some(2));
        assert_eq!(s.close(), Some(2));
        assert_eq!(s.claim(1, false), Claim::Closed);
    }

    #[test]
    fn stale_transfer_and_refusals_are_atomic() {
        let mut s = State::new();
        assert_eq!(s.claim(7, false), Claim::Acquired { reused_owner_ref: false });
        let before = s;
        assert_eq!(s.claim(7, true), Claim::Recursive);
        assert_eq!(s, before);
        assert_eq!(s.release(9, None), Err(ReleaseError::NotOwner));
        assert_eq!(s, before);
        assert_eq!(s.claim(8, false), Claim::Acquired { reused_owner_ref: true });
        assert_eq!(s.owner(), Some(8));
    }
}
