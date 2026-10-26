//! Generation-bound storage for scheduler task hot state.
//!
//! The outer kernel supplies one lock per slot.  This type prevents a delayed
//! wake, PI, or migration command for an old task generation from reading or
//! mutating the task that later reuses the same slot.

use crate::task_index::Token;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    WrongSlot,
    Stale,
    Empty,
    Occupied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot<T> {
    slot: usize,
    generation: u64,
    value: Option<T>,
}

impl<T> Slot<T> {
    pub const fn empty(slot: usize) -> Self {
        Self {
            slot,
            generation: 0,
            value: None,
        }
    }

    pub const fn occupied(&self) -> bool {
        self.value.is_some()
    }

    /// Constructs the one boot-time occupant of a slot. Runtime publication
    /// must use [`Slot::publish`] so reuse still requires an empty slot.
    pub const fn initial(slot: usize, generation: u64, value: T) -> Self {
        Self {
            slot,
            generation,
            value: Some(value),
        }
    }

    pub const fn generation(&self) -> Option<u64> {
        if self.value.is_some() {
            Some(self.generation)
        } else {
            None
        }
    }

    pub fn publish(&mut self, token: Token, value: T) -> Result<(), Error> {
        if token.slot != self.slot {
            return Err(Error::WrongSlot);
        }
        if self.value.is_some() {
            return Err(Error::Occupied);
        }
        self.generation = token.generation;
        self.value = Some(value);
        Ok(())
    }

    pub fn get(&self, token: Token) -> Result<&T, Error> {
        self.check(token)?;
        self.value.as_ref().ok_or(Error::Empty)
    }

    pub fn get_mut(&mut self, token: Token) -> Result<&mut T, Error> {
        self.check(token)?;
        self.value.as_mut().ok_or(Error::Empty)
    }

    pub fn retire(&mut self, token: Token) -> Result<T, Error> {
        self.check(token)?;
        self.value.take().ok_or(Error::Empty)
    }

    fn check(&self, token: Token) -> Result<(), Error> {
        if token.slot != self.slot {
            return Err(Error::WrongSlot);
        }
        if self.value.is_none() {
            return Err(Error::Empty);
        }
        if token.generation != self.generation {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn stale_generation_cannot_mutate_reused_slot() {
        let old_generation: u64 = kani::any();
        let old = Token {
            slot: 3,
            generation: old_generation,
        };
        let new = Token {
            slot: 3,
            generation: old_generation.wrapping_add(1),
        };
        let mut slot = Slot::empty(3);
        assert_eq!(slot.publish(old, 7u32), Ok(()));
        assert_eq!(slot.retire(old), Ok(7));
        assert_eq!(slot.publish(new, 11), Ok(()));
        assert!(matches!(slot.get_mut(old), Err(Error::Stale)));
        assert_eq!(slot.get(new), Ok(&11));
    }

    #[kani::proof]
    fn wrong_slot_never_changes_owner() {
        let generation: u64 = kani::any();
        let owner = Token {
            slot: 1,
            generation,
        };
        let wrong = Token {
            slot: 2,
            generation,
        };
        let mut slot = Slot::empty(1);
        assert_eq!(slot.publish(owner, 9u8), Ok(()));
        assert_eq!(slot.retire(wrong), Err(Error::WrongSlot));
        assert_eq!(slot.get(owner), Ok(&9));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_requires_exact_identity() {
        let boot_token = Token {
            slot: 0,
            generation: 1,
        };
        let mut boot = Slot::initial(0, 1, 99u32);
        assert_eq!(boot.get(boot_token), Ok(&99));
        assert_eq!(boot.retire(boot_token), Ok(99));

        let first = Token {
            slot: 4,
            generation: 8,
        };
        let next = Token {
            slot: 4,
            generation: 9,
        };
        let other = Token {
            slot: 5,
            generation: 8,
        };
        let mut slot = Slot::empty(4);

        assert_eq!(slot.get(first), Err(Error::Empty));
        assert_eq!(slot.publish(other, 1u32), Err(Error::WrongSlot));
        assert_eq!(slot.publish(first, 2), Ok(()));
        assert_eq!(slot.publish(first, 3), Err(Error::Occupied));
        *slot.get_mut(first).unwrap() = 4;
        assert_eq!(slot.get(first), Ok(&4));
        assert_eq!(slot.get(next), Err(Error::Stale));
        assert_eq!(slot.retire(next), Err(Error::Stale));
        assert_eq!(slot.retire(first), Ok(4));
        assert_eq!(slot.publish(next, 5), Ok(()));
        assert_eq!(slot.get(first), Err(Error::Stale));
        assert_eq!(slot.get(next), Ok(&5));
    }
}
