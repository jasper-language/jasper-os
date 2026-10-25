//! SHM-1 mapping admission and page-reference quota contracts. Author: chatgpt.
//! Pure preflight: errors never mutate usage; actual page tables and references are kernel-owned.
use crate::object::Rights;

pub const PAGE_BYTES: u64 = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Range, Rights, Quota, Accounting }

/// Validated subrange of an object; no executable shared mappings in SHM-1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapRange { pub offset_pages: u64, pub pages: u64, pub va: u64, pub end: u64 }
impl MapRange {
    pub fn checked(object_pages: u64, offset_pages: u64, pages: u64, va: u64,
                   window: (u64, u64), max_pages: u64, have: Rights, writable: bool) -> Result<Self, Error> {
        let need = Rights::READ.union(Rights::MAP).union(if writable { Rights::WRITE } else { Rights::NONE });
        if !have.contains(need) { return Err(Error::Rights); }
        if pages == 0 || pages > max_pages || va % PAGE_BYTES != 0 || va < window.0 {
            return Err(Error::Range);
        }
        if offset_pages.checked_add(pages).filter(|&end| end <= object_pages).is_none() { return Err(Error::Range); }
        let end = pages.checked_mul(PAGE_BYTES).and_then(|n| va.checked_add(n)).ok_or(Error::Range)?;
        if end > window.1 { return Err(Error::Range); }
        Ok(Self { offset_pages, pages, va, end })
    }
}

/// Per-process page-reference charges. Repeated aliases/pins each cost their own references.
/// Backing ownership is charged separately and must survive handle transfer/creator exit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage { pub mapped: u64, pub pinned: u64 }
impl Usage {
    pub fn reserve(&mut self, mapped: u64, pinned: u64, limits: Self) -> Result<(), Error> {
        let next_mapped = self.mapped.checked_add(mapped).filter(|&v| v <= limits.mapped).ok_or(Error::Quota)?;
        let next_pinned = self.pinned.checked_add(pinned).filter(|&v| v <= limits.pinned).ok_or(Error::Quota)?;
        *self = Self { mapped: next_mapped, pinned: next_pinned };
        Ok(())
    }
    pub fn release(&mut self, mapped: u64, pinned: u64) -> Result<(), Error> {
        let next_mapped = self.mapped.checked_sub(mapped).ok_or(Error::Accounting)?;
        let next_pinned = self.pinned.checked_sub(pinned).ok_or(Error::Accounting)?;
        *self = Self { mapped: next_mapped, pinned: next_pinned };
        Ok(())
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn shm_usage_reserve_is_atomic_and_reversible() {
        let before = Usage { mapped: kani::any(), pinned: kani::any() };
        let m: u64 = kani::any(); let p: u64 = kani::any();
        let limits = Usage { mapped: kani::any(), pinned: kani::any() };
        let mut after = before;
        match after.reserve(m, p, limits) {
            Ok(()) => {
                assert_eq!(before.mapped.checked_add(m), Some(after.mapped));
                assert_eq!(before.pinned.checked_add(p), Some(after.pinned));
                assert!(after.mapped <= limits.mapped && after.pinned <= limits.pinned);
                assert_eq!(after.release(m, p), Ok(())); assert_eq!(after, before);
            }
            Err(e) => { assert_eq!(e, Error::Quota); assert_eq!(after, before);
                assert!(before.mapped.checked_add(m).filter(|v| *v <= limits.mapped).is_none()
                    || before.pinned.checked_add(p).filter(|v| *v <= limits.pinned).is_none()); }
        }
    }
}
