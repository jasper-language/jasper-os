//! Bounded idempotency identity ledger for USI requests.
//!
//! The caller scopes one ledger to one process. Read-only USI v1 operations have no
//! side effects, so a retry with the same request ID and service is safe. Reusing a
//! request ID for another service is a conflict. Future mutating operations must
//! extend completed entries with their durable result instead of only recording the
//! service identity.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begin {
    New(usize),
    Retry,
    Busy,
    Conflict,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pending,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    request_id: u64,
    service: u16,
    state: State,
    order: u64,
}

pub struct Ledger<const N: usize> {
    entries: [Option<Entry>; N],
    order: u64,
}

impl<const N: usize> Ledger<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            order: 0,
        }
    }

    pub fn begin(&mut self, request_id: u64, service: u16) -> Begin {
        for entry in self.entries.iter().flatten() {
            if entry.request_id != request_id {
                continue;
            }
            if entry.service != service {
                return Begin::Conflict;
            }
            return match entry.state {
                State::Pending => Begin::Busy,
                State::Completed => Begin::Retry,
            };
        }

        let free = self.entries.iter().position(Option::is_none);
        let evict = free.or_else(|| {
            self.entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| {
                    let entry = entry.as_ref()?;
                    (entry.state == State::Completed).then_some((index, entry.order))
                })
                .min_by_key(|(_, order)| *order)
                .map(|(index, _)| index)
        });
        let Some(slot) = evict else {
            return Begin::Exhausted;
        };
        self.order = match self.order.checked_add(1) {
            Some(order) => order,
            None => {
                self.entries.fill(None);
                1
            }
        };
        self.entries[slot] = Some(Entry {
            request_id,
            service,
            state: State::Pending,
            order: self.order,
        });
        Begin::New(slot)
    }

    pub fn complete(&mut self, slot: usize, request_id: u64, service: u16) {
        if let Some(entry) = self.entries.get_mut(slot).and_then(Option::as_mut) {
            if entry.request_id == request_id && entry.service == service {
                entry.state = State::Completed;
            }
        }
    }

    pub fn abort(&mut self, slot: usize, request_id: u64, service: u16) {
        if let Some(entry) = self.entries.get_mut(slot).and_then(Option::as_mut) {
            if entry.request_id == request_id
                && entry.service == service
                && entry.state == State::Pending
            {
                self.entries[slot] = None;
            }
        }
    }
}

impl<const N: usize> Default for Ledger<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_conflict_busy_and_abort_are_distinct() {
        let mut ledger = Ledger::<2>::new();
        let Begin::New(slot) = ledger.begin(7, 1) else {
            panic!("first request must be new");
        };
        assert_eq!(ledger.begin(7, 1), Begin::Busy);
        assert_eq!(ledger.begin(7, 2), Begin::Conflict);
        ledger.complete(slot, 7, 1);
        assert_eq!(ledger.begin(7, 1), Begin::Retry);
        assert_eq!(ledger.begin(8, 1), Begin::New(1));
        ledger.abort(1, 8, 1);
        assert_eq!(ledger.begin(8, 1), Begin::New(1));
    }

    #[test]
    fn completed_entries_evict_oldest_but_pending_entries_remain() {
        let mut ledger = Ledger::<2>::new();
        let Begin::New(a) = ledger.begin(1, 1) else {
            panic!();
        };
        let Begin::New(b) = ledger.begin(2, 1) else {
            panic!();
        };
        ledger.complete(a, 1, 1);
        ledger.complete(b, 2, 1);
        let Begin::New(slot) = ledger.begin(3, 1) else {
            panic!("oldest completed entry must be evicted");
        };
        assert_eq!(slot, a);
        assert_eq!(ledger.begin(1, 1), Begin::New(b), "evicted key may be reused");
        assert_eq!(ledger.begin(3, 1), Begin::Busy);
        assert_eq!(ledger.begin(4, 1), Begin::Exhausted);
    }

    #[test]
    fn conflicting_request_performs_no_mutation() {
        let mut ledger = Ledger::<1>::new();
        let Begin::New(slot) = ledger.begin(11, 3) else {
            panic!();
        };
        assert_eq!(ledger.begin(11, 4), Begin::Conflict);
        ledger.complete(slot, 11, 3);
        assert_eq!(ledger.begin(11, 3), Begin::Retry);
    }
}
