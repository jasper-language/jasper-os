//! Capability-publication event source.
//!
//! The event value is the live `ServiceGate` mask. Subscribers receive the current
//! mask as their initial snapshot and a coalesced state update whenever assembly
//! publication changes. The source is a normal EventSource object; USI does not
//! introduce a second notification mechanism.

use core::sync::atomic::{AtomicU64, Ordering};

use kernel_core::objtable::ObjId;
use kernel_core::subscription::Snapshot;

use crate::kobj::{self, Table};
use crate::{assembly, subscription};

static SOURCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn source_in(t: &mut Table) -> Result<ObjId, subscription::Error> {
    let stored = SOURCE.load(Ordering::Acquire);
    if let Some(id) = ObjId::from_raw(stored) {
        if t.get(id).is_ok() {
            return Ok(id);
        }
        let _ = SOURCE.compare_exchange(stored, 0, Ordering::AcqRel, Ordering::Acquire);
    }
    let id = subscription::create_publisher_in(
        t,
        Snapshot {
            version: 0,
            value: u64::from(assembly::published_mask()),
        },
    )?;
    SOURCE.store(id.raw(), Ordering::Release);
    Ok(id)
}

/// Publish the post-transition capability mask. No event is generated for an
/// unchanged mask, so state coalescing cannot manufacture capability changes.
pub(crate) fn publish_capabilities(mask: u32) {
    let Some(id) = ObjId::from_raw(SOURCE.load(Ordering::Acquire)) else {
        return;
    };
    let result = kobj::with(|t| {
        if subscription::snapshot_in(t, id).is_some_and(|snapshot| snapshot.value == u64::from(mask)) {
            return Ok(());
        }
        subscription::publish_value_in(t, id, u64::from(mask), u64::from(mask))
    });
    if result.is_err() {
        let _ = SOURCE.compare_exchange(id.raw(), 0, Ordering::AcqRel, Ordering::Acquire);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_zero_source_is_absent() {
        assert!(ObjId::from_raw(0).is_none());
    }
}
