//! Standard EventSource carrying successful SEC-2 revocation notices.
//!
//! The source is deliberately separate from service publication. It reports
//! the number of capabilities revoked by the latest completed transaction so
//! affected owners can invalidate cached delegation state without polling.

use core::sync::atomic::{AtomicU64, Ordering};

use kernel_core::objtable::ObjId;
use kernel_core::subscription::Snapshot;

use crate::kobj::{self, Table};
use crate::subscription;

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
            value: 0,
        },
    )?;
    SOURCE.store(id.raw(), Ordering::Release);
    Ok(id)
}

/// Publish only after revocation has committed. A missing source means no
/// observer has requested notices, not that revocation failed.
pub(crate) fn publish_in(t: &mut Table, revoked: usize) -> Result<(), subscription::Error> {
    let Some(id) = ObjId::from_raw(SOURCE.load(Ordering::Acquire)) else {
        return Ok(());
    };
    subscription::publish_in(t, id, revoked as u64)
}

pub(crate) fn ensure() {
    let _ = kobj::with(source_in);
}
