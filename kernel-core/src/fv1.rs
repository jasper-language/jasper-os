//! FV-1 real-code Kani harnesses. Author: chatgpt.
//! No assume clauses: inputs span all bit patterns of the declared types.
use crate::object::{Rights, HandleTable, HandleError};

#[kani::proof]
#[kani::unwind(4)]
fn rights_access_and_reduction_do_not_escalate() {
    let grant = Rights::from_bits_truncate(kani::any::<u32>());
    let required = Rights::from_bits_truncate(kani::any::<u32>());
    let requested = Rights::from_bits_truncate(kani::any::<u32>());
    let mut table = HandleTable::<u8, 2>::new();
    let handle = table.put(7, grant).unwrap();
    if grant.contains(required) {
        assert_eq!(table.get_checked(handle, required), Ok(&7));
    } else {
        assert_eq!(table.get_checked(handle, required), Err(HandleError::RightsDenied));
    }
    let result = table.reduce_rights(handle, requested);
    let (_, after) = table.get(handle).unwrap();
    if grant.contains(requested) {
        assert!(result.is_ok()); assert_eq!(after, requested);
    } else {
        assert_eq!(result, Err(HandleError::RightsDenied)); assert_eq!(after, grant);
    }
    assert!(grant.contains(after));
    assert_eq!(table.len(), 1);
}

#[kani::proof]
#[kani::unwind(4)]
fn removed_handle_is_stale_and_capacity_rejects_atomically() {
    let mut table = HandleTable::<u8, 2>::new();
    let old = table.put(kani::any(), Rights::ALL).unwrap();
    table.remove(old).unwrap();
    let new = table.put(9, Rights::READ).unwrap();
    assert_ne!(old, new);
    assert_eq!(table.get(old), Err(HandleError::Invalid));
    assert_eq!(table.get_checked(new, Rights::WRITE), Err(HandleError::RightsDenied));
    let second = table.put(10, Rights::NONE).unwrap();
    assert_eq!(table.put(11, Rights::ALL), Err(HandleError::TableFull));
    assert_eq!(table.len(), 2);
    assert_eq!(table.get(new), Ok((&9, Rights::READ)));
    assert_eq!(table.get(second), Ok((&10, Rights::NONE)));
}

#[kani::proof]
#[kani::unwind(4)]
fn arbitrary_handle_index_does_not_bypass_validation() {
    use crate::object::{HandleId, HandleRaw};
    let mut table = HandleTable::<u8, 2>::new();
    let valid = table.put(7, Rights::READ).unwrap();
    let candidate = HandleId::from_raw(kani::any::<HandleRaw>());
    let result = table.get(candidate);
    if candidate == valid { assert_eq!(result, Ok((&7, Rights::READ))); }
    else { assert_eq!(result, Err(HandleError::Invalid)); }
}

#[kani::proof]
#[kani::unwind(6)]
fn ring_terminal_and_credit_uniqueness_four_steps() {
    use crate::async_ring::{AsyncRing, Submission, Exec};
    let mut ring = AsyncRing::<1, 1>::new(1).unwrap();
    let id = ring.submit(Submission { op: 1, user_tag: 2, context: 3,
        uses_buffer: kani::any() }).unwrap();
    if kani::any::<bool>() {
        ring.start(id, if kani::any() { Exec::Abortable } else { Exec::NonAbortable }).unwrap();
    }
    let mut decision = None;
    let mut reclaimed = 0;
    for _ in 0..4 {
        match kani::any::<u8>() % 6 {
            0 => { let _ = ring.cancel(id); }
            1 => { ring.close(|_, _| {}); }
            2 => { let _ = ring.finish(id, 17); }
            3 => { let _ = ring.quiesce(id); }
            4 => { ring.consume(1); }
            _ => { let _ = ring.start(id, Exec::Abortable); }
        }
        if let Some(Some(t)) = ring.decision(id) {
            if let Some(old) = decision { assert_eq!(old, t); }
            decision = Some(t);
        }
        if let Some(context) = ring.take_reclaimed() { assert_eq!(context, 3); reclaimed += 1; }
        assert!(reclaimed <= 1);
        assert!(ring.stats().published <= 1);
        assert!(ring.stats().destroyed <= 1);
        assert_eq!(ring.credits() + ring.reserved() + ring.ready(), 1);
        assert!(ring.in_flight() <= 1);
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn cross_table_transfer_is_atomic_and_preserves_rights() {
    let grant = Rights::from_bits_truncate(kani::any());
    let full: bool = kani::any();
    use crate::object::{ObjectRef, ObjectId, ObjectType};
    let value = ObjectRef { id: ObjectId(kani::any()), ty: ObjectType::Event };
    let blocker = ObjectRef { id: ObjectId(99), ty: ObjectType::Timer };
    let mut from = HandleTable::<ObjectRef, 1>::new();
    let mut to = HandleTable::<ObjectRef, 1>::new();
    let source = from.put(value, grant).unwrap();
    let existing = if full { Some(to.put(blocker, Rights::READ).unwrap()) } else { None };
    let result = from.transfer_to(source, &mut to);
    if !grant.contains(Rights::TRANSFER) || full {
        assert!(result.is_err());
        assert_eq!(from.get(source), Ok((&value, grant)));
        assert_eq!(from.len(), 1);
        assert_eq!(to.len(), if full { 1 } else { 0 });
        if let Some(existing) = existing { assert_eq!(to.get(existing), Ok((&blocker, Rights::READ))); }
    } else {
        let destination = result.unwrap();
        assert_eq!(from.get(source), Err(HandleError::Invalid));
        assert_eq!(from.len(), 0);
        assert_eq!(to.get(destination), Ok((&value, grant)));
        assert_eq!(to.len(), 1);
    }
}

#[kani::proof]
#[kani::unwind(4)]
fn ring_capacity_and_quota_reject_without_partial_submission() {
    use crate::async_ring::{AsyncRing, Submission, SubmitError};
    let capacity: usize = kani::any();
    let created = AsyncRing::<2, 2>::new(capacity);
    if capacity == 0 || capacity > 2 { assert!(created.is_none()); return; }
    let mut ring = created.unwrap();
    let sub = Submission { op: 1, user_tag: 2, context: 3, uses_buffer: false };
    ring.submit(sub).unwrap();
    if capacity == 2 { ring.submit(sub).unwrap(); }
    let before = ring.stats();
    let next = ring.next_id();
    assert_eq!(ring.submit(sub), Err(SubmitError::CqFull));
    assert_eq!(ring.next_id(), next);
    assert_eq!(ring.in_flight(), capacity);
    assert_eq!(ring.stats().accepted, before.accepted);
    assert_eq!(ring.credits() + ring.reserved() + ring.ready(), capacity);
}
