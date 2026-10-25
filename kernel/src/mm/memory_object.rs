//! SHM-1 backing pages. Author: chatgpt.
//! A page has one allocation identity shared by object, mappings and pins.
//! Dropping a reference never takes the object-table lock; final destruction only takes pin/frame locks.
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use kernel_core::{frame::{PhysFrame, FRAME_SIZE}, memory_object::MapRange};

static QUARANTINED_PAGES: AtomicU32=AtomicU32::new(0);
/// Unique physical backing pages intentionally withheld after uncertain TLB revocation.
pub fn quarantined_pages() -> u32 { QUARANTINED_PAGES.load(Ordering::Acquire) }

pub struct Page {
    frame: PhysFrame,
    /// A failed shootdown makes this allocation permanently non-reusable.
    quarantined: AtomicBool,
    owned: Option<super::memory_quota::Charge>,
}
impl Page {
    pub(crate) fn zeroed(owned: super::memory_quota::Charge) -> Option<Arc<Self>> {
        let frame = super::frame::allocate().ok()?;
        let Some(ptr) = super::phys_to_virt(frame.start()) else {
            let _ = super::frame::deallocate(frame); return None;
        };
        // SAFETY: this newly allocated frame has not been published to any mapping.
        unsafe { core::ptr::write_bytes(ptr, 0, FRAME_SIZE as usize); }
        // Arc::try_new failure drops Page, returning the unpublished frame exactly once.
        Arc::try_new(Self { frame, quarantined: AtomicBool::new(false), owned: Some(owned) }).ok()
    }
    pub fn frame(&self) -> PhysFrame { self.frame }
    pub fn quarantine(&self) {
        if !self.quarantined.swap(true,Ordering::AcqRel) { QUARANTINED_PAGES.fetch_add(1,Ordering::Relaxed); }
    }
    pub fn is_quarantined(&self) -> bool { self.quarantined.load(Ordering::Acquire) }
}
impl Drop for Page {
    fn drop(&mut self) {
        if !self.is_quarantined() { let _ = super::frame::deallocate(self.frame); }
        else if let Some(charge) = self.owned.take() {
            // Permanent physical quarantine also permanently retains its allocation charge.
            charge.quarantine_owned();
        }
    }
}

/// A leaf: holds pages only, never Process/Task/Handle references (no ownership cycles).
/// Offsets identify pages rather than virtual addresses, so future page-cache owners can share them.
pub struct MemoryObject { pages: Vec<Arc<Page>> }
impl MemoryObject {
    pub fn zeroed(pages: u64, limit: u64, mut charge: super::memory_quota::Charge) -> Option<Self> {
        if pages == 0 || pages > limit || charge.owned() != pages { return None; }
        let n = usize::try_from(pages).ok()?;
        let mut backing = Vec::new(); backing.try_reserve_exact(n).ok()?;
        for _ in 0..n { backing.push(Page::zeroed(charge.take_page()?)?); }
        Some(Self { pages: backing })
    }
    pub fn page_count(&self) -> u64 { self.pages.len() as u64 }
    /// Range must still be checked here even when the caller used core admission.
    pub fn retain_range(&self, range: MapRange) -> Option<Vec<Arc<Page>>> {
        let start = usize::try_from(range.offset_pages).ok()?;
        let len = usize::try_from(range.pages).ok()?;
        let source = self.pages.get(start..start.checked_add(len)?)?;
        let mut refs = Vec::new(); refs.try_reserve_exact(len).ok()?;
        refs.extend(source.iter().cloned()); Some(refs)
    }
}
