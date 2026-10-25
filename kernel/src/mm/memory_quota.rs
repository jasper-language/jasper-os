//! Page charges survive creator exit through an independent account, without Process references.
//! Author: chatgpt. Account locks are never held while taking object-table or pin locks.
use alloc::sync::Arc;
use kernel_core::memory_object::Usage;
use crate::sync::IrqSpinLock;

pub struct Account { usage: IrqSpinLock<Usage> }
impl Account {
    pub fn new() -> Option<Arc<Self>> {
        Arc::try_new(Self { usage: IrqSpinLock::ranked(crate::lockorder::MEMORY_PINS, Usage::default()) }).ok()
    }
    /// mapped here counts allocated backing references, not virtual aliases (those use Process limits).
    pub fn snapshot(&self) -> Usage { *self.usage.lock() }
    pub fn reserve(self: &Arc<Self>, owned: u64, pinned: u64, owned_limit: u64, pin_limit: u64) -> Option<Charge> {
        self.usage.lock().reserve(owned,pinned,Usage { mapped:owned_limit,pinned:pin_limit }).ok()?;
        Some(Charge { account:Arc::clone(self), owned, pinned })
    }
}
/// An admission credit transfers into each actual Page or PinnedRange; all error paths drop the remainder.
pub struct Charge { account: Arc<Account>, owned: u64, pinned: u64 }
impl Charge {
    pub fn take_page(&mut self) -> Option<Self> {
        if self.owned == 0 { return None; }
        self.owned -= 1;
        Some(Self { account:Arc::clone(&self.account), owned:1, pinned:0 })
    }
    pub fn owned(&self) -> u64 { self.owned }
    /// Keep allocated pages charged to any surviving account, but do not leak the Arc itself.
    /// When no process/page/pin uses the account, its metadata can die; the frame quarantine remains permanent.
    pub fn quarantine_owned(mut self) { self.owned=0; }
}
impl Drop for Charge {
    fn drop(&mut self) {
        assert!(self.account.usage.lock().release(self.owned,self.pinned).is_ok(), "memory quota charge underflow");
    }
}
