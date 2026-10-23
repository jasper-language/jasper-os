//! Checked quota admission shared with real Ring/IPC callers. Author: chatgpt.
//! Pure preflight: None means neither counter nor resources may be committed.
pub fn reserve_u32(current: u32, amount: u32, limit: u32) -> Option<u32> {
    current.checked_add(amount).filter(|&next| next <= limit)
}
pub fn reserve_usize(current: usize, amount: usize, limit: usize) -> Option<usize> {
    current.checked_add(amount).filter(|&next| next <= limit)
}
#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn quota_admission_never_wraps_or_exceeds_limit() {
        let current: u32 = kani::any();
        let amount: u32 = kani::any();
        let limit: u32 = kani::any();
        match reserve_u32(current, amount, limit) {
            Some(next) => {
                assert!(next >= current && next <= limit);
                assert_eq!(next as u64, current as u64 + amount as u64);
            }
            None => assert!(current as u64 + amount as u64 > limit as u64),
        }
        let current: usize = kani::any();
        let amount: usize = kani::any();
        let limit: usize = kani::any();
        match reserve_usize(current, amount, limit) {
            Some(next) => {
                assert!(next >= current && next <= limit);
                assert_eq!(next as u128, current as u128 + amount as u128);
            }
            None => assert!(current as u128 + amount as u128 > limit as u128),
        }
    }
}
