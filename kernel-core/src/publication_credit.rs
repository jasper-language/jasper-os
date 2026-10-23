//! Author: chatgpt. Serial, publication-local count of granted group credits.
//! Caller resets touched counts before returning; this is not persistent limit.
//! Capacity is the existing conservative allowance, not the raw token balance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicationCredit(u32);
impl PublicationCredit {
    pub const fn new() -> Self { Self(0) }
    /// On success increment once; on refusal preserve the count, including MAX.
    pub fn grant(&mut self, allowance: u32) -> bool {
        if self.0 >= allowance { return false; }
        self.0 += 1; // Strict comparison proves this cannot overflow.
        true
    }
    pub fn count(&self) -> u32 { self.0 }
    pub fn reset(&mut self) { self.0 = 0; }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundaries_and_reset() {
        let mut c = PublicationCredit::new();
        assert!(!c.grant(0)); assert!(c.grant(1)); assert!(!c.grant(1));
        c.reset(); assert_eq!(c.count(), 0);
        let mut c = PublicationCredit(u32::MAX - 1);
        assert!(c.grant(u32::MAX)); assert!(!c.grant(u32::MAX));
        assert_eq!(c.count(), u32::MAX);
    }
    #[derive(Clone, Copy, Debug)]
    struct Request { group: usize, allowance: u32, token: bool, reset: bool }
    // Independent old algorithm: count accepted owners again for every request.
    fn replay(requests: &[Request]) -> bool {
        let mut counts = [PublicationCredit::new(); 5];
        let mut owners = std::vec::Vec::new();
        for r in requests {
            if r.reset {
                for c in &mut counts { c.reset(); }
                owners.clear();
            }
            if !r.token { continue; } // No canonical owner means no issued credit.
            let prior = owners.iter().filter(|g| **g == r.group).count() as u32;
            let expected = prior < r.allowance;
            if counts[r.group].grant(r.allowance) != expected { return false; }
            if expected { owners.push(r.group); }
            for g in 0..5 {
                if counts[g].count() != owners.iter().filter(|x| **x == g).count() as u32 { return false; }
            }
        }
        true
    }
    #[test]
    fn fixed_seed_matches_repeated_owner_scan_with_failure_shrinking() {
        let mut seed = 0x435245444954u64;
        let mut requests = std::vec::Vec::new();
        for n in 0..20_000 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
            requests.push(Request { group: (seed % 5) as usize,
                allowance: ((seed >> 8) % 34) as u32, token: seed & 8 != 0,
                reset: n % 32 == 0 });
        }
        if !replay(&requests) {
            let mut i = 0;
            while i < requests.len() {
                let mut reduced = requests.clone(); reduced.remove(i);
                if !replay(&reduced) { requests = reduced; } else { i += 1; }
            }
            panic!("minimal failing request sequence: {requests:?}");
        }
    }
}
