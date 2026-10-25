//! Author: chatgpt. Serialized diagnostic attribution, never scheduling input.
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum Origin { Read, Mutation, Switch, BspTick, ApFallback, Diagnostic }
impl Origin {
    pub const ALL: [Self; 6] = [Self::Read, Self::Mutation, Self::Switch, Self::BspTick, Self::ApFallback, Self::Diagnostic];
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts { pub by_origin: [u64; 6], pub total: u64, pub overflow: bool }
impl Counts {
    pub const EMPTY: Self = Self { by_origin: [0; 6], total: 0, overflow: false };
    pub fn record(&mut self, origin: Origin) {
        let i = origin as usize;
        self.by_origin[i] = match self.by_origin[i].checked_add(1) {
            Some(n) => n, None => { self.overflow = true; u64::MAX }
        };
        self.total = match self.total.checked_add(1) {
            Some(n) => n, None => { self.overflow = true; u64::MAX }
        };
    }
    pub fn clear(&mut self) { *self = Self::EMPTY; }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_sources_total_and_window_reset() {
        let mut total = Counts::EMPTY; let mut window = Counts::EMPTY;
        for i in 0..20_000 { let origin = Origin::ALL[(i * 17 + 3) % 6];
            total.record(origin); window.record(origin);
            if i == 9999 { window.clear(); }
        }
        assert_eq!(total.total, 20_000); assert_eq!(window.total, 10_000);
        assert_eq!(total.by_origin.iter().sum::<u64>(), total.total);
        assert_eq!(window.by_origin.iter().sum::<u64>(), window.total);
        assert!(!total.overflow && !window.overflow);
        let saved = total; window.clear(); assert_eq!(total, saved); assert_eq!(window, Counts::EMPTY);
    }
    #[test]
    fn saturation_is_explicit_and_reset_clears_it() {
        let mut c = Counts { by_origin: [u64::MAX; 6], total: u64::MAX, overflow: false };
        c.record(Origin::Switch); assert!(c.overflow); assert_eq!(c.total, u64::MAX);
        assert_eq!(c.by_origin, [u64::MAX; 6]); c.clear(); assert_eq!(c, Counts::EMPTY);
        let mut c = Counts { total: u64::MAX, ..Counts::EMPTY }; c.record(Origin::Read);
        assert_eq!(c.by_origin[0], 1); assert!(c.overflow);
    }
}
