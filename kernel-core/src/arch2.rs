//! Shared control-page layout for the ARCH-2 user-space driver acceptance.
//!
//! The page contains only diagnostics and opaque process-local handles. It is
//! not a new user ABI and cannot authorize device or Ring operations.

/// Magic word published only after the driver has opened the device, created a
/// Ring and completed its BAR mapping.
pub const CONTROL_MAGIC: u64 = 0x4152_4348_325f_5631;

/// Control-page word indexes.
pub const DEVICE_HANDLE_WORD: usize = 1;
pub const RING_HANDLE_WORD: usize = 2;
pub const BAR_MAP_WORD: usize = 3;
pub const READY_WORD: usize = 4;
pub const CONTROL_WORDS: usize = 8;

/// Value published in [`READY_WORD`] after all setup operations succeeded.
pub const READY_VALUE: u64 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_layout_is_fixed_and_fits_one_page() {
        assert!(CONTROL_WORDS * core::mem::size_of::<u64>() <= 4096);
        assert!(DEVICE_HANDLE_WORD < RING_HANDLE_WORD);
        assert!(RING_HANDLE_WORD < BAR_MAP_WORD);
        assert!(BAR_MAP_WORD < READY_WORD);
    }
}
