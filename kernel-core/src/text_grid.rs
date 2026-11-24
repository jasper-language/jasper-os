//! Shared fixed-cell width policy for native text frontends.
//!
//! This is a bounded width policy, not a complete UAX #11/#29 implementation.
//! Full grapheme shaping, emoji ZWJ sequences and language-specific line
//! breaking remain terminal-service responsibilities.

pub const COMBINING: u8 = 0;
pub const HALF_WIDTH: u8 = 1;
pub const FULL_WIDTH: u8 = 2;

pub fn cell_width(character: char) -> u8 {
    let value = character as u32;
    if matches!(
        value,
        0x0300..=0x036f
            | 0x1ab0..=0x1aff
            | 0x1dc0..=0x1dff
            | 0x20d0..=0x20ff
            | 0xfe20..=0xfe2f
    ) {
        return COMBINING;
    }
    if matches!(
        value,
        0x1100..=0x115f
            | 0x2329..=0x232a
            | 0x2e80..=0xa4cf
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe10..=0xfe19
            | 0xfe30..=0xfe6f
            | 0xff00..=0xff60
            | 0xffe0..=0xffe6
            | 0x1f300..=0x1faff
            | 0x20000..=0x3fffd
    ) {
        FULL_WIDTH
    } else {
        HALF_WIDTH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_terminal_widths_are_stable() {
        assert_eq!(cell_width('A'), HALF_WIDTH);
        assert_eq!(cell_width('中'), FULL_WIDTH);
        assert_eq!(cell_width('，'), FULL_WIDTH);
        assert_eq!(cell_width('\u{0301}'), COMBINING);
    }
}
