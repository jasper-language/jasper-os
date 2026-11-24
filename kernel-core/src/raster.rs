//! Integer pixel-coverage blending shared by native text renderers.

/// Blend one foreground/background channel with an 8-bit coverage value.
///
/// The formula is `(foreground * coverage + background * (255 - coverage) +
/// 127) / 255`, with a widened integer intermediate and nearest rounding.
pub const fn blend_coverage(foreground: u8, background: u8, coverage: u8) -> u8 {
    let foreground = foreground as u16 * coverage as u16;
    let background = background as u16 * (255 - coverage) as u16;
    ((foreground + background + 127) / 255) as u8
}

#[cfg(test)]
mod tests {
    use super::blend_coverage;

    #[test]
    fn coverage_preserves_zero_full_and_intermediate_alpha() {
        assert_eq!(blend_coverage(255, 0, 0), 0);
        assert_eq!(blend_coverage(255, 0, 1), 1);
        assert_eq!(blend_coverage(255, 0, 127), 127);
        assert_eq!(blend_coverage(255, 0, 254), 254);
        assert_eq!(blend_coverage(255, 0, 255), 255);
        assert_eq!(blend_coverage(0, 255, 127), 128);
    }
}
