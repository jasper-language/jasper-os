//! Validation for standard-format x86 XSAVE images crossing a trust boundary.
//!
//! The kernel must not pass a user-controlled image directly to privileged
//! XRSTOR. This parser validates the standard header, component mask and MXCSR
//! reserved bits without interpreting CPU-specific component payloads.
//!
//! 用户态跨信任边界交回内核的 x86 XSAVE 标准格式映像必须先经过本模块校验；
//! 禁止把未经检查的用户映像直接交给特权态 XRSTOR。

pub const LEGACY_AREA_BYTES: usize = 512;
pub const STANDARD_HEADER_BYTES: usize = 64;
pub const MIN_STANDARD_IMAGE_BYTES: usize = LEGACY_AREA_BYTES + STANDARD_HEADER_BYTES;
pub const X87_STATE_BIT: u64 = 1 << 0;
pub const MXCSR_OFFSET: usize = 24;
pub const XSTATE_BV_OFFSET: usize = LEGACY_AREA_BYTES;
pub const XCOMP_BV_OFFSET: usize = XSTATE_BV_OFFSET + 8;
pub const HEADER_RESERVED_OFFSET: usize = XCOMP_BV_OFFSET + 8;
pub const XCOMP_BV_COMPACTED_FORMAT: u64 = 1 << 63;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XsaveImageError {
    TooShort,
    UnsupportedCompactFormat,
    ReservedHeader,
    DisabledComponent,
    MissingX87State,
    InvalidMxcsr,
}

/// Validate one standard-format XSAVE image for the active XCR0 policy.
///
/// `allowed_mask` is the exact XCR0 mask installed by this kernel. Compressed
/// XSAVE formats are rejected because Jasper has not admitted their alternate
/// offsets/layouts. Legacy x87 state must be present, and MXCSR bits 16..31
/// must be zero.
pub fn validate_standard_image(
    bytes: &[u8],
    allowed_mask: u64,
) -> Result<(), XsaveImageError> {
    if bytes.len() < MIN_STANDARD_IMAGE_BYTES {
        return Err(XsaveImageError::TooShort);
    }
    let xstate_bv = read_u64(bytes, XSTATE_BV_OFFSET)?;
    let xcomp_bv = read_u64(bytes, XCOMP_BV_OFFSET)?;
    if xcomp_bv & XCOMP_BV_COMPACTED_FORMAT != 0 {
        return Err(XsaveImageError::UnsupportedCompactFormat);
    }
    if xcomp_bv != 0
        || bytes[HEADER_RESERVED_OFFSET..MIN_STANDARD_IMAGE_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(XsaveImageError::ReservedHeader);
    }
    if xstate_bv & !allowed_mask != 0 {
        return Err(XsaveImageError::DisabledComponent);
    }
    if xstate_bv & X87_STATE_BIT == 0 {
        return Err(XsaveImageError::MissingX87State);
    }
    let mxcsr = u32::from_le_bytes(
        bytes[MXCSR_OFFSET..MXCSR_OFFSET + 4]
            .try_into()
            .expect("fixed MXCSR range"),
    );
    if mxcsr & 0xffff_0000 != 0 {
        return Err(XsaveImageError::InvalidMxcsr);
    }
    Ok(())
}

/// Validate the legacy FXSAVE fallback when XSAVE is not enabled.
pub fn validate_legacy_fxsave(bytes: &[u8]) -> Result<(), XsaveImageError> {
    if bytes.len() != LEGACY_AREA_BYTES {
        return Err(XsaveImageError::TooShort);
    }
    let mxcsr = u32::from_le_bytes(
        bytes[MXCSR_OFFSET..MXCSR_OFFSET + 4]
            .try_into()
            .expect("fixed MXCSR range"),
    );
    if mxcsr & 0xffff_0000 != 0 {
        return Err(XsaveImageError::InvalidMxcsr);
    }
    Ok(())
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, XsaveImageError> {
    bytes
        .get(offset..offset + 8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(XsaveImageError::TooShort)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_image(mask: u64) -> [u8; MIN_STANDARD_IMAGE_BYTES] {
        let mut image = [0u8; MIN_STANDARD_IMAGE_BYTES];
        image[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8].copy_from_slice(&mask.to_le_bytes());
        image[MXCSR_OFFSET..MXCSR_OFFSET + 4].copy_from_slice(&0x1f80u32.to_le_bytes());
        image
    }

    #[test]
    fn accepts_only_standard_enabled_x87_sse_images() {
        let image = valid_image(0x3);
        assert_eq!(validate_standard_image(&image, 0x3), Ok(()));
        assert_eq!(
            validate_standard_image(&image, 0x1),
            Err(XsaveImageError::DisabledComponent)
        );
        assert_eq!(validate_legacy_fxsave(&image[..LEGACY_AREA_BYTES]), Ok(()));
    }

    #[test]
    fn rejects_compact_reserved_disabled_and_bad_mxcsr_headers() {
        let mut compact = valid_image(0x3);
        compact[XCOMP_BV_OFFSET] = 1;
        assert_eq!(
            validate_standard_image(&compact, 0x3),
            Err(XsaveImageError::ReservedHeader)
        );
        compact[XCOMP_BV_OFFSET + 7] = 0x80;
        assert_eq!(
            validate_standard_image(&compact, 0x3),
            Err(XsaveImageError::UnsupportedCompactFormat)
        );

        let mut reserved = valid_image(0x3);
        reserved[HEADER_RESERVED_OFFSET] = 1;
        assert_eq!(
            validate_standard_image(&reserved, 0x3),
            Err(XsaveImageError::ReservedHeader)
        );

        let mut no_x87 = valid_image(0x2);
        assert_eq!(
            validate_standard_image(&no_x87, 0x3),
            Err(XsaveImageError::MissingX87State)
        );
        no_x87[XSTATE_BV_OFFSET..XSTATE_BV_OFFSET + 8]
            .copy_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
        assert_eq!(
            validate_standard_image(&no_x87, 0x3),
            Err(XsaveImageError::DisabledComponent)
        );

        let mut moved = valid_image(0x3);
        moved[MXCSR_OFFSET + 2] = 1;
        assert_eq!(
            validate_standard_image(&moved, 0x3),
            Err(XsaveImageError::InvalidMxcsr)
        );
        assert_eq!(
            validate_standard_image(&moved[..MIN_STANDARD_IMAGE_BYTES - 1], 0x3),
            Err(XsaveImageError::TooShort)
        );
    }
}
