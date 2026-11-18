//! Architecture-neutral admission for the bootstrap linear physical map.

/// Round a requested physical end up to the platform mapping granule.
///
/// Returns `None` when the request or rounding overflows, the granule is
/// invalid, or the complete discovered graph cannot fit inside the explicit
/// mapping envelope. Callers must fail the boot instead of publishing a
/// truncated usable-RAM set.
///
/// 将请求的物理终点按平台映射粒度向上取整。溢出、非法粒度或完整发现图超过显式
/// 映射包络时返回 `None`；调用者必须让启动失败，不能发布被截断的可用 RAM。
pub const fn linear_map_end(
    requested_end: u64,
    minimum_end: u64,
    maximum_end: u64,
    granule: u64,
) -> Option<u64> {
    if granule == 0 || minimum_end > maximum_end {
        return None;
    }
    let required = if requested_end > minimum_end {
        requested_end
    } else {
        minimum_end
    };
    let Some(last) = required.checked_add(granule - 1) else {
        return None;
    };
    let admitted = (last / granule) * granule;
    if admitted > maximum_end {
        None
    } else {
        Some(admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::linear_map_end;

    const GIB: u64 = 1 << 30;

    #[test]
    fn admits_exact_boundaries_and_preserves_discovered_end() {
        assert_eq!(linear_map_end(0, 2 * GIB, 64 * GIB, GIB), Some(2 * GIB));
        assert_eq!(
            linear_map_end(33 * GIB, 2 * GIB, 64 * GIB, GIB),
            Some(33 * GIB)
        );
        assert_eq!(
            linear_map_end(64 * GIB, 2 * GIB, 64 * GIB, GIB),
            Some(64 * GIB)
        );
        assert_eq!(
            linear_map_end(64 * GIB - 1, 2 * GIB, 64 * GIB, GIB),
            Some(64 * GIB)
        );
    }

    #[test]
    fn rejects_cross_envelope_and_overflow_instead_of_truncating() {
        assert_eq!(linear_map_end(64 * GIB + 1, 2 * GIB, 64 * GIB, GIB), None);
        assert_eq!(linear_map_end(u64::MAX, 2 * GIB, 512 * GIB, GIB), None);
        assert_eq!(linear_map_end(1, 0, u64::MAX, 0), None);
        assert_eq!(linear_map_end(1, 2, 1, 1), None);
    }
}
