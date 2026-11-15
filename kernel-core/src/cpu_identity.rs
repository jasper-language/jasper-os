//! Fail-closed processor identity resolution shared by architecture adapters.

/// Processor identity resolution failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuIdentityError {
    /// The hardware identity has no admitted logical index.
    Unregistered { hw_id: u32 },
    /// A registered logical index is outside the fixed CPU table.
    OutOfRange { index: usize },
    /// The logical CPU is registered but not currently online.
    Offline { index: usize },
}

impl CpuIdentityError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unregistered { .. } => "system.cpu.error.id_unregistered",
            Self::OutOfRange { .. } => "system.cpu.error.index_out_of_range",
            Self::Offline { .. } => "system.cpu.error.offline",
        }
    }
}

/// Resolve one hardware ID to its admitted logical CPU index.
///
/// A registered index is authoritative and must fit the fixed table. Before
/// topology publication, only the explicitly recorded bootstrap hardware ID
/// may resolve to logical CPU0; every other unknown identity fails closed.
pub fn resolve_index(
    hw_id: u32,
    registered: Option<usize>,
    topology_ready: bool,
    bootstrap_id: Option<u32>,
    max_cpus: usize,
) -> Result<usize, CpuIdentityError> {
    if let Some(index) = registered {
        return if index < max_cpus && max_cpus != 0 {
            Ok(index)
        } else {
            Err(CpuIdentityError::OutOfRange { index })
        };
    }
    if !topology_ready && bootstrap_id == Some(hw_id) && max_cpus != 0 {
        return Ok(0);
    }
    Err(CpuIdentityError::Unregistered { hw_id })
}

/// Validate that a resolved logical index may execute on this CPU.
pub fn validate_online(
    index: usize,
    max_cpus: usize,
    online: bool,
) -> Result<usize, CpuIdentityError> {
    if index >= max_cpus || max_cpus == 0 {
        return Err(CpuIdentityError::OutOfRange { index });
    }
    if !online {
        return Err(CpuIdentityError::Offline { index });
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_identity_wins_and_must_fit_the_table() {
        assert_eq!(resolve_index(9, Some(3), true, Some(9), 8), Ok(3));
        assert_eq!(resolve_index(9, Some(3), false, Some(9), 8), Ok(3));
        assert_eq!(
            resolve_index(9, Some(8), true, Some(9), 8),
            Err(CpuIdentityError::OutOfRange { index: 8 })
        );
    }

    #[test]
    fn only_explicit_bootstrap_id_can_alias_cpu_zero() {
        assert_eq!(resolve_index(7, None, false, Some(7), 8), Ok(0));
        assert_eq!(
            resolve_index(6, None, false, Some(7), 8),
            Err(CpuIdentityError::Unregistered { hw_id: 6 })
        );
        assert_eq!(
            resolve_index(7, None, true, Some(7), 8),
            Err(CpuIdentityError::Unregistered { hw_id: 7 })
        );
        assert_eq!(
            resolve_index(7, None, false, None, 8),
            Err(CpuIdentityError::Unregistered { hw_id: 7 })
        );
    }

    #[test]
    fn zero_capacity_and_offline_indices_fail_closed() {
        assert_eq!(
            resolve_index(0, None, false, Some(0), 0),
            Err(CpuIdentityError::Unregistered { hw_id: 0 })
        );
        assert_eq!(
            validate_online(0, 0, true),
            Err(CpuIdentityError::OutOfRange { index: 0 })
        );
        assert_eq!(
            validate_online(3, 8, false),
            Err(CpuIdentityError::Offline { index: 3 })
        );
        assert_eq!(validate_online(3, 8, true), Ok(3));
        assert_eq!(
            CpuIdentityError::Unregistered { hw_id: 4 }.name(),
            "system.cpu.error.id_unregistered"
        );
        assert_eq!(
            CpuIdentityError::OutOfRange { index: 8 }.name(),
            "system.cpu.error.index_out_of_range"
        );
        assert_eq!(
            CpuIdentityError::Offline { index: 2 }.name(),
            "system.cpu.error.offline"
        );
    }
}
