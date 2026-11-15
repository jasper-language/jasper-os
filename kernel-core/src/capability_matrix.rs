//! Shared discovered/supported/admitted/enabled/exposed/verified policy.

/// Highest lifecycle state justified by one capability inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityStage {
    NotProbed,
    DiscoveryFailed,
    Unsupported,
    Discovered,
    KernelSupported,
    Admitted,
    Enabled,
    Exposed,
    Verified,
    Rejected,
}

impl CapabilityStage {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotProbed => "not-probed",
            Self::DiscoveryFailed => "discovery-failed",
            Self::Unsupported => "unsupported",
            Self::Discovered => "discovered",
            Self::KernelSupported => "kernel-supported",
            Self::Admitted => "admitted",
            Self::Enabled => "enabled",
            Self::Exposed => "exposed",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

/// Whether an adapter actually attempted the inventory that produced its counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapabilityCoverage {
    /// The subsystem was not wired into this boot or is absent from this build.
    #[default]
    NotProbed,
    /// Discovery ran to completion and all discovered entries are accounted for.
    Complete,
    /// Discovery ran but could not produce a trustworthy inventory.
    Failed,
}

impl CapabilityCoverage {
    pub const fn name(self) -> &'static str {
        match self {
            Self::NotProbed => "not-probed",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }
}

/// Numeric inventory used by boot, CPU, device, network and GPU adapters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityFacts {
    pub coverage: CapabilityCoverage,
    pub discovered: u32,
    pub kernel_supported: u32,
    pub admitted: u32,
    pub rejected: u32,
    pub unsupported: u32,
    pub enabled: u32,
    pub exposed: u32,
    pub verified: u32,
    pub security_critical: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    InventoryMismatch,
    SupportedExceedsDiscovered,
    StageWithoutPredecessor(&'static str),
    SecurityCriticalRejectionPublished,
}

impl CapabilityError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InventoryMismatch => "system.capability.error.inventory_mismatch",
            Self::SupportedExceedsDiscovered => {
                "system.capability.error.supported_exceeds_discovered"
            }
            Self::StageWithoutPredecessor(_) => "system.capability.error.stage_without_predecessor",
            Self::SecurityCriticalRejectionPublished => {
                "system.capability.error.security_rejection_published"
            }
        }
    }
}

/// Classify a complete inventory and prevent stage skipping or unsafe publication.
pub fn classify(facts: CapabilityFacts) -> Result<CapabilityStage, CapabilityError> {
    let no_facts = facts.discovered == 0
        && facts.kernel_supported == 0
        && facts.admitted == 0
        && facts.rejected == 0
        && facts.unsupported == 0
        && facts.enabled == 0
        && facts.exposed == 0
        && facts.verified == 0;
    match facts.coverage {
        CapabilityCoverage::NotProbed if no_facts => return Ok(CapabilityStage::NotProbed),
        CapabilityCoverage::NotProbed => return Err(CapabilityError::InventoryMismatch),
        CapabilityCoverage::Failed if no_facts => return Ok(CapabilityStage::DiscoveryFailed),
        CapabilityCoverage::Failed => return Err(CapabilityError::InventoryMismatch),
        CapabilityCoverage::Complete => {}
    }
    if facts.discovered
        != facts
            .admitted
            .saturating_add(facts.rejected)
            .saturating_add(facts.unsupported)
    {
        return Err(CapabilityError::InventoryMismatch);
    }
    if facts.kernel_supported > facts.discovered {
        return Err(CapabilityError::SupportedExceedsDiscovered);
    }
    if facts.enabled > facts.admitted || facts.enabled > facts.kernel_supported {
        return Err(CapabilityError::StageWithoutPredecessor("enabled"));
    }
    if facts.exposed > facts.enabled {
        return Err(CapabilityError::StageWithoutPredecessor("exposed"));
    }
    if facts.verified > facts.exposed {
        return Err(CapabilityError::StageWithoutPredecessor("verified"));
    }
    if facts.security_critical && facts.rejected != 0 && (facts.exposed != 0 || facts.verified != 0)
    {
        return Err(CapabilityError::SecurityCriticalRejectionPublished);
    }
    if facts.security_critical && facts.rejected != 0 {
        return Ok(CapabilityStage::Rejected);
    }
    Ok(if facts.verified != 0 {
        CapabilityStage::Verified
    } else if facts.exposed != 0 {
        CapabilityStage::Exposed
    } else if facts.enabled != 0 {
        CapabilityStage::Enabled
    } else if facts.admitted != 0 {
        CapabilityStage::Admitted
    } else if facts.kernel_supported != 0 {
        CapabilityStage::KernelSupported
    } else if facts.discovered != 0 {
        CapabilityStage::Discovered
    } else {
        CapabilityStage::Unsupported
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_order_requires_every_predecessor() {
        let verified = CapabilityFacts {
            coverage: CapabilityCoverage::Complete,
            discovered: 4,
            kernel_supported: 4,
            admitted: 4,
            rejected: 0,
            unsupported: 0,
            enabled: 4,
            exposed: 4,
            verified: 4,
            security_critical: true,
        };
        assert_eq!(classify(verified), Ok(CapabilityStage::Verified));

        let skipped = CapabilityFacts {
            discovered: 4,
            kernel_supported: 4,
            admitted: 4,
            enabled: 0,
            exposed: 1,
            ..verified
        };
        assert_eq!(
            classify(skipped),
            Err(CapabilityError::StageWithoutPredecessor("exposed"))
        );
    }

    #[test]
    fn unaccounted_capacity_and_heterogeneous_support_fail_closed() {
        let truncated = CapabilityFacts {
            coverage: CapabilityCoverage::Complete,
            discovered: 17,
            kernel_supported: 17,
            admitted: 16,
            rejected: 0,
            unsupported: 0,
            security_critical: true,
            ..CapabilityFacts::default()
        };
        assert_eq!(classify(truncated), Err(CapabilityError::InventoryMismatch));

        let heterogeneous = CapabilityFacts {
            coverage: CapabilityCoverage::Complete,
            discovered: 2,
            kernel_supported: 1,
            admitted: 2,
            rejected: 0,
            unsupported: 0,
            enabled: 2,
            security_critical: true,
            ..CapabilityFacts::default()
        };
        assert_eq!(
            classify(heterogeneous),
            Err(CapabilityError::StageWithoutPredecessor("enabled"))
        );
    }

    #[test]
    fn security_rejection_is_visible_and_never_published() {
        let rejected = CapabilityFacts {
            coverage: CapabilityCoverage::Complete,
            discovered: 17,
            kernel_supported: 17,
            admitted: 16,
            rejected: 1,
            unsupported: 0,
            enabled: 16,
            exposed: 0,
            verified: 0,
            security_critical: true,
        };
        assert_eq!(classify(rejected), Ok(CapabilityStage::Rejected));

        let published = CapabilityFacts {
            exposed: 16,
            verified: 16,
            ..rejected
        };
        assert_eq!(
            classify(published),
            Err(CapabilityError::SecurityCriticalRejectionPublished)
        );
    }

    #[test]
    fn not_probed_is_not_misreported_as_unsupported() {
        let unknown = CapabilityFacts::default();
        assert_eq!(classify(unknown), Ok(CapabilityStage::NotProbed));

        let fabricated = CapabilityFacts {
            discovered: 1,
            ..unknown
        };
        assert_eq!(
            classify(fabricated),
            Err(CapabilityError::InventoryMismatch)
        );
    }

    #[test]
    fn enabled_does_not_become_verified_without_evidence() {
        let exposed = CapabilityFacts {
            coverage: CapabilityCoverage::Complete,
            discovered: 2,
            kernel_supported: 2,
            admitted: 2,
            rejected: 0,
            unsupported: 0,
            enabled: 2,
            exposed: 2,
            verified: 0,
            security_critical: true,
        };
        assert_eq!(classify(exposed), Ok(CapabilityStage::Exposed));
    }

    #[test]
    fn failed_discovery_is_distinct_from_no_hardware() {
        let failed = CapabilityFacts {
            coverage: CapabilityCoverage::Failed,
            ..CapabilityFacts::default()
        };
        assert_eq!(classify(failed), Ok(CapabilityStage::DiscoveryFailed));

        let absent = CapabilityFacts {
            coverage: CapabilityCoverage::Complete,
            ..CapabilityFacts::default()
        };
        assert_eq!(classify(absent), Ok(CapabilityStage::Unsupported));
    }
}
