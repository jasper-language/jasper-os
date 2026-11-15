//! Cross-module capability diagnostics using the shared kernel-core policy.

use kernel_core::capability_matrix::{classify, CapabilityFacts};

use crate::boot::BootSpec;
use crate::kprintln;

fn emit(domain: &'static str, facts: CapabilityFacts) {
    match classify(facts) {
        Ok(stage) => kprintln!(
            "[JSR-CAPABILITY] domain={} state={} discovered={} supported={} admitted={} rejected={} unsupported={} enabled={} exposed={} verified={} fault=none",
            domain,
            stage.name(),
            facts.discovered,
            facts.kernel_supported,
            facts.admitted,
            facts.rejected,
            facts.unsupported,
            facts.enabled,
            facts.exposed,
            facts.verified
        ),
        Err(error) => kprintln!(
            "[JSR-CAPABILITY] domain={} state=invalid discovered={} supported={} admitted={} rejected={} unsupported={} enabled={} exposed={} verified={} fault={}",
            domain,
            facts.discovered,
            facts.kernel_supported,
            facts.admitted,
            facts.rejected,
            facts.unsupported,
            facts.enabled,
            facts.exposed,
            facts.verified,
            error.name()
        ),
    }
}

/// Emit one machine-readable inventory after boot stages have discovered and
/// assembled their resources.
pub fn report(boot: &BootSpec) {
    let memory_admitted = boot.admitted_regions() as u32;
    let memory_rejected = (boot.invalid_regions() + boot.dropped_regions()) as u32;
    emit(
        "system.memory.boot-map",
        CapabilityFacts {
            discovered: boot.discovered_regions() as u32,
            kernel_supported: memory_admitted,
            admitted: memory_admitted,
            rejected: memory_rejected,
            unsupported: 0,
            enabled: memory_admitted,
            exposed: memory_admitted,
            verified: memory_admitted,
            security_critical: true,
        },
    );

    #[cfg(target_arch = "x86_64")]
    {
        let supported_mask = u64::from(core::arch::x86_64::__cpuid_count(0xD, 0).eax);
        let enabled_mask = crate::arch::x86_64::xstate::mask();
        let supported = supported_mask.count_ones();
        let enabled = enabled_mask.count_ones();
        emit(
            "system.cpu.xstate",
            CapabilityFacts {
                discovered: supported_mask.count_ones(),
                kernel_supported: supported,
                admitted: enabled,
                rejected: 0,
                unsupported: (supported_mask & !enabled_mask).count_ones(),
                enabled,
                exposed: enabled,
                verified: enabled,
                security_critical: true,
            },
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    emit("system.cpu.xstate", CapabilityFacts::default());

    let (pci_discovered, pci_admitted, pci_rejected) =
        crate::pci::table().devices().fold((0u32, 0u32, 0u32), |counts, device| {
            let chain_failure =
                u32::from(device.caps_error && device.cap_truncated == 0);
            (
                counts.0
                    .saturating_add(device.cap_discovered as u32)
                    .saturating_add(chain_failure),
                counts.1.saturating_add(device.cap_admitted as u32),
                counts.2
                    .saturating_add(device.cap_truncated as u32)
                    .saturating_add(chain_failure),
            )
        });
    let pci_publishable = pci_rejected == 0;
    emit(
        "system.device.pci-capabilities",
        CapabilityFacts {
            discovered: pci_discovered,
            kernel_supported: pci_discovered,
            admitted: pci_admitted,
            rejected: pci_rejected,
            unsupported: 0,
            enabled: if pci_publishable { pci_admitted } else { 0 },
            exposed: if pci_publishable { pci_admitted } else { 0 },
            verified: if pci_publishable { pci_admitted } else { 0 },
            security_critical: true,
        },
    );

    // No cross-device completeness inventory exists yet. Keep these domains
    // visible as unsupported instead of inferring capabilities from Profile
    // declarations or optional libraries.
    emit("system.network", CapabilityFacts::default());
    emit("system.device.gpu", CapabilityFacts::default());
}
