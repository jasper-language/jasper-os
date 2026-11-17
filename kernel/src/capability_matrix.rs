//! Cross-module capability diagnostics using the shared kernel-core policy.

use kernel_core::capability_matrix::{classify, CapabilityCoverage, CapabilityFacts};
use kernel_core::device::{CAP_CFG_COMMON, CAP_CFG_DEVICE, CAP_CFG_ISR, CAP_CFG_NOTIFY};

use crate::boot::BootSpec;
use crate::kprintln;
use crate::pci::Device;

/// PCI base class for network controllers.
const PCI_CLASS_NETWORK: u8 = 0x02;
/// PCI base class for display controllers.
const PCI_CLASS_DISPLAY: u8 = 0x03;

/// Whether a device exposes the four modern virtio PCI capability windows used
/// by the native transport. A device ID alone is not enough to claim support
/// for a transitional-only function.
fn has_modern_virtio_transport(device: &Device) -> bool {
    if device.caps_error {
        return false;
    }
    [CAP_CFG_COMMON, CAP_CFG_NOTIFY, CAP_CFG_ISR, CAP_CFG_DEVICE]
        .into_iter()
        .all(|kind| device.caps.iter().any(|cap| cap.cfg_type == kind))
}

/// Build facts for one PCI device class from the completed boot inventory.
///
/// Discovery is independent of driver support: every function in the class is
/// counted first. Only functions whose device family and transport the kernel
/// actually implements are reported as supported. No driver instance is
/// admitted, enabled, exposed or verified by inventory inspection alone.
fn pci_class_facts(class: u8, supported: impl Fn(&Device) -> bool) -> CapabilityFacts {
    if !crate::pci::ready() || !crate::pci::table().complete {
        return CapabilityFacts {
            coverage: CapabilityCoverage::Failed,
            ..CapabilityFacts::default()
        };
    }

    let mut discovered = 0u32;
    let mut kernel_supported = 0u32;
    for device in crate::pci::table()
        .devices()
        .filter(|device| device.header.class == class)
    {
        discovered = discovered.saturating_add(1);
        if supported(device) {
            kernel_supported = kernel_supported.saturating_add(1);
        }
    }

    CapabilityFacts {
        coverage: CapabilityCoverage::Complete,
        discovered,
        kernel_supported,
        admitted: 0,
        rejected: 0,
        // The shared lifecycle contract accounts every discovery as admitted,
        // rejected or currently unavailable. A supported function that has not
        // passed driver admission remains unavailable and cannot skip stages.
        unsupported: discovered,
        enabled: 0,
        exposed: 0,
        verified: 0,
        security_critical: true,
    }
}

fn emit(domain: &'static str, facts: CapabilityFacts) {
    match classify(facts) {
        Ok(stage) => kprintln!(
            "[JSR-CAPABILITY] domain={} state={} inventory={} discovered={} supported={} admitted={} rejected={} unsupported={} enabled={} exposed={} verified={} fault=none",
            domain,
            stage.name(),
            facts.coverage.name(),
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
            "[JSR-CAPABILITY] domain={} state=invalid inventory={} discovered={} supported={} admitted={} rejected={} unsupported={} enabled={} exposed={} verified={} fault={}",
            domain,
            facts.coverage.name(),
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
            coverage: CapabilityCoverage::Complete,
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
        let supported_mask = u64::from(core::arch::x86_64::__cpuid_count(0xD, 0).eax); // JASPER-ISA-REFERENCE: x86 XSAVE discovery.
        let enabled_mask = crate::arch::x86_64::xstate::mask(); // JASPER-ISA-REFERENCE: x86 XSAVE policy.
        let supported = supported_mask.count_ones();
        let enabled = enabled_mask.count_ones();
        emit(
            "system.cpu.xstate",
            CapabilityFacts {
                coverage: CapabilityCoverage::Complete,
                discovered: supported_mask.count_ones(),
                kernel_supported: supported,
                admitted: enabled,
                rejected: 0,
                unsupported: (supported_mask & !enabled_mask).count_ones(),
                enabled,
                exposed: enabled,
                verified: 0,
                security_critical: true,
            },
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    emit("system.cpu.xstate", CapabilityFacts::default());

    let (pci_discovered, pci_admitted, pci_rejected) =
        crate::pci::table()
            .devices()
            .fold((0u32, 0u32, 0u32), |counts, device| {
                let chain_failure = u32::from(device.caps_error);
                (
                    counts
                        .0
                        .saturating_add(device.cap_discovered as u32)
                        .saturating_add(chain_failure),
                    counts.1.saturating_add(device.caps.len() as u32),
                    counts
                        .2
                        .saturating_add(device.cap_rejected as u32)
                        .saturating_add(chain_failure),
                )
            });
    let pci_publishable = pci_rejected == 0;
    emit(
        "system.device.pci-capabilities",
        CapabilityFacts {
            coverage: CapabilityCoverage::Complete,
            discovered: pci_discovered,
            kernel_supported: pci_discovered,
            admitted: pci_admitted,
            rejected: pci_rejected,
            unsupported: 0,
            enabled: if pci_publishable { pci_admitted } else { 0 },
            exposed: if pci_publishable { pci_admitted } else { 0 },
            verified: 0,
            security_critical: true,
        },
    );

    emit(
        "system.network",
        pci_class_facts(PCI_CLASS_NETWORK, |device| {
            device.header.vendor == crate::virtio::VIRTIO_VENDOR
                && crate::virtio::is_net_device(device.header.device)
                && has_modern_virtio_transport(device)
        }),
    );
    emit(
        "system.device.gpu",
        pci_class_facts(PCI_CLASS_DISPLAY, |device| {
            device.header.vendor == crate::virtio::VIRTIO_VENDOR
                && crate::virtio::is_gpu_device(device.header.device)
                && has_modern_virtio_transport(device)
        }),
    );
}
