//! HWV-0 hardware-virtualization capability contract.
//!
//! Discovery is deliberately separate from activation. This module only names
//! capabilities, validates dependencies and rejects unsupported requests. A
//! successful selection is permission for a later backend milestone, not
//! evidence that VMX/SVM has been entered.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    Intel,
    Amd,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Capability {
    Vmx = 0,
    Svm = 1,
    Ept = 2,
    Npt = 3,
    Iommu = 4,
    Vtd = 5,
    AmdVi = 6,
    InterruptRemapping = 7,
    X2Apic = 8,
    PostedInterrupts = 9,
}

impl Capability {
    pub const ALL: [Capability; 10] = [
        Capability::Vmx,
        Capability::Svm,
        Capability::Ept,
        Capability::Npt,
        Capability::Iommu,
        Capability::Vtd,
        Capability::AmdVi,
        Capability::InterruptRemapping,
        Capability::X2Apic,
        Capability::PostedInterrupts,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Capability::Vmx => "vmx",
            Capability::Svm => "svm",
            Capability::Ept => "ept",
            Capability::Npt => "npt",
            Capability::Iommu => "iommu",
            Capability::Vtd => "vtd",
            Capability::AmdVi => "amd_vi",
            Capability::InterruptRemapping => "interrupt_remapping",
            Capability::X2Apic => "x2apic",
            Capability::PostedInterrupts => "posted_interrupts",
        }
    }

    pub const fn dependency(self) -> Option<Capability> {
        match self {
            Capability::Ept => Some(Capability::Vmx),
            Capability::Npt => Some(Capability::Svm),
            Capability::Vtd | Capability::AmdVi | Capability::InterruptRemapping => {
                Some(Capability::Iommu)
            }
            Capability::Vmx
            | Capability::Svm
            | Capability::Iommu
            | Capability::X2Apic
            | Capability::PostedInterrupts => None,
        }
    }

    const fn bit(self) -> u64 {
        1u64 << self as u8
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities(u64);

impl Capabilities {
    pub const EMPTY: Self = Self(0);
    const VALID: u64 = (1u64 << Capability::ALL.len()) - 1;

    pub const fn from_bits(bits: u64) -> Result<Self, ContractError> {
        if bits & !Self::VALID != 0 {
            Err(ContractError::UnknownBits)
        } else {
            Ok(Self(bits))
        }
    }

    pub const fn from_capabilities(caps: &[Capability]) -> Self {
        let mut bits = 0u64;
        let mut i = 0;
        while i < caps.len() {
            bits |= caps[i].bit();
            i += 1;
        }
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Vmx,
    Svm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilitySpec {
    pub capability: Capability,
    pub dependency: Option<Capability>,
    pub unsupported: &'static str,
}

pub const CAPABILITY_MATRIX: &[CapabilitySpec] = &[
    CapabilitySpec { capability: Capability::Vmx, dependency: None, unsupported: "hwvirt.unsupported.vmx" },
    CapabilitySpec { capability: Capability::Svm, dependency: None, unsupported: "hwvirt.unsupported.svm" },
    CapabilitySpec { capability: Capability::Ept, dependency: Some(Capability::Vmx), unsupported: "hwvirt.unsupported.ept" },
    CapabilitySpec { capability: Capability::Npt, dependency: Some(Capability::Svm), unsupported: "hwvirt.unsupported.npt" },
    CapabilitySpec { capability: Capability::Iommu, dependency: None, unsupported: "hwvirt.unsupported.iommu" },
    CapabilitySpec { capability: Capability::Vtd, dependency: Some(Capability::Iommu), unsupported: "hwvirt.unsupported.vtd" },
    CapabilitySpec { capability: Capability::AmdVi, dependency: Some(Capability::Iommu), unsupported: "hwvirt.unsupported.amd_vi" },
    CapabilitySpec { capability: Capability::InterruptRemapping, dependency: Some(Capability::Iommu), unsupported: "hwvirt.unsupported.interrupt_remapping" },
    CapabilitySpec { capability: Capability::X2Apic, dependency: None, unsupported: "hwvirt.unsupported.x2apic" },
    CapabilitySpec { capability: Capability::PostedInterrupts, dependency: None, unsupported: "hwvirt.unsupported.posted_interrupts" },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    UnknownBits,
    NoBackend,
    VendorMismatch,
    Missing(Capability),
    Dependency { requested: Capability, required: Capability },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Discovery {
    pub vendor: Vendor,
    pub available: Capabilities,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub backend: Option<Backend>,
    pub required: Capabilities,
}

/// Select exactly one vendor backend and enforce the dependency closure.
pub fn select(discovery: Discovery, request: Request) -> Result<Backend, ContractError> {
    for capability in Capability::ALL {
        if let Some(required) = capability.dependency() {
            if request.required.contains(capability) && !request.required.contains(required) {
                return Err(ContractError::Dependency { requested: capability, required });
            }
        }
        if request.required.contains(capability) && !discovery.available.contains(capability) {
            return Err(ContractError::Missing(capability));
        }
    }

    let backend = match request.backend {
        Some(Backend::Vmx) if discovery.vendor != Vendor::Intel => {
            return Err(ContractError::VendorMismatch)
        }
        Some(Backend::Svm) if discovery.vendor != Vendor::Amd => {
            return Err(ContractError::VendorMismatch)
        }
        Some(Backend::Vmx) => Backend::Vmx,
        Some(Backend::Svm) => Backend::Svm,
        None if discovery.vendor == Vendor::Intel && discovery.available.contains(Capability::Vmx) => {
            Backend::Vmx
        }
        None if discovery.vendor == Vendor::Amd && discovery.available.contains(Capability::Svm) => {
            Backend::Svm
        }
        None => return Err(ContractError::NoBackend),
    };

    let required_backend = match backend {
        Backend::Vmx => Capability::Vmx,
        Backend::Svm => Capability::Svm,
    };
    if !discovery.available.contains(required_backend) {
        return Err(ContractError::Missing(required_backend));
    }
    if request.required.contains(Capability::Ept) && backend != Backend::Vmx {
        return Err(ContractError::Dependency { requested: Capability::Ept, required: Capability::Vmx });
    }
    if request.required.contains(Capability::Npt) && backend != Backend::Svm {
        return Err(ContractError::Dependency { requested: Capability::Npt, required: Capability::Svm });
    }
    Ok(backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(items: &[Capability]) -> Capabilities {
        Capabilities::from_capabilities(items)
    }

    #[test]
    fn matrix_is_one_to_one_and_dependencies_match() {
        assert_eq!(CAPABILITY_MATRIX.len(), Capability::ALL.len());
        for (i, capability) in Capability::ALL.iter().enumerate() {
            assert_eq!(CAPABILITY_MATRIX[i].capability, *capability);
            assert_eq!(CAPABILITY_MATRIX[i].dependency, capability.dependency());
            assert!(CAPABILITY_MATRIX[i].unsupported.starts_with("hwvirt.unsupported."));
        }
    }

    #[test]
    fn intel_and_amd_keep_vendor_backends_distinct() {
        let intel = Discovery {
            vendor: Vendor::Intel,
            available: caps(&[Capability::Vmx, Capability::Ept, Capability::X2Apic]),
        };
        assert_eq!(
            select(intel, Request { backend: None, required: caps(&[Capability::Vmx, Capability::Ept]) }),
            Ok(Backend::Vmx)
        );
        assert_eq!(
            select(intel, Request { backend: Some(Backend::Svm), required: Capabilities::EMPTY }),
            Err(ContractError::VendorMismatch)
        );

        let amd = Discovery {
            vendor: Vendor::Amd,
            available: caps(&[Capability::Svm, Capability::Npt]),
        };
        assert_eq!(
            select(amd, Request { backend: None, required: caps(&[Capability::Svm, Capability::Npt]) }),
            Ok(Backend::Svm)
        );
    }

    #[test]
    fn unsupported_and_unknown_inputs_fail_closed() {
        assert_eq!(Capabilities::from_bits(1 << 63), Err(ContractError::UnknownBits));
        let none = Discovery { vendor: Vendor::Other, available: Capabilities::EMPTY };
        assert_eq!(
            select(none, Request { backend: None, required: Capabilities::EMPTY }),
            Err(ContractError::NoBackend)
        );
        assert_eq!(
            select(none, Request { backend: Some(Backend::Vmx), required: caps(&[Capability::Iommu]) }),
            Err(ContractError::Missing(Capability::Iommu))
        );
    }

    #[test]
    fn dependencies_are_checked_before_discovery() {
        let intel = Discovery { vendor: Vendor::Intel, available: caps(&[Capability::Vmx, Capability::Ept]) };
        assert_eq!(
            select(intel, Request { backend: Some(Backend::Vmx), required: caps(&[Capability::Ept]) }),
            Err(ContractError::Dependency { requested: Capability::Ept, required: Capability::Vmx })
        );
        let iommu = Discovery {
            vendor: Vendor::Intel,
            available: caps(&[Capability::Vmx, Capability::Iommu, Capability::Vtd]),
        };
        assert_eq!(
            select(iommu, Request {
                backend: Some(Backend::Vmx),
                required: caps(&[Capability::Iommu, Capability::Vtd]),
            }),
            Ok(Backend::Vmx)
        );
    }
}
