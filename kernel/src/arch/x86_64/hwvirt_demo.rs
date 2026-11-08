//! HWV-0 discovery probe. It never enters VMX root or SVM host mode.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use kernel_core::hwvirt::{
    select, Backend, Capabilities, Capability, ContractError, Discovery, Request, Vendor,
};
use crate::kprintln;

static FAILED: AtomicU32 = AtomicU32::new(0);
static SELECTED_BACKEND: AtomicU8 = AtomicU8::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// Backend selected by the real HWV-0 probe. `None` means the host exposed no
/// supported hardware-virtualization backend.
pub fn selected_backend() -> Option<Backend> {
    match SELECTED_BACKEND.load(Ordering::Acquire) {
        1 => Some(Backend::Vmx),
        2 => Some(Backend::Svm),
        _ => None,
    }
}

fn read_msr(index: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: callers only read IA32_VMX_EPT_VPID_CAP after CPUID advertises
    // VMX. The probe performs no write and does not enter VMX operation.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") index,
            out("eax") lo,
            out("edx") hi,
            options(nostack)
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

pub fn run() {
    let leaf0 = core::arch::x86_64::__cpuid(0);
    let leaf1 = core::arch::x86_64::__cpuid(1);
    let vendor = if leaf0.ebx == u32::from_le_bytes(*b"Genu")
        && leaf0.edx == u32::from_le_bytes(*b"ineI")
        && leaf0.ecx == u32::from_le_bytes(*b"ntel")
    {
        Vendor::Intel
    } else if leaf0.ebx == u32::from_le_bytes(*b"Auth")
        && leaf0.edx == u32::from_le_bytes(*b"enti")
        && leaf0.ecx == u32::from_le_bytes(*b"cAMD")
    {
        Vendor::Amd
    } else {
        Vendor::Other
    };

    let mut caps = Vec::new();
    let vmx = leaf1.ecx & (1 << 5) != 0;
    if vmx {
        caps.push(Capability::Vmx);
    }
    if leaf1.ecx & (1 << 21) != 0 {
        caps.push(Capability::X2Apic);
    }

    let ext_max = core::arch::x86_64::__cpuid(0x8000_0000).eax;
    let mut svm = false;
    if ext_max >= 0x8000_0001 {
        let ext1 = core::arch::x86_64::__cpuid(0x8000_0001);
        svm = ext1.ecx & (1 << 2) != 0;
        if svm {
            caps.push(Capability::Svm);
        }
    }
    if svm && ext_max >= 0x8000_000a {
        let ext_a = core::arch::x86_64::__cpuid(0x8000_000a);
        if ext_a.edx & 1 != 0 {
            caps.push(Capability::Npt);
        }
    }
    if vmx {
        // IA32_VMX_EPT_VPID_CAP: bit 6 is the four-level EPT page-walk form.
        let ept = read_msr(0x48c);
        if ept & (1 << 6) != 0 {
            caps.push(Capability::Ept);
        }
    }

    let available = Capabilities::from_capabilities(&caps);
    let discovery = Discovery { vendor, available };
    let selected = select(discovery, Request { backend: None, required: Capabilities::EMPTY });
    let selected_name = match selected {
        Ok(Backend::Vmx) => "vmx",
        Ok(Backend::Svm) => "svm",
        Err(_) => "unsupported",
    };
    SELECTED_BACKEND.store(
        match selected {
            Ok(Backend::Vmx) => 1,
            Ok(Backend::Svm) => 2,
            Err(_) => 0,
        },
        Ordering::Release,
    );

    let rejection = select(
        discovery,
        Request {
            backend: None,
            required: Capabilities::from_capabilities(&[
                Capability::Iommu,
                Capability::InterruptRemapping,
            ]),
        },
    );
    let rejection_name = match rejection {
        Err(ContractError::Missing(Capability::Iommu)) => "iommu",
        Err(ContractError::Dependency { requested, required }) => {
            let _ = (requested.name(), required.name());
            "dependency"
        }
        Ok(_) => "accepted",
        Err(_) => "rejected",
    };

    let mut failed = 0u32;
    if selected.is_err() && !matches!(selected, Err(ContractError::NoBackend)) {
        failed += 1;
    }
    FAILED.store(failed, Ordering::Relaxed);
    kprintln!(
        "[JSR-HWV0] vendor={:?} matrix={} caps={:#x} selected={} reject={} failed={}",
        vendor,
        kernel_core::hwvirt::CAPABILITY_MATRIX.len(),
        available.bits(),
        selected_name,
        rejection_name,
        failed
    );
}
