//! PCI configuration access through the QEMU LoongArch `virt` ECAM window.
//!
//! The QEMU firmware describes an ECAM at physical `0x2000_0000`, covering
//! buses 0..=127. The uncached DMW0 window provides a stable, strongly ordered
//! kernel alias without consuming page-table frames.

use alloc::boxed::Box;

use kernel_core::pci::{Bdf, ConfigSpace};

use crate::arch::{PciAccess, PciMechanism};

const ECAM_PA: u64 = 0x2000_0000;
const ECAM_BUSES: core::ops::RangeInclusive<u8> = 0..=127;

struct EcamConfig {
    base: u64,
}

impl EcamConfig {
    fn address(&self, bdf: Bdf, offset: u16) -> Option<u64> {
        if offset > 0xfff {
            return None;
        }
        let bus = u64::from(bdf.bus()) << 20;
        let device = u64::from(bdf.device()) << 15;
        let function = u64::from(bdf.function()) << 12;
        self.base
            .checked_add(bus + device + function + u64::from(offset))
    }
}

impl ConfigSpace for EcamConfig {
    fn read32(&mut self, bdf: Bdf, offset: u16) -> Option<u32> {
        let address = self.address(bdf, offset)?;
        // SAFETY: address is inside the firmware-described ECAM and is a
        // naturally aligned 32-bit configuration-register read.
        Some(unsafe { (address as *const u32).read_volatile() })
    }

    fn write32(&mut self, bdf: Bdf, offset: u16, value: u32) -> bool {
        let Some(address) = self.address(bdf, offset) else {
            return false;
        };
        // SAFETY: as for read32; this writes one configuration double-word.
        unsafe { (address as *mut u32).write_volatile(value) };
        true
    }
}

pub fn access() -> PciAccess {
    let config = Box::leak(Box::new(EcamConfig {
        base: super::mmu::UNCACHED_OFFSET + ECAM_PA,
    }));
    PciAccess {
        config,
        mechanism: PciMechanism::Ecam,
        buses: ECAM_BUSES,
    }
}
