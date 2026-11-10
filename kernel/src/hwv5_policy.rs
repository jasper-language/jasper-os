//! Runtime binding for the HWV-5 unified device and VMM policy gate.
//!
//! 职责：固定资源登记、统一授权和审计计数；设备驱动在产生效果前调用。
//! Responsibility: fail-closed runtime entry for all HWV-5 device surfaces.

use core::sync::atomic::{AtomicBool, Ordering};

use kernel_core::hwv5_pep::{
    Hwv5Decision, Hwv5Effect, Hwv5Pep, Hwv5Request, Hwv5Resource, Hwv5Subject, Hwv5Surface,
    CONTROL, READ, VM_ENTER, WRITE,
};
use kernel_core::mac::{class_bit, Integrity, MacLabel, Secrecy, OBJECT_CLASS_ALL};
use kernel_core::security::SecurityDomain;
use kernel_core::security_domain::DomainKey;

use crate::sync::IrqSpinLock;

const PIO_OBJECT: u64 = 0x5000;
const NET_OBJECT: u64 = 0x5001;
const FS_OBJECT: u64 = 0x5002;
const VMM_OBJECT_BASE: u64 = 0x6000;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static PEP: IrqSpinLock<Hwv5Pep<8, 8, 4096>> =
    IrqSpinLock::ranked(crate::lockorder::HWV5_POLICY, Hwv5Pep::new());

fn owner() -> DomainKey {
    DomainKey {
        id: 1,
        generation: 1,
    }
}

fn subject() -> Hwv5Subject {
    Hwv5Subject {
        domain: owner(),
        label: MacLabel::new(
            SecurityDomain::USER,
            Secrecy::Secret,
            Integrity::System,
            OBJECT_CLASS_ALL,
        ),
    }
}

fn resource(object: u64, surface: Hwv5Surface, generation: u32) -> Hwv5Resource {
    let class = surface.identity_class();
    Hwv5Resource {
        object,
        generation,
        owner: owner(),
        surface,
        label: MacLabel::new(
            SecurityDomain::USER,
            Secrecy::Internal,
            Integrity::Managed,
            class_bit(class),
        ),
        rights: surface.allowed_rights(),
    }
}

fn register_if_absent(object: u64, surface: Hwv5Surface, generation: u32) -> bool {
    let mut pep = PEP.lock();
    pep.renew(resource(object, surface, generation)).is_ok()
}

pub fn init() -> bool {
    if INITIALIZED.load(Ordering::Acquire) {
        return true;
    }
    let ok = register_if_absent(PIO_OBJECT, Hwv5Surface::Pio, 1)
        && register_if_absent(NET_OBJECT, Hwv5Surface::Net, 1)
        && register_if_absent(FS_OBJECT, Hwv5Surface::Fs, 1)
        && register_if_absent(VMM_OBJECT_BASE, Hwv5Surface::Vmm, 1);
    if ok {
        INITIALIZED.store(true, Ordering::Release);
    }
    ok
}

pub fn prepare_vmm(generation: u32) -> bool {
    if generation == 0 {
        return false;
    }
    register_if_absent(VMM_OBJECT_BASE, Hwv5Surface::Vmm, generation)
}

fn allow(
    object: u64,
    generation: u32,
    surface: Hwv5Surface,
    rights: u32,
    effect: Hwv5Effect,
) -> bool {
    if !INITIALIZED.load(Ordering::Acquire) && !init() {
        return false;
    }
    PEP.lock().authorize(
        subject(),
        Hwv5Request {
            object,
            generation,
            surface,
            rights,
            effect,
        },
    ) == Ok(Hwv5Decision::Allowed)
}

pub fn pio_read() -> bool {
    allow(PIO_OBJECT, 1, Hwv5Surface::Pio, READ, Hwv5Effect::Read)
}

pub fn pio_write() -> bool {
    allow(PIO_OBJECT, 1, Hwv5Surface::Pio, WRITE, Hwv5Effect::Write)
}

pub fn net_read() -> bool {
    allow(NET_OBJECT, 1, Hwv5Surface::Net, READ, Hwv5Effect::Read)
}

pub fn net_write() -> bool {
    allow(NET_OBJECT, 1, Hwv5Surface::Net, WRITE, Hwv5Effect::Write)
}

pub fn fs_read() -> bool {
    allow(FS_OBJECT, 1, Hwv5Surface::Fs, READ, Hwv5Effect::Read)
}

pub fn fs_write() -> bool {
    allow(FS_OBJECT, 1, Hwv5Surface::Fs, WRITE, Hwv5Effect::Write)
}

pub fn vmm_exit(generation: u32) -> bool {
    prepare_vmm(generation);
    allow(
        VMM_OBJECT_BASE,
        generation,
        Hwv5Surface::Vmm,
        VM_ENTER | CONTROL,
        Hwv5Effect::Control,
    )
}

pub fn revive_vmm(generation: u32) -> bool {
    generation != 0 && prepare_vmm(generation)
}

pub fn stats() -> (usize, usize, u64) {
    let pep = PEP.lock();
    let mut allowed = 0usize;
    let mut denied = 0usize;
    for event in pep.audit_events() {
        match event.decision {
            Hwv5Decision::Allowed => allowed += 1,
            Hwv5Decision::Denied(_) => denied += 1,
        }
    }
    (allowed, denied, pep.audit_overflow())
}

pub fn verify_runtime() -> bool {
    init();
    let mut pep = PEP.lock();
    let allowed = pep.authorize(
        subject(),
        Hwv5Request {
            object: PIO_OBJECT,
            generation: 1,
            surface: Hwv5Surface::Pio,
            rights: READ,
            effect: Hwv5Effect::Read,
        },
    ) == Ok(Hwv5Decision::Allowed);
    let denied = matches!(
        pep.authorize(
            subject(),
            Hwv5Request {
                object: PIO_OBJECT,
                generation: 2,
                surface: Hwv5Surface::Pio,
                rights: READ,
                effect: Hwv5Effect::Read,
            },
        ),
        Ok(Hwv5Decision::Denied(_))
    );
    allowed && denied
}
