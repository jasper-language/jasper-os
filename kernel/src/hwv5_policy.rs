//! Runtime binding for the HWV-5 unified device and VMM policy gate.
//!
//! 职责：固定资源登记、统一授权和审计计数；设备驱动在产生效果前调用。
//! Responsibility: fail-closed runtime entry for all HWV-5 device surfaces.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kernel_core::hwv5_pep::{
    Hwv5Decision, Hwv5Effect, Hwv5Pep, Hwv5Request, Hwv5Resource, Hwv5Subject, CONTROL, READ,
    VM_ENTER, WRITE,
};
pub use kernel_core::hwv5_pep::Hwv5Surface;
use kernel_core::mac::{class_bit, Integrity, MacLabel, Secrecy, OBJECT_CLASS_ALL};
use kernel_core::security::SecurityDomain;
use kernel_core::security_domain::DomainKey;

use crate::sync::IrqSpinLock;

const PIO_OBJECT: u64 = 0x5000;
const NET_OBJECT: u64 = 0x5001;
const FS_OBJECT: u64 = 0x5002;
const VMM_OBJECT_BASE: u64 = 0x6000;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static SURFACE_ROTATIONS: AtomicU64 = AtomicU64::new(0);
static PEP: IrqSpinLock<Hwv5Pep<8, 8, 4096>> =
    IrqSpinLock::ranked(crate::lockorder::HWV5_POLICY, Hwv5Pep::new());

/// 一个设备面在创建时取得的安全世代租约。
///
/// A security-generation lease captured when a VM device or VMM service is
/// created. A retired surface rejects the stale lease even while its backend
/// object is still reachable through an old execution context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hwv5Lease {
    pub object: u64,
    pub generation: u32,
    pub surface: Hwv5Surface,
}

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

const fn object_for_surface(surface: Hwv5Surface) -> u64 {
    match surface {
        Hwv5Surface::Pio => PIO_OBJECT,
        Hwv5Surface::Net => NET_OBJECT,
        Hwv5Surface::Fs => FS_OBJECT,
        Hwv5Surface::Vmm => VMM_OBJECT_BASE,
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

/// 读取当前活动的设备面租约。
///
/// Returns the current active lease, or `None` when the surface is retired.
pub fn lease(surface: Hwv5Surface) -> Option<Hwv5Lease> {
    if !INITIALIZED.load(Ordering::Acquire) && !init() {
        return None;
    }
    let object = object_for_surface(surface);
    let pep = PEP.lock();
    Some(Hwv5Lease {
        object,
        generation: pep.active_generation(object)?,
        surface,
    })
}

/// 使用显式世代租约检查一次效果。
///
/// Authorizes one effect with the exact generation captured by the caller.
pub fn authorize_lease(lease: Hwv5Lease, rights: u32, effect: Hwv5Effect) -> bool {
    if lease.object != object_for_surface(lease.surface) {
        return false;
    }
    PEP.lock().authorize(
        subject(),
        Hwv5Request {
            object: lease.object,
            generation: lease.generation,
            surface: lease.surface,
            rights,
            effect,
        },
    ) == Ok(Hwv5Decision::Allowed)
}

/// 撤销一个设备面的当前对象，所有旧租约立即失效。
///
/// Retires the current object for one surface; the caller must obtain a new
/// lease through [`resume_surface`] with a newer generation.
pub fn retire_surface(surface: Hwv5Surface) -> bool {
    if !INITIALIZED.load(Ordering::Acquire) && !init() {
        return false;
    }
    PEP.lock().revoke(object_for_surface(surface)).is_ok()
}

/// 以严格递增的世代恢复一个被撤销的设备面。
///
/// Restores a retired surface by binding a strictly newer generation.
pub fn resume_surface(surface: Hwv5Surface) -> Option<Hwv5Lease> {
    if !INITIALIZED.load(Ordering::Acquire) && !init() {
        return None;
    }
    let object = object_for_surface(surface);
    let mut pep = PEP.lock();
    let next = pep.registered_generation(object)?.checked_add(1)?;
    pep.renew(resource(object, surface, next)).ok()?;
    SURFACE_ROTATIONS.fetch_add(1, Ordering::Relaxed);
    Some(Hwv5Lease {
        object,
        generation: next,
        surface,
    })
}

/// 设备复位时原子撤销旧世代并安装下一世代租约。
///
/// Rotates one surface on reset. If reset validation fails, no partial state
/// change is published and no new lease is returned.
pub fn rotate_surface(surface: Hwv5Surface) -> Option<Hwv5Lease> {
    if !INITIALIZED.load(Ordering::Acquire) && !init() {
        return None;
    }
    let object = object_for_surface(surface);
    let mut pep = PEP.lock();
    let next = pep.registered_generation(object)?.checked_add(1)?;
    pep.reset_surface(surface).ok()?;
    pep.renew(resource(object, surface, next)).ok()?;
    SURFACE_ROTATIONS.fetch_add(1, Ordering::Relaxed);
    Some(Hwv5Lease {
        object,
        generation: next,
        surface,
    })
}

fn allow(
    surface: Hwv5Surface,
    rights: u32,
    effect: Hwv5Effect,
) -> bool {
    if !INITIALIZED.load(Ordering::Acquire) && !init() {
        return false;
    }
    lease(surface).is_some_and(|lease| authorize_lease(lease, rights, effect))
}

pub fn pio_read() -> bool {
    allow(Hwv5Surface::Pio, READ, Hwv5Effect::Read)
}

pub fn pio_write() -> bool {
    allow(Hwv5Surface::Pio, WRITE, Hwv5Effect::Write)
}

pub fn net_read() -> bool {
    allow(Hwv5Surface::Net, READ, Hwv5Effect::Read)
}

pub fn net_write() -> bool {
    allow(Hwv5Surface::Net, WRITE, Hwv5Effect::Write)
}

pub fn fs_read() -> bool {
    allow(Hwv5Surface::Fs, READ, Hwv5Effect::Read)
}

pub fn fs_write() -> bool {
    allow(Hwv5Surface::Fs, WRITE, Hwv5Effect::Write)
}

/// 使用创建时的 PIO 租约授权一次读取。
///
/// Authorizes one PIO read with a caller-held generation lease.
pub fn pio_read_at(lease: Option<Hwv5Lease>) -> bool {
    lease.is_some_and(|lease| authorize_lease(lease, READ, Hwv5Effect::Read))
}

/// 使用创建时的 PIO 租约授权一次写入。
///
/// Authorizes one PIO write with a caller-held generation lease.
pub fn pio_write_at(lease: Option<Hwv5Lease>) -> bool {
    lease.is_some_and(|lease| authorize_lease(lease, WRITE, Hwv5Effect::Write))
}

/// 使用创建时的网络租约授权一次读取。
///
/// Authorizes one network read with a caller-held generation lease.
pub fn net_read_at(lease: Option<Hwv5Lease>) -> bool {
    lease.is_some_and(|lease| authorize_lease(lease, READ, Hwv5Effect::Read))
}

/// 使用创建时的网络租约授权一次写入。
///
/// Authorizes one network write with a caller-held generation lease.
pub fn net_write_at(lease: Option<Hwv5Lease>) -> bool {
    lease.is_some_and(|lease| authorize_lease(lease, WRITE, Hwv5Effect::Write))
}

/// 使用创建时的文件租约授权一次读取。
///
/// Authorizes one filesystem read with a caller-held generation lease.
pub fn fs_read_at(lease: Option<Hwv5Lease>) -> bool {
    lease.is_some_and(|lease| authorize_lease(lease, READ, Hwv5Effect::Read))
}

/// 使用创建时的文件租约授权一次写入。
///
/// Authorizes one filesystem write with a caller-held generation lease.
pub fn fs_write_at(lease: Option<Hwv5Lease>) -> bool {
    lease.is_some_and(|lease| authorize_lease(lease, WRITE, Hwv5Effect::Write))
}

pub fn vmm_exit(generation: u32) -> bool {
    prepare_vmm(generation)
        && lease(Hwv5Surface::Vmm).is_some_and(|lease| {
            lease.generation == generation
                && authorize_lease(lease, VM_ENTER | CONTROL, Hwv5Effect::Control)
        })
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

/// 返回已完成的设备面安全世代轮换次数。
///
/// Returns the number of completed device-surface generation rotations.
pub fn surface_rotations() -> u64 {
    SURFACE_ROTATIONS.load(Ordering::Relaxed)
}

pub fn verify_runtime() -> bool {
    init();
    let allowed = pio_read();
    let denied = lease(Hwv5Surface::Pio).is_some_and(|lease| {
        lease.generation.checked_add(1).is_none_or(|generation| {
            let stale = Hwv5Lease { generation, ..lease };
            !authorize_lease(stale, READ, Hwv5Effect::Read)
        })
    });
    allowed && denied
}
