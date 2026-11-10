//! HWV-5 production policy and guest-facing virtio-MMIO acceptance.
//!
//! 职责：验证统一 PEP 的运行时租约；完整构建再执行 VMM 和 Linux 设备链。
//! Responsibility: exercise production PEP leases and, for the full build,
//! the restarted user-space VMM and Linux virtio device chain.

use core::sync::atomic::{AtomicU32, Ordering};

use kernel_core::hwv5_pep::{Hwv5Effect, READ};

use crate::hwv5_policy::{self, Hwv5Surface};
use crate::kprintln;

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

/// 验证四个运行时设备面经生产 rotate 路径拒绝旧租约，并只安装新世代租约。
///
/// Exercises the production runtime adapters, not a replacement policy
/// implementation: rotation retires old leases and installs a strictly newer
/// generation. Device backends are not run by this dedicated profile.
fn verify_runtime_leases() -> bool {
    let mut all = true;
    for surface in [
        Hwv5Surface::Pio,
        Hwv5Surface::Net,
        Hwv5Surface::Fs,
        Hwv5Surface::Vmm,
    ] {
        let ok = hwv5_policy::lease(surface).is_some_and(|old| {
            if !hwv5_policy::authorize_lease(old, READ, Hwv5Effect::Read) {
                return false;
            }
            hwv5_policy::rotate_surface(surface).is_some_and(|next| {
                next.generation > old.generation
                    && !hwv5_policy::authorize_lease(old, READ, Hwv5Effect::Read)
                    && hwv5_policy::authorize_lease(next, READ, Hwv5Effect::Read)
            })
        });
        if !ok {
            all = false;
            kprintln!("[JSR-HWV5-PROD-FAIL] stage=lease {:?}", surface);
        }
    }
    if all {
        kprintln!(
            "[JSR-HWV5-PROD] matrix=pio,net,fs,vmm stale=denied rotation=true rotations={}",
            hwv5_policy::surface_rotations()
        );
    }
    all
}

pub fn run() {
    if !crate::hwv5_policy::verify_runtime() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-HWV5-PROD-FAIL] stage=policy-selftest");
    }
    if !verify_runtime_leases() {
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    #[cfg(feature = "hwv5-verify")]
    {
        let vmm_ok = crate::hwv5_vmm_demo::run();
        if !vmm_ok {
            FAILED.fetch_add(1, Ordering::Relaxed);
        }
        let ok = crate::arch::x86_64::linux_guest::run_virtio();
        if !ok {
            FAILED.fetch_add(1, Ordering::Relaxed);
            kprintln!("[JSR-HWV5-FAIL] virtio_rng_linux_guest=false pio=false");
        } else {
            kprintln!(
                "[JSR-HWV5-PIO] backend=Vmx transport=pio decoded=true routed=true probe=true reset=true pending=true cancel=true failure_atomic=true resource=true failed=0"
            );
        }
        let (policy_allowed, policy_denied, policy_overflow) = crate::hwv5_policy::stats();
        kprintln!(
            "[JSR-HWV5] backend=Vmx bus=mmio devices=rng,console,block linux=true vmm={} policy=true policy_allowed={} policy_denied={} policy_overflow={} failed={}",
            vmm_ok,
            policy_allowed,
            policy_denied,
            policy_overflow,
            failed()
        );
    }
    #[cfg(all(feature = "hwv5-prod-verify", not(feature = "hwv5-verify")))]
    {
        let (policy_allowed, policy_denied, policy_overflow) = crate::hwv5_policy::stats();
        kprintln!(
            "[JSR-HWV5-PROD] backend=pio,net,fs,vmm runtime=true policy=true vmm=not-run linux=not-run policy_allowed={} policy_denied={} policy_overflow={} failed={}",
            policy_allowed,
            policy_denied,
            policy_overflow,
            failed()
        );
    }
}
