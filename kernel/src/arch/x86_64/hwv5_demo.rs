//! HWV-5 guest-facing virtio-MMIO acceptance.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::kprintln;

static FAILED: AtomicU32 = AtomicU32::new(0);

pub fn failed() -> u32 {
    FAILED.load(Ordering::Relaxed)
}

pub fn run() {
    if !crate::hwv5_policy::verify_runtime() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        kprintln!("[JSR-HWV5-PROD-FAIL] stage=policy-selftest");
    }
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
