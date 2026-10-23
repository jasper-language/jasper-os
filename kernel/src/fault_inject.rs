//! Test-only fault sites, disabled unless explicitly armed.
pub use kernel_core::fault::FaultPoint;
pub static FRAME: FaultPoint = FaultPoint::new();
pub static HEAP: FaultPoint = FaultPoint::new();
pub static RESET_TIMEOUT: FaultPoint = FaultPoint::new();
pub static IPI_TIMEOUT: FaultPoint = FaultPoint::new();

/// Bootstrap acceptance: explicitly arm each real hook, then verify recovery.
/// Calls occur before general workloads; a seed fixes the per-site invocation.
pub fn selftest() -> u32 {
    use core::alloc::{GlobalAlloc, Layout};
    use crate::{mm, smp, virtio, pci, kprintln};
    let mut failed = 0u32;
    let frames = mm::frame::free_frames();
    FRAME.arm(0xb001, 1).unwrap();
    if mm::frame::allocate().is_ok() { failed += 1; }
    if mm::frame::free_frames() != frames { failed += 1; }
    // Verify the site is one-shot and the allocator still works.
    match mm::frame::allocate() {
        Ok(f) => { if mm::frame::deallocate(f).is_err() { failed += 1; } }
        Err(_) => failed += 1,
    }
    if mm::frame::free_frames() != frames { failed += 1; }
    let frame_conserved = mm::frame::free_frames() == frames;
    let heap = mm::heap::stats();
    HEAP.arm(0xb002, 1).unwrap();
    let layout = Layout::from_size_align(64, 16).unwrap();
    // Direct fallible GlobalAlloc call: never feed an injected null to Box/Vec.
    let ptr = unsafe { mm::heap::KernelHeap.alloc(layout) };
    if !ptr.is_null() {
        failed += 1;
        unsafe { mm::heap::KernelHeap.dealloc(ptr, layout); }
    }
    if mm::heap::stats() != heap { failed += 1; }
    let heap_conserved = mm::heap::stats() == heap;
    IPI_TIMEOUT.arm(0xb003, 1).unwrap();
    // Invalidate a valid, unmapped page; no mapping or frame is reclaimed here.
    let va = mm::heap::HEAP_START;
    if smp::tlb_shootdown_on(smp::online_set(), va, 1) != Err(kernel_core::smp::SmpError::Timeout) {
        failed += 1;
    }
    if smp::tlb_shootdown_on(smp::online_set(), va, 1).is_err() { failed += 1; }
    let device = pci::table().devices().find(|d|
        d.header.vendor == virtio::VIRTIO_VENDOR && virtio::is_rng_device(d.header.device));
    if let Some(d) = device {
        match virtio::VirtioPci::new(d) {
            Ok(v) => {
                RESET_TIMEOUT.arm(0xb004, 1).unwrap();
                if !matches!(v.reset(), Err(virtio::VirtioError::ResetTimeout)) { failed += 1; }
                if v.reset().is_err() { failed += 1; }
            }
            Err(_) => failed += 1,
        }
    } else { failed += 1; }
    FRAME.disarm(); HEAP.disarm(); IPI_TIMEOUT.disarm(); RESET_TIMEOUT.disarm();
    kprintln!("[JSR-FAULT] sites=4 seed=45057 frame_conserved={} heap_conserved={} failed={}",
        frame_conserved, heap_conserved, failed);
    failed
}
