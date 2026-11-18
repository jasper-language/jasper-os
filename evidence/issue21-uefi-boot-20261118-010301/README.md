# DC-1 opaque IOVA to VT-d final acceptance

Date: 2026-11-18

The final architecture-neutral DMA path boots through OVMF with QEMU's
emulated Intel IOMMU. `dma::create_for` allocates an opaque IOVA and, when a
DMAR unit covers the device, programs a bounded 4 KiB VT-d second-level
mapping through the `arch` seam.

```text
[JSR-IOMMU-DMA] hardware_iommu=true iova=0x1000000 physical=0x10aa000 translated=true
[JSR-DRV3] device=0x300 iova=0x1000000 pages=1 writable=true
  iova_opaque=true pinned=true owner_close=true reclaim=true failed=0
[JSR-IOMMU-DMA] finish failed=0
qemu_rc=33
```

The test compares a hardware translation walk with the pinned Memory frame.
Closing the DMA handle disables bus mastering, clears the PTE, invalidates VT-d,
and returns all temporary IOMMU page tables so the frame baseline is restored.

This closes only the minimum opaque IOVA -> VT-d translation -> unmap backend.
It does not close a real user Driver Host descriptor/notify/used-ring
completion, physical-device DMA fault injection, or Pixel 6a driver lifecycle.
