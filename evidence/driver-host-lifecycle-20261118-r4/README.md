# Persistent Driver Host lifecycle receipts

Date: 2026-11-18.

This two-boot OVMF/virtio-blk drill connects the package lifecycle controller
and Driver Host broker to one persisted receipt history. It resets a real
virtio-rng transport, reads back the PCI bus-master state, and uses that
quiescence fact for crash, recovery and orderly reset.

First boot:

```text
event=admitted host_generation=1 pass_generation=1
event=crashed revoked_passes=1 dma_quiesced=true irq_quiesced=true
event=recovered host_generation=2 dma_quiesced=true irq_quiesced=true
event=reset host_generation=3 dma_quiesced=true irq_quiesced=true
mounted=true initialized=true sequence=5 last=reset
live_restored=false
qemu_rc=33
```

Second boot on the same P0 and OVMF state:

```text
mounted=true initialized=false sequence=5 last=reset
device=0x00000300 generation=1
live_restored=false
qemu_rc=33
```

Command:

```text
LC4_LIFECYCLE_OUT="$PWD/evidence/driver-host-lifecycle-20261118-r4" \
LC4_LIFECYCLE_TARGET="$PWD/target/issue21-driver-lifecycle" \
ISSUE21_UEFI_TIMEOUT=180 \
bash scripts/driver-host-lifecycle-check.sh
```

This proves QEMU/OVMF-controlled persistent lifecycle receipts and real
virtio transport reset/bus-master readback. It does not prove Pixel UFS/GPU
driver reuse, physical SMMU/IOMMU teardown, vendor firmware recovery or a
second physical hardware profile.
