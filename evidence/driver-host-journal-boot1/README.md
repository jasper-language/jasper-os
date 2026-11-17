# Driver Host authority journal — first boot

The first real OVMF boot mounts the reserved P0 journal region, verifies that
it is completely empty, formats it, and records one host registration followed
by one device admission.

```text
ISSUE21_UEFI_MODE=driver-host-journal \
ISSUE21_QEMU_CPUS=6-7 \
ISSUE21_QEMU_SMP=2 \
ISSUE21_DRIVER_HOST_EXPECT=initialized \
bash scripts/issue21-uefi-boot-check.sh
```

```text
[JSR-DRIVER-HOST-JOURNAL] mounted=true initialized=true sequence=2 last=admitted device=0x00000400 generation=1 live_restored=false
[JSR-DRIVER-HOST-JOURNAL] summary initialized=true sequence=2 device=0x00000400 generation=1 live_restored=false ok=true
```

The device identity is derived from the admitted virtio-blk PCI function.
The journal stores authority receipts only and never a live host pass or
request. The P0 image and OVMF variables were retained for the second boot.
