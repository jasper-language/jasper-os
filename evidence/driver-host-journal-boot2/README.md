# Driver Host authority journal — second boot

This boot reuses the exact P0 image and OVMF state produced by
`driver-host-journal-boot1`. It does not regenerate the GPT, filesystems,
control records, or journal.

```text
ISSUE21_UEFI_MODE=driver-host-journal \
ISSUE21_UEFI_PREBUILT=1 \
ISSUE21_REUSE_P0=1 \
ISSUE21_QEMU_CPUS=6-7 \
ISSUE21_QEMU_SMP=2 \
ISSUE21_DRIVER_HOST_EXPECT=reopened \
bash scripts/issue21-uefi-boot-check.sh
```

```text
[JSR-DRIVER-HOST-JOURNAL] mounted=true initialized=false sequence=2 last=admitted device=0x00000400 generation=1 live_restored=false
[JSR-DRIVER-HOST-JOURNAL] summary initialized=false sequence=2 device=0x00000400 generation=1 live_restored=false ok=true
```

The persisted registration/admission receipt chain survives a real reboot.
No live capability is restored: a future host must pass fresh admission and
hardware quiescence checks.
