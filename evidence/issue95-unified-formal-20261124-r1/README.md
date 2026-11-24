# Issue 95 unified formal PXE image

Formal physical-test image, 2026-11-24.

- Profile: `smp-matrix-only`
- Sample scale: 1,000,000 per metric per participating CPU
- Matrix order: `SMP_SINGLE`, `SMP_PHYSICAL`, `SMP_LOGICAL`
- QEMU smoke exclusion: all three modes passed the separate QEMU control
- Physical result: pending

Artifact digests:

```text
0e575162b6792710d54085c6d54f228e33c15dee15e14eeccb897e6e3547b0d6  kernel-x86_64
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  bootloader.efi
```

The image booted through the real UEFI PXE control path in QEMU/OVMF. This does
not claim a physical result. The deployed PXE service serves this exact kernel
digest.
