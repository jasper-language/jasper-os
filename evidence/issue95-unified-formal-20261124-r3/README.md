# Issue 95 unified formal PXE image r3

Formal physical-test image after the switch-barrier and early-console layout
fixes.

- Profile: `smp-matrix-only`
- Sample scale: 1,000,000 per metric per participating CPU
- Matrix order: `SMP_SINGLE`, `SMP_PHYSICAL`, `SMP_LOGICAL`
- Physical result: pending

Artifact digests:

```text
b1c22f046e1f49e26f1ecc82a2f5afd5d3fa1f5f030aa16ecb31df1fa350e213  kernel-x86_64
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  bootloader.efi
```

The deployed PXE service serves this exact kernel digest.
