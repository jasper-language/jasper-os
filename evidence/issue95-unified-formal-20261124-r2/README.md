# Issue 95 unified formal PXE image r2

Formal physical-test image after the single-CPU context-switch fix.

- Profile: `smp-matrix-only`
- Sample scale: 1,000,000 per metric per participating CPU
- Matrix order: `SMP_SINGLE`, `SMP_PHYSICAL`, `SMP_LOGICAL`
- Physical result: pending

Artifact digests:

```text
c98acd67e464b72633db975df315c3799ad8df3a83ce9fe43893b0d11f80ccab  kernel-x86_64
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  bootloader.efi
```

The deployed PXE service serves this exact kernel digest.
