# Issue 95 formal AMD physical deployment

Status: **PXE/TFTP ready; physical result pending user restart.**

- Profile: `smp-matrix-only`
- Formal sample scale: 1,000,000 per metric per CPU
- QEMU smoke: disabled
- Emulator auto-exit: disabled
- Rejected `fast-leaf-yield` candidate: disabled and removed from source
- PXE/TFTP server: `192.168.68.52`

```text
0bf4ac7fceb6b56e2fa0ebf41ac11e5065c0418d43507c110e64a30763a166f8  kernel-x86_64
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  bootloader.efi
```

No physical performance result is claimed by this directory yet.
