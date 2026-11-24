# Issue 95 formal AMD physical deployment

Status: **PXE/TFTP ready; physical result pending user restart.**

- Profile: `smp-matrix-only`
- Formal sample scale: 1,000,000 per metric per CPU
- QEMU smoke: disabled
- Emulator auto-exit: disabled
- Rejected `fast-leaf-yield` candidate: disabled and removed from source
- PXE/TFTP server: `192.168.68.52`

```text
a22941d362d7dcaf194f207f86eb49ffd9f60e4c1e19a74e516c53d3dd56f7c1  kernel-x86_64
c21e82553c838189191e05c303eddde3dfb6b4e5893c02aa1a1bc1d2a2121b65  bootloader.efi
```

No physical performance result is claimed by this directory yet.
