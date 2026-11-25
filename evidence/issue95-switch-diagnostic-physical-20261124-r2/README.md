# Issue 95 physical general-switch diagnostic deployment

Date: 2026-11-24.

The PXE TFTP files were refreshed on 2026-11-25 with the BSP trampoline-stage
control in `evidence/issue95-trampoline-stage-qemu-20261125-r2`, using forced
x2APIC.

```text
57de75a2b11f86c55d3b4aa2df702f2c09ed4c8e0b2f9112ab0df0757f91b3db  tftp/kernel-x86_64
011daf7593a1589ffdfca754ce017edd1229f737eb6a9e7053b25ed27d279461  tftp/bootloader.efi
```

The TFTP service was read back after the atomic replacement and returned the
same two hashes. Physical results are not claimed until the AMD machine runs
the refreshed image and reports the post-`T17` stages.
