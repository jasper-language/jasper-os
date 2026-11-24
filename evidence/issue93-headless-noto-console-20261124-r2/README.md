# Issue 93 Headless First Noto console evidence

QEMU/BIOS framebuffer observation, 2026-11-24.

The normal Headless First boot path used the feature-gated exact
`noto-sans-mono-bitmap =0.3.2` raster at 20 pixels. The framebuffer capture
shows the allocation-free Boot Console before the normal display runtime:

```text
JASPER-OS BOOT CONSOLE
[INIT] K00 ENTRY
[INIT] K01 BOOTINFO
[INIT] K02 MEMORY MAP
[INIT] K03 KMAIN
```

This is a QEMU framebuffer capture, not physical-hardware acceptance. The
serial path remains independent, and serial-only profiles may omit the font
feature.

```text
9bb77f12ca682182daade92d9f71cedfd37f3a45bf2d41f392b339ad5405d7c5  headless-boot.png
```
