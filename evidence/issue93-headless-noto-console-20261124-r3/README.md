# Issue 93 Headless console anti-aliasing and layout evidence

QEMU/OVMF framebuffer observation, 2026-11-24.

The early allocation-free console now:

- consumes Noto 8-bit coverage with integer alpha blending;
- renders UTF-8 characters rather than bytes;
- calculates columns and rows from the actual framebuffer size;
- wraps long lines and scrolls instead of applying a fixed 90-byte limit;
- reserves two cells for East Asian wide characters and emits a visible
  fallback when the early bitmap font has no glyph.

The capture is 1280x800 and shows the Boot Console before the normal display
runtime starts.

```text
b1ea320f460d68087b6bc65dad261667e50d66d07199645f8694129f0c15b298  headless-boot.png
```

This is QEMU evidence, not physical display-mode, EDID, CJK coverage or full
`os-terminal + Swash` acceptance.
