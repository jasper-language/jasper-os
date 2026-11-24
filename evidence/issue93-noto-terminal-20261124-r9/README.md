# Issue 93 pinned Noto terminal acceptance

QEMU/OVMF status: **PASS** (`qemu_rc=33`).

Verified behavior:

- pinned Noto Sans Mono bitmap 0.3.2 normal framebuffer text;
- prompt, typed commands, history recall, backspace editing, Ctrl-C and EOF;
- update status command rendered in the native terminal;
- first program exited zero with complete resource reclamation;
- two distinct framebuffer captures.

SHA-256:

```text
e3a66718a53bca2d2656f6c703a871379942353315fc04e5e617fcd348df6fa5  frame-prompt.png
2334437b989a808896f3ae46c7a29a499a1e23a6e2080a80c1a5786c338e8419  frame-command.png
```

The full PPM and serial evidence are retained in the local evidence directory.
