# Issue 93 normal framebuffer UTF-8 terminal observation

QEMU/OVMF interactive framebuffer observation, 2026-11-24.

The normal framebuffer terminal now:

- decodes UTF-8 incrementally across output calls;
- stores Unicode scalar values instead of individual bytes;
- applies the shared half-width/full-width/combining-cell policy;
- preserves original text case;
- derives its text grid from the active 1280x800 framebuffer;
- blends Noto coverage against the current destination pixel.

Interactive evidence shows prompt, help, update status, history recall,
backspace editing, Ctrl-C, EOF and clean process exit. Two distinct frames were
captured:

```text
ed73ed67c0ede809f7222a2277d116d36af3b315f680286c14fa2d736428bfd4  frame-prompt.png
5e565aaa0da5e66a2261fd07dc1d980132bc791e8415567923ccb24924661365  frame-command.png
```

The harness recorded an unexpected QEMU process status `3` instead of its
usual debug-exit success value, even though all guest markers and first-program
reclamation passed. This capture therefore does not close the QEMU exit-code
gate and is not physical-hardware, CJK glyph coverage or `os-terminal + Swash`
acceptance.
