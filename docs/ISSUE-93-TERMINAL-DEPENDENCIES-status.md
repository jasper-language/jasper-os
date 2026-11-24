# Issue 93 terminal dependency status

Updated: 2026-11-24.

Status: **early font dependency upgraded and checked; normal terminal
integration remains engineering work.**

The early console must remain independent from the normal terminal and UI
stack. Candidate libraries are:

| Layer | Candidate | License | Boundary |
| --- | --- | --- | --- |
| Early/emergency text | `noto-sans-mono-bitmap =0.3.2` | MIT plus font terms | no heap/float dependency; independent fallback |
| Normal terminal | `os-terminal =0.7.4` with Swash | MIT; Swash MIT/Apache-2.0 | userspace/service side |
| TUI | `ratatui =0.30.2` | MIT | consumes a Jasper terminal adapter, never physical devices |

It is not valid to put the normal terminal engine or TUI into the kernel, or
to create a second session/input/display authority. The current framebuffer
diagnostic path remains the emergency path until the userspace terminal
adapter and font dependency checks are actually integrated.

The BM-1 early framebuffer path now pins `noto-sans-mono-bitmap =0.3.2` with
the 20-pixel raster, regular/bold weights, basic Latin and Unicode specials.
The allocation-free Headless First Boot Console uses the same pinned raster
through `noto-console`; the 5x7 table remains only as an emergency fallback.
The default and `smp-matrix-only` builds include `noto-console`, while a pure
serial/no-display profile can omit it without changing serial dependencies.
Normal `os-terminal` + Swash and Ratatui are not yet integrated.

The normal framebuffer text frontend now has a `noto-terminal` backend using
the same pinned 20-pixel raster. The 5x7 built-in glyph table remains the
compile-time/emergency fallback. `os-terminal` + Swash and Ratatui are still
not integrated into the userspace terminal service.

Native framebuffer verification passed with the pinned Noto backend:

- QEMU/OVMF `qemu_rc=33`;
- visible prompt/help, typed command, history recall, backspace edit,
  Ctrl-C cancellation and Ctrl-D EOF;
- two different framebuffer frames with recorded hashes;
- first-program exit code zero and complete resource reclamation;
- evidence: `evidence/issue93-noto-terminal-20261124-r9`.

The separate Headless First boot-console framebuffer capture is retained at
`evidence/issue93-headless-noto-console-20261124-r2`.

The later observer issue update identified two additional defects in the
early console: non-zero Noto coverage was drawn as an opaque pixel, and text
was interpreted as bytes with a fixed 90-byte limit. The current early path
now:

- blends each RGB channel with integer 8-bit coverage and nearest rounding;
- renders UTF-8 scalar values rather than individual UTF-8 bytes;
- derives columns and rows from framebuffer width/height and shared margins;
- wraps on cell boundaries and scrolls the text region at the bottom;
- reserves two cells for recognized East Asian wide ranges and displays a
  visible fallback when the early bitmap font has no glyph;
- retains the complete original text on the independent serial/log path.

QEMU/OVMF evidence for this correction is retained at
`evidence/issue93-headless-noto-console-20261124-r3`. This is still only the
early console slice. It is not EDID/display-mode evidence, physical DPI
qualification, CJK font coverage, normal `os-terminal + Swash` integration or
#84 complete Chinese acceptance.

The normal framebuffer terminal has also moved from byte cells to a UTF-8
streaming decoder and a dynamic `Vec<char>` grid:

- incomplete UTF-8 sequences are retained across `terminal_write` calls;
- malformed sequences produce a visible replacement character;
- case is preserved instead of forcibly uppercased;
- half-width, full-width and combining-cell policy is shared with the early
  renderer through `kernel_core::text_grid`;
- columns and rows are derived from the active framebuffer dimensions;
- Noto coverage is alpha-blended against the current destination pixel;
- the text store no longer allocates while the DISPLAY lock is held.

The streaming decoder is now a tested `kernel_core::utf8_stream` primitive.
Unit tests cover a multibyte scalar split across calls, consecutive decoded
characters across calls, invalid leading bytes, invalid continuation bytes and
preservation of an ASCII byte that follows a partial sequence.

Interactive QEMU evidence is retained at
`evidence/issue93-utf8-terminal-qemu-20261124-r4`. Prompt/help/update/history/
edit/Ctrl-C/EOF markers and first-program reclamation passed, but the harness
observed an unexpected QEMU process status instead of its usual debug-exit
success value, so that evidence does not close the exit-code gate. Physical
mode/DPI, full CJK coverage and `os-terminal + Swash` remain open.

This closes the bounded native framebuffer font/terminal integration gate. It
does not claim that `os-terminal` + Swash or Ratatui are yet the production
userspace terminal stack.

Required before promotion:

- fetch and lock exact crate versions and full transitive dependency graph;
- verify feature names, MSRV and no accidental `std`/alloc/float leakage into
  emergency builds;
- verify font asset names, SHA-256, OFL terms and CJK/wide/fallback behavior;
- run serial and framebuffer tests without graphical UI dependencies;
- validate real screenshots across supported display modes;
- retain `qemu_rc`, process exit, framebuffer checksum and input evidence.

Only the early pre-rasterized font has been promoted. No normal-console or TUI
dependency has been promoted by this record.
