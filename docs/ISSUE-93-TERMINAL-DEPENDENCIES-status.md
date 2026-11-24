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
It remains an independent emergency renderer. Normal `os-terminal` + Swash
and Ratatui are not yet integrated.

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
