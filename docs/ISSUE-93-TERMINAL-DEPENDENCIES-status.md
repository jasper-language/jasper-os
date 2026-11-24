# Issue 93 terminal dependency status

Updated: 2026-11-24.

Status: **candidate selection recorded; normal terminal integration remains
engineering work.**

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

Required before promotion:

- fetch and lock exact crate versions and full transitive dependency graph;
- verify feature names, MSRV and no accidental `std`/alloc/float leakage into
  emergency builds;
- verify font asset names, SHA-256, OFL terms and CJK/wide/fallback behavior;
- run serial and framebuffer tests without graphical UI dependencies;
- validate real screenshots across supported display modes;
- retain `qemu_rc`, process exit, framebuffer checksum and input evidence.

No dependency has been promoted to the normal-console path by this record.
