# Darling Jasper guest CLI acceptance r156

Date: 2026-11-23

This run executes the pinned, unmodified Darling `v0.1.20260608` release in
the Jasper x86-64 OVMF/virtio-blk guest. The payload and normalization inputs
are unchanged from `verification/darling-payload.toml`; RPATH normalization is
limited to removing the upstream CI build prefix from the probe image.

The first cold launch starts launchd and shellspawn but does not complete the
CLI request. The bounded warm retry then runs:

```text
darling exec /data/runtimes/darling/usr/libexec/darling/bin/echo DARLING_EXEC_OK
```

The required markers are:

```text
DARLING_EXEC_OK
[JSR-DARLING-START] attempt=1 exited_zero=true
[JSR-DARLING-CLEANUP] frames_before=433353 frames_after=446517 retained=0 processes=0
[JSR-LIFE-HEALTH] result=root_execution_complete
```

`qemu.rc` is `33`; no panic, Linux ABI failure or compatibility dynamic failure
is present. The process count and frame-retention gate therefore pass after the
successful CLI result.

This closes real non-GUI Darling CLI execution and cleanup in Jasper. It does
not claim Darling GUI/AppKit/WindowServer support, Metal presentation, physical
GPU execution, Pixel 6a support for this amd64-only payload, official
compatibility support, or a native Darwin/Mach ABI. Those boundaries remain
research-only under Issues #31, #55 and #56.

Reproduction environment:

```text
ISSUE21_UEFI_MODE=compat-darling
ISSUE21_REUSE_ROOT=1
ISSUE21_KEEP_DERIVED=1
ISSUE21_QEMU_SMP=4
ISSUE21_QEMU_CPUS=4-7
ISSUE21_QEMU_ACCEL=tcg
JASPER_ANDROID_TREE=<normalized darling probe tree>
```

The serial transcript is in `serial.log`; the host build and image assembly
logs are retained beside it.
