# Jasper UI Engine completed-shard integration

Date: 2026-11-19.

Exact source:

```text
repository=https://github.com/jasper-language/jasper-ui-engine
branch=codex/no-std-core
commit=8adb6d4432c8385250192304eef04a07b22594d2
feature=no-std-core
license=Apache-2.0
```

This commit contains the completed UI Engine shards through the full Scene
Move subtree-swap proof. Jasper-OS pins the exact commit and selects only the
bare-metal `no-std-core` feature.

## OS integration

The CPL3 UI Service uses:

- `NativeUiDocument` for Typed UI IR admission;
- `CoreRgbaRenderer` with an exact host-owned frame budget;
- JSUI Scene/Patch/Input/Present/Close;
- native Channel, Surface generation, Compositor and framebuffer ownership.

The UI Engine is not linked into `kernel` or `kernel-core`.

## Verified path

```text
2 sequential Service sessions
-> 3 RGBA8 Present frames per session
-> QEMU i8042/PS-2 Enter per session
-> per-session process/object/Channel/frame baseline
-> qemu_rc=33
```

Kernel image SHA-256:

```text
83d3874332f8f0553aaf8b2b17b57689363ed05104cc0adbb4022b0d9ff34e8b
```

Evidence:

```text
evidence/ui-engine-8adb6d4-20261119/serial.txt
evidence/ui-engine-8adb6d4-20261119/qemu_rc.txt
evidence/ui-engine-8adb6d4-20261119/artifacts.sha256
```

## Scope

This integrates the UI Engine shards that are already committed and complete.
It does not include later uncommitted UI Engine work. Physical display/input,
Surface retire/crash recovery, long-running input, multi-application isolation,
fonts/text completeness and GPU/WSI remain outside this integration.
