# Jasper-OS UI Service restart continuity

Date: 2026-11-18.

This run creates and tears down two independent UI Service processes in one
boot. Each round opens a fresh native host/service Channel, receives and renders
Scene, Patch and physical-keyboard Input, emits three RGBA8 Present frames,
closes normally and reclaims its process, object, Channel and frame resources.

## Path

```text
round 0: new host + service process + Channel + Surface generation
-> Scene + Patch + native i8042/PS-2 Enter
-> 3 RGBA8 Present frames
-> normal exit + reap + cleanup + per-round baseline

round 1: recreate the same bounded chain with new process identities
-> Scene + Patch + second native i8042/PS-2 Enter
-> 3 RGBA8 Present frames
-> normal exit + reap + cleanup + per-round baseline
```

The monotonic kernel heap retains first-use capacity, so each round measures
against its own baseline after heap warm-up. Process objects, Channel queues,
pins, event/object tables and frame counts return exactly to that round's
baseline.

## Result

```text
[JSR-UI-SESSION] round=0 ... frames=3 ... resources=true checks=15 failed=0
[JSR-UI-SESSION] round=1 ... frames=3 ... resources=true checks=30 failed=0
[JSR-UI-PROCESS] rounds=2 ... frames=6 ... restart=true resources=true checks=31 failed=0
qemu_rc=33
```

No `panicked`, `JSR-PANIC` or `JSR-UI-PROCESS-FAIL` marker occurs.

## Artifacts

```text
serial.txt
qemu_rc.txt
artifacts.sha256
kernel.img
PASS
```

Kernel image SHA-256:

```text
0f7896acaa8a2060538e64e5280edea9df4ed784af8f7187a2f6a027e33d3cc2
```

## Scope

This proves sequential Service recreation after normal teardown on x86_64 QEMU.
It does not prove crash recovery, mid-frame cancellation, Surface retire,
physical display/keyboard qualification, long-running input, multi-application
focus isolation or Pixel 6a hardware restart continuity.
