# Darling Jasper mount/runtime gate r12

Date: 2026-11-22

Mode: `compat-darling`

This is a real UEFI Jasper guest run of the pinned unmodified Darling
`0.1.20260609~noble` launcher. It is a diagnostic gate, not a Darling success
result.

The staged payload contains the launcher, darlingserver, mldr, vchroot, dyld
and libSystem. The guest creates bounded UTS/IPC/mount/PID namespaces, mounts
tmpfs on `/dev/shm`, applies the root slave propagation request, creates the
bounded overlay view and mounts proc.

Execution then reaches darlingserver and mldr startup. The measured run stops
at:

```text
Failed to create socket: Invalid argument
Cannot mmap commpage: Cannot allocate memory
```

The second measured run reports `retained=0`, no orphaned frames and no pins,
and the health chain reaches `JSR-LIFE-HEALTH result=root_execution_complete`.

No `DARLING_JASPER_GUEST_OK`, Mach-O execution, dyld handoff, darlingserver RPC,
WindowServer or Metal result is claimed.
