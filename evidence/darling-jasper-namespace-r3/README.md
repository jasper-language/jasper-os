# Darling Jasper namespace gate probe

Date: 2026-11-22

Mode: `compat-darling`

This is a real UEFI Jasper guest run of the pinned unmodified Darling
`0.1.20260609~noble` Linux launcher. It records the expected namespace
fail-closed gate; it is not a Darling success result.

The launcher was staged from the verified release payload under
`/data/runtimes/darling`. The first warm execution initialized the writable
prefix under `/tmp/darlingprefix` and stopped at the missing Linux
`/etc/passwd`; the measured execution reused that prefix, reached the namespace
gate, and printed:

```text
Cannot unshare UTS and IPC namespaces to create darling-init: Operation not permitted
```

The process exited nonzero, retained zero frames, and the health chain reached
`JSR-LIFE-HEALTH result=root_execution_complete`.

No `DARLING_JASPER_GUEST_OK`, Mach-O execution, dyld handoff, darlingserver RPC,
WindowServer or Metal result is claimed.
