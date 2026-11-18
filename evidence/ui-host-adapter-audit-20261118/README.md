# UI host adapter audit

Date: 2026-11-18.

This run validates the Jasper-OS-side host scaffold against the pinned Jasper UI
Engine revision `4194117011f13fdc063977683162fd5a145c85d7`. The engine itself is
not built into Jasper-OS and remains `blocked-no-std`.

```text
user-ui-service tests: 3 passed; 0 failed
ui-service x86_64-unknown-none release build: PASS
kernel x86_64-unknown-none check: PASS
ELF type EXEC with .note.jasper.abi and .note.jasper.caps: PASS
ui-engine pin and GPU/UI boundary gates: PASS
```

The adapter requires exact RGBA8 Surface extents, checks Surface generation and
monotonic frame sequence before invoking the engine renderer, and binds the
native Channel endpoint to JSUI v1 frames. A stale sequence is rejected before
engine rendering or buffer mutation.

The process intentionally reports `service.ui.error.engine_unavailable` and
exits 69 until the independent Engine repository supplies a target-buildable
`no_std + alloc` core. No host loopback, synthetic frame or GPU present result
is treated as Jasper-OS UI completion.
