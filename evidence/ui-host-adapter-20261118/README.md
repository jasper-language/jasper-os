# Jasper-OS UI host adapter evidence

Date: 2026-11-18.

The pinned Jasper UI Engine remains `4194117011f13fdc063977683162fd5a145c85d7`
with target status `blocked-no-std`. The other development line owns the engine
port; this evidence verifies the Jasper-OS host side only.

```text
cargo test -p user-ui-service --lib
2 passed; 0 failed

cargo build -p user-ui-service --bin ui-service \
  --target x86_64-unknown-none --features native-transport --release
PASS

ELF type=EXEC
Sections: .note.jasper.abi, .note.jasper.caps, .text, .rodata, .data, .bss

cargo check -p jasper-kernel \
  --target x86_64-unknown-none --no-default-features
PASS

ui-engine-pin: PASS commit=4194117011f13fdc063977683162fd5a145c85d7
gpu-abi-boundary: PASS registry=backend-neutral kernel/no-ui-engine
```

The service process accepts a pre-opened native Channel and fails closed with
`service.ui.error.engine_unavailable` until the independent engine supplies a
Jasper-OS target build. No loopback, screenshot, mock scene or synthetic frame
is treated as OS integration.
