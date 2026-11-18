# Jasper UI Engine exact-pin audit

Date: 2026-11-18.

Pinned repository and revision:

```text
https://github.com/jasper-language/jasper-ui-engine
4194117011f13fdc063977683162fd5a145c85d7 (v0.1.0, Apache-2.0)
Cargo.lock sha256=dd733d3930c9e18224463ba3979997a86e589f272da79b46dbd26c166536f78e
Cargo.toml sha256=428c56cf48ae7551055f07ea7befa9bc4deb157a270518600fd2c5624f1ce0b5
```

Host-side core verification, on the pinned clean worktree:

```text
cargo +nightly-2026-10-17-x86_64-unknown-linux-gnu test \
  --locked --no-default-features --lib
180 passed; 0 failed
```

Jasper native target verification:

```text
cargo +nightly-2026-10-17-x86_64-unknown-linux-gnu check \
  --locked --no-default-features --target x86_64-unknown-none
error[E0463]: can't find crate for `std`
--> memchr/src/lib.rs: extern crate std
```

The dependency graph enables `serde/std`, `serde_json/std` and `taffy/std`
even with Cargo features disabled. The selected `native-engine-cpu` path adds
more `std` consumers for collections, file/error I/O, time, fonts, image
decoding and the Blitz/Vello adapter stack. Therefore the pinned engine cannot
yet be linked into the current `x86_64-unknown-none` Jasper user process.

This is a verified integration blocker, not an OS integration result. The
Ubuntu host loopback, desktop window, GPU or AT-SPI evidence does not close the
Jasper-OS UI Service gate.
