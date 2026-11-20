# DC-4 Android HAL adapter status

Updated: 2026-11-20.

Status: **software contract slice passed; DC-4 remains open.**

## Implemented

`kernel-core/src/android_hal.rs` defines a bounded Android HAL adapter contract:

- Android API level and HAL interface/package/instance/version facts are
  explicit and validated;
- Binder identity is a read-only projection of the existing
  `security::SubjectIdentity`, not a second process or account authority;
- service binding requires an admitted Device Host pass plus the unified
  `authz::Decision` for `service.android.hal.bind`, device scope and a valid
  policy epoch;
- MMIO, DMA and IRQ requests use the existing `DriverHostBroker` and
  `PassToken`; this adapter does not create a second device authority;
- service death waiters use existing `event_wait::Registration` / `WaitSet`
  generations and become invalid after crash or stop;
- crash delegates to the Driver Host quiescence-gated crash API, releases the
  local pass and advances the service generation;
- restart requires a fresh broker pass, matching immutable pass facts and a new
  unified authorization decision; old generations cannot restart implicitly;
- API/profile/identity, authorization, stale generation, unavailable service,
  capacity and one-shot waiter failures are explicit.

Vendor Binder transactions, HIDL/AIDL payloads and vendor ioctl formats remain
compatibility-layer data. They are not registered as Jasper native ABI.

## Verification

```text
cargo test --locked -p kernel-core android_hal --lib
5 passed; 0 failed

cargo check --locked -p jasper-os-kernel --target x86_64-unknown-none
PASS
```

## Remaining gates

- A real AOSP/API-level HAL must complete Binder identity and permission
  mapping, device operations, death notification and restart on an ARM64
  device.
- The compatibility Binder/HAL host and native Device Service transport must
  use this contract without exposing vendor private protocols or a second
  permission/device root.
- Physical Pixel 6a HAL/APEX/SELinux and non-Pixel matrices remain required;
  QEMU state-machine tests are not DC-4 completion evidence.
