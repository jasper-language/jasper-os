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

Guest authority projection is now explicit: Linux UID 0, Android UID 0,
Android system and HAL identities are compatibility facts only. Projecting a
guest claim requires a valid kernel-authenticated `SubjectIdentity` and returns
that host subject unchanged. Guest fields cannot alter object ID, generation,
application identity, policy epoch or handle rights. Unit coverage proves all
four privileged guest classes are non-elevating and malformed host/guest
identity facts fail closed.

## Verification

```text
cargo test --locked -p kernel-core android_hal --lib
5 passed; 0 failed

cargo check --locked -p jasper-kernel --target x86_64-unknown-none
PASS
```

## Remaining gates

- A real AOSP/API-level HAL must complete Binder identity and permission
  mapping, device operations, death notification and restart on an ARM64
  device.
- The host/guest identity projection must execute through the real Binder HAL
  transport and SELinux policy enforcement, not only the contract tests.
- The compatibility Binder/HAL host and native Device Service transport must
  use this contract without exposing vendor private protocols or a second
  permission/device root.
- Physical Pixel 6a HAL/APEX/SELinux and non-Pixel matrices remain required;
  QEMU state-machine tests are not DC-4 completion evidence.
