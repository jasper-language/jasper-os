# Issue 95 general switch QEMU control

Date: 2026-11-24.

This QEMU/OVMF control uses one build with forced x2APIC and two vCPUs. It runs
the scheduler completion-event workload and the separate controlled round-trip
workload in `SMP_SINGLE`, `SMP_PHYSICAL` and `SMP_LOGICAL` modes.

Result:

```text
SMP CONCURRENT FINAL SINGLE=true PHYSICAL=true LOGICAL=true
FAILED=0 TIMING_FAILED=0 RECLAIMED=true
```

Artifact hashes:

```text
11467b26b5f6fb1401a237a7d22a7c664a6e0c167b87115f5a0b01dbff3db289  serial.log
19b8d5c59e421f037fe563007c7254eb8d98bc221b278c3db3e5fdbbfd52e273  qemu.rc
6b3fcc73d6be23524b434c956e36ab1a5836abd17624ee47edf78ab0d6a8ae94  kernel-build.log
```

`qemu.rc=33` is the expected successful debug-exit value. These numbers are a
functional and measurement control, not a physical performance baseline.
