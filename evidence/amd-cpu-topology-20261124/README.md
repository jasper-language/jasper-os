# AMD Ryzen 7 5700X topology and SMP bring-up audit

## Physical report that opened this audit

Before the topology reconciliation changes, the AMD machine reported:

```text
DISCOVERED=32
ADMITTED=1
ONLINE=1
DISABLED=16
PARTICIPATING=1
LOGICAL_PER_PACKAGE=1
PACKAGES=2
VMX=true
SVM=true
```

The user separately confirmed the physical processor is a single-socket AMD
Ryzen 7 5700X with 8 physical cores and 16 logical threads.

## Root causes found

- `bench-only` includes `smp-bsp-only`; the previous one-CPU result was an
  explicit profile policy, not evidence that all APs had been attempted.
- MADT can contain legacy Local APIC and x2APIC records for the same hardware
  ID. Disabled compatibility records were previously counted as absent CPUs.
  Raw, enabled, disabled, duplicate, conflicting-duplicate and unique counts
  are now separate facts.
- CPUID `0x8000_0001.ECX[5]` is LZCNT on AMD, not Intel VMX. AMD reporting now
  checks SVM only and reports VMX false.
- AMD topology now uses CPUID `0x8000001E` and `0x80000008`, rather than
  treating Intel/legacy leaf values as authoritative.
- The PXE loader now disables the UEFI watchdog before ExitBootServices.

## Physical SMP reset isolation

The machine rebooted at the following progressively narrowed markers:

```text
AP SEND 1 APIC=2 Vector=0x1000
AP INIT DEASSERT
AP INIT DEASSERT SKIP
```

The first marker proves the target AP never reached Jasper-OS Rust code. The
later markers isolate the reset to the INIT/SIPI bring-up path. A diagnostic
`smp-skip-init` image was then observed running long enough to display CPU
topology without entering the prior reboot loop.

This is not yet completion evidence for SMP: physical `online`/`participating`
counts and the SMP performance matrix still need to be captured.

## QEMU/OVMF control group

QEMU reached:

```text
present=4 online=4 failed=0
```

It completed the single-CPU, all-physical-core and all-logical-thread
1,000,000-operation matrix, plus x2APIC INIT/SIPI execution. QEMU results are
control-group evidence only.
