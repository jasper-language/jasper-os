# AArch64 EL2 resident-host evidence

Date: 2026-11-18.

The verification image runs on QEMU `virt,virtualization=on` with two vCPUs and
keeps an EL2 vector handler resident while the main kernel runs at EL1.

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2=false driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The two nonzero failure counters are the pre-existing AArch64 x86-only baseline.
They are not EL2, SMP, HVC, or host-residency failures.

This proves only EL2 vector residency and BSP/AP HVC round trips. Stage-2 was not
enabled in this run; later identity-stage-2 evidence is in
`evidence/aarch64-el2-stage2-20261118-r2/`.
