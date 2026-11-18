# AArch64 stage-2 VM-exit evidence

Date: 2026-11-18.

The reproducible verification script ran the EL2-retain image on QEMU
`virt,virtualization=on` with two vCPUs.

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true
stage2=true vm_exit=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
aarch64-el2-retain: PASS bsp=true ap=true hvc=true
stage2=true vm_exit=true driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The EL2 entry saved the host ELR/SPSR, entered a bounded EL1 test guest, and
resumed the host after a stage-2 data abort from a denied 2 MiB IPA. The normal
kernel then completed with the pre-existing AArch64 x86-only failure baseline.

This is a minimal world-switch and exit-classification proof. It does not provide
full vCPU save/restore, per-capability stage-2 mappings, interrupt/timer
virtualization or a Driver VM.
