# AArch64 EL2 vCPU context-restore evidence

Date: 2026-11-18.

The reproducible verification script ran on QEMU
`virt,virtualization=on` with two vCPUs:

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true
stage2=true vm_exit=true vcpu_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
aarch64-el2-retain: PASS bsp=true ap=true hvc=true
stage2=true vm_exit=true vcpu_context=true driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The EL2 entry saved x0-x30, SP_EL1, ELR_EL2 and SPSR_EL2 on an independent
hypervisor stack. A bounded EL1 guest used a separate stack, overwrote every
general-purpose register with a distinct sentinel and executed a stage-2-denied
load. On return, the assembly probe verified the restored x2-x8, x11-x29 and
the x30 return address; the full SMP kernel then completed with only the
pre-existing x86-only failure baseline.

This still omits FP/SIMD/SVE, system-register virtualization, interrupt and
timer virtualization, multi-vCPU scheduling and device injection.
