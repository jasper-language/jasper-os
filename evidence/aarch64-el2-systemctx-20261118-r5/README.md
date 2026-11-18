# AArch64 EL2 vCPU system-context evidence

Date: 2026-11-18.

The reproducible verification script ran on QEMU
`virt,virtualization=on` with two vCPUs:

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true
stage2=true vm_exit=true vcpu_context=true system_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
aarch64-el2-retain: PASS bsp=true ap=true hvc=true stage2=true
vm_exit=true vcpu_context=true system_context=true driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

In addition to x0-x30, SP_EL1, ELR and SPSR, the host frame stores SP_EL0,
TPIDR_EL0, TPIDR_EL1 and CONTEXTIDR_EL1. The test guest changes those registers
before its stage-2 fault; the assembly probe verifies the restored host
sentinels before returning to Rust.

Translation-control/base registers, FP/SIMD/SVE, debug/performance/security
registers, interrupt/timer virtualization and multi-vCPU scheduling remain
outside this proof.
