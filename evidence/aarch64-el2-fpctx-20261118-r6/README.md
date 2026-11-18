# AArch64 EL2 FP/SIMD vCPU-context evidence

Date: 2026-11-18.

The reproducible verification script ran on QEMU
`virt,virtualization=on` with two vCPUs:

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true
vm_exit=true vcpu_context=true system_context=true fp_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
aarch64-el2-retain: PASS bsp=true ap=true hvc=true stage2=true
vm_exit=true vcpu_context=true system_context=true fp_context=true driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The vCPU frame now saves q0-q31, FPCR, FPSR and CPACR in addition to general and
basic system state. The guest enables CPACR, writes all vector registers,
executes an FP add and faults through stage 2. EL2 restores the host FP state and
resets CPACR to zero; the assembly probe verifies that the host FP unit is
disabled again before the full SMP kernel continues.

SVE, interrupt/timer virtualization, capability-scoped stage-2 mappings and
multi-vCPU scheduling remain outside this proof.
