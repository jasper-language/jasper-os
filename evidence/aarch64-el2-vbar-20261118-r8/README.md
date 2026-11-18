# AArch64 EL2 virtual IRQ and VBAR evidence

Date: 2026-11-18.

The reproducible verification script ran on QEMU
`virt,virtualization=on` with two vCPUs:

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true
vm_exit=true virtual_irq=true vbar_context=true vcpu_context=true
system_context=true fp_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
aarch64-el2-retain: PASS bsp=true ap=true hvc=true stage2=true
vm_exit=true virtual_irq=true vbar_context=true vcpu_context=true
system_context=true fp_context=true driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

EL2 asserts `HCR_EL2.IMO` and `HCR_EL2.VI` before returning to an EL1 test
guest with IRQs unmasked. The guest installs its own `VBAR_EL1`, takes the
virtual IRQ and reports delivery through HVC. The vCPU frame preserves VBAR
through the probe, and the assembly/Rust caller compares the host value before
and after guest execution. EL2 then restores the full saved host context and
normal two-vCPU SMP continues.

This remains a minimal virtual-interrupt and VBAR restoration proof. TTBR/TCR/
MAIR, the remaining debug/performance/security register model, vGIC
allocation/EOI, timer virtualisation, device injection, a Linux Driver VM and a
Pixel EL2-preserving boot chain remain outside this evidence.
