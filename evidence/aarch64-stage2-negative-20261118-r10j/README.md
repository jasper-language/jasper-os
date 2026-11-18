# AArch64 EL2 stage-2 explicit negative-map evidence

Date: 2026-11-18.

The reproducible verification script ran on QEMU
`virt,virtualization=on` with two vCPUs:

```text
[JSR-A64-EL2-STEP] stage2_table=true
[JSR-A64-EL2-STEP] stage2=true
[JSR-A64-STAGE2] vm_exit=true hpfar=0x4fe000
[JSR-A64-EL2-STEP] vm_exit=true
[JSR-A64-EL2-STEP] stage2_open=true
[JSR-A64-VIRQ] status=4 reply=0x4952 vbar_same=true timer_ctl_same=true
timer_cval_same=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true
vm_exit=true virtual_irq=true timer_context=true vbar_context=true
vcpu_context=true system_context=true fp_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The declared 1 GiB RAM block is translated by an L2 table. IPA `0x4fe00000`
(254 MiB, inside the stage-1-mapped 256 MiB RAM region) is intentionally
invalid. The test guest accesses it through Jasper's physical linear map, EL2
classifies the exit as a stage-2 data abort, and `HPFAR_EL2` matches the denied
IPA. EL2 then restores that 2 MiB block and invalidates stage-2 TLB entries
before the host reuses the same RAM.

This proves one auditable negative mapping and its safe reopening. The broad
Device blocks outside the RAM window, capability-derived dynamic mappings,
device/MMIO injection, IOMMU isolation, a Linux Driver VM and a Pixel
EL2-preserving boot chain remain outside this evidence.
