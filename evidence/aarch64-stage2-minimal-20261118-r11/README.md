# AArch64 EL2 capability-scoped stage-2 evidence

Date: 2026-11-18.

The reproducible verification script ran on QEMU
`virt,virtualization=on` with two vCPUs:

```text
[JSR-A64-EL2-STEP] stage2_table=true
[JSR-A64-STAGE2] vm_exit=true hpfar=0x4fe000 stage2_open=true
[JSR-A64-EL2-STEP] stage2=true
[JSR-A64-EL2-STEP] vm_exit=true
[JSR-A64-VIRQ] status=4 reply=0x4952 vbar_same=true timer_ctl_same=true
timer_cval_same=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true
vm_exit=true virtual_irq=true timer_context=true vbar_context=true
vcpu_context=true system_context=true fp_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

While the EL1 test guest executes, the stage-2 map contains only 2 MiB blocks
intersecting the kernel image and guest stack. All other RAM and device blocks
are invalid. The guest accesses IPA `0x4fe00000` through Jasper's stage-1
physical linear map and exits on the expected stage-2 data abort; `HPFAR_EL2`
matches the denied IPA.

After the guest exits, EL2 restores the host RAM/device map and invalidates
stage-2 TLB entries before any host MMIO or ordinary output. The full two-vCPU
SMP and registered acceptance workload then continue with `qemu_rc=35` and only
the pre-existing AArch64 `pci_failed=3,krn0_failed=1` baseline.

This proves stage-gated least mapping for the synthetic guest and a checked
transition back to host mappings. The restored host device map is still broad;
capability-derived dynamically sized mappings, vGIC/device injection, IOMMU
isolation, a Linux Driver VM and a Pixel EL2-preserving boot chain remain
outside this evidence.
