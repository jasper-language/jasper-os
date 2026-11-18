# GICv3 virtual-device interrupt and Driver Host completion evidence

Date: 2026-11-18.

The reproducible run used QEMU 10.2.1 with
`-M virt,gic-version=3,virtualization=on -cpu cortex-a72 -smp 2 -m 256M`.
Build and QEMU work used separate pinned host CPU sets.

```text
[JSR-A64-STAGE2] vm_exit=true hpfar=0x4fe000 stage2_open=true
[JSR-A64-VGIC] direct=true status=5 reply=0x5647 ack=true eoi=true lr_cleared=true host_restored=true vbar_same=true
timer_ctl_same=true timer_cval_same=true
[JSR-A64-VGIC] timer_irq=true status=6 reply=0x5449 ack=true eoi=true lr_cleared=true host_restored=true vbar_same=true
timer_ctl_same=true timer_cval_same=true
[JSR-A64-VGIC] driver_host_irq=true completed=true pending=0 completed_count=1
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true vm_exit=true virtual_irq=true
vgic=true timer_irq=true timer_context=true vbar_context=true vcpu_context=true system_context=true fp_context=true
driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
[JSR-SMP] summary cpus=2 online=2 checks=32 failed=0
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The direct path first proves that an empty virtual interface acknowledges as
SPURIOUS 1023. EL2 then places vINTID 64 as a pending group-1 interrupt in
`ICH_LR0_EL2`; the guest receives the IRQ, reads 64 through `ICC_IAR1_EL1`,
deactivates it through `ICC_EOIR1_EL1`, and verifies a second acknowledgement
is SPURIOUS. `ICH_ELRSR0_EL2` confirms that LR0 is empty before the transaction
is accepted.

The timer path enables the architectural virtual timer from EL1. Its physical
PPI 27 is taken by EL2, checked, masked, and physically EOIed before EL2 injects
vINTID 27 through LR0. The guest acknowledges and deactivates the virtual timer
interrupt and the same LR-empty check applies. A bounded counter deadline
distinguishes a missing physical interrupt from successful injection.

The real interrupt transaction is then reported through the existing
`DriverHostBroker`: a discovered platform device generation is admitted for
`DEVICE|IRQ`, one bounded IRQ route is reserved, the delivered and EOIed virtual
timer interrupt completes that request, and the pending count returns to zero.
This proves an actual interrupt completion path enters the existing Driver Host
authority model without adding a parallel device or permission system. It does
not yet prove MMIO or virtqueue data completion through Driver Host.

The common restore path compares HCR_EL2, ICH_HCR_EL2, ICH_VMCR_EL2 and LR0-3
against the values saved at guest entry while `ICC_SRE_EL2.Enable` is still set.
Rust then compares VBAR_EL1, CNTV_CTL_EL0 and CNTV_CVAL_EL0 before ordinary
kernel execution resumes. The full two-vCPU kernel run has only the pre-existing
AArch64 `pci_failed=3,krn0_failed=1` baseline.

This closes the QEMU GICv3 direct-vGIC, timer-virtualization and Driver Host IRQ
completion slice. It does not include maintenance interrupts, a complete virtual
GICD/GICR device model, a Driver VM, MMIO/virtqueue completion through Driver
Host, real IOMMU isolation, real firmware, or Pixel/non-Pixel physical validation.
