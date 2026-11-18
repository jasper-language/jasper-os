# AArch64 EL2 virtual timer, IRQ and VBAR evidence

Date: 2026-11-18.

The reproducible verification script ran on QEMU
`virt,virtualization=on` with two vCPUs:

```text
[JSR-A64-VIRQ] status=4 reply=0x4952 vbar_same=true timer_ctl_same=true
timer_cval_same=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true
vm_exit=true virtual_irq=true timer_context=true vbar_context=true
vcpu_context=true system_context=true fp_context=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
aarch64-el2-retain: PASS bsp=true ap=true hvc=true stage2=true
vm_exit=true virtual_irq=true timer_context=true vbar_context=true
vcpu_context=true system_context=true fp_context=true driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

EL2 saves `CNTV_CTL_EL0` and the absolute compare value `CNTV_CVAL_EL0` in the
vCPU frame. The EL1 guest receives a virtual IRQ through its own `VBAR_EL1`,
changes the timer control and compare value, then exits through HVC. EL2 clears
VI/IMO and restores the host timer control/compare state and VBAR. The Rust
caller compares all three host values before and after guest execution.

The evidence intentionally uses `CNTV_CVAL_EL0` rather than the decrementing
`CNTV_TVAL_EL0` view for equality. It proves timer register context switching,
not vGIC timer allocation/injection, acknowledgement/EOI, device injection, a
Linux Driver VM or a Pixel EL2-preserving boot chain.
