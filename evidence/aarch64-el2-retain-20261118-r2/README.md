# Reproduced AArch64 EL2 resident-host evidence

Date: 2026-11-18.

The repository check script rebuilt the feature image and reproduced the BSP/AP
EL2 residency result on QEMU with two vCPUs:

```text
aarch64-el2-retain: PASS bsp=true ap=true hvc=true stage2=false driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The failure baseline is unchanged from the registered AArch64 x86-only tests.
