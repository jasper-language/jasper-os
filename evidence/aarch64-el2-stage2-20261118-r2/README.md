# AArch64 resident EL2 stage-2 identity-map evidence

Date: 2026-11-18.

The reproducible verification script built the EL2-retain feature image and ran
it on QEMU `virt,virtualization=on` with two vCPUs.

```text
[JSR-A64-EL] entry=2 execution=1 el2_available=true el2_retained=true
[JSR-A64-EL2] retained=true hvc_round_trip=true stage2_table=true stage2=true driver_vm=false
[JSR-SMP] start present=2 online=2 failed=0 source=fdt.cpus dropped=0 disabled=0
aarch64-el2-retain: PASS bsp=true ap=true hvc=true stage2=true driver_vm=false
qemu_rc=35
exit_failures=pci_failed:3,krn0_failed:1
```

The nonzero counters are the registered AArch64 x86-only test baseline.
This run predates the minimal stage-2 VM-exit probe; that later evidence is in
`evidence/aarch64-el2-vmexit-20261118-r3/`.

The stage-2 map covers a 39-bit IPA identity range with 1 GiB blocks. The RAM
block is Normal memory and other blocks are temporarily Device memory so high
MMIO remains reachable. This is not a final capability map or isolation policy.
