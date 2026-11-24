# Issue 95 physical general-switch diagnostic deployment

Date: 2026-11-24.

The PXE TFTP files serve the same source revision that passed QEMU control
`evidence/issue95-general-switch-qemu-20261124-r5`, with forced x2APIC.

```text
c2ca75adb35917aa31559d3ef3740619b2f894745513451769f01bfc210b6eb9  tftp/kernel-x86_64
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  tftp/bootloader.efi
```

Physical results are not claimed until the AMD machine reports all three
switch workloads and resource reclamation.
