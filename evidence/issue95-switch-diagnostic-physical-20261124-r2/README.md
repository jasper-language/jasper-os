# Issue 95 physical general-switch diagnostic deployment

Date: 2026-11-24.

The PXE TFTP files serve the same source revision that passed QEMU control
`evidence/issue95-general-switch-qemu-20261124-r5`, with forced x2APIC.

```text
569c87fa5c81fe93fde8440cf1c9b30c52634a98b73da5a7ba65c1ae2856aeb0  tftp/kernel-x86_64
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  tftp/bootloader.efi
```

Physical results are not claimed until the AMD machine reports all three
switch workloads and resource reclamation.
