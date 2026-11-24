# Issue 95 physical general-switch diagnostic deployment

Date: 2026-11-24.

The PXE TFTP files serve the same source revision that passed QEMU control
`evidence/issue95-general-switch-qemu-20261124-r5`, with forced x2APIC.

```text
90aec7fbb6a707ec742dba5ddb37a53d5dff2069e29c547fc288413f59f37b53  tftp/kernel-x86_64
61e9aaad21bacb98abfcfe02306c6322559db3ab68303e3fae3e4cc191042782  tftp/bootloader.efi
```

Physical results are not claimed until the AMD machine reports all three
switch workloads and resource reclamation.
