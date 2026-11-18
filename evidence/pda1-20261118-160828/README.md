# AArch64 direct-boot exception-level evidence

Date: 2026-11-18.

The complete PDA-1 acceptance passed 16/16 checks. The raw serial log records
the architecture entry level directly:

```text
[JSR-A64-EL] entry=1 execution=1 el2_available=false el2_retained=false
```

The same run passed arm64 Image layout, strict FDT parsing, memory/timer/GIC/PSCI
discovery, and the two malformed-image rejection paths. The unrecorded failure
counts are the already registered AArch64 x86-only PCI/KRN-0 baseline.

Raw local evidence:

```text
serial-single.log
serial-bad-flags.log
serial-bad-size.log
summary.txt
```
