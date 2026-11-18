# Pixel 6a exception-level entry probe

Date: 2026-11-18.

This physical probe distinguishes whether the stock Pixel AVB/PE carrier hands
Jasper control at EL2. It does not flash, erase, or change a slot.

## Method

The normal Pixel runtime completed in `4.59s` in
`evidence/pixel6a-entry-el-20261118-r3`.

The observation build used the same runtime and added exactly one behavior: if
the assembly entry observed `CurrentEL == EL2`, it waited five physical-counter
seconds before the normal PSCI reset. It then completed in `4.60s`. The five
second EL2 branch therefore did not execute.

```text
normal runtime:
runtime_return_seconds=4.59
android boot_completed=1

EL2-observation runtime:
runtime_return_seconds=4.60
android boot_completed=1
```

QEMU AArch64 direct boot independently emits:

```text
[JSR-A64-EL] entry=1 execution=1 el2_available=false el2_retained=false
```

## Conclusion

The current stock Pixel carrier enters Jasper at EL1. EL2 is not available to the
current boot carrier, so an isolated Linux Driver VM cannot currently be hosted
inside this entry path. A public, recoverable EL2-preserving boot-chain adapter
must be designed and validated before the Driver VM route can proceed.

This result does not authorize a private UFS driver. It also does not close LC-2,
LC-4, or any hardware DAG node.
