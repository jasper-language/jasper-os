# OpenJDK 21 Jasper Linux ABI acceptance

Date: 2026-11-22

Mode: `compat-jvm`

Runtime: unmodified OpenJDK `21.0.13.1`, minimized with its own `jlink
--add-modules java.base` and staged under `/data/runtimes/openjdk` from a real
System-root image.

CPU profile: QEMU KVM `host,-avx,-avx2`.

Command:

```sh
ISSUE21_UEFI_MODE=compat-jvm \
ISSUE21_QEMU_ACCEL=kvm \
ISSUE21_QEMU_SMP=4 \
ISSUE21_QEMU_CPUS=4-7 \
ISSUE21_UEFI_TIMEOUT=900 \
JASPER_ANDROID_TREE=/tmp/jasper-openjdk-tree-c717-r5 \
bash scripts/issue21-uefi-boot-check.sh
```

Measured result:

```text
JVM_PROBE_OK value=499500 thread=true gc=true file=true java=21.0.13.1
[JSR-LIFE-ROOT-DYNAMIC] program=openjdk21-jvm ... exit_zero=true resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
qemu_rc=33
```

The fixture covers JVM startup, Java thread creation and join, a 1 MiB
allocation with garbage collection, and file output.

This is a baseline x86-64 pass. OpenJDK's AVX-preservation self-test
intentionally dereferences null on AVX-capable CPUs. Jasper still needs
synchronous guest `SIGSEGV` delivery before an AVX-enabled profile can pass; no
AVX claim is made here.
