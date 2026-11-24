# .NET CoreCLR Jasper Linux ABI acceptance

Date: 2026-11-22

Mode: `compat-dotnet`

Runtime: unmodified Microsoft .NET Runtime `10.0.15`, published by the
unmodified `10.0.404` SDK as a self-contained Linux x64 application and staged
under `/data/runtimes/dotnet`.

Command:

```sh
ISSUE21_UEFI_MODE=compat-dotnet \
ISSUE21_QEMU_ACCEL=tcg \
ISSUE21_QEMU_SMP=4 \
ISSUE21_QEMU_CPUS=4-7 \
ISSUE21_UEFI_TIMEOUT=900 \
JASPER_ANDROID_TREE=/tmp/jasper-dotnet-tree-e8b9-r6 \
bash scripts/issue21-uefi-boot-check.sh
```

Measured result:

```text
DOTNET_PROBE_OK runtime=10.0.15 checksum=150015000 thread=true task=true gc=true exception=true file=true socket=true
[JSR-LIFE-ROOT-DYNAMIC] program=dotnet10-coreclr ... exit_zero=true resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
qemu_rc=33
```

The fixture covers CoreCLR/JIT startup, managed threads, Task/thread-pool work,
a forced GC, managed exceptions, file I/O, and AF_UNIX stream sockets.

`System.Diagnostics.Process`/`posix_spawn` is intentionally not part of this
runtime baseline. Its vfork/exec-confirmation/wait semantics belong to the
POSIX and Linux semantic-conformance track and are not claimed complete here.
