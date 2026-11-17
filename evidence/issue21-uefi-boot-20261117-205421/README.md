# Native install update-list ABI 3.20

Command:

```text
JASPER_BUILD_ALLOW_VBOX=1 \
JASPER_BUILD_CPUS=4-5 \
ISSUE21_UEFI_MODE=native-install-abi \
ISSUE21_UEFI_TIMEOUT=120 \
ISSUE21_QEMU_CPUS=6-7 \
ISSUE21_QEMU_SMP=2 \
bash scripts/issue21-uefi-boot-check.sh
```

Result:

```text
issue21-uefi-boot: PASS mode=native-install-abi qemu_rc=33
system.install.update.list id=114 ret=128 status=OK
short buffer: system.error.invalid_argument, unchanged
forged reserved identity byte: system.error.invalid_argument
native-install-abi: updates=true update_short=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

The caller cannot provide tenant, subject, path or package selection. The kernel
derives the authenticated caller and returns only explicitly update-authorized
installations. The service backend is initialized before the first-program
resource baseline so its resident store allocation is accounted as system
service state rather than a per-process leak.
