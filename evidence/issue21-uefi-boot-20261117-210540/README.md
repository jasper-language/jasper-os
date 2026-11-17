# LC-2 tenant update-list native CLI

Command:

```text
ISSUE21_UEFI_PREBUILT=1 \
ISSUE21_UEFI_MODE=update-list \
ISSUE21_UEFI_TIMEOUT=120 \
ISSUE21_QEMU_CPUS=6-7 \
ISSUE21_QEMU_SMP=2 \
bash scripts/issue21-uefi-boot-check.sh
```

Result:

```text
issue21-uefi-boot: PASS mode=update-list qemu_rc=33
system-update list=ok command=system.update.list count=0 request=1
{"schema":"service.update.list/1","command":"system.update.list","status":"ok","request":2,"records":[]}
system update list [--help|--schema|--json]
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

The native CLI discovered and invoked `system update list` through ABI 3.20.
Human and structured JSON output use the same bounded list client; identity and
tenant remain kernel-derived. This verify-profile backend is RAM-backed, so this
evidence does not claim production installation persistence.
