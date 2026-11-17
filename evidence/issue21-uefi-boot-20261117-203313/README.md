# LC-2 external update Agent replay hardening

Command:

```text
JASPER_BUILD_ALLOW_VBOX=1 \
JASPER_BUILD_CPUS=4-5 \
ISSUE21_UEFI_MODE=update-agent \
ISSUE21_UEFI_TIMEOUT=120 \
ISSUE21_QEMU_CPUS=6-7 \
ISSUE21_QEMU_SMP=2 \
bash scripts/issue21-uefi-boot-check.sh
```

Result:

```text
issue21-uefi-boot: PASS mode=update-agent qemu_rc=33
[JSR-UPDATE-AGENT] transport=channel status=true recover=true archive=true
replay=true timeout=true after_timeout=true server_app=1430340679 child_exit=0
ok=true payload_mismatch=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

The retry cache ignores only a refreshed deadline. Reusing the same message ID
and operation with a different status payload is rejected instead of returning
stale success.
