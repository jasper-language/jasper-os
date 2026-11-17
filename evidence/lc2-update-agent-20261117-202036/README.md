# LC-2 external structured update Agent

Command:

```text
ISSUE21_UEFI_PREBUILT=1 \
ISSUE21_UEFI_MODE=update-agent \
ISSUE21_UEFI_TIMEOUT=120 \
ISSUE21_QEMU_CPUS=6-7 \
ISSUE21_QEMU_SMP=2 \
bash scripts/issue21-uefi-boot-check.sh
```

Result:

```text
issue21-uefi-boot: PASS mode=update-agent qemu_rc=33
```

The parent probe spawned a separate `user-updateagentd` process. The broker used
the kernel-stamped application identity `1430340679`; the parent pinned that
identity from the first Channel reply. The exchange covered:

```text
status=true recover=true archive=true replay=true
timeout=true after_timeout=true child_exit=0 ok=true
```

The serial log also shows the update syscalls executed by the spawned broker
task, a repeated request returning the cached envelope, a deadline-expired
request being rejected, and a subsequent status request still succeeding. The
first program then exited with code 0 and all frames were reclaimed.

This closes the external structured transport slice only. Tenant-scoped update
sets, the complete concurrency/power-loss matrix and Pixel installation/update
acceptance remain pending.
