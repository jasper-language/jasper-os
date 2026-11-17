# LC-2 terminal archive UEFI acceptance

Command:

```text
ISSUE21_UEFI_MODE=terminal-recovery \
ISSUE21_UEFI_PREBUILT=1 \
ISSUE21_UEFI_TIMEOUT=120 \
bash scripts/issue21-uefi-boot-check.sh
```

Result:

```text
issue21-uefi-boot: PASS mode=terminal-recovery qemu_rc=124
```

The mode intentionally exits through the bounded QEMU timeout after the native
CLI has completed and the production kernel has logged its final liveness
marker. The serial log proves:

- human and JSON `system.update.archive` calls return `archived=true`;
- schema/help expose `system.update.archive`;
- the kernel derives `terminal=Complete`, transaction and manifest digest from
  the authenticated control record;
- a repeated archive action is idempotent;
- the native CLI exits zero and the production kernel reports
  `reclaimed=true`.
