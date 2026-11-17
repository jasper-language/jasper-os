# LC-2 external update Agent concurrency acceptance

Date: 2026-11-17

This run exercises the native update ABI through four independent
`user-updateagentd` broker processes. Four client threads use one broker each,
issue six overlapping status request IDs, and each issues one bounded list
request. A process-isolated request-ID cache must therefore remain independent
while the kernel update service, persistent P0 block device, Channel transport,
deadline/cancel path, process admission, task lifecycle, and frame reclamation
remain shared.

Command:

```text
ISSUE21_UEFI_MODE=update-agent \
ISSUE21_UEFI_PREBUILT=1 \
ISSUE21_QEMU_CPUS=12-15 \
ISSUE21_QEMU_SMP=4 \
ISSUE21_UEFI_TIMEOUT=120 \
bash scripts/issue21-uefi-boot-check.sh
```

Result:

```text
issue21-uefi-boot: PASS mode=update-agent qemu_rc=33
[JSR-UPDATE-AGENT-CONCURRENT] workers=4 rounds=6 process_isolation=true failed=0 ok=true
[JSR-UPDATE-AGENT] ... concurrent=true ... ok=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

This is real OVMF and virtio-blk evidence for the concurrent broker/request
slice. It is not Pixel 6a installation/update/power-loss acceptance and does
not by itself satisfy the full LC-2 exit gate.
