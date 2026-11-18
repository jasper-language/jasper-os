# LC-2 declared-profile exit matrix

Date: 2026-11-18.

This run revalidated the declared QEMU/OVMF plus P0 virtio-blk profile from the
current public main. It does not claim Pixel physical installation.

## Commands and results

```text
issue21-trial-powercut-check.sh
PASS cuts=3 recovered=A

issue21-confirm-cut-check.sh
PASS prior_generation=3 reconfirmed_generation=5

issue21-control-copy-cut-check.sh
PASS recovered_generation=2 confirmed=B

ISSUE21_UEFI_MODE=terminal-recovery
PASS qemu_rc=124

ISSUE21_UEFI_MODE=update-agent
PASS qemu_rc=33
workers=4 rounds=6 process_isolation=true failed=0 ok=true

ISSUE21_UEFI_MODE=update-list
PASS qemu_rc=33

native-install-abi first boot
PASS qemu_rc=33
mounted=true initialized=true

native-install-abi second boot with the same P0/OVMF state
PASS qemu_rc=33
mounted=true initialized=false
```

The persistent installation store is the same P0 block-device authority used by
the lifecycle services. The second boot reopens the existing package,
installation, grant, runtime and list state without formatting it again.

Evidence directories:

```text
evidence/lc2-exit-trial-powercut-20261118
evidence/lc2-exit-confirm-cut-20261118
evidence/lc2-exit-control-copy-cut-20261118
evidence/lc2-exit-terminal-recovery-20261118-r5
evidence/lc2-exit-update-agent-20261118
evidence/lc2-exit-update-list-20261118
evidence/lc2-exit-install-boot1-20261118-r2
evidence/lc2-exit-install-boot2-20261118
```

`issue21-uefi-boot-check.sh` now accepts
`ISSUE21_UEFI_CARGO_TARGET` so the kernel build can reuse the shared target
while derived GPT/ESP/A-B images remain isolated under
`ISSUE21_UEFI_TARGET`. This avoids duplicating multi-gigabyte build trees for
each LC-2 guest.

## Remaining physical gate

Pixel 6a preflight and read-only LUN enumeration are recorded in
`docs/PIXEL6A-LC2-PREFLIGHT.md`. There is no named Jasper-only persistent
partition; AOSP/Linux UFS is GPL-2.0-family and tied to Linux kernel APIs. No
private UFS driver or unsafe reuse of `userdata`/`super`/`metadata` was
performed. Pixel install, update, rollback and power-cut acceptance therefore
remain blocked on an isolated public-driver execution domain or an equivalent
stable public UFS UAPI backend.
