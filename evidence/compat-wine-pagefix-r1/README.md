# Linux reserved-page fork inheritance evidence

Date: 2026-11-22.

`scripts/issue21-uefi-boot-check.sh` ran the unmodified Ubuntu Wine 10.0
command path through the real Jasper UEFI/root-image Linux ABI. The same run
first executed a generic POSIX regression that:

1. creates an anonymous `PROT_NONE` reservation;
2. changes two pages to `PROT_READ | PROT_WRITE`;
3. writes to the first page;
4. forks and verifies that the child can read the materialized page.

The regression failed before the fix because `mprotect` materialization created
backing pages without adding them to the Linux mapping table, so `fork` could
not copy them. Wine exposes the same semantic failure through its PEB page,
which is inside a reservation materialized with `mprotect`.

Relevant serial markers:

```text
FILE_STDIO_OK ... shared_mmap=true materialized_fork_inherit=true low_window=true
WINE_CMD_OK
[JSR-LIFE-ROOT-DYNAMIC] program=compat-wine-cmd ... exit_zero=true ... resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
qemu_rc=33
```

This closes the reservation-to-fork mapping gap. It does not close
`COMPAT-D3D-1`: Wine 11.22 still needs a working desktop/display path before
`D3D11_PROBE_OK`, D3D12/WSI presentation and physical-GPU acceptance.
