# Linux fixed PROT_NONE replacement evidence

Date: 2026-11-22.

The generic POSIX fixture now covers both reservation-to-fork inheritance and
`MAP_FIXED` replacement of a materialized anonymous reservation:

1. reserve anonymous `PROT_NONE` pages;
2. materialize them with `mprotect` and write a marker;
3. replace the complete range with a new fixed `PROT_NONE` reservation;
4. materialize again, verify the old content is gone, fork, and verify the
   replacement survives in the child.

Before the fix, the fixed `PROT_NONE` fast path removed reservation metadata
but left concrete pages and Linux mapping metadata in place.
`linux_reserve_range` therefore rejected the replacement as overlapping and
returned `ENOMEM`. Wine hit this path while resetting its low address window,
then retried mappings through a large address scan.

Relevant serial markers:

```text
FILE_STDIO_OK ... materialized_fork_inherit=true fixed_prot_none_replace=true low_window=true
WINE_CMD_OK
[JSR-LIFE-ROOT-DYNAMIC] program=compat-wine-cmd ... exit_zero=true ... resources=true failed=0
[JSR-LIFE-HEALTH] result=root_execution_complete
qemu_rc=33
```

The replacement path removes private/shared pages and their mapping metadata
before publishing the new reservation, matching Linux `MAP_FIXED` replacement
semantics. This does not complete Direct3D; Wine still has a later headless
desktop/address-placement blocker.
