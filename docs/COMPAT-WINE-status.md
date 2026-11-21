# COMPAT-WINE-1 Status

Updated: 2026-11-21

Status: **planned / partial groundwork**.

The compatibility DAG node remains `planned` until the unmodified upstream
Linux Wine build installs, starts, updates, unloads and executes a Windows
executable through Jasper's real Linux ABI.

## Current groundwork

- `scripts/prepare-wine-tree.sh` reproduces an Ubuntu resolute Wine
  `10.0~repack-12ubuntu1` root tree without installing or modifying Wine.
- The four Wine package archives, `wine64-preloader` and the matching MinGW
  zlib runtime are digest-pinned.
- The script closes the Unix-side ELF dependency graph from the exact matching
  Ubuntu host and records the Wine loader, wineserver and built-in `cmd.exe`
  digests.
- The extracted loader runs `wine --version` successfully in an isolated root
  environment.
- A feature-gated `compat-wine` QEMU mode routes the unmodified Wine loader
  through the existing Jasper Linux ELF/syscall path and requires a literal
  `WINE_CMD_OK` marker before its host-side check can pass.

## Remaining blocker

Windows command execution currently stops during Wine prefix bootstrap. Wine
reaches its built-in Windows loader but still requires a display/server
initialization path; without a pre-created prefix it cannot complete the
`cmd.exe` run. This is not a passing Wine result and the DAG node remains
planned.

The next slice must either:

1. stage a prefix created by the same unmodified Wine build and verify that
   Jasper does not need a second initialization process; or
2. implement the missing native wait/Unix-socket/loader behavior required by
   Wine prefix bootstrap.

The physical Pixel and hardware GPU paths are not part of this first Wine
acceptance.
