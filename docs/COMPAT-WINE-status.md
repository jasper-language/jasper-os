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
- The unmodified extracted Wine build, driven by its official static
  preloader, executes `cmd.exe /c echo WINE_CMD_OK` successfully in that
  isolated host root.
- A feature-gated `compat-wine` QEMU mode routes the unmodified Wine loader
  through the existing Jasper Linux ELF/syscall path and requires a literal
  `WINE_CMD_OK` marker before its host-side check can pass.

## Remaining blocker

Inside Jasper, Wine loads the executable and reaches the Unix ntdll loader, but
`dladdr(init_paths)` cannot recover the path of the manually loaded
`ntdll.so`. Jasper now exposes the Wine directory hierarchy, interpreter,
`ntdll.so`, libunwind and the custom preload shim through its bounded Linux VFS;
the shim also maps `dladdr` through `dl_iterate_phdr` and an explicit path
environment fallback. The Jasper run still reports
`wine: cannot get path to ntdll.so`, so glibc/Wine DSO registration remains the
active compatibility gap. This is not a passing Wine result and the DAG node
remains in progress.

The next slice must either:

1. complete the Linux loader's DSO directory/link-map semantics so `dladdr`
   reports the actual loaded `ntdll.so` path; and
2. continue through Wine prefix bootstrap, service creation and the built-in
   Windows command execution.

The physical Pixel and hardware GPU paths are not part of this first Wine
acceptance.
