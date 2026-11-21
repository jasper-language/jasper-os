# COMPAT-WINE-1 Status

Updated: 2026-11-22

Status: **in-progress / partial groundwork**.

The compatibility DAG node remains `in-progress` until the unmodified upstream
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

Jasper now passes the earlier path-discovery failures:

- `readlinkat` distinguishes existing non-links (`EINVAL`) from missing paths
  (`ENOENT`), allowing glibc `realpath` to consume the `ntdll.so` path;
- the root reader follows bounded relative symlinks, and the fixture preserves
  symlink inodes;
- Wine's `wine-preloader` is registered as a real executable;
- `/data/wineprefix` and `/tmp` are available through the bounded writable
  compatibility namespace;
- `creat` can create temporary-prefix files, and shared fd status flags report
  `O_WRONLY` rather than falsely reporting `O_RDONLY`;
- `MAP_FIXED_NOREPLACE` is exposed with failure-closed replacement semantics;
- the Wine-specific `LD_PRELOAD` path shim is removed. Wine reaches the same
  bootstrap point without it, so generic Linux `readlink`/`realpath` semantics
  now carry the path-discovery path;
- the optional `WINEPRELOADRESERVE` override is removed. Its presence or absence
  does not change the failure, so it was not the source of corruption;
- fixed-map tracing shows Wine replacing its own ELF-load mappings as expected;
  the official preloader still warns that its default low/high reservations lie
  outside Jasper's bounded private user windows.

The current Jasper run reaches Wine prefix creation, creates the wineserver
temp-state file, and passes `fcntl`/`fstat`, but later aborts in glibc with
`free(): invalid pointer` (`code=134`).

A generic unmodified C/POSIX fixture now performs the same
`creat -> fdopen -> fputs -> fclose` sequence twice through Jasper and exits
zero with resources recovered. Disabling tcache does not change the Wine
failure, and removing the preload shim does not change it either. The current
evidence therefore points to Wine-specific runtime state established before
this stdio sequence, not to the stdio sequence or path shim itself.

The next slices must:

1. isolate the Wine-specific heap corruption before wineserver startup;
2. complete wineserver process and socket startup;
3. load the first Windows PE executable and produce `WINE_CMD_OK`;
4. then stage DXVK/VKD3D-Proton and continue through Direct3D to Vulkan.

The physical Pixel and hardware GPU paths are not part of this first Wine
acceptance.
