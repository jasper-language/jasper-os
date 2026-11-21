# COMPAT-WINE-1 Status

Updated: 2026-11-21

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
- the bounded compatibility VFS now performs standard lexical normalization of
  `.`, `..` and repeated separators without allowing escape above `/`;
- Wine's pinned upstream `c_20127.nls`, `locale.nls` and `l_intl.nls` are
  exposed under `/usr/share/wine/nls`; all three now open and `fstat`
  successfully instead of returning `ENOENT`.

The earlier Jasper run aborted in glibc with `free(): invalid pointer`
(`code=134`). The trigger was isolated to Ubuntu Wine's
`include/wine/server_tmpdir.h`: when `TMPDIR` is present its helper frees the
pointer returned by `secure_getenv()`. Removing the unnecessary
`TMPDIR=/tmp` launch override avoids that invalid free; Wine already defaults
to `/tmp`.

With the trigger removed, the real Wine preloader and wineserver start inside
Jasper, create the prefix and registry state, complete the Unix-socket protocol
handshake, transfer descriptors with `SCM_RIGHTS`, and process vectored protocol
replies. The compatibility layer now also preserves an open file after unlink,
maps writable cache files as coherent shared pages, and exposes the Linux low
private address ranges used by Wine PE images.

The unmodified `start.exe` PE loads and its bundled import closure is available
from the official Wine `x86_64-windows` tree. The current stop is
`ntdll.dll` initialization: Wine reports `c0000017` after its `vprot` mmap and
Jasper mmap both return success. This remains `partial`; a Windows executable has
not completed and `WINE_CMD_OK` has not been emitted.

A generic unmodified C/POSIX fixture performs the same
`creat -> fdopen -> fputs -> fclose` sequence twice through Jasper and exits
zero with resources recovered. Disabling tcache did not change the earlier
failure, and removing the preload shim did not change it either.

The next slices must:

1. determine why Wine rejects its successfully mapped `vprot` table during
   `ntdll.dll` initialization;
2. load the first Windows PE executable and produce `WINE_CMD_OK`;
3. then stage DXVK/VKD3D-Proton and continue through Direct3D to Vulkan.

Every ABI discovered by this work is recorded in
`verification/linux-posix-abi-matrix.toml`. Wine progress alone does not
promote a row to `verified`.

The physical Pixel and hardware GPU paths are not part of this first Wine
acceptance.
