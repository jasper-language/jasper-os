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
from the official Wine `x86_64-windows` tree. The baseline Wine 10 command path
now completes with `WINE_CMD_OK`.

A generic Linux mapping bug blocked deeper Wine 11 execution. `mprotect`
could materialize an anonymous `PROT_NONE` reservation, but the resulting pages
were absent from the Linux mapping table, so `fork` did not copy them. Wine's
PEB lives in such a materialized reservation, causing its nested process spawn
to fault at `0x20002d020`. The Linux ABI now records every materialized page,
rolls back the mapping on metadata failure, and restores the reservation on
failure. The generic regression marker is
`materialized_fork_inherit=true`; the full `compat-wine` run remains green.

The same test now replaces the materialized range with a new fixed
`PROT_NONE` anonymous reservation. Jasper previously removed the reservation
metadata but not the concrete pages, so `linux_reserve_range` reported an
overlap and Wine retried low mappings while scanning the address space. The
fixed path now honors `MAP_FIXED` by removing all previous private/shared pages
and their Linux mapping metadata before publishing the replacement reservation.
The regression marker is `fixed_prot_none_replace=true`.

After that fix, Wine 11.22 can spawn and load Explorer through Jasper without
the PEB fault. The ordinary headless desktop path still cannot create a
desktop window, and the current test tree still lacks parts of the full Wine
display/module closure.

The offscreen D3D11 core slice has now passed separately through the Wine
service desktop and Mesa lavapipe. The unmodified DXVK 3.1.1 path reported
`D3D11_PROBE_OK feature=0xb000 pixel=32,64,128,255`, and the probe exited zero.
The probe binary is intentionally linked without `DYNAMIC_BASE` for this
verification profile because Jasper's current x86_64 user window does not yet
cover Wine's randomized high PE base. This is a bounded core result, not a
claim of general ASLR, desktop, D3D12/WSI, or physical-GPU compatibility.
The process resource baseline still reports `resources=false`; cleanup of the
DXVK worker/thread/cache state remains open.

The Wine/DXVK/lavapipe staging inputs are now pinned in
`verification/wine-d3d-staging.json` and assembled by
`scripts/prepare-wine-d3d-staging.py`. The staging path fails closed on host
package drift, archive or probe digest mismatch, missing final artifacts and
an existing output directory. See `docs/WINE-D3D-STAGING.md`. This removes the
manual-root dependency without changing the guest acceptance claim.

The WSI slice now passes in the Jasper guest. It creates a Wine service-desktop
HWND, DXGI swapchain and backbuffer, clears and reads back the backbuffer, and
executes DXVK `vkCreateSwapchainKHR`, `vkAcquireNextImageKHR` and
`vkQueuePresentKHR`. The third mandatory steady-state run also passes
`resources=true`. This remains a hidden Mesa lavapipe desktop result, not
visible desktop or physical GPU acceptance. See
`docs/COMPAT-D3D11-WSI-status.md` and
`evidence/compat-wine-wsi-r125/README.md`.

The reproducible staging root now also carries unmodified VKD3D-Proton 3.1,
the D3D12 offscreen probe and the D3D11 WSI probe. Two separate verification
features and `issue21-uefi-boot-check.sh` modes are wired:

```text
ISSUE21_UEFI_MODE=compat-wine-d3d12
ISSUE21_UEFI_MODE=compat-wine-wsi
```

Each mode requires its own literal marker plus `resources=true`; no fallback
from D3D11 offscreen to D3D12/WSI is accepted.

A generic unmodified C/POSIX fixture performs the same
`creat -> fdopen -> fputs -> fclose` sequence twice through Jasper and exits
zero with resources recovered. Disabling tcache did not change the earlier
failure, and removing the preload shim did not change it either.

The remaining slices must:

1. complete VKD3D-Proton D3D12 in the Jasper guest;
2. add visible desktop input/focus and resize/revoke coverage;
3. continue through real GPU, display and Pixel 6a acceptance.

Every ABI discovered by this work is recorded in
`verification/linux-posix-abi-matrix.toml`. Wine progress alone does not
promote a row to `verified`.

The physical Pixel and hardware GPU paths are not part of this first Wine
acceptance.
