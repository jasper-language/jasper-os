# Compatibility ABI evidence index

This index preserves reusable evidence paths for the Linux/POSIX compatibility
ABI. The raw serial logs remain local artifacts; the source, environment and
result are recorded here so semantic conformance work can select affected rows
instead of rescanning the complete ABI surface.

## Path resolution

- `evidence/compat-wine-path-normalize-r31`
- `evidence/compat-wine-readlink-r4-20261121`
- `evidence/compat-wine-symlink-r9-20261121`
- `evidence/compat-wine-nls-r30`
- `evidence/compat-wine-remaining-abi-r96`
- Positive evidence: writable cache entries support `symlink`, `readlink`,
  repeated separators, `.`, `..`, `realpath`, and crossing from a writable
  prefix symlink into the read-only VFS.
- Negative evidence: missing paths and attempted escapes above the
  compatibility root return `ENOENT`; `readlink` on a non-link returns
  `EINVAL`.
- Environment: Jasper UEFI, Linux x86_64 compatibility ABI.

## File status, modes and open-file lifetime

- `evidence/compat-wine-modes-r37`
- `evidence/compat-wine-fdopen-vm-r17`
- `evidence/compat-wine-unlink-open-file-20261121-r14`
- `evidence/compat-wine-file-mode-r65`
- `evidence/compat-wine-remaining-abi-r96`
- `evidence/compat-wine-steady-r116`
- The last run proves an unlinked cache file remains addressable through an
  imported descriptor and that Wine can map it after `unlink`. The standard-fd
  fixture proves `fstat(1)` reports a character device, pipe and socket pairs
  report FIFO/socket types, invalid descriptors return `EBADF`, umask-derived
  mode is reported accurately, and descriptor status flags and file size match
  the opened description.

## Positioned I/O

- `evidence/compat-wine-pwrite-r40`
- `evidence/compat-wine-positioned-io-r68`
- Positive evidence: cache-file `pread64/pwrite64` use explicit offsets,
  preserve the shared file cursor, and observe the updated file size.
- Negative evidence: negative offsets return `EINVAL`, bad descriptors return
  `EBADF`, invalid user buffers return `EFAULT`, and reads past EOF stop at
  the bounded file length.
- Environment: Jasper UEFI, Linux x86_64 compatibility ABI.

## Current directory

- `evidence/compat-wine-cwd-r38`
- `evidence/compat-wine-cwd-status-r69`
- Positive evidence: `chdir`, `fchdir` and `getcwd` preserve cache-directory
  identity.
- Negative evidence: deleting the active current directory makes `getcwd`
  and relative pathname resolution fail with `ENOENT`; invalid `fchdir` and
  `chdir` targets preserve `EBADF` and `ENOENT`.
- Environment: Jasper UEFI, Linux x86_64 compatibility ABI.

## POSIX record locks

- `evidence/compat-wine-fcntl-r39`
- `evidence/compat-wine-record-lock-wait-r73`
- Positive evidence: a parent write lock is visible to a forked child through
  `F_GETLK`; a blocked `F_SETLKW` succeeds after unlock, and close releases the
  byte range for a later child.
- Negative evidence: a conflicting nonblocking child lock returns
  `EACCES`/`EAGAIN`, a read-only descriptor fails with `EBADF`, and a blocked
  waiter interrupted by `SIGUSR1` returns `EINTR`.
- Environment: Jasper UEFI, Linux x86_64 compatibility ABI.

## Unix sockets

- `evidence/compat-wine-socket-name-r42`
- `evidence/compat-wine-listener-r45`
- `evidence/compat-wine-listener-poll-r46`
- `evidence/compat-wine-protocol-io-r49`
- `evidence/compat-wine-protocol-r50`
- `evidence/compat-wine-read-enter-r52`
- `evidence/compat-wine-unix-socket-r76`
- `evidence/compat-wine-scm-truncation-r85`
- Positive evidence: pathname bind/listen/connect/accept, pending accept
  readiness, socket inode stat, unlink and peer EOF work.
- Negative evidence: duplicate pathname bind returns `EADDRINUSE` and connect
  through either a missing or stale name returns `ENOENT`.
- Positive message evidence: `send/recv`, `sendmsg/recvmsg`, `SCM_RIGHTS`,
  `readv/writev`, and transferred-descriptor lifetime work.
- Negative message evidence: invalid control length returns `EINVAL`, invalid
  iovec storage returns `EFAULT`, peer closure returns EOF, and descriptor-table
  exhaustion returns payload with `MSG_CTRUNC` and zero control length.
- Environment: Jasper UEFI, Linux x86_64 compatibility ABI.

## Vectored I/O

- `evidence/compat-wine-writev-pipe-20261121-r5`
- `evidence/compat-wine-scm-truncation-r85`
- `evidence/compat-wine-vectored-abi-r98`
- Positive evidence: unmodified wineserver returns the 64-byte reply header
  plus its variable payload through `writev`, allowing the client to complete
  `init_first_thread` and continue the Wine protocol.
- Positive evidence: cache files support split-iovec `readv/writev`,
  `preadv/pwritev` at explicit offsets, and preserve the shared descriptor
  cursor for positioned operations; a 4 KiB nonblocking pipe reports a
  bounded short write.
- Negative evidence: 1025 iovecs return `EINVAL`, bad iovec storage returns
  `EFAULT` without advancing the cursor, and access-mode mismatches return
  `EBADF`.
- Environment: Jasper UEFI, Linux x86_64 compatibility ABI.

## Poll and epoll readiness

- `evidence/compat-wine-epoll-r47`
- `evidence/compat-wine-epoll-pri-20261121`
- `evidence/compat-wine-listener-ready-r53`
- `evidence/compat-wine-scm-truncation-r85`
- Positive evidence: `EPOLLPRI`, zero-interest `MOD`, listener queues and
  accepted-socket readability, edge delivery and elapsed timeout expiry.
- Negative evidence: invalid descriptors return `EBADF`, no-ready registrations
  time out, and `SIGUSR1` interrupts a blocking wait with `EINTR`.

## Monotonic time

- `evidence/compat-wine-epoll-timeout-r78`
- Positive evidence: `CLOCK_MONOTONIC` advances across relative sleep and
  blocking absolute `clock_nanosleep` reaches its deadline.
- Negative evidence: invalid clock IDs and negative `timespec` values return
  `EINVAL`.

## File-backed shared mapping

- `evidence/compat-wine-mmap-cache-20261121-r7`
- `evidence/compat-wine-cache-shared-run-20261121-r12`
- `evidence/compat-wine-file-mmap-r101`
- Positive evidence: writable cache files share one page-backed object across
  wineserver and the Wine client; `MAP_SHARED` maps `user_shared_data`.
- `evidence/compat-wine-remaining-abi-r96`
- Positive evidence: `MAP_SHARED` writes are visible between parent and
  forked-child mappings; `MAP_PRIVATE` creates a write-private copy of the
  current shared content; an unlinked file remains readable through its open
  descriptor and existing mapping.
- Negative evidence: a writable `MAP_SHARED` request through a read-only
  descriptor returns `EACCES`.
- Positive evidence: a file mapping at byte offset 4096 reads its own page;
  mapping writes are visible through `pread`, and `MAP_FIXED` replaces an
  existing shared range.
- Negative evidence: after truncating an 8 KiB file to 4 KiB, `fstat` and
  `pread` observe the new length and a child accessing the invalidated second
  mapped page terminates with `SIGBUS`.

## Low private address window

- `evidence/compat-wine-low-window-20261121-r19`
- `evidence/compat-wine-mmap-cursor-r27`
- `evidence/compat-wine-low-prot-none-r57`
- Positive evidence: the 4 GiB `vprot` allocation range is admitted in the
  compatibility low private window.
- Positive evidence: ordinary `mmap(NULL)` can restart from the base or search
  top-down after a fixed mapping exhausts the forward cursor.
- Positive evidence: PROT_NONE reservations prefer the low private window,
  avoiding overlap with Wine's fixed high system views.
- `evidence/compat-wine-remaining-abi-r96`
- Positive evidence: explicit 4 GiB and 5 GiB mappings succeed and
  `MAP_32BIT` remains in `[128 MiB, 2 GiB)`.
- Negative evidence: an address below 128 MiB and the 512 GiB boundary fail
  with `ENOMEM`.

## Wine bootstrap

- `evidence/compat-wine-server-r44`
- `evidence/compat-wine-protocol-r50`
- `evidence/compat-wine-read-enter-r52`
- `evidence/compat-wine-pe-imports-20261121-r15`
- `evidence/compat-wine-module-debug-20261121-r18`
- `evidence/compat-wine-apisetschema-r28`
- `evidence/compat-wine-mmap-cursor-r27`
- `evidence/compat-wine-bootstrap-r37`
- `evidence/compat-wine-win32u-imm-r44`
- `evidence/compat-wine-low-prot-none-r57`
- `evidence/compat-wine-file-mode-r65`
- `evidence/compat-wine-remaining-abi-r96`
- Positive evidence: the unmodified Wine preloader, wineserver, prefix creation,
  protocol exchange, PE `start.exe`, `ntdll.dll`, `kernel32.dll`,
  `kernelbase.dll`, `win32u.dll`, `imm32.dll` and `cmd.exe` load work.
- Positive evidence: `cmd.exe /c echo WINE_CMD_OK` executes the built-in,
  writes the literal output directly through the inherited standard-output
  handle, exits 0, and the bytes reach the serial log.
- Positive evidence: an immediately repeated Wine command exits 0 with
  `resources=true`; process frames, shared mappings, object-table entries,
  process-signal state and all cache allocation buckets return to baseline.
- Remaining Wine work is Direct3D through DXVK/VKD3D-Proton and Vulkan
  presentation, tracked separately from the POSIX runtime ABI.
