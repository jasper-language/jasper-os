# Linux/POSIX and Android ABI status

Audit baseline: current public `main`, including the `KCMP_SYSVSEM`, LSM
self-attribute, `remap_file_pages`, fanotify, and userfaultfd implementations.

## Coverage

- Linux x86_64 enum surface: **385/385 mapped**
  - 382 entries dispatch through `kernel/src/linux_abi.rs::execute`
  - 3 pre-dispatch entries: `execve`, `execveat`, and `rt_sigreturn`
- Android kernel ABI: **94/94** strict items verified
- Native ABI contract: **3.14.0**

The compatibility ABI ledger is
`verification/linux-posix-abi-matrix.toml`. Its `mapped` count is syscall
surface coverage, not semantic verification. Each item records positive and
negative coverage, evidence, source commit and execution environment; semantic
work reruns only `partial`, `missing`, `stale` and implementation-affected
items. Validate the ledger with:

```text
python3 scripts/check-compat-abi-matrix.py --self-test
python3 scripts/check-compat-abi-matrix.py
```

The first semantically verified ledger items are Linux file status/mode,
positioned I/O, current-directory lifecycle and POSIX record locks. `fstat`
file type and umask-derived permissions, descriptor status flags, file size,
standard-character streams, FIFOs, sockets, `EBADF` and `ENOENT` are covered,
as are cache-file `pread64/pwrite64` cursor/error semantics, deleted-cwd
`getcwd`/relative-path behavior and cross-process fcntl lock conflicts/release.

`map_shadow_stack` returns `EOPNOTSUPP` because the current Jasper kernel
advertises no user shadow-stack feature through `ARCH_SHSTK_STATUS`. This is a
hardware/configuration boundary, not a claim that CET shadow stacks run.

Privileged operations such as mount, BPF, ptrace, kexec, and module loading
return `EPERM` under the compatibility authority model. Obsolete x86_64
entry points return `ENOSYS`, matching a Linux kernel built without those
removed interfaces.

## Verified behavior

- Processes and threads: fork, real vfork, exec, wait, orphan reaping, process
  groups, sessions, credentials, subreapers, and Binder thread identity.
- File descriptors: shared open-file descriptions, CLOEXEC, dup/dup2/dup3,
  pidfds, epoll, pipes, sockets, eventfd, timerfd, signalfd, inotify, mq,
  aio, and io_uring.
- Vectored I/O and batched messaging use Linux `UIO_MAXIOV=1024` rather than
  the former implementation-specific 16/64 limits; futex2 waitv uses the
  Linux `FUTEX_WAITV_MAX=128`. The CPL3 fixture executes 17 zero-length
  iovecs, sends 17 messages, rejects 1025 entries and 1025 iovecs, and uses a
  4-entry io_uring.
- io_uring ring/SQEs geometry is derived from requested entries and stored
  per instance. The native fixture also creates ten simultaneous rings,
  covering the former eight-instance process limit.
- VFS and memory: root-backed dynamic ELF execution, file metadata, read-only
  file `MAP_SHARED`, mmap/mremap/munmap/mprotect, mseal, memfd/ashmem, ION,
  dma-buf, `remap_file_pages`, and bounded NUMA policy operations.
- Signals and time: standard/realtime signals, signal payloads, sigreturn,
  timers, rusage, times, and clock operations.
- CPU affinity follows Linux's `cpumask_size()` eight-byte word granularity
  even on a one-CPU machine, so undersized caller masks fail with `EINVAL`.
- IPC: POSIX mqueue and all System V message, semaphore, and shared-memory
  lifecycle paths, including `KCMP_SYSVSEM`.
- Security: Landlock, seccomp, keyrings, fs-verity, fscrypt, Jasper MAC
  contexts, and attenuated `lsm_set_self_attr`.
- File notification: inotify and classic fanotify notification groups.
- userfaultfd missing-page mode: registered ranges, real fault delivery,
  COPY/ZEROPAGE registration, fault parking, resolution, and instruction retry.
- Probe trampoline ABI: untrusted `uprobe`/`uretprobe` calls return the
  kernel-compatible `EPROTO`/`SIGILL` behavior.
- Android: Binder freeze, references, security contexts, fscrypt, and
  fs-verity.

## Upstream userspace runtime checks

- Unmodified upstream Toybox was built as static PIE and executed through the
  Jasper UEFI/root-image/Linux ABI path: `uname`, `printf`, and `sha256sum`
  all exited zero.
- The unmodified AOSP Binder `binderDriverInterfaceTest.cpp` passed **20/20**
  cases on the Jasper UEFI path, including transactions, death and freeze
  notifications, reference commands, ioctl errors, and nonblocking reads.
- Unmodified Ubuntu Wine 10.0 loaded its preloader, wineserver, PE
  `start.exe`, `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `win32u.dll`,
  `imm32.dll`, and `cmd.exe` through the Linux ABI. `cmd.exe /c echo
  WINE_CMD_OK` executed the built-in, wrote directly to the inherited standard
  output, and exited 0.
- The upstream multi-DEX `AndroidAutoBuildAPK-v18.apk` passed AOSP `aapt2`
  container/Manifest validation and one Java entry executed through unmodified
  Bionic and ART in the Jasper UEFI root-image path with exit 0 and
  `resources=true`. Android Activity lifecycle remains pending.
- See [ecosystem-runtime-tests.md](ecosystem-runtime-tests.md) for exact
  evidence and for host-only DXVK/VKD3D-Proton, Metal2Vulkan, Darling,
  OpenJDK and ART baselines. Host results and synthetic syscall mappings are
  not counted as Jasper ABI semantic passes.

## Acceptance evidence

- Latest full Linux/Android root UEFI slice:
  `evidence/issue21-uefi-boot-20261120-204541`
- Compatibility ABI / Wine command execution:
  `evidence/compat-wine-record-lock-wait-r73`

- Full Linux/Android root UEFI:
  `evidence/issue21-uefi-boot-20261115-userfaultfd-v123-clean`
- Sandbox launch UEFI:
  `evidence/issue21-uefi-boot-20261115-userfaultfd-sandbox-v124`
- Android-focused UEFI:
  `evidence/issue21-uefi-boot-20261114-linux-android-merged-v100`
- `KCMP_SYSVSEM`:
  `evidence/issue21-uefi-boot-20261114-kcmp-sysvsem-v105`
- LSM self-label attenuation:
  `evidence/issue21-uefi-boot-20261114-lsm-set-self-attr-v106`
- `remap_file_pages` transactional remap:
  `evidence/issue21-uefi-boot-20261114-remap-file-pages-v107`
- fanotify open/access/close delivery:
  `evidence/issue21-uefi-boot-20261114-fanotify-v109`
- uprobe/uretprobe entry semantics:
  `evidence/issue21-uefi-boot-20261114-uprobe-entry-v111`
- userfaultfd missing-page recovery:
  `evidence/issue21-uefi-boot-20261115-userfaultfd-v123-clean`

Every QEMU run above exits with `qemu_rc=33`, reaches
`root_execution_complete`, and performs no parallel issue21 boot.
