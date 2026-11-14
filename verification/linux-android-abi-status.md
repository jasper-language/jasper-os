# Linux/POSIX and Android ABI status

Audit baseline: current public `main`, including the `KCMP_SYSVSEM`, LSM
self-attribute, `remap_file_pages`, fanotify, and userfaultfd implementations.

## Coverage

- Linux x86_64 enum surface: **385/385 mapped**
  - 382 entries dispatch through `kernel/src/linux_abi.rs::execute`
  - 3 pre-dispatch entries: `execve`, `execveat`, and `rt_sigreturn`
- Android kernel ABI: **94/94** strict items verified
- Native ABI contract: **3.14.0**

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
- VFS and memory: root-backed dynamic ELF execution, file metadata, read-only
  file `MAP_SHARED`, mmap/mremap/munmap/mprotect, mseal, memfd/ashmem, ION,
  dma-buf, `remap_file_pages`, and bounded NUMA policy operations.
- Signals and time: standard/realtime signals, signal payloads, sigreturn,
  timers, rusage, times, and clock operations.
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

## Acceptance evidence

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
