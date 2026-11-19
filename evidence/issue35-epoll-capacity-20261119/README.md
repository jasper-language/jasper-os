# Issue #35 epoll instance-capacity closure

Date: 2026-11-19.

The Linux compatibility layer previously imposed an additional hard limit of
eight epoll instances per process. That count had no protocol or security
meaning and bypassed the runtime FdTable budget.

The fixed count gate is removed. Epoll creation now fails only through the
existing bounded paths:

```text
runtime FdTable soft/hard capacity
-> metadata Vec::try_reserve
-> native Handle/Rights generation checks
```

## Runtime evidence

The static x86_64 Linux ET_EXEC probe creates twelve epoll descriptors in one
process, closes all twelve, then continues through futex, mmap and io_uring
tests and exits successfully.

```text
linux-native: epoll=true many_epolls=true futex=true mmap=true io_uring=true
[JSR-LINUX-ABI] exec=true flavor=true write=true getpid=true gettid=true denied=true exit=true cpl3=true native=true epoll=true futex=true mmap=true io_uring=true syscalls=76 frames_before=60666 resources=true failed=0
```

Acceptance result:

```text
COMPAT-SYSCALL PASS
qemu_rc=33
```

Artifacts:

```text
serial.txt
summary.txt
```

## Scope

This run used x86_64 KVM, the real Jasper CPL3 Linux flavor dispatcher, and a
static Linux ET_EXEC. It proves twelve simultaneous epoll instances and complete
process cleanup, not unbounded epoll/interest storage or the remaining
poll/signalfd/fanotify large-batch matrices.
