# Issue #35 timerfd/signalfd runtime-capacity closure

Date: 2026-11-19.

The Linux compatibility layer previously imposed separate fixed limits of 32
timerfd objects and 32 signalfd objects per process. Those counts were redundant
with descriptor-table admission and are removed.

Both object families now use:

```text
runtime FdTable soft/hard budget
-> metadata Vec::try_reserve
-> native Rights/Handle generation
```

## Runtime evidence

A real static x86_64 Linux ET_EXEC in Jasper CPL3 creates forty timerfds,
closes them, creates forty signalfds, closes them, and continues through the
remaining compatibility probes.

```text
linux-native: epoll=true many_epolls=true many_eventfds=true many_timerfds=true many_signalfds=true futex=true mmap=true io_uring=true
[JSR-LINUX-ABI] exec=true flavor=true write=true getpid=true gettid=true denied=true exit=true cpl3=true native=true epoll=true futex=true mmap=true io_uring=true syscalls=318 frames_before=60666 resources=true failed=0
COMPAT-SYSCALL PASS
qemu_rc=33
```

Artifacts:

```text
serial.txt
summary.txt
```

## Scope

This proves forty simultaneous instances of each family on x86_64 KVM and full
process cleanup. It is not an unbounded metadata claim and does not replace the
remaining signalfd delivery/large-batch/cancellation matrices.
