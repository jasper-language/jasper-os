# Issue #35 eventfd runtime-capacity closure

Date: 2026-11-19.

The Linux compatibility layer previously imposed an additional fixed limit of
32 eventfd objects per process. That count was removed; eventfd metadata now
uses `Vec::try_reserve`, while descriptor admission remains governed by the
runtime FdTable soft/hard budget and native Rights.

## Probe correction

The first expanded probe used `syscall1` for `eventfd2`. The second syscall
argument is the defined flags word; leaving RSI unspecified produced flags=2 on
the third iteration and the kernel correctly returned `EINVAL`. The fixture now
uses `syscall3(SYS_EVENTFD2, 0, 0, 0)`.

This also confirms that malformed eventfd flags fail closed rather than being
ignored.

## Runtime evidence

The real static x86_64 Linux ET_EXEC inside Jasper CPL3:

```text
creates 40 eventfd descriptors
-> writes 7 to one eventfd
-> reads 7 back
-> closes all 40
-> continues futex/mmap/io_uring and exits 0
```

```text
linux-native: epoll=true many_epolls=true many_eventfds=true futex=true mmap=true io_uring=true
[JSR-LINUX-ABI] exec=true flavor=true write=true getpid=true gettid=true denied=true exit=true cpl3=true native=true epoll=true futex=true mmap=true io_uring=true syscalls=157 frames_before=60666 resources=true failed=0
COMPAT-SYSCALL PASS
qemu_rc=33
```

Artifacts:

```text
serial.txt
summary.txt
```

## Scope

This proves forty simultaneous eventfd instances and complete process cleanup
on x86_64 KVM. It does not prove unbounded eventfd metadata or the remaining
large-batch matrices for other compatibility objects.
