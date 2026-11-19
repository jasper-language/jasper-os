# Issue #35 pipe instance-capacity closure

Date: 2026-11-19.

The Linux compatibility layer previously imposed a fixed limit of 32 pipe
endpoint records per process. Pipe creation already receives two descriptor
slots from the runtime FdTable budget, so the separate count was redundant.

The fixed record count is removed. Both endpoints still require:

```text
runtime FdTable admission
-> Rights::READ / Rights::WRITE
-> failure-atomic endpoint installation
```

## Runtime evidence

A real static x86_64 Linux ET_EXEC creates forty simultaneous pipe2 pairs
(eighty endpoint descriptors), writes and reads one byte through every pair,
then closes all eighty descriptors and continues the remaining probes.

```text
linux-native: epoll=true many_epolls=true many_eventfds=true many_timerfds=true many_signalfds=true many_pipes=true futex=true mmap=true io_uring=true
[JSR-LINUX-ABI] exec=true flavor=true write=true getpid=true gettid=true denied=true exit=true cpl3=true native=true epoll=true futex=true mmap=true io_uring=true syscalls=518 frames_before=60666 resources=true failed=0
COMPAT-SYSCALL PASS
qemu_rc=33
```

Artifacts:

```text
serial.txt
summary.txt
```

## Scope

This proves forty simultaneous pipe pairs and full process cleanup on x86_64
KVM. It does not replace the remaining stream capacity, blocking/cancellation
and large-buffer pipe matrices.
