# Atomic ppoll/pselect6 signal-mask replacement

Date: 2026-11-18.

Command:

```text
COMPAT_SIGNAL_OUT=/tmp/compat-signal-atomic-qemu-r2 \
COMPAT_SIGNAL_TARGET=/tmp/compat-signal-atomic-target \
COMPAT_SIGNAL_TIMEOUT=240 \
COMPAT_SIGNAL_CPUS=1 \
bash scripts/compat-signal-sample.sh
```

The unmodified Ubuntu glibc fixture temporarily unblocks `SIGUSR1` through
`ppoll()` and `pselect6()` while the thread's persistent mask blocks it. Both
calls must return successfully and leave the original blocked mask intact.
It then leaves `SIGURG` persistently blocked, temporarily unblocks it in
`ppoll()`, and has another thread deliver `SIGURG`; `ppoll()` returns `EINTR`,
the handler runs, and `rt_sigreturn` restores the persistent blocked mask.

Result:

```text
compat-signal: PASS cpus=1
qemu_rc=33
jasper-signal-ok
[JSR-LINUX-SIGNAL] queued ... signal=23 pending=0x400000
[JSR-LINUX-SIGNAL] delivered ... signal=23 interrupted_result=-4
[JSR-COMPAT-SIGNAL] ... exit_zero=true resources=true failed=0
[JSR-COMPAT-SIGRETURN-XSTATE] ... exit_zero=true resources=true failed=0
```

This closes the previously explicit `ppoll` NULL-mask-only limitation and the
matching `pselect6` no-mask limitation. It does not claim every Linux signal
conformance case or physical-hardware qualification.
