# Issue #42 subscription broadcast replay

Date: 2026-11-18.

This evidence covers the subscription version-continuity slice only. It does
not claim completion of every mechanism family audited under Issue #42.

## Configuration

```text
qemu-system-x86_64
accelerator=tcg
icount=shift=0
cpus=8
memory=768M
build=target/x86_64-unknown-none/release/jasper-kernel
feature=evt2-broadcast-verify
host_cpu_affinity=4-11
```

The dedicated plan uses the stage closure required by the real kernel APIs:
Console, Platform, Timer, Frames, KernelMap, Heap, Capacity, Devices, Profile,
Assembly, SchedMode, Space and SMP. It intentionally skips unrelated acceptance
cases from the shared prefix.

The drill creates a Process, one EventSource and seven Subscriptions. A
4096-event warm-up round runs first; the measured round publishes 1,000,000
strictly increasing events while seven consumer CPUs verify each delivered
sequence or a complete authoritative Resync snapshot.

## Result

```text
[JSR-SMP] start present=8 online=8 failed=0 source=acpi.madt dropped=0 disabled=0
[JSR-EVT2-BROADCAST-SUB] cpu=1 final=1000000 resyncs=20 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=2 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=3 final=1000000 resyncs=21 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=4 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=5 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=6 final=1000000 resyncs=20 continuous_or_resync=true
[JSR-EVT2-BROADCAST-SUB] cpu=7 final=1000000 resyncs=18 continuous_or_resync=true
[JSR-EVT2-BROADCAST] cpus=8 events=1000000 subscribers=7 all_final=true sequence=true bounded=true resources=true failed=0
qemu_rc=33
```

The final resource baseline is restored after both rounds. Cleanup destroys all
seven Subscriptions, the EventSource, Process and ExitState. No `panicked` or
`JSR-PANIC` marker occurs.

## Artifacts

```text
serial.txt
qemu_rc.txt
artifacts.sha256
kernel.img
```

Kernel image SHA-256:

```text
e170dd78dbda6df0eb8cfd8b26f2a2da007e1b3ba5857ee0efb1bd7d1fb20249
```

## Scope

This is a mechanism and sequence-consistency acceptance run. It is not a CPL3
multi-client load test, a hardware throughput benchmark, a p99 latency claim,
or evidence for the remaining Issue #42 native address-sync, Pager and backend
quiescence work.
