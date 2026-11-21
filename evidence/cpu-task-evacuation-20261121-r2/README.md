# CPU departure with task evacuation

This four-vCPU KVM run blocks a scheduler task whose home is CPU 1, then moves
the complete task from that CPU as part of the CPU software-departure
transaction. The departing CPU is followed by scheduler, MSI, runtime and quota
cleanup; the migrated task wakes and finishes.

## Result

```text
[JSR-CPU-DEPART] stage=scheduler cpu=1 routes=0 tasks=1
[JSR-IRQRING] depart target=1 objects=1 bindings=1 vectors=1 residual=0 routes=0 tasks=1 runtime_offline=true runtime_online=true generation=5/6 resumed=true sched_detached=true sched_resumed=true ok=true
[JSR-IRQRING] summary cpus=4 rounds=4 delivered=4/4 rejects=7/7 cancel=ok close_cancels_wait=ok cpu_depart=ok vectors_back=true frames_back=true failed=0
```

The QEMU run reached the named IRQ Ring marker and then hit its 100-second
watchdog in the unrelated long matrix (`qemu_rc=124`). It is targeted mechanism
evidence, not a full acceptance claim.
