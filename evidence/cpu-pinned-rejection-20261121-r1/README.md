# CPU departure rejects a task without a migration destination

This four-vCPU run blocks a task whose home and affinity are both the target
CPU. CPU departure preflight must reject `no-affinity-destination` before route,
MSI, runtime or scheduler membership changes.

After the pinned task completes, the same boot performs successful blocked-task
migration and CPU departure.

## Result

```text
[JSR-IRQRING] depart target=1 objects=1 bindings=1 vectors=1 residual=0 routes=0 tasks=1 running_rejected=true pinned_rejected=true runtime_offline=true runtime_online=true generation=5/6 resumed=true sched_detached=true sched_resumed=true ok=true
[JSR-IRQRING] summary cpus=4 rounds=4 delivered=4/4 rejects=7/7 cancel=ok close_cancels_wait=ok cpu_depart=ok vectors_back=true frames_back=true failed=0
```

The bounded QEMU run later hit its 100-second watchdog in the unrelated long
matrix (`qemu_rc=124`); this is targeted mechanism evidence, not a full
acceptance claim.
