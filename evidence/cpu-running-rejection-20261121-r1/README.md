# CPU departure rejects a running task

This four-vCPU run first places a running task on the target CPU and attempts
the complete CPU membership-departure transaction. The scheduler preflight must
reject the attempt without moving routes, closing MSI state, changing runtime
generation, or removing scheduler membership.

After the running task is released, the same boot performs the successful
migration/offline path.

## Result

```text
[JSR-IRQRING] depart target=1 objects=1 bindings=1 vectors=1 residual=0 routes=0 tasks=1 running_rejected=true runtime_offline=true runtime_online=true generation=5/6 resumed=true sched_detached=true sched_resumed=true ok=true
[JSR-IRQRING] summary cpus=4 rounds=4 delivered=4/4 rejects=7/7 cancel=ok close_cancels_wait=ok cpu_depart=ok vectors_back=true frames_back=true failed=0
```

The bounded QEMU process later hit its 100-second watchdog in the unrelated
long matrix (`qemu_rc=124`); this is targeted mechanism evidence, not a full
acceptance claim.
