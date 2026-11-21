# CPU membership departure, 4-vCPU KVM

This evidence exercises the native CPU software-departure transaction:

1. preflight CPU runtime and scheduler membership;
2. move active device-IRQ routes away from the target;
3. withdraw scheduler membership;
4. close the target's Interrupt objects and return MSI-X bindings/vectors;
5. advance the CPU runtime generation;
6. update the per-CPU state and demote the line-IRQ quota;
7. restore MSI dispatch, runtime generation, state and scheduler membership.

## Command

The target was pinned to host CPUs 4-7 and bounded by `timeout 300`:

```sh
taskset -c 4-7 timeout 300 qemu-system-x86_64 \
  -accel kvm -cpu host -smp 4 -m 256M \
  -drive format=raw,file=target/cpu-membership-r6.img \
  -device virtio-rng-pci \
  -device virtio-net-pci,netdev=n0,host_mtu=1500,mq=on,vectors=10,rx_queue_size=256 \
  -netdev user,id=n0 \
  -device virtio-blk-pci,drive=d1 \
  -drive if=none,id=d1,file=evidence/cpu-membership-depart-20261121-r6/virtio-blank.img,format=raw,discard=unmap \
  -serial stdio -display none -no-reboot
```

## Result

The targeted IRQ Ring CPU-departure check passed:

```text
[JSR-IRQRING] depart target=1 objects=1 bindings=1 vectors=1 residual=0 routes=0 runtime_offline=true runtime_online=true generation=5/6 resumed=true sched_detached=true sched_resumed=true ok=true
[JSR-IRQRING] summary cpus=4 rounds=4 delivered=4/4 rejects=7/7 cancel=ok close_cancels_wait=ok cpu_depart=ok vectors_back=true frames_back=true failed=0
```

The same boot then exercised active route handoff:

```text
[JSR-SMP3] case=detach target=3 lines=2 rerouted=Ok(2) stale_targets=0 outside_online=0 msi_quiesced=true quota_demoted=true resources=true
[JSR-SMP3] summary cpus=4 device_lines=2 free_frames=57987/57987 objects=0/0 reclaimed=true checks=35 failed=0
```

The overall bounded QEMU process exited `124` later in an unrelated long timing
matrix. That timeout is not counted as a full acceptance pass; this directory
only proves the named CPU-membership and route-handoff checks.

## Regression found and fixed

The first run reproduced a lock-order failure because unused preallocated
`Vec` entries were dropped while `system.irq.routing` was held. The drop
entered the lower-ranked heap lock. Both line-IRQ detach and route rebalance now
release the routing guard before truncating those vectors.
