# Issue #42 M02 multi-CPU address synchronization

This drill keeps the two native Process objects and shared MemoryObject from the
previous M02 test, but pins both waiters and the publisher to distinct online
CPUs. Each task parks through the existing scheduler Task event-wait key; one
cross-CPU publish produces exactly one terminal state and wakes both waiters.

## Command

```sh
taskset -c 4-7 timeout 100 qemu-system-x86_64 \
  -accel kvm -cpu host -smp 4 -m 256M \
  -drive format=raw,file=target/m02-multicpu-r2.img \
  -device virtio-rng-pci \
  -device virtio-net-pci,netdev=n0,host_mtu=1500,mq=on,vectors=10,rx_queue_size=256 \
  -netdev user,id=n0 \
  -device virtio-blk-pci,drive=d1 \
  -drive if=none,id=d1,file=evidence/issue42-m02-multicpu-20261121-r2/virtio-blank.img,format=raw,discard=unmap \
  -serial stdio -display none -no-reboot
```

## Result

```text
[JSR-ADDRESS-SYNC] pass=1 phase=warmup cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=2 phase=measured cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
```

The bounded QEMU process later reached its 100-second watchdog and exited
`124`; that timeout does not invalidate the two named M02 passes, but it is not
recorded as a full boot acceptance.
