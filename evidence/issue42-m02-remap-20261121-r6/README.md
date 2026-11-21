# Issue #42 M02 mapped-capability remap

The fifth M02 pass parks one Process on an AddressSync key, unmaps its old
mapping, re-maps the same shared MemoryObject handle at a new user address,
drains the scheduler wait key, and verifies that the old capability is revoked
while the new mapping is admitted. Resources return to baseline.

## Result

```text
[JSR-ADDRESS-SYNC] pass=1 phase=warmup mode=sync cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=2 phase=measured mode=sync cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=3 phase=revoke mode=revoke cpus=4 distributed=true parked=1 terminal=true revoked=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=4 phase=exit mode=exit cpus=4 distributed=true parked=1 terminal=true exited=true revoked=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=5 phase=remap mode=remap cpus=4 distributed=true parked=1 terminal=true remapped=true revoked=true resources=true failed=0
```

The bounded QEMU process later reached its 100-second watchdog and exited
`124`; this is targeted mechanism evidence, not a complete boot acceptance.
