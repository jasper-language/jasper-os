# Issue #42 M02 mapped-capability revocation

The third M02 pass parks one real Process on an AddressSync key backed by a
shared MemoryObject, then unmaps the waiter's mapping from another CPU. The
revoker drains the scheduler wait key, the waiter revalidates its
MemoryCapability and fails closed with the mapping revoked, and frames/objects
return to baseline.

## Result

```text
[JSR-ADDRESS-SYNC] pass=1 phase=warmup mode=sync cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=2 phase=measured mode=sync cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=3 phase=revoke mode=revoke cpus=4 distributed=true parked=1 terminal=true revoked=true resources=true failed=0
```

The bounded QEMU process later reached its 100-second watchdog and exited
`124`; this is targeted mechanism evidence, not a complete boot acceptance.
