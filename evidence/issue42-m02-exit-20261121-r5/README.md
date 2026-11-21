# Issue #42 M02 parked-process exit

The fourth M02 pass parks a real Process on an AddressSync scheduler key, then
exits and reaps that Process from another CPU. Process teardown revokes the
mapped capability, the waiter is woken and fails closed, and all resources
return to baseline.

## Result

```text
[JSR-ADDRESS-SYNC] pass=1 phase=warmup mode=sync cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=2 phase=measured mode=sync cpus=4 distributed=true publisher_distributed=true parked=2 terminal=true same_object=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=3 phase=revoke mode=revoke cpus=4 distributed=true parked=1 terminal=true revoked=true resources=true failed=0
[JSR-ADDRESS-SYNC] pass=4 phase=exit mode=exit cpus=4 distributed=true parked=1 terminal=true exited=true revoked=true resources=true failed=0
```

The bounded QEMU process later reached its 100-second watchdog and exited
`124`; this is targeted mechanism evidence, not a complete boot acceptance.
