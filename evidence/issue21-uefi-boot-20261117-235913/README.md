# LC-2 unified authorization projection acceptance

Date: 2026-11-18

The update status, recover, archive, and audit kernel adapters now project the
authenticated process identity, tenant, MAC domain, SysCallSet authority,
policy epoch, and operation effect into the shared `kernel-core::authz`
decision record. The adapter does not create a second permission table.

The real OVMF/virtio-blk update-Agent acceptance completed with the shared
authorization gate enabled:

```text
[JSR-AUTHZ] ... subject=11 executor_generation=0 tenant=1430340679 domain=1
  operation=system.update.status scope=platform effect=read
  decision=true reason=allowed
[JSR-AUTHZ] ... operation=system.update.recover ... effect=write
  decision=true reason=allowed
[JSR-AUTHZ] ... operation=system.update.archive ... effect=write
  decision=true reason=allowed
[JSR-UPDATE-AGENT-CONCURRENT] workers=4 rounds=6 process_isolation=true failed=0 ok=true
[JSR-UPDATE-AGENT] ... child_exit=0 ok=true payload_mismatch=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
qemu_rc=33
```

Host unit tests cover untrusted issuer, inactive identity, missing tenant,
scope mismatch, operation/effect mismatch, missing SysCallSet capability,
stale policy/revocation facts, untrusted-clock leases, and delegation depth.
First-generation object id `generation=0` remains a valid active subject, as
required by the kernel object table.

This proves LC-2 consumers use the shared authorization projection. It does
not prove the full system-wide Issue #39 matrix, production policy service,
revocation propagation, Pixel 6a installation lifecycle, or LC-2 done.
