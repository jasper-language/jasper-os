# LC-2 unified authorization on current public main

Date: 2026-11-18

This run combines the current public main with the authorization
consistency fixes. The kernel update status, recover, archive, and audit paths
project authenticated identity, tenant, MAC domain, SysCallSet authority,
policy epoch, and operation effect into one shared `kernel-core::authz`
decision. No second permission table is introduced.

```text
[JSR-AUTHZ] ... subject=11 executor_generation=0 tenant=1430340679 domain=1
  operation=system.update.status scope=platform effect=read
  decision=true reason=allowed
[JSR-AUTHZ] ... operation=system.update.recover ... effect=write
  decision=true reason=allowed
[JSR-AUTHZ] ... operation=system.update.archive ... effect=write
  decision=true reason=allowed
[JSR-UPDATE-AGENT-CONCURRENT] workers=4 rounds=6 process_isolation=true
  failed=0 ok=true
[JSR-UPDATE-AGENT] ... child_exit=0 ok=true payload_mismatch=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
qemu_rc=33
```

The first object-table generation, `generation=0`, is accepted only after the
same active `SecurityContext` validation used by the security subsystem.
Temporary agents receive distinct generations and all decisions remain bound
to the authenticated tenant/domain.

Unit tests fail closed for a foreign issuer, non-subject object class,
inactive identity, zero tenant, scope mismatch, operation/effect mismatch,
missing SysCallSet capability, stale policy/revocation facts, untrusted-clock
leases, and excessive delegation depth.

This closes the LC-2 shared authorization projection consistency slice. It
does not close the full Issue #39 system-wide policy matrix, revocation
propagation, Pixel 6a installation lifecycle, or LC-2.
