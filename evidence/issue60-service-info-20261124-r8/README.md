# Issue 60 independent service.info acceptance

QEMU/OVMF status: **PASS** (`qemu_rc=33`).

```text
[JSR-SERVICE-INFO] describe=true snapshot=true replay=true deadline=true protocol=true conflict=true conflict_status=1 restart=true denied_capability=true ok=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

The daemon is a separately spawned least-capability process reached through a
native Channel. The test covers protocol discovery, projected process/module
counts, replay, expiration, malformed protocol, request-ID conflict, restart
and denial when fact-reading capabilities are absent.
