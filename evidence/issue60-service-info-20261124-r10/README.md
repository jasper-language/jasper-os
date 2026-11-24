# Issue 60 service.info list acceptance

Date: 2026-11-24.

The independent `infod` process now exposes:

- fixed describe/snapshot responses;
- canonical USI process-list records;
- canonical USI module-list records;
- replay, request-ID conflict, deadline, malformed-version, restart and
  missing-capability failures.

The list operations project the existing kernel process/module facts over one
native Channel. They do not create a second process or module registry.

```text
[JSR-SERVICE-INFO] describe=true snapshot=true replay=true process_list=true
module_list=true list_replay=true deadline=true protocol=true conflict=true
conflict_status=1 restart=true denied_capability=true ok=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

Artifact hashes:

```text
72323271f8fa0ddd3c5b13bc61bea57623e833f3875816b6dc53c87bc040adc1  serial.log
19b8d5c59e421f037fe563007c7254eb8d98bc221b278c3db3e5fdbbfd52e273  qemu.rc
a7039164c891361a7de79eb1bf38136993c3d290e7563c6421e6999cec2c6afb  kernel-build.log
```

The service replacement is deployed while the legacy syscall registration
remains for callers that have not yet migrated.
