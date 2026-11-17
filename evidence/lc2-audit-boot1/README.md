# LC-2 terminal archive audit — first boot

The first OVMF boot archives the current terminal transaction and queries the
durable receipt through `system update audit`, both human and JSON.

```text
[JSR-UPDATE-AUDIT] available=true sequence=1 transaction=1 result=ok
system-update audit=ok command=system.update.audit available=true sequence=1 transaction=1 terminal=complete
{"schema":"service.update.audit/1","command":"system.update.audit","available":true,"sequence":1,"transaction":1,"terminal":"complete"}
qemu_rc=124
```

`qemu_rc=124` is the declared terminal-recovery success exit after the CLI has
finished and the production kernel reports `reclaimed=true`. The P0 image and
OVMF variables were retained for the second boot.
