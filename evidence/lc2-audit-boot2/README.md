# LC-2 terminal archive audit — second boot

This boot reuses the exact P0/OVMF state from `lc2-audit-boot1`; no control,
GPT, filesystem or archive initialization was run. `system update audit`
returns the persisted receipt:

```text
sequence=1 transaction=1 terminal=complete
digest=68d00296644483d365ecb17f4163588c5f1b27944a56f26f73556507a9c2bd3a
previous=0000000000000000000000000000000000000000000000000000000000000000
available=true qemu_rc=124
```

The digest and sequence match the first boot, proving the audit query crosses a
real OVMF restart without a RAM-backed substitute. This is not a physical Pixel
update qualification.
