# LC-2 native install/list second boot

This boot reuses the exact P0 image and OVMF state from the first boot. The
installation store opens the existing committed state instead of formatting.

```text
[JSR-NATIVE-INSTALL-STORE] mounted=true initialized=false base=34605072 sectors=32768
native-install-abi: ok package=true idempotent=true register=true grant=true query=true updates=true update_short=true handle=true rights=true close=true denied_short=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
qemu_rc=33
```

This proves package bytes, installation identity, tenant-visible update records,
grants and list ABI state survive a real OVMF reboot. Pixel physical update
acceptance and the full power-loss matrix remain separate gates.
