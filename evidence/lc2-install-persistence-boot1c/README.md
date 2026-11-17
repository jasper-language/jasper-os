# LC-2 native install/list first boot

The first boot mounts the real P0 virtio-blk installation region and formats it
only because the reserved 16 MiB area is completely empty.

```text
[JSR-NATIVE-INSTALL-STORE] mounted=true initialized=true base=34605072 sectors=32768
native-install-abi: ok package=true idempotent=true register=true grant=true query=true updates=true update_short=true handle=true rights=true close=true denied_short=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
qemu_rc=33
```

The P0 image and OVMF variables were retained for the second boot.
