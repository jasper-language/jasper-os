# LC-2 concurrent Agent start-gate acceptance

This run rebuilds the four-process update-Agent test from a clean P0/OVMF image
with the committed readiness barrier. All four broker/client pairs must reach
the gate before any request is released, so their request phases genuinely
overlap.

```text
issue21-uefi-boot: PASS mode=update-agent qemu_rc=33
[JSR-UPDATE-AGENT-CONCURRENT] workers=4 rounds=6 process_isolation=true failed=0 ok=true
[JSR-UPDATE-AGENT] ... concurrent=true ... child_exit=0 ok=true payload_mismatch=true
[JSR-PROD] first_program state=Some(Exited { code: 0 }) reclaimed=true
```

Each worker owns a separate `user-updateagentd` process and Channel. Identical
service request IDs remain process-local while the shared update service and P0
virtio-blk backend are exercised concurrently.

This is OVMF/virtio-blk concurrency evidence. It is not Pixel 6a installation,
rollback, or power-loss acceptance, and therefore does not close LC-2.
