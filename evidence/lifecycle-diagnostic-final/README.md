# LC-1 two-boot diagnostic persistence

Command:

```text
JASPER_BUILD_ALLOW_VBOX=1 LIFECYCLE_DIAG_ALLOW_VBOX=1 \
  bash scripts/lifecycle-diagnostic-block-check.sh
```

Result: two real QEMU boots, both exit 33.

```text
round 1: events=5 sequence=6 query=4 sources=2 privacy=true append=true failed=0
round 2: events=6 sequence=7 query=4 sources=0 privacy=true append=true failed=0
summary: resources=true
```

The allow-VBox gate exists so an isolated TCG verifier can run on CPU 0 while
unrelated VirtualBox guests remain on other CPUs. `qemu-system*` is never
allowed to stack.
