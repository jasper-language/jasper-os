# LC-2 application upgrade on the default production stack

Date: 2026-11-18.

This two-boot OVMF/virtio-blk regression uses
`native-install-block-verify` without the fault-injection verification feature.

```text
round-1:
stage=format upgrade=true runtime_old=true data_new=true packages=2
installations=2 grants=1 runtimes=1 data=1 failed=0
qemu_rc=33

round-2:
stage=reopen upgrade=true runtime_old=true data_new=true packages=2
installations=2 grants=1 runtimes=1 data=1 bytes=26 faults=0 failed=0
qemu_rc=33

summary failed=0 resources=true
```

The result shows the v3 persistence format and application-update semantics are
not dependent on test-only fault injection.

Command:

```text
NATIVE_INSTALL_DEFAULT_OUT="$PWD/evidence/lc2-app-upgrade-default-20261118" \
NATIVE_INSTALL_DEFAULT_TARGET="$PWD/target/native-install-upgrade-20261118" \
NATIVE_INSTALL_DEFAULT_QEMU_CPUS=6-7 \
NATIVE_INSTALL_ALLOW_VIRTUALBOX=1 \
JASPER_BUILD_ALLOW_VBOX=1 \
JASPER_BUILD_CPUS=4-5 \
NATIVE_INSTALL_DEFAULT_TIMEOUT=120 \
bash scripts/native-install-default-stack-check.sh
```
