# LC-2 application upgrade and data-scope persistence

Date: 2026-11-18.

This drill runs the application upgrade model on three consecutive boots over the
same real OVMF/virtio-blk data image. It proves the QEMU software profile only;
Pixel physical installation remains a separate gate.

First boot formats the bounded store and creates:

- package v1 and package v2 with the same AppID and publisher;
- user 7 and user 8 installations of v1;
- one active user 7 runtime and one user 7 data scope;
- one explicit user 7 launch grant;
- an atomic user 7 upgrade to v2.

The active runtime remains bound to v1, user 7's installation and owned data move
to v2, and user 8's installation and data remain on v1.

Key evidence:

```text
round-1:
stage=format upgrade=true runtime_old=true data_new=true packages=2
installations=2 grants=1 runtimes=1 data=1 failed=0

round-2 and round-3:
stage=reopen upgrade=true runtime_old=true data_new=true packages=2
installations=2 grants=1 runtimes=1 data=1 bytes=26 faults=9 failed=0

all rounds:
summary failed=0 resources=true
qemu_rc=33
```

The reopen rounds also run all nine injected snapshot write/flush interruption
points. Every interruption preserves either the complete old state or the
complete new state; no partial installation/data migration is accepted.

Command:

```text
NATIVE_INSTALL_OUT="$PWD/evidence/lc2-app-upgrade-20261118" \
NATIVE_INSTALL_TARGET="$PWD/target/native-install-upgrade-20261118" \
NATIVE_INSTALL_QEMU_CPUS=6-7 \
NATIVE_INSTALL_ALLOW_VIRTUALBOX=1 \
JASPER_BUILD_ALLOW_VBOX=1 \
JASPER_BUILD_CPUS=4-5 \
NATIVE_INSTALL_TIMEOUT=120 \
bash scripts/native-install-block-check.sh
```
