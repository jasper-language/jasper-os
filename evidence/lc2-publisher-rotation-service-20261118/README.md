# LC-2 publisher rotation service evidence

Date: 2026-11-18.

The native installation drill ran three consecutive OVMF/virtio-blk boots over
the same P0 data image. The first boot installed two package versions, two user
registrations, a runtime, a grant and owned data, updated user 7 to package v2,
then rotated that installation from its old Ed25519 publisher key to a new key.

The rotation request was authorized through the shared kernel authorization
projection before mutation:

```text
[JSR-AUTHZ] version=1 issuer=1 tenant=7 domain=1
operation=system.install.publisher.rotate scope=user effect=write
policy=1 revocation=None decision=true reason=allowed
```

The real Ed25519 adapter verified both old-key and new-key signatures over the
installation/app/version/generation/nonce-bound canonical message. The kernel
service then persisted key generation 2 only after the audit decision.

```text
round 1:
stage=format upgrade=true runtime_old=true data_new=true
publisher_rotation=true packages=2 installations=2 grants=1 runtimes=1 data=1 failed=0

rounds 2 and 3:
stage=reopen upgrade=true runtime_old=true data_new=true
publisher_rotation=true packages=2 installations=2 grants=1 runtimes=1 data=1
bytes=26 faults=9 failed=0

all rounds:
summary failed=0 resources=true
qemu_rc=33
```

The reopened state verifies user 7 has the replacement key at generation 2,
while user 8 keeps the old key at generation 1. Active runtime package identity,
grant, data lineage and fault-injection outcomes remain unchanged.

The standard two-boot production stack also passed:

```text
native-install-default-stack: PASS rounds=2
```

The acceptance harness runs this case on the bootloader-provided stack before
task stacks exist. Its verification-only boot stack is 512 KiB; the kernel task
profile remains the standard 128 KiB. The earlier 128 KiB harness stack hit its
guard page in `InstallModel::restore_state`; snapshot reader buffers were moved
off the nested stack and the bootloader stack policy was made explicit.

This is a real QEMU/OVMF software-profile result. It is not a frozen user ABI,
CLI integration, hardware monotonic anchor, Pixel install or physical power-cut
acceptance.
