# Issue 60 native ABI domain audit

Updated: 2026-11-24.

Status: **audit and policy inventory started; no ABI migration is claimed.**

The target naming decision is:

- `kernel.*`: operations that must be enforced at the kernel boundary;
- `service.*`: independently versioned domain services;
- `exokernel.*`: optional, evidence-driven DDI for genuinely constrained
  out-of-kernel modules; it may remain empty;
- Compatibility: Linux, Android, Win32 and Darwin ABI remain outside the
  native public protocol.

`system.*` and `extension.*` are retired for new native protocols. Existing
operations remain until their real consumers, wire layouts, authorization and
migration tests are resolved. IDs are not reassigned for cosmetic consistency.

## Current repository baseline

- ABI generation: `3.22.0`;
- registry: 109 current `op` records plus errors;
- 5 reserved operations: IDs 37, 38, 39, 40 and 42;
- no generic Extension Manager or universal dispatch is to be introduced;
- `kernel-core/src/extension_abi.rs` is a mixed historical reservation file,
  not a live extension authority. `check_sqe_flags()` remains an active Ring
  protection and must not be removed with the name.

## New audit gate

`verification/native-abi-domain-policy.toml` and
`scripts/check-native-abi-domains.py` classify every current op into:

- `retain-kernel`;
- `migrate-service`;
- `split-review`;
- `reserved-review`.

This gate proves that the registry is fully classified and that no proposed
target name remains in `system.*` or `extension.*`. It does **not** prove that
any operation can be removed or migrated. A migration still requires a real
consumer matrix, replacement service/gate, security boundary, wire and ABI
snapshot decisions, failure/cancel/recovery tests, and public runtime changes.

USI v1 metadata now exposes canonical service names (`service.info.get`,
`service.process.list`, `service.module.*` and `service.time.now`) while the
existing syscall entries and numeric IDs retain their legacy registry names
for current callers. Wire service IDs are unchanged, and the old name remains
available as an explicit migration label. This is a naming vertical, not yet an
independently deployed Info/Process/Module service.

Run:

```text
python3 scripts/check-native-abi-domains.py
python3 scripts/check-native-abi-domains.py --json
```

## Important split boundaries

- Device discovery/listing/policy and device MMIO/IRQ/DMA/IOMMU enforcement
  must not be assigned as one atomic rename.
- Workload/Sandbox management and image/volume/launch services must retain
  the kernel's process, memory, quota and revocation primitives.
- A service endpoint is not a second permission root and cannot authorize on
  behalf of the kernel, SEC/PEP or resource owner.
- Existing `system.*` names remain for current callers until a versioned
  migration is implemented and verified.
