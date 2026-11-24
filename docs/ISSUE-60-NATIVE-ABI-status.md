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

`verification/native-abi-operation-matrix.tsv` now records every one of the
109 operations independently:

- registry ID, legacy name, version and side effect;
- retained/split/service/reserved decision and proposed target name;
- whether the operation is present in the kernel dispatch table;
- every current source consumer found by its generated registry symbol;
- candidate errors from the same operation family plus generic ABI errors;
- explicit wire-layout and PEP/consumer-authorization review gates;
- current evidence and migration status;
- the concrete condition still required before migration or retirement.

The default checker verifies the matrix is byte-for-byte current rather than
trusting a hand-written status file. Only `service.info` records a deployed
service runtime in this matrix; the legacy operation remains registered and
pending caller migration. All other operations remain classification-only.

USI v1 metadata now exposes canonical service names (`service.info.get`,
`service.process.list`, `service.module.*` and `service.time.now`) while the
existing syscall entries and numeric IDs retain their legacy registry names
for current callers. Wire service IDs are unchanged, and the old name remains
available as an explicit migration label. This is a naming vertical, not yet an
independently deployed Info/Process/Module service.

The shared eight-byte `ServiceHeader` wire shape has moved from the historical
`extension_abi` reservation file to `kernel_core::service_protocol`. Its
protocol/version/bytes layout is unchanged, and it carries no authority or
dispatch semantics.

The first independently deployed service vertical is `service.info`:

- `kernel_core::service_info` defines request/response discovery, idempotency
  identity, protocol/version and bounded response records;
- `user/infod` is a separate least-capability process receiving only one
  bootstrap Channel and the process/module read capabilities it needs;
- `user/infoprobe` exercises discovery, projected process/module counts,
  replay, deadline failure, malformed-version rejection, request-ID conflict,
  clean stop/restart and missing-capability denial;
- the service does not call the legacy `system.info.get` aggregation operation;
  it projects facts supplied by the existing process and module kernel
  boundaries, preserving SEC/PEP and avoiding a second registry.

The legacy operations remain registered for current callers. Their eventual
retirement still requires caller migration and ABI snapshot handling.

The external QEMU/OVMF gate now passes all ten checks:

```text
[JSR-SERVICE-INFO] describe=true snapshot=true replay=true deadline=true
protocol=true conflict=true conflict_status=1 restart=true
denied_capability=true ok=true
```

Evidence: `evidence/issue60-service-info-20261124-r8`. The test uses a real
child process, native Channel transport, process/module kernel read
boundaries, fresh restart, request replay/conflict and a deliberately reduced
capability set for denial.

## Framework updates incorporated

The latest #24/#61/#77/#82/#84 constraints establish one shared Charset and
content-revision fact owned by File Provider and interpreted by Globalization.
Logical directory views, search indexes and application interoperability consume
that authorized projection; they do not create parallel metadata authorities.
These constraints will be reused when File Service lands and do not justify new
kernel Charset, search or application-registry operations.

Run:

```text
python3 scripts/check-native-abi-domains.py
python3 scripts/check-native-abi-domains.py --check-matrix
python3 scripts/check-native-abi-domains.py --json
python3 scripts/check-native-abi-domains.py --write-matrix
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
