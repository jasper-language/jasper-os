# UI Policy Contract Status

Updated: 2026-11-20

Status: **schema and lifecycle state-machine slice implemented; UI-POLICY-CONTRACT-1
remains open.**

`kernel-core/src/ui_policy.rs` defines a versioned, no-allocation contract with:

- observed capability facts independent of device names;
- explicit SinglePrimary/Split/MultiWindow preference negotiation with
  `Selected`, `Degraded` and `Unsupported` outcomes;
- immutable capability, policy and revocation epochs;
- Scene visible/focused/rendering/background-grant facts with fail-closed
  invariants;
- generation-safe Surface migration bound to scene and input generations and to
  the existing unified `authz::Decision`, specifically
  `ServiceUiFramePresent`, user scope, tenant and policy epoch;
- bounded 80-byte snapshot encoding with version, length, magic, reserved-byte,
  profile, surface and epoch rejection.

The contract does not decide permissions, create a second UI authority, route
input, own display sessions or select a platform from a hardware model string.

## Verification

```text
cargo test -p kernel-core ui_policy
5 passed; 0 failed

cargo check -p kernel-core --target x86_64-unknown-none
PASS
```

Tests cover capability-based profile degradation, snapshot round-trip and
malformed/unsupported records, invisible focus, independent hidden rendering,
focus conflicts, stale scene/surface generations, stale revocation epochs,
authorization epoch mismatch and migration rollback identity.
The contract does not define a parallel authorization receipt type.

## Remaining gates

- A user-space Policy Service must publish these immutable snapshots and consume
  real capability-change events.
- The real CPL3 UI Service must bind unified PEP authorization and display/input
  resource preflight to migration commits.
- Two real applications must prove Mobile single-primary focus and background
  grant behavior; multi-window and hotplug are later DAG nodes.
- Existing QEMU framebuffer/PS-2 evidence is not a physical product matrix.
