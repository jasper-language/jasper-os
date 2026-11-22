# UI Multi-window Transition Status

Updated: 2026-11-21

Status: **done for the declared DAG gate: layout, CPL3 migration, dual-Surface
framebuffer output, capability/budget rollback and a platform capability event
producer are verified. Physical Pixel 6a display/input qualification remains a
separate `UI-PHYSICAL-MATRIX-1` node.**

`kernel-core::ui_workspace` provides a bounded, allocation-fallible contract for
the same application/Scene model under Single, Split and MultiWindow layouts:

- each Scene keeps its own Scene, Surface and input generation;
- Split uses an explicit primary-region permille; MultiWindow computes a
  non-overlapping grid;
- a capability event carries capability/policy/revocation epochs, display
  geometry and DPI;
- one unified `ServiceUiFramePresent` decision authorizes the complete workspace
  migration;
- total Surface bytes are preflighted against the caller's memory budget;
- all Scene generations and viewports are staged before commit, so malformed
  events, stale epochs, authorization failures and budget failures leave the old
  workspace unchanged;
- each Scene has one prepared-frame ticket; migration atomically clears all
  pending tickets, stale tickets cannot commit, and duplicate tickets fail;
- frames and input using pre-migration Surface/input generations are rejected.
- `UiCapabilityProducer` converts observed surface, DPI, keyboard and policy
  facts into one monotonically versioned capability event; unchanged polling
  does not rotate generations or cancel pending frames.

## Verification

```text
cargo test -p kernel-core ui_workspace --lib
4 passed; 0 failed
```

Tests cover single/split geometry, independent generation rotation, stale frame
and input rejection, pending-frame cancellation, capability degradation to Split,
budget failure atomicity and authorization failure atomicity.

The real CPL3 UI process drill constructs a two-Scene workspace from the active
framebuffer's actual geometry and keyboard availability. It first injects a
capability-loss event and then a Surface-budget failure; both are rejected
without changing the old mode, Surface generations or pending frame ticket,
and the old-generation frame remains usable. A retry with the real framebuffer
facts then commits MultiWindow migration and atomically cancels the pending
ticket. The real QEMU run passes twice with `qemu_rc=33`, no panic and complete
resource restoration; marker:

```text
[JSR-UI-MULTIWINDOW] layout=Ok(MultiWindow) source=framebuffer keyboard=true \
capability_rollback=true budget_rollback=true pending_canceled=true \
old_frame_rejected=true \
old_input_rejected=true new_surface_generation=true new_input_generation=true
```

The native framebuffer compositor also accepts two Engine Surfaces in one
transaction: it retires the decorative accent layer, validates and copies both
pixel buffers before locking display state, then places the applications in
independent left/right viewports. QEMU validates both pixels directly:

```text
[JSR-DISPLAY-UI] presented_layers=2 ... layers=3
[JSR-UI-MOBILE] ... display_layers=true
```

Both rounds restore all process, Channel, Surface and frame resources.

## Platform capability event producer

`kernel/src/display.rs` records display/input observations from the platform
event source without migrating a workspace or granting authority. The QEMU UI
process drill injects F12 through the real PS/2 path; the bounded producer
converts the changed platform facts into capability epoch 3, recomputes the
workspace, performs the unified `ServiceUiFramePresent` authorization and
budget preflight, then commits the new Surface/DPI/keyboard state atomically.
Two rounds report:

```text
[JSR-UI-HOTPLUG] observed=true source=platform key=0x012e event_epoch=3 \
surface=1216x720 dpi=128 keyboard=false committed=true \
old_frame_rejected=true failed=0
```

The QEMU run exits 33 and restores all process, Channel, Surface and frame
resources. The producer is part of the production display integration; the
verification feature provides the externally injected platform event used by
the deterministic QEMU matrix.

## Physical gate boundary

Pixel 6a physical display geometry/DPI/keyboard changes, degraded display
recovery and direct on-screen verification belong to `UI-PHYSICAL-MATRIX-1`.
They do not reopen the transport-independent multi-window transaction gate.
