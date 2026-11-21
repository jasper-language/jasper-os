# UI Multi-window Transition Status

Updated: 2026-11-21

Status: **core-passed: layout, CPL3 migration, dual-Surface framebuffer output
and capability/budget rollback are verified; an emitted hardware/QEMU hotplug
event source remains open.**

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

## Remaining gates

- Add a production/QEMU display-size/DPI/keyboard hotplug event producer and
  route its events through the existing capability transaction.
- Exercise that producer and the physical display matrix on Pixel 6a.

`UI-MULTIWINDOW-TRANSITION-1` therefore remains in progress.
