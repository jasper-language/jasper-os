# UI Multi-window Transition Status

Updated: 2026-11-21

Status: **layout and atomic migration contract implemented; runtime hotplug
event wiring remains open.**

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
- frames and input using pre-migration Surface/input generations are rejected.

## Verification

```text
cargo test -p kernel-core ui_workspace --lib
4 passed; 0 failed
```

Tests cover single/split geometry, independent generation rotation, stale frame
and input rejection, capability degradation to Split, budget failure atomicity
and authorization failure atomicity.

The real CPL3 UI process drill now constructs a two-Scene workspace and submits
a capability event with new geometry/DPI, policy and revocation epochs. It
recomputes MultiWindow layout, applies the unified present authorization and
memory budget, starts successful new-generation frame/input streams, and checks
that the old generations are rejected. The real QEMU run passes with
`qemu_rc=33`; marker:

```text
[JSR-UI-MULTIWINDOW] layout=Ok(MultiWindow) old_frame_rejected=true \
old_input_rejected=true new_surface_generation=true new_input_generation=true
```

## Remaining gates

- Emit display-size/DPI/keyboard capability events from actual hardware/QEMU
  hotplug rather than the verification input.
- Exercise the migrated compositor/framebuffer output, rollback and pending-frame
  cancellation on QEMU and then on a real display hotplug matrix.

`UI-MULTIWINDOW-TRANSITION-1` therefore remains in progress.
