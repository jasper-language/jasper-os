# UI Mobile Foreground Status

Updated: 2026-11-21

Status: **done for the declared two-application Mobile foreground profile.**

The real CPL3 UI process drill now launches two independent application
instances over separate Channels:

- the primary application owns focus and is the only application whose native
  keyboard Enter is admitted;
- the peer remains resident and renders while not focused;
- ordinary hidden rendering is rejected until an exact unified
  `ServiceUiFramePresent` capability grants background rendering;
- revoking that grant immediately rejects another hidden render;
- the peer then injects an invalid protocol frame, emits a terminal Error and
  exits through the failure path rather than pretending success;
- both process identities, Channels, frames and peer sessions return to the
  resource baseline, while the serial Terminal remains alive.

## Verification

```text
scripts/ui-process-check.sh
PASS
qemu_rc=33
```

The QEMU serial evidence contains:

```text
[JSR-UI-MOBILE] primary_focus=true primary_input=true peer_resident=true \
peer_present=true ordinary_background_rejected=true background_grant=true \
background_revoked=true peer_failed=true resources=true failed=0
```

The run performs two rounds. `kernel-core::ui_session` also has 7/7 host tests
covering the same policy, cross-user isolation and generation recovery.

Multi-window transitions and the physical Pixel display/input matrix remain
separate DAG nodes.
