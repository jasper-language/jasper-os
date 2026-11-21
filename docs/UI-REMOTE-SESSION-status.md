# UI Remote Session Contract Status

Updated: 2026-11-21

Status: **native isolation contract implemented and host-tested; real network
transport and CPL3 integration remain open.**

`kernel-core::ui_session` provides a scalar, generation-bound session contract:

- local and remote sessions require an admitted unified UI capability bound to
  the exact subject, user, tenant, session, display seat and input seat;
- session keys are disposable numeric identities, never transferable native
  Handles;
- only the focused session for the same subject may accept input;
- input generation and monotonic sequence reject stale and replayed records;
- active sessions from different users cannot share a seat, focus or Surface;
- remote disconnect clears focus and requires an explicit recovery decision,
  new session generation and new input generation;
- no-display profiles degrade explicitly to Headless or Console instead of
  inventing a Surface.

## Verification

```text
cargo test -p kernel-core ui_session --lib
6 passed; 0 failed
```

Tests cover cross-user seat/Surface rejection, focus-gated input, stale and
replayed input, remote disconnect/recovery generation rotation, and Headless /
Console degradation. Invisible rendering requires an explicit unified
`ServiceUiFramePresent` capability and stops after background revocation.
Closing and reopening a slot always rotates the session generation and rejects
the old Surface token.

## Remaining gates

- Wire the contract into the real CPL3 UI process and an authenticated remote
  transport rather than only an in-memory registry.
- Prove disconnect/reconnect, replay, revocation and cross-user attempts over a
  real loopback or physical transport with resource reclamation.
- Demonstrate Headless/Console fallback while Terminal rescue remains alive.

`UI-REMOTE-SESSION-1` remains in progress until those runtime gates pass.
