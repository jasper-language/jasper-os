# UI Remote Session Contract Status

Updated: 2026-11-21

Status: **done for the declared transport-independent isolation gate.**

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
7 passed; 0 failed
```

Tests cover cross-user seat/Surface rejection, focus-gated input, stale and
replayed input, remote disconnect/recovery generation rotation, and Headless /
Console degradation. Invisible rendering requires an explicit unified
`ServiceUiFramePresent` capability and stops after background revocation.
Closing and reopening a slot always rotates the session generation and rejects
the old Surface token.

The contract is transport-independent: a future network adapter must carry the
same authenticated scope, generation and replay facts, but no specific network
protocol is part of this DAG node. The real CPL3 Channel path has exercised
disconnect/recovery and input lifecycle, while host tests cover cross-user and
revocation negatives plus Headless/Console selection.
