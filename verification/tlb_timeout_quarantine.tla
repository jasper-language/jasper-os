------------------------- MODULE tlb_timeout_quarantine -------------------------
\* One process mutation whose remote TLB acknowledgement may time out.
\* A timed-out mutation must quarantine its frames: they are neither returned to
\* the allocator nor released later when the process is destroyed.
EXTENDS Naturals

CONSTANT Frames, UnsafeRelease
ASSUME Frames > 0

VARIABLES phase, free, quarantined, stale
vars == <<phase, free, quarantined, stale>>

Init ==
    /\ phase = "mapped"
    /\ free = 0
    /\ quarantined = 0
    /\ stale = FALSE

\* The page-table change is visible locally before any remote acknowledgement.
Unmap ==
    /\ phase = "mapped"
    /\ phase' = "pending"
    /\ stale' = TRUE
    /\ UNCHANGED <<free, quarantined>>

\* Every target acknowledged: the frames may be returned.
Ack ==
    /\ phase = "pending"
    /\ phase' = "released"
    /\ stale' = FALSE
    /\ free' = free + Frames
    /\ UNCHANGED quarantined

\* At least one target did not acknowledge: withhold every affected frame.
Timeout ==
    /\ phase = "pending"
    /\ phase' = "quarantined"
    /\ quarantined' = quarantined + Frames
    /\ UNCHANGED <<free, stale>>

\* Process teardown after a safe release, or after timeout, never frees again.
DestroyReleased ==
    /\ phase = "released"
    /\ phase' = "destroyed"
    /\ UNCHANGED <<free, quarantined, stale>>

DestroyQuarantined ==
    /\ phase = "quarantined"
    /\ phase' = "destroyed"
    /\ UNCHANGED <<free, quarantined, stale>>

\* Negative configuration: the pre-fix behavior returns timed-out frames.
ReleaseAfterTimeout ==
    /\ UnsafeRelease
    /\ phase = "quarantined"
    /\ phase' = "destroyed"
    /\ free' = free + Frames
    /\ UNCHANGED <<quarantined, stale>>

Next == Unmap \/ Ack \/ Timeout \/ DestroyReleased \/ DestroyQuarantined \/ ReleaseAfterTimeout
Spec == Init /\ [][Next]_vars

\* No frame is returned while any remote view may still be stale.
NoReleaseWhileStale == stale => free = 0
\* Frames are either still accounted to the process, returned once, or quarantined.
Accounted == free + quarantined <= Frames
\* A timeout leaves every affected frame in the quarantine set.
TimeoutQuarantines == phase \in {"quarantined", "destroyed"} /\ quarantined > 0 => quarantined = Frames
=============================================================================
