------------------------- MODULE mmio_rollback -------------------------
EXTENDS Naturals
\* Author: chatgpt. One failed partial mapping with a potentially stale TLB.
CONSTANT UnsafeRelease
VARIABLES phase, stale, slotFree
vars == <<phase, stale, slotFree>>
Init == /\ phase = "partial" /\ stale = TRUE /\ slotFree = FALSE
RollbackOK == /\ phase = "partial" /\ phase' = "done"
              /\ stale' = FALSE /\ slotFree' = TRUE
RollbackTimeout == /\ phase = "partial" /\ phase' = "done"
                   /\ stale' = TRUE /\ slotFree' = UnsafeRelease
Next == RollbackOK \/ RollbackTimeout
NoStaleReuse == slotFree => ~stale
Spec == Init /\ [][Next]_vars
=============================================================================
