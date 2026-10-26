--------------------------- MODULE rt3_ring_donation ---------------------------
EXTENDS Naturals, TLC

CONSTANT MissingClear

VARIABLES service, registered, blocked, edge, ready, resumed, base, effective

vars == <<service, registered, blocked, edge, ready, resumed, base, effective>>

Init == /\ service = TRUE
        /\ registered = FALSE /\ blocked = FALSE /\ edge = FALSE
        /\ ready = FALSE /\ resumed = FALSE
        /\ base = 0 /\ effective = 0

Enroll == /\ service /\ ~registered /\ ~ready
          /\ registered' = TRUE /\ blocked' = TRUE /\ edge' = TRUE
          /\ effective' = 2
          /\ UNCHANGED <<service, ready, resumed, base>>

Complete == /\ registered /\ blocked /\ edge /\ ~ready
            /\ ready' = TRUE /\ blocked' = FALSE /\ resumed' = TRUE
            /\ registered' = FALSE
            /\ edge' = IF MissingClear THEN TRUE ELSE FALSE
            /\ effective' = IF MissingClear THEN 2 ELSE base
            /\ UNCHANGED <<service, base>>

Close == /\ registered /\ blocked /\ edge
         /\ service' = FALSE /\ blocked' = FALSE /\ resumed' = TRUE
         /\ registered' = FALSE
         /\ edge' = IF MissingClear THEN TRUE ELSE FALSE
         /\ effective' = IF MissingClear THEN 2 ELSE base
         /\ UNCHANGED <<ready, base>>

Next == Enroll \/ Complete \/ Close

Spec == Init /\ [][Next]_vars /\ WF_vars(Enroll) /\ WF_vars(Complete) /\ WF_vars(Close)

Safety == /\ (edge => registered /\ blocked)
          /\ (effective = 2) = edge
          /\ (resumed => ~registered /\ ~blocked /\ ~edge)

Termination == <>resumed
=============================================================================
