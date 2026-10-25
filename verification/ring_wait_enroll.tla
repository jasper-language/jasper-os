------------------------- MODULE ring_wait_enroll -------------------------
EXTENDS Naturals
\* Author: chatgpt. One wait, one completion/close; abstract serialized locks.
CONSTANT AtomicEnroll
VARIABLES phase, registered, blocked, pending, ready, closed
vars == <<phase, registered, blocked, pending, ready, closed>>
Terminal == ready \/ closed
Init == /\ phase = "new" /\ registered = FALSE /\ blocked = FALSE
        /\ pending = FALSE /\ ready = FALSE /\ closed = FALSE
Immediate == /\ phase = "new" /\ Terminal /\ phase' = "done"
             /\ UNCHANGED <<registered, blocked, pending, ready, closed>>
AtomicPark == /\ AtomicEnroll /\ phase = "new" /\ ~Terminal
              /\ phase' = "parked" /\ registered' = TRUE /\ blocked' = TRUE
              /\ UNCHANGED <<pending, ready, closed>>
SplitInspect == /\ ~AtomicEnroll /\ phase = "new" /\ ~Terminal
                /\ phase' = "checked"
                /\ UNCHANGED <<registered, blocked, pending, ready, closed>>
SplitPark == /\ ~AtomicEnroll /\ phase = "checked"
             /\ phase' = "parked" /\ registered' = TRUE /\ blocked' = TRUE
             /\ UNCHANGED <<pending, ready, closed>>
Publish == /\ ~ready /\ ready' = TRUE /\ pending' = (pending \/ registered)
           /\ UNCHANGED <<phase, registered, blocked, closed>>
Close == /\ ~closed /\ closed' = TRUE /\ pending' = (pending \/ registered)
         /\ UNCHANGED <<phase, registered, blocked, ready>>
Consume == /\ pending /\ blocked /\ blocked' = FALSE
           /\ registered' = FALSE /\ pending' = FALSE
           /\ UNCHANGED <<phase, ready, closed>>
Timeout == /\ phase = "parked" /\ blocked /\ blocked' = FALSE
           /\ registered' = FALSE /\ pending' = FALSE
           /\ UNCHANGED <<phase, ready, closed>>
Finish == /\ phase = "parked" /\ ~blocked /\ phase' = "done"
          /\ UNCHANGED <<registered, blocked, pending, ready, closed>>
Enroll == Immediate \/ AtomicPark \/ SplitInspect \/ SplitPark
Next == Enroll \/ Publish \/ Close \/ Consume \/ Timeout \/ Finish
Spec == Init /\ [][Next]_vars /\ WF_vars(Enroll) /\ WF_vars(Consume) /\ WF_vars(Finish)
Safety == /\ (blocked => registered)
          /\ ((phase = "parked" /\ Terminal) => (~blocked \/ pending))
Settles == Terminal ~> (phase = "done")
=============================================================================
