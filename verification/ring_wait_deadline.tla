----------------------- MODULE ring_wait_deadline -----------------------
EXTENDS Naturals
\* Author: chatgpt. One explicit deadline at tick1; outcome uses final locked observation.
CONSTANT ReadyFirst
VARIABLES now, ready, closed, phase, refs, result, sawReady, sawClosed, sawExpired
vars == <<now,ready,closed,phase,refs,result,sawReady,sawClosed,sawExpired>>
Init == /\ now = 0 /\ ready = FALSE /\ closed = FALSE /\ phase = "new"
        /\ refs = 0 /\ result = "none" /\ sawReady = FALSE /\ sawClosed = FALSE /\ sawExpired = FALSE
Tick == /\ now = 0 /\ now' = 1 /\ UNCHANGED <<ready,closed,phase,refs,result,sawReady,sawClosed,sawExpired>>
Publish == /\ ~ready /\ ready' = TRUE /\ UNCHANGED <<now,closed,phase,refs,result,sawReady,sawClosed,sawExpired>>
Close == /\ ~closed /\ closed' = TRUE /\ UNCHANGED <<now,ready,phase,refs,result,sawReady,sawClosed,sawExpired>>
Enroll == /\ phase = "new" /\ phase' = "waiting" /\ refs' = 1
          /\ UNCHANGED <<now,ready,closed,result,sawReady,sawClosed,sawExpired>>
Finish == /\ phase = "waiting" /\ (closed \/ ready \/ now = 1)
          /\ phase' = "done" /\ refs' = 0
          /\ sawReady' = ready /\ sawClosed' = closed /\ sawExpired' = (now = 1)
          /\ result' = IF closed THEN "closed" ELSE
                       IF ReadyFirst /\ ready THEN "ready" ELSE
                       IF now = 1 THEN "timeout" ELSE "ready"
          /\ UNCHANGED <<now,ready,closed>>
Next == Tick \/ Publish \/ Close \/ Enroll \/ Finish
Spec == Init /\ [][Next]_vars /\ WF_vars(Tick) /\ WF_vars(Enroll) /\ WF_vars(Finish)
Safety == /\ refs = IF phase = "waiting" THEN 1 ELSE 0
          /\ (phase = "done" => result = IF sawClosed THEN "closed" ELSE IF sawReady THEN "ready" ELSE "timeout")
Settles == <> (phase = "done")
=============================================================================
