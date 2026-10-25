----------------------- MODULE ring_wait_lifecycle -----------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Two waiters/two rounds; abstract retained object references.
CONSTANTS CheckRound, ReleaseRef
W == 0..1
VARIABLES round, phase, queue, messages, refs, closed, badWake
vars == <<round,phase,queue,messages,refs,closed,badWake>>
Key(w) == <<w,round[w]>>
Init == /\ round = [w \in W |-> 1] /\ phase = [w \in W |-> "idle"]
        /\ queue = {} /\ messages = {} /\ refs = {}
        /\ closed = FALSE /\ badWake = FALSE
Enroll(w) == /\ phase[w] = "idle" /\ ~closed
             /\ phase' = [phase EXCEPT ![w] = "blocked"]
             /\ queue' = queue \cup {Key(w)} /\ refs' = refs \cup {w}
             /\ UNCHANGED <<round,messages,closed,badWake>>
Notify == /\ queue # {} /\ messages' = messages \cup queue /\ queue' = {}
          /\ UNCHANGED <<round,phase,refs,closed,badWake>>
Close == /\ ~closed /\ closed' = TRUE /\ messages' = messages \cup queue /\ queue' = {}
         /\ UNCHANGED <<round,phase,refs,badWake>>
Consume(m) == /\ m \in messages /\ messages' = messages \ {m}
              /\ LET w == m[1]
                     accept == phase[w] = "blocked" /\ (~CheckRound \/ m = Key(w))
                 IN /\ phase' = IF accept THEN [phase EXCEPT ![w] = "awake"] ELSE phase
                    /\ queue' = IF accept THEN queue \ {Key(w)} ELSE queue
                    /\ badWake' = (badWake \/ (accept /\ m # Key(w)))
              /\ UNCHANGED <<round,refs,closed>>
TimeoutOrCancel(w) == /\ phase[w] = "blocked"
                     /\ phase' = [phase EXCEPT ![w] = "awake"] /\ queue' = queue \ {Key(w)}
                     /\ UNCHANGED <<round,messages,refs,closed,badWake>>
Cleanup(w) == /\ phase[w] = "awake" /\ phase' = [phase EXCEPT ![w] = "done"]
              /\ refs' = IF ReleaseRef THEN refs \ {w} ELSE refs
              /\ UNCHANGED <<round,queue,messages,closed,badWake>>
Again(w) == /\ phase[w] = "done" /\ round[w] < 2 /\ ~closed
            /\ round' = [round EXCEPT ![w] = @ + 1] /\ phase' = [phase EXCEPT ![w] = "idle"]
            /\ UNCHANGED <<queue,messages,refs,closed,badWake>>
Next == Notify \/ Close \/ (\E w \in W: Enroll(w) \/ TimeoutOrCancel(w) \/ Cleanup(w) \/ Again(w))
        \/ (\E m \in messages: Consume(m))
Spec == Init /\ [][Next]_vars
Safety == /\ ~badWake
          /\ refs = {w \in W: phase[w] \in {"blocked","awake"}}
          /\ \A m \in queue: phase[m[1]] = "blocked" /\ m = Key(m[1])
=============================================================================
