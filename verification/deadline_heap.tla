--------------------------- MODULE deadline_heap ---------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Locked arm/cancel/expire/reuse, two slots and two generations.
\* Heap ordering is checked separately against the executable reference test.
Slots == {1,2}
VARIABLES generation, blocked, at, queued, queuedGen, now, badWake
vars == <<generation, blocked, at, queued, queuedGen, now, badWake>>
Init == /\ generation = [s \in Slots |-> 0] /\ blocked = {}
        /\ at = [s \in Slots |-> 0] /\ queued = {}
        /\ queuedGen = [s \in Slots |-> 0] /\ now = 0 /\ badWake = FALSE
Arm(s,d) == /\ d \in {1,2} /\ d > now
            /\ blocked' = blocked \cup {s} /\ queued' = queued \cup {s}
            /\ at' = [at EXCEPT ![s] = d]
            /\ queuedGen' = [queuedGen EXCEPT ![s] = generation[s]]
            /\ UNCHANGED <<generation,now,badWake>>
Cancel(s) == /\ s \in blocked
             /\ blocked' = blocked \ {s} /\ queued' = queued \ {s}
             /\ UNCHANGED <<generation,at,queuedGen,now,badWake>>
Reuse(s) == /\ s \notin blocked /\ s \notin queued /\ generation[s] = 0
            /\ generation' = [generation EXCEPT ![s] = 1]
            /\ UNCHANGED <<blocked,at,queued,queuedGen,now,badWake>>
Expire(s) == /\ s \in queued /\ at[s] <= now
             /\ queued' = queued \ {s} /\ blocked' = blocked \ {s}
             /\ badWake' = badWake \/ (queuedGen[s] # generation[s]) \/ (s \notin blocked)
             /\ UNCHANGED <<generation,at,queuedGen,now>>
Advance == /\ now < 2 /\ now' = now + 1
           /\ UNCHANGED <<generation,blocked,at,queued,queuedGen,badWake>>
Next == (\E s \in Slots: Cancel(s) \/ Reuse(s) \/ Expire(s) \/ (\E d \in {1,2}: Arm(s,d))) \/ Advance
Spec == Init /\ [][Next]_vars
Safe == /\ ~badWake /\ queued = blocked /\ Cardinality(queued) <= 2
        /\ \A s \in queued: queuedGen[s] = generation[s]
=============================================================================
