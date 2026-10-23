---------------------------- MODULE worker_count ----------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Locked publish/exit count with deferred context release.
Slots == {1,2}
VARIABLES live, oncpu, count, generation
vars == <<live, oncpu, count, generation>>
Init == /\ live = {} /\ oncpu = {} /\ count = 0
        /\ generation = [s \in Slots |-> 0]
Publish(s) == /\ s \notin live /\ s \notin oncpu /\ generation[s] < 2
              /\ live' = live \cup {s} /\ count' = count + 1
              /\ generation' = [generation EXCEPT ![s] = @ + 1]
              /\ UNCHANGED oncpu
Dispatch(s) == /\ s \in live /\ s \notin oncpu
               /\ oncpu' = oncpu \cup {s}
               /\ UNCHANGED <<live,count,generation>>
Exit(s) == /\ s \in live /\ s \in oncpu
           /\ live' = live \ {s} /\ count' = count - 1
           /\ UNCHANGED <<oncpu,generation>>
SwitchDone(s) == /\ s \in oncpu /\ s \notin live
                 /\ oncpu' = oncpu \ {s}
                 /\ UNCHANGED <<live,count,generation>>
Next == \E s \in Slots: Publish(s) \/ Dispatch(s) \/ Exit(s) \/ SwitchDone(s)
Spec == Init /\ [][Next]_vars
Safety == /\ count = Cardinality(live) /\ count \in 0..2
          /\ live \subseteq Slots /\ oncpu \subseteq Slots
=============================================================================
