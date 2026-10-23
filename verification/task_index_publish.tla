------------------------- MODULE task_index_publish -------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Serialized two-slot index/identity publication transaction.
CONSTANT RemoveOld
Slots == {1,2}
Labels == {1,2,3}
VARIABLES label, generation, index, live, oncpu
vars == <<label, generation, index, live, oncpu>>
Init == /\ label = [s \in Slots |-> 0]
        /\ generation = [s \in Slots |-> 0]
        /\ index = [l \in Labels |-> 0]
        /\ live = {} /\ oncpu = {}
Publish(s,l) == /\ s \notin live /\ s \notin oncpu /\ generation[s] < 2
                /\ index[l] \in {0,s}
                /\ label' = [label EXCEPT ![s] = l]
                /\ generation' = [generation EXCEPT ![s] = @ + 1]
                /\ index' = [k \in Labels |-> IF k = l THEN s
                     ELSE IF RemoveOld /\ k = label[s] THEN 0 ELSE index[k]]
                /\ live' = live \cup {s}
                /\ UNCHANGED oncpu
Dispatch(s) == /\ s \in live /\ s \notin oncpu /\ oncpu' = oncpu \cup {s}
               /\ UNCHANGED <<label,generation,index,live>>
Exit(s) == /\ s \in live /\ live' = live \ {s}
           /\ UNCHANGED <<label,generation,index,oncpu>>
Detach(s) == /\ s \in oncpu /\ oncpu' = oncpu \ {s}
             /\ UNCHANGED <<label,generation,index,live>>
Next == (\E s \in Slots, l \in Labels: Publish(s,l))
        \/ (\E s \in Slots: Dispatch(s) \/ Exit(s) \/ Detach(s))
Spec == Init /\ [][Next]_vars
IndexMatches == /\ \A s \in Slots: label[s] # 0 => index[label[s]] = s
                /\ \A l \in Labels: index[l] # 0 => label[index[l]] = l
                /\ \A a,b \in Slots: (label[a] # 0 /\ label[a] = label[b]) => a = b
=============================================================================
