------------------------- MODULE group_membership -------------------------
EXTENDS Naturals, FiniteSets, Sequences, TLC
\* Author: chatgpt. Proposed serial live-group index, not production yet.
\* Three slots, refs 0..2, each slot may be created at most twice.
CONSTANT RemoveOnLast
VARIABLES refs, listed, creates
vars == <<refs, listed, creates>>
Slots == 0..2
Members == {listed[i] : i \in 1..Len(listed)}
Init == /\ refs = [s \in Slots |-> 0]
        /\ listed = <<>> /\ creates = [s \in Slots |-> 0]
Create(s) == /\ refs[s] = 0 /\ creates[s] < 2
             /\ refs' = [refs EXCEPT ![s] = 1]
             /\ creates' = [creates EXCEPT ![s] = @ + 1]
             /\ listed' = Append(listed, s)
Retain(s) == /\ refs[s] = 1 /\ refs' = [refs EXCEPT ![s] = 2]
             /\ UNCHANGED <<listed,creates>>
Release(s) == /\ refs[s] > 0 /\ refs' = [refs EXCEPT ![s] = @ - 1]
              /\ listed' = IF refs[s] = 1 /\ RemoveOnLast
                            THEN SelectSeq(listed, LAMBDA x: x # s)
                            ELSE listed
              /\ UNCHANGED creates
Next == \E s \in Slots: Create(s) \/ Retain(s) \/ Release(s)
Spec == Init /\ [][Next]_vars
Safety == /\ Members = {s \in Slots: refs[s] > 0}
          /\ Len(listed) = Cardinality(Members)
          /\ \A s \in Slots: refs[s] \in 0..2
=============================================================================
