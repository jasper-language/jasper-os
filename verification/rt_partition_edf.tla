----------------------- MODULE rt_partition_edf -----------------------
EXTENDS Naturals, FiniteSets, TLC
CONSTANT ReverseOrder
VARIABLES ready, chosen
vars == <<ready,chosen>>
Tasks == {1,2,3}
Deadline(t) == CASE t=1 -> 2 [] t=2 -> 1 [] OTHER -> 3
Best(r) == CHOOSE t \in r: \A j \in r: Deadline(t)<=Deadline(j)
Init == /\ ready={} /\ chosen=0
Change == \E r \in SUBSET Tasks: /\ ready'=r /\ chosen'=0
Pick == /\ ready#{} /\ UNCHANGED ready
        /\ chosen'=IF ReverseOrder THEN (CHOOSE t \in ready: \A j \in ready: Deadline(t)>=Deadline(j)) ELSE Best(ready)
Next == Change \/ Pick
Safety == chosen=0 \/ (chosen \in ready /\ \A j \in ready: Deadline(chosen)<=Deadline(j))
Spec == Init /\ [][Next]_vars
======================================================================
