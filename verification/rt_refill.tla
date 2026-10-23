------------------------------ MODULE rt_refill ------------------------------
EXTENDS Naturals
\* Author: chatgpt. Serial tick debit then bounded periodic refill, not EDF.
Tasks == {1,2}
Quota(t) == t
Period(t) == t + 1
VARIABLES now, remaining, due, active
vars == <<now, remaining, due, active>>
Init == /\ now = 0 /\ remaining = [t \in Tasks |-> Quota(t)]
        /\ due = [t \in Tasks |-> Period(t)] /\ active = Tasks
Tick(t) == /\ now < 6 /\ now' = now + 1
           /\ remaining' = [s \in Tasks |->
               IF s \notin active THEN remaining[s]
               ELSE IF now + 1 >= due[s] THEN Quota(s)
               ELSE IF s = t /\ remaining[s] > 0 THEN remaining[s] - 1
               ELSE remaining[s]]
           /\ due' = [s \in Tasks |-> IF s \in active /\ now + 1 >= due[s]
               THEN due[s] + Period(s) ELSE due[s]]
           /\ UNCHANGED active
Exit(t) == /\ t \in active /\ active' = active \ {t}
           /\ UNCHANGED <<now,remaining,due>>
Next == \E t \in Tasks: Tick(t) \/ Exit(t)
Spec == Init /\ [][Next]_vars
Safety == /\ \A t \in Tasks: remaining[t] \in 0..Quota(t)
          /\ \A t \in active: due[t] > now
=============================================================================
