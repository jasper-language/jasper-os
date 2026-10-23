------------------------ MODULE fault_countdown ------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Models successful CAS linearization of one armed site.
\* Re-arming is deliberately excluded: workload must be quiescent at arm time.
VARIABLES remaining, fired, calls
vars == <<remaining, fired, calls>>
Init == /\ remaining = 3 /\ fired = 0 /\ calls = [w \in 1..2 |-> 0]
Hit(w) == /\ calls[w] < 4
          /\ calls' = [calls EXCEPT ![w] = @ + 1]
          /\ remaining' = IF remaining > 0 THEN remaining - 1 ELSE 0
          /\ fired' = IF remaining = 1 THEN fired + 1 ELSE fired
Next == \E w \in 1..2 : Hit(w)
TypeOK == /\ remaining \in 0..3 /\ fired \in 0..1
          /\ calls \in [1..2 -> 0..4]
Conserved == remaining + fired <= 3
SingleFire == fired <= 1
Consumed == (calls[1] + calls[2] >= 3) => fired = 1
Spec == Init /\ [][Next]_vars
=============================================================================
