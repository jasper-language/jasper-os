-------------------------- MODULE soak_accept --------------------------
EXTENDS Naturals
\* Author: chatgpt. Bounded acceptance controller, not a workload model.
VARIABLES elapsed, stopped, complete, healthy, terminal, accepted
vars == <<elapsed, stopped, complete, healthy, terminal, accepted>>
Init == /\ elapsed = 0 /\ stopped = FALSE /\ complete = FALSE
        /\ healthy = TRUE /\ terminal = FALSE /\ accepted = FALSE
Tick == /\ elapsed < 2 /\ elapsed' = elapsed + 1
        /\ UNCHANGED <<stopped, complete, healthy, terminal, accepted>>
Stop == /\ elapsed = 2 /\ ~stopped /\ stopped' = TRUE
        /\ UNCHANGED <<elapsed, complete, healthy, terminal, accepted>>
Finish == /\ stopped /\ ~complete /\ complete' = TRUE
          /\ UNCHANGED <<elapsed, stopped, healthy, terminal, accepted>>
Exit == /\ complete /\ ~terminal /\ terminal' = TRUE
        /\ UNCHANGED <<elapsed, stopped, complete, healthy, accepted>>
Fail == /\ ~accepted /\ healthy /\ healthy' = FALSE
        /\ UNCHANGED <<elapsed, stopped, complete, terminal, accepted>>
Accept == /\ elapsed = 2 /\ stopped /\ complete /\ terminal /\ healthy
          /\ ~accepted /\ accepted' = TRUE
          /\ UNCHANGED <<elapsed, stopped, complete, healthy, terminal>>
Next == Tick \/ Stop \/ Finish \/ Exit \/ Fail \/ Accept
NoEarlyAccept == accepted => (elapsed = 2 /\ stopped /\ complete /\ terminal /\ healthy)
Spec == Init /\ [][Next]_vars
=============================================================================
