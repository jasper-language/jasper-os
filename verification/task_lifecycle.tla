--------------------------- MODULE task_lifecycle ---------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. One canonical slot, bounded generation limit 2.
CONSTANT CheckGeneration
VARIABLES seq, phase, history, pending, oncpu, sent, bad
vars == <<seq, phase, history, pending, oncpu, sent, bad>>
Init == /\ seq = 0 /\ phase = "vacant" /\ history = 0
        /\ pending = 0 /\ oncpu = FALSE /\ sent = {} /\ bad = FALSE
Reserve == /\ phase # "live" /\ ~oncpu /\ pending = 0 /\ seq < 2
           /\ seq' = seq + 1 /\ pending' = seq + 1
           /\ UNCHANGED <<phase, history, oncpu, sent, bad>>
Abort == /\ pending # 0 /\ pending' = 0
         /\ UNCHANGED <<seq, phase, history, oncpu, sent, bad>>
Publish == /\ pending # 0 /\ history' = pending /\ pending' = 0
           /\ phase' = "live" /\ bad' = (bad \/ oncpu)
           /\ UNCHANGED <<seq, oncpu, sent>>
Dispatch == /\ phase = "live" /\ ~oncpu /\ oncpu' = TRUE
            /\ UNCHANGED <<seq, phase, history, pending, sent, bad>>
Exit == /\ phase = "live" /\ phase' = "exited"
        /\ UNCHANGED <<seq, history, pending, oncpu, sent, bad>>
Detach == /\ oncpu /\ oncpu' = FALSE
          /\ UNCHANGED <<seq, phase, history, pending, sent, bad>>
Send == /\ phase = "live" /\ sent' = sent \cup {history}
        /\ UNCHANGED <<seq, phase, history, pending, oncpu, bad>>
Deliver(g) == /\ g \in sent
              /\ bad' = (bad \/ (phase = "live" /\ (~CheckGeneration \/ g = history) /\ g # history))
              /\ UNCHANGED <<seq, phase, history, pending, oncpu, sent>>
Next == Reserve \/ Abort \/ Publish \/ Dispatch \/ Exit \/ Detach \/ Send \/ (\E g \in sent: Deliver(g))
Spec == Init /\ [][Next]_vars
Safety == /\ ~bad /\ seq \in 0..2 /\ history \in 0..seq
          /\ pending \in 0..seq
          /\ (pending # 0 => /\ pending > history /\ phase # "live" /\ ~oncpu)
          /\ (oncpu => history # 0)
          /\ (phase = "live" => history # 0)
=============================================================================
