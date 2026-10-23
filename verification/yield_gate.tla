----------------------------- MODULE yield_gate -----------------------------
EXTENDS Integers
\* Author: chatgpt. One CPU's IRQ-masked fast yield, remote queue mutation,
\* local switch, commit publication, and locked watchdog drain. Hardware visibility/timer progress
\* remain explicit environment obligations, not proved by this finite model.
CONSTANT DrainPending
VARIABLES owner, waiting, permit, phase, mode, reading, captured, pending, bad
vars == <<owner,waiting,permit,phase,mode,reading,captured,pending,bad>>
Init == /\ owner = 0 /\ waiting = FALSE /\ permit = TRUE
        /\ phase = "outside" /\ mode = "none" /\ reading = FALSE
        /\ captured = 0 /\ pending = -1 /\ bad = FALSE
Acquire(m) == /\ phase = "outside" /\ m \in {"local","remote"}
              /\ (m = "local" => ~reading)
              /\ phase' = "revoked" /\ mode' = m
              /\ UNCHANGED <<owner,waiting,permit,reading,captured,pending,bad>>
Drain == /\ phase = "revoked" /\ phase' = "drained"
         /\ bad' = bad \/ (pending # -1 /\ pending # owner)
         /\ pending' = IF DrainPending THEN -1 ELSE pending
         /\ UNCHANGED <<owner,waiting,permit,mode,reading,captured>>
Mutate == /\ phase = "drained" /\ phase' = "mutated"
          /\ owner' = IF mode = "local" THEN 1-owner ELSE owner
          /\ waiting' \in BOOLEAN
          /\ UNCHANGED <<permit,mode,reading,captured,pending,bad>>
Publish == /\ phase = "mutated" /\ phase' = "outside" /\ mode' = "none"
           /\ permit' = ~waiting
           /\ UNCHANGED <<owner,waiting,reading,captured,pending,bad>>
Read == /\ permit /\ ~reading /\ mode # "local"
        /\ reading' = TRUE /\ captured' = owner
        /\ UNCHANGED <<owner,waiting,permit,phase,mode,pending,bad>>
Return == /\ reading /\ reading' = FALSE /\ pending' = captured
          /\ bad' = bad \/ (pending # -1 /\ pending # captured)
          /\ UNCHANGED <<owner,waiting,permit,phase,mode,captured>>
Next == (\E m \in {"local","remote"}: Acquire(m)) \/ Drain \/ Mutate \/ Publish \/ Read \/ Return
Spec == Init /\ [][Next]_vars
Safe == /\ ~bad /\ (pending # -1 => pending = owner)
        /\ (reading => captured = owner)
        /\ (phase = "outside" => permit = ~waiting)
=============================================================================
