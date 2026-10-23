------------------------- MODULE sleep_registration -------------------------
EXTENDS Naturals
\* Author: chatgpt. One sleep registration, bounded clock, no delivery proof.
CONSTANT AtomicRegistration
VARIABLES clock, phase, deadline, registered
vars == <<clock,phase,deadline,registered>>
Init == /\ clock = 0 /\ phase = 0 /\ deadline = 0 /\ registered = FALSE
Read == /\ ~AtomicRegistration /\ phase = 0
        /\ deadline' = clock + 1 /\ phase' = 1
        /\ UNCHANGED <<clock,registered>>
Register == /\ (IF AtomicRegistration THEN phase = 0 ELSE phase = 1)
            /\ registered' = IF AtomicRegistration THEN TRUE ELSE clock < deadline
            /\ deadline' = IF AtomicRegistration THEN clock + 1 ELSE deadline
            /\ phase' = 2 /\ UNCHANGED clock
Tick == /\ clock < 2 /\ clock' = clock + 1
        /\ UNCHANGED <<phase,deadline,registered>>
Next == Read \/ Register \/ Tick
Spec == Init /\ [][Next]_vars
Safety == phase = 2 => registered
=============================================================================
