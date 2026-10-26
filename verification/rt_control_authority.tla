---------------------- MODULE rt_control_authority ----------------------
EXTENDS TLC
CONSTANT SplitCommit
VARIABLES call, profile, control, alive, phase, bad
vars == <<call,profile,control,alive,phase,bad>>
Allowed == call /\ profile /\ control /\ alive
Init == /\ call \in BOOLEAN /\ profile \in BOOLEAN /\ control \in BOOLEAN
        /\ alive \in BOOLEAN /\ phase=0 /\ bad=FALSE
Check == /\ phase=0 /\ Allowed /\ phase'=1 /\ UNCHANGED <<call,profile,control,alive,bad>>
Exit == /\ phase=1 /\ alive /\ alive'=FALSE /\ UNCHANGED <<call,profile,control,phase,bad>>
Commit == /\ phase=1 /\ (Allowed \/ SplitCommit) /\ phase'=2 /\ bad'=~Allowed
          /\ UNCHANGED <<call,profile,control,alive>>
Reject == /\ phase=1 /\ ~Allowed /\ phase'=2 /\ UNCHANGED <<call,profile,control,alive,bad>>
Next == Check \/ Exit \/ Commit \/ Reject
Safety == ~bad
Spec == Init /\ [][Next]_vars
=======================================================================
