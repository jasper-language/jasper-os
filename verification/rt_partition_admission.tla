-------------------- MODULE rt_partition_admission --------------------
EXTENDS Naturals, TLC
CONSTANT BreakReject
Tasks == {1,2,3}
CPUs == {1,2}
VARIABLES home, units, bad
vars == <<home,units,bad>>
Load(c,h,u) == (IF h[1]=c THEN u[1] ELSE 0) + (IF h[2]=c THEN u[2] ELSE 0) + (IF h[3]=c THEN u[3] ELSE 0)
Init == /\ home=[t \in Tasks |-> 0] /\ units=[t \in Tasks |-> 1] /\ bad=FALSE
Configure(t,c,q) ==
 LET h == [home EXCEPT ![t]=c]
     u == [units EXCEPT ![t]=q]
 IN IF Load(c,h,u)<=2
       THEN /\ home'=h /\ units'=u /\ UNCHANGED bad
       ELSE IF BreakReject /\ home[t]#0
         THEN /\ home'=[home EXCEPT ![t]=0] /\ bad'=TRUE /\ UNCHANGED units
         ELSE UNCHANGED vars
Release(t) == /\ home[t]#0 /\ home'=[home EXCEPT ![t]=0] /\ UNCHANGED <<units,bad>>
Next == (\E t \in Tasks,c \in CPUs,q \in {1,2}: Configure(t,c,q)) \/ (\E t \in Tasks: Release(t))
Safety == /\ ~bad /\ \A c \in CPUs: Load(c,home,units)<=2
Spec == Init /\ [][Next]_vars
======================================================================
