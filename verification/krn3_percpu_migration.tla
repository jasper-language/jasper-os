---------------------- MODULE krn3_percpu_migration ----------------------
EXTENDS Naturals, Integers
\* Author: chatgpt. Two-CPU migration ownership and single-consume PI message.
CONSTANT BrokenDetach
VARIABLES owner, phase, firstLock, secondLock, piPending, piApplied, liveGen, msgGen
vars == <<owner, phase, firstLock, secondLock, piPending, piApplied, liveGen, msgGen>>
Cpu == {0,1}
Init == /\ owner = 0 /\ phase = "source" /\ firstLock = -1 /\ secondLock = -1
        /\ piPending = TRUE /\ piApplied = 0 /\ liveGen = 1 /\ msgGen \in {0,1}
LockFirst == /\ phase = "source" /\ firstLock' = 0 /\ phase' = "first"
             /\ UNCHANGED <<owner,secondLock,piPending,piApplied,liveGen,msgGen>>
LockSecond == /\ phase = "first" /\ secondLock' = 1 /\ phase' = "locked"
              /\ UNCHANGED <<owner,firstLock,piPending,piApplied,liveGen,msgGen>>
Detach == /\ phase = "locked" /\ phase' = "transit"
          /\ owner' = IF BrokenDetach THEN 1 ELSE 2
          /\ UNCHANGED <<firstLock,secondLock,piPending,piApplied,liveGen,msgGen>>
Commit == /\ phase = "transit" /\ owner' = 1 /\ phase' = "done"
          /\ firstLock' = -1 /\ secondLock' = -1
          /\ UNCHANGED <<piPending,piApplied,liveGen,msgGen>>
ConsumePi == /\ piPending /\ piPending' = FALSE
             /\ piApplied' = IF msgGen = liveGen THEN piApplied+1 ELSE piApplied
             /\ UNCHANGED <<owner,phase,firstLock,secondLock,liveGen,msgGen>>
Next == LockFirst \/ LockSecond \/ Detach \/ Commit \/ ConsumePi
Spec == Init /\ [][Next]_vars
TypeOk == /\ owner \in {0,1,2} /\ phase \in {"source","first","locked","transit","done"}
          /\ firstLock \in {-1,0} /\ secondLock \in {-1,1}
Safety == /\ TypeOk
          /\ (phase = "transit" => owner = 2)
          /\ (phase = "done" => owner = 1)
          /\ secondLock = 1 => firstLock = 0
          /\ piApplied <= 1
=============================================================================
