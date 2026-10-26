---------------- MODULE timer_deadline_recheck ----------------
EXTENDS Naturals, TLC
CONSTANT WakeOnChunk
VARIABLES now, armed, done
vars == <<now,armed,done>>
Deadline == 5
Init == /\ now=0 /\ armed=2 /\ done=FALSE
Tick == /\ now<6 /\ now'=now+1 /\ UNCHANGED <<armed,done>>
IRQ == /\ ~done /\ now>=armed
       /\ IF now>=Deadline \/ WakeOnChunk
          THEN /\ done'=TRUE /\ UNCHANGED armed
          ELSE /\ armed'=IF now+2<Deadline THEN now+2 ELSE Deadline
               /\ UNCHANGED done
       /\ UNCHANGED now
Next == Tick \/ IRQ
Safety == done => now>=Deadline
Spec == Init /\ [][Next]_vars
===============================================================
