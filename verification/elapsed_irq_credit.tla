---------------- MODULE elapsed_irq_credit ----------------
EXTENDS Naturals, TLC
CONSTANT PerIRQ
VARIABLES now, seen, charged, remainder
vars == <<now,seen,charged,remainder>>
Init == /\ now=0 /\ seen=0 /\ charged=0 /\ remainder=0
Advance == /\ now<5 /\ now'=now+1 /\ UNCHANGED <<seen,charged,remainder>>
IRQ == /\ seen'=now
       /\ charged'=IF PerIRQ THEN charged+1 ELSE charged+(now-seen+remainder)\div 2
       /\ remainder'=(now-seen+remainder)%2
       /\ UNCHANGED now
Next == Advance \/ IRQ
Safety == /\ charged=seen\div 2 /\ remainder=seen%2
Spec == Init /\ [][Next]_vars
===========================================================
