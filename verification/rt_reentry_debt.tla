----------------------- MODULE rt_reentry_debt -----------------------
EXTENDS Naturals, TLC
CONSTANT FreeRefresh
VARIABLES now, deadline, remaining, active, spent
vars == <<now,deadline,remaining,active,spent>>
Init == /\ now=0 /\ deadline=4 /\ remaining=2 /\ active=TRUE /\ spent=0
Charge == /\ active /\ remaining>0 /\ remaining'=remaining-1 /\ spent'=spent+1 /\ UNCHANGED <<now,deadline,active>>
Disable == /\ active /\ active'=FALSE /\ remaining'=0 /\ UNCHANGED <<now,deadline,spent>>
Enable == /\ ~active /\ (now>=deadline \/ FreeRefresh)
          /\ UNCHANGED now
          /\ active'=TRUE /\ remaining'=2
          /\ IF now>=deadline THEN /\ deadline'=now+4 /\ spent'=0
                                 ELSE UNCHANGED <<deadline,spent>>
Tick == /\ now<8 /\ now'=now+1
        /\ IF active /\ now'>=deadline
              THEN /\ deadline'=deadline+4 /\ remaining'=2 /\ spent'=0
              ELSE UNCHANGED <<deadline,remaining,spent>>
        /\ UNCHANGED active
Next == Charge \/ Disable \/ Enable \/ Tick
Safety == spent<=2
Spec == Init /\ [][Next]_vars
======================================================================
