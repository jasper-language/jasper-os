---------------- MODULE ns_owner_accounting ----------------
EXTENDS Naturals, TLC
CONSTANT SwapBeforeCharge
VARIABLES now,at,owner,actual,charged
vars==<<now,at,owner,actual,charged>>
Init==/\now=0 /\at=0 /\owner=1 /\actual=[i\in{1,2}|->0] /\charged=[i\in{1,2}|->0]
Run==/\now<4 /\now'=now+1 /\actual'=[actual EXCEPT ![owner]=@+1] /\UNCHANGED <<at,owner,charged>>
Account==/\charged'=[charged EXCEPT ![owner]=@+now-at] /\at'=now /\UNCHANGED <<now,owner,actual>>
Switch==/\owner'=3-owner /\at'=now
        /\charged'=[charged EXCEPT ![IF SwapBeforeCharge THEN 3-owner ELSE owner]=@+now-at]
        /\UNCHANGED <<now,actual>>
Next==Run \/ Account \/ Switch
Safety==/\ \A i\in{1,2}:charged[i]<=actual[i]
        /\ (at=now => charged=actual)
Spec==Init /\[][Next]_vars
===========================================================
