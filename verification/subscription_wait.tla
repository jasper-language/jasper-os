---------------- MODULE subscription_wait ----------------
EXTENDS Naturals
CONSTANT ReleaseTwice
VARIABLES phase, queued, closed, refs, completions
vars == <<phase,queued,closed,refs,completions>>
Init == /\ phase="idle" /\ queued=0 /\ closed=FALSE /\ refs=0 /\ completions=0
Submit == /\ phase="idle" /\ phase'="pending" /\ refs'=1
 /\ UNCHANGED <<queued,closed,completions>>
Publish == /\ ~closed /\ queued<2 /\ queued'=queued+1
 /\ UNCHANGED <<phase,closed,refs,completions>>
Finish == /\ phase="pending" /\ (queued>0 \/ closed)
 /\ phase'="terminal" /\ refs'=0 /\ completions'=completions+1
 /\ queued'=(IF queued>0 THEN 0 ELSE queued) /\ UNCHANGED closed
Cancel == /\ phase="pending" /\ phase'="terminal"
 /\ refs'=0 /\ completions'=completions+1 /\ UNCHANGED <<queued,closed>>
Close == /\ ~closed /\ closed'=TRUE /\ UNCHANGED <<phase,queued,refs,completions>>
Late == /\ phase="terminal" /\ ReleaseTwice /\ completions'=completions+1
 /\ UNCHANGED <<phase,queued,closed,refs>>
Next == Submit \/ Publish \/ Finish \/ Cancel \/ Close \/ Late
Spec == Init /\ [][Next]_vars
Safety == /\ completions<=1 /\ refs=(IF phase="pending" THEN 1 ELSE 0)
===============================================================
