---------------- MODULE pressure_event_dirty ----------------
EXTENDS Naturals
CONSTANT ClearAfterSample
VARIABLES actual, published, dirty, sample, stage
vars == <<actual,published,dirty,sample,stage>>
Init == /\ actual=0 /\ published=0 /\ dirty=FALSE /\ sample=0 /\ stage=0
Change == /\ actual<2 /\ actual'=actual+1 /\ dirty'=TRUE /\ UNCHANGED <<published,sample,stage>>
Start == /\ stage=0 /\ dirty /\ stage'=1
 /\ dirty'=(IF ClearAfterSample THEN dirty ELSE FALSE) /\ UNCHANGED <<actual,published,sample>>
Sample == /\ stage=1 /\ sample'=actual /\ stage'=2 /\ UNCHANGED <<actual,published,dirty>>
Commit == /\ stage=2 /\ published'=sample /\ stage'=0
 /\ dirty'=(IF ClearAfterSample THEN FALSE ELSE dirty) /\ UNCHANGED <<actual,sample>>
Next == Change \/ Start \/ Sample \/ Commit
Spec == Init /\ [][Next]_vars
Safety == (stage=0 /\ ~dirty) => actual=published
===============================================================
