---------------- MODULE subscription_lifetime ----------------
EXTENDS Naturals, FiniteSets
CONSTANT ReleaseOnSourceClose
VARIABLES owner, subscribers, refs, dead
vars == <<owner,subscribers,refs,dead>>
Init == /\ owner=TRUE /\ subscribers={} /\ refs=0 /\ dead=FALSE
Subscribe(s) == /\ owner /\ ~dead /\ s \notin subscribers
 /\ subscribers'=subscribers \cup {s} /\ refs'=refs+1
 /\ UNCHANGED <<owner,dead>>
CloseSource == /\ owner /\ owner'=FALSE
 /\ refs'=(IF ReleaseOnSourceClose THEN 0 ELSE refs)
 /\ dead'=(IF ReleaseOnSourceClose THEN TRUE ELSE refs=0)
 /\ UNCHANGED subscribers
CloseSub(s) == /\ s \in subscribers /\ subscribers'=subscribers \ {s}
 /\ refs'=(IF refs>0 THEN refs-1 ELSE 0)
 /\ dead'=(dead \/ (~owner /\ refs=1)) /\ UNCHANGED owner
Next == CloseSource \/ (\E s \in {1,2}: Subscribe(s) \/ CloseSub(s))
Spec == Init /\ [][Next]_vars
Safety == /\ refs=Cardinality(subscribers) /\ (subscribers # {} => ~dead)
===============================================================
