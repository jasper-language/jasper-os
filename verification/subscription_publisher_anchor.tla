---------------- MODULE subscription_publisher_anchor ----------------
EXTENDS Naturals
CONSTANT Anchor
VARIABLES publisher, cap, closing
vars == <<publisher,cap,closing>>
Init == /\ publisher=TRUE /\ cap=0 /\ closing=FALSE
Grant == /\ ~closing /\ cap<2 /\ cap'=cap+1 /\ UNCHANGED <<publisher,closing>>
Release == /\ cap>0 /\ cap'=cap-1
 /\ closing'=(closing \/ (cap=1 /\ (~Anchor \/ ~publisher))) /\ UNCHANGED publisher
Finish == /\ publisher /\ publisher'=FALSE
 /\ closing'=(closing \/ cap=0) /\ UNCHANGED cap
Next == Grant \/ Release \/ Finish
Spec == Init /\ [][Next]_vars
Safety == publisher => ~closing
===============================================================
