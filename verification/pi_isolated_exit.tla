------------------------- MODULE pi_isolated_exit -------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Serial three-node, two-priority noninterference lemma.
CONSTANT CheckOutgoing
VARIABLES base, waits, exiting, alive, before, phase
vars == <<base,waits,exiting,alive,before,phase>>
Nodes == 0..2
None == 3
RECURSIVE Reach(_,_,_)
Reach(w, d, n) == IF n = 0 \/ w[d] = None THEN {}
                  ELSE {w[d]} \cup Reach(w, w[d], n-1)
Boosted(b,w,a) == {r \in a: b[r] \/ (\E d \in a: b[d] /\ r \in Reach(w,d,3))}
Init == /\ base \in [Nodes -> BOOLEAN]
        /\ waits \in [Nodes -> (Nodes \cup {None})]
        /\ exiting \in Nodes
        /\ \A d \in Nodes: waits[d] # exiting
        /\ (CheckOutgoing => waits[exiting] = None)
        /\ alive = Nodes /\ before = Boosted(base,waits,Nodes) /\ phase = 0
Exit == /\ phase = 0 /\ phase' = 1
        /\ alive' = alive \ {exiting}
        /\ waits' = [waits EXCEPT ![exiting] = None]
        /\ UNCHANGED <<base,exiting,before>>
Next == Exit
Spec == Init /\ [][Next]_vars
Safety == \A r \in alive: (r \in before) = (r \in Boosted(base,waits,alive))
=============================================================================
