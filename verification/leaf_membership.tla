------------------------ MODULE leaf_membership ------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Two CPUs, monotone online membership, serialized global owner.
CONSTANT IncludeCaller
VARIABLES online, caller, held, phase, permit, pending, accepted, charged
vars == <<online,caller,held,phase,permit,pending,accepted,charged>>
CPUs == {0,1}
Init == /\ online = {0} /\ caller = 0 /\ held = {} /\ phase = "idle"
        /\ permit = {} /\ pending = {} /\ accepted = 0 /\ charged = 0
Acquire(c) == /\ phase = "idle" /\ caller' = c /\ phase' = "drain"
              /\ held' = IF IncludeCaller THEN online \cup {c} ELSE online
              /\ UNCHANGED <<online,permit,pending,accepted,charged>>
Tick(c) == /\ c \in permit \ held /\ c \notin pending /\ accepted < 3
           /\ pending' = pending \cup {c} /\ permit' = permit \ {c}
           /\ accepted' = accepted + 1
           /\ UNCHANGED <<online,caller,held,phase,charged>>
Drain == /\ phase = "drain" /\ phase' = "mutate"
         /\ charged' = charged + Cardinality(pending \cap held)
         /\ pending' = pending \ held
         /\ UNCHANGED <<online,caller,held,permit,accepted>>
Register == /\ phase = "mutate" /\ phase' = "publish"
            /\ online' = online \cup {caller}
            /\ UNCHANGED <<caller,held,permit,pending,accepted,charged>>
Publish == /\ phase = "publish" /\ phase' = "idle"
           /\ permit' = online /\ held' = {}
           /\ UNCHANGED <<online,caller,pending,accepted,charged>>
Next == (\E c \in CPUs: Acquire(c) \/ Tick(c)) \/ Drain \/ Register \/ Publish
Spec == Init /\ [][Next]_vars
Safety == /\ pending \subseteq online /\ permit \subseteq online
          /\ (phase # "idle" => online \subseteq held)
          /\ accepted = charged + Cardinality(pending)
          /\ (phase \in {"mutate","publish"} => pending = {})
=============================================================================
