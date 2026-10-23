-------------------------- MODULE churn_barrier --------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Two pinned CPUs, one measurement epoch, SC abstraction.
CONSTANT RequireAllReady
VARIABLES published, ready, go, done
vars == <<published,ready,go,done>>
CPUs == {0,1}
Init == /\ published = {} /\ ready = {} /\ go = FALSE /\ done = {}
Publish(c) == /\ c \notin published /\ (c = 0 => 1 \in published)
              /\ published' = published \cup {c}
              /\ UNCHANGED <<ready,go,done>>
Arrive(c) == /\ c \in published \ ready /\ ready' = ready \cup {c}
             /\ UNCHANGED <<published,go,done>>
Release == /\ ~go /\ (RequireAllReady => ready = CPUs)
           /\ go' = TRUE /\ UNCHANGED <<published,ready,done>>
Finish(c) == /\ go /\ c \in ready \ done /\ done' = done \cup {c}
             /\ UNCHANGED <<published,ready,go>>
Next == (\E c \in CPUs: Publish(c) \/ Arrive(c) \/ Finish(c)) \/ Release
Spec == Init /\ [][Next]_vars
Safety == /\ (go => ready = CPUs) /\ done \subseteq ready
          /\ (0 \in published => 1 \in published)
=============================================================================
