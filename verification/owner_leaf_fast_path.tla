------------------------ MODULE owner_leaf_fast_path ------------------------
EXTENDS Naturals, FiniteSets
\* Candidate owner-leaf expiry: observe under one CPU lease, then publish a
\* wake. Migration and non-owner publication are explicit negative controls.
CONSTANT SerializeCanonical, AllowNonOwner
CPUs == {0,1}
VARIABLES home, eventOwner, eventGen, state, wakeCount,
          claimed, claimOwner, claimGen, bad
vars == <<home, eventOwner, eventGen, state, wakeCount,
          claimed, claimOwner, claimGen, bad>>

Init == /\ home = 0
        /\ eventOwner = 0
        /\ eventGen = 1
        /\ state = "blocked"
        /\ wakeCount = 0
        /\ claimed = FALSE
        /\ claimOwner = 0
        /\ claimGen = 0
        /\ bad = FALSE

FastObserve(c) ==
    /\ ~claimed
    /\ state = "blocked"
    /\ c \in CPUs
    /\ (c = eventOwner \/ AllowNonOwner)
    /\ claimed' = TRUE
    /\ claimOwner' = c
    /\ claimGen' = eventGen
    /\ UNCHANGED <<home, eventOwner, eventGen, state, wakeCount, bad>>

Migrate(d) ==
    /\ state = "blocked"
    /\ d \in CPUs
    /\ eventGen < 3
    /\ (IF SerializeCanonical THEN ~claimed ELSE TRUE)
    /\ home' = d
    /\ eventOwner' = d
    /\ eventGen' = eventGen + 1
    /\ UNCHANGED <<state, wakeCount, claimed, claimOwner, claimGen, bad>>

FastWake ==
    /\ claimed
    /\ state = "blocked"
    /\ wakeCount' = wakeCount + 1
    /\ state' = "runnable"
    /\ claimed' = FALSE
    /\ bad' = (bad \/ (claimOwner # eventOwner \/ claimGen # eventGen))
    /\ UNCHANGED <<home, eventOwner, eventGen, claimOwner, claimGen>>

Next ==
    \/ \E c \in CPUs: FastObserve(c)
    \/ \E d \in CPUs: Migrate(d)
    \/ FastWake

Spec == Init /\ [][Next]_vars

NoStaleWake == ~bad
OwnerMatchesClaim == ~claimed \/ (claimOwner = eventOwner /\ claimGen = eventGen)
AtMostOneWake == wakeCount <= 1
=============================================================================
