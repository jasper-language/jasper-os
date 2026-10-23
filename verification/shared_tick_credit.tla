------------------------- MODULE shared_tick_credit -------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. Two CPUs, unit tick cost, one serialized publication epoch.
\* Allocation leaves one positive token. All leaves held across drain/mutation.
CONSTANTS SharedAllocation, DrainBeforeMutation
VARIABLES balance, permits, pending, used, charged, phase, bad
vars == <<balance, permits, pending, used, charged, phase, bad>>
CPUs == {1,2}
Init == /\ balance = 2 /\ permits = {} /\ pending = {}
        /\ used = 0 /\ charged = 0 /\ phase = "publish" /\ bad = FALSE
Publish == /\ phase = "publish"
           /\ permits' \in SUBSET CPUs
           /\ (SharedAllocation => Cardinality(permits') < balance)
           /\ phase' = "run"
           /\ UNCHANGED <<balance,pending,used,charged,bad>>
Tick(c) == /\ phase = "run" /\ c \in permits
           /\ permits' = permits \ {c} /\ pending' = pending \cup {c}
           /\ used' = used + 1
           /\ UNCHANGED <<balance,charged,phase,bad>>
Acquire == /\ phase = "run" /\ phase' = "drain"
           /\ permits' = {}
           /\ UNCHANGED <<balance,pending,used,charged,bad>>
Drain == /\ phase = "drain" /\ phase' = "mutate"
         /\ IF DrainBeforeMutation
               THEN /\ balance' = balance - Cardinality(pending)
                    /\ charged' = charged + Cardinality(pending) /\ pending' = {}
               ELSE UNCHANGED <<balance,charged,pending>>
         /\ UNCHANGED <<permits,used,bad>>
Mutate == /\ phase = "mutate" /\ phase' = "done"
          /\ bad' = (bad \/ pending # {})
          /\ UNCHANGED <<balance,permits,pending,used,charged>>
Next == Publish \/ (\E c \in CPUs: Tick(c)) \/ Acquire \/ Drain \/ Mutate
Spec == Init /\ [][Next]_vars
Safety == /\ ~bad /\ balance > Cardinality(pending)
          /\ used = charged + Cardinality(pending)
=============================================================================
