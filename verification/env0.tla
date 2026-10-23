------------------------------ MODULE env0 ------------------------------
EXTENDS Integers, FiniteSets, TLC
\* Author: chatgpt. Per-core locked versioned admission contract.
Tasks == {1, 2, 3}
VARIABLES admitted, ceiling, version, pending
vars == <<admitted, ceiling, version, pending>>
Fits(s, c) == Cardinality(s) <= c /\ (1 \in s => Cardinality(s) = 1)
Init == /\ admitted = {} /\ ceiling = 2 /\ version = 0
        /\ pending = [t \in Tasks |-> -1]
Prepare(t) == /\ pending[t] = -1 /\ t \notin admitted
              /\ Fits(admitted \cup {t}, ceiling)
              /\ pending' = [pending EXCEPT ![t] = version]
              /\ UNCHANGED <<admitted, ceiling, version>>
Commit(t) == /\ pending[t] = version /\ version < 4
             /\ admitted' = admitted \cup {t}
             /\ version' = version + 1
             /\ pending' = [pending EXCEPT ![t] = -1]
             /\ UNCHANGED ceiling
Reject(t) == /\ pending[t] >= 0 /\ pending[t] # version
             /\ pending' = [pending EXCEPT ![t] = -1]
             /\ UNCHANGED <<admitted, ceiling, version>>
\* Criticality increases with task ID. Retain highest priority first.
Degrade == /\ ceiling > 0 /\ version < 4
           /\ ceiling' = ceiling - 1 /\ version' = version + 1
           /\ admitted' = IF Cardinality(admitted) <= ceiling - 1 THEN admitted
                          ELSE IF ceiling = 1 THEN {}
                          ELSE {CHOOSE t \in admitted: \A u \in admitted: t >= u}
           /\ UNCHANGED pending
Unknown == UNCHANGED vars
Next == (\E t \in Tasks: Prepare(t) \/ Commit(t) \/ Reject(t)) \/ Degrade \/ Unknown
Spec == Init /\ [][Next]_vars
Safety == /\ admitted \subseteq Tasks /\ ceiling \in 0..2
          /\ Fits(admitted, ceiling)
=============================================================================
