----------------------- MODULE shm_page_lifetime -----------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. One physical page, two process mappings, one pin per process.
\* Atomic metadata transactions; hardware TLB acknowledgement is an explicit assumption.
CONSTANTS WaitForAck, KeepPinned
P == 0..1
VARIABLES owner, phase, pte, tlb, pins, quarantined, freed
vars == <<owner,phase,pte,tlb,pins,quarantined,freed>>
Init == /\ owner = TRUE /\ phase = [p \in P |-> "new"]
        /\ pte = {} /\ tlb = {} /\ pins = {}
        /\ quarantined = FALSE /\ freed = FALSE
Map(p) == /\ owner /\ ~freed /\ phase[p] = "new"
          /\ phase' = [phase EXCEPT ![p] = "mapped"]
          /\ pte' = pte \cup {p} /\ tlb' = tlb \cup {p}
          /\ UNCHANGED <<owner,pins,quarantined,freed>>
Pin(p) == /\ p \in pte /\ p \notin pins /\ ~freed
          /\ pins' = pins \cup {p}
          /\ UNCHANGED <<owner,phase,pte,tlb,quarantined,freed>>
Unpin(p) == /\ p \in pins /\ pins' = pins \ {p}
            /\ UNCHANGED <<owner,phase,pte,tlb,quarantined,freed>>
Revoke(p) == /\ phase[p] = "mapped"
             /\ phase' = [phase EXCEPT ![p] = IF WaitForAck THEN "revoking" ELSE "retired"]
             /\ pte' = pte \ {p}
             /\ UNCHANGED <<owner,tlb,pins,quarantined,freed>>
Ack(p) == /\ phase[p] = "revoking"
          /\ phase' = [phase EXCEPT ![p] = "retired"] /\ tlb' = tlb \ {p}
          /\ UNCHANGED <<owner,pte,pins,quarantined,freed>>
Timeout(p) == /\ phase[p] = "revoking"
              /\ phase' = [phase EXCEPT ![p] = "quarantined"]
              /\ quarantined' = TRUE
              /\ UNCHANGED <<owner,pte,tlb,pins,freed>>
Close == /\ owner /\ owner' = FALSE
         /\ UNCHANGED <<phase,pte,tlb,pins,quarantined,freed>>
Free == /\ ~owner /\ ~freed /\ ~quarantined
        /\ \A p \in P: phase[p] \in {"new","retired"}
        /\ (~KeepPinned \/ pins = {}) /\ freed' = TRUE
        /\ UNCHANGED <<owner,phase,pte,tlb,pins,quarantined>>
Next == Close \/ Free \/ (\E p \in P: Map(p) \/ Pin(p) \/ Unpin(p) \/ Revoke(p) \/ Ack(p) \/ Timeout(p))
Spec == Init /\ [][Next]_vars
Safety == /\ (freed => ~owner /\ pte = {} /\ tlb = {} /\ pins = {} /\ ~quarantined)
          /\ pte \subseteq tlb
          /\ \A p \in P: (phase[p] = "mapped") <=> (p \in pte)
=============================================================================
