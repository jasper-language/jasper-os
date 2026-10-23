----------------------------- MODULE bm1_boot -----------------------------
EXTENDS Naturals, FiniteSets
CONSTANT ChunkCount
VARIABLES stage, owned, allocated, received, hashOK, serialOK, screenOK, resets, passes
vars == <<stage, owned, allocated, received, hashOK, serialOK, screenOK, resets, passes>>
Init == /\ stage = "capture" /\ owned = FALSE /\ allocated = FALSE
        /\ received = {} /\ hashOK = FALSE /\ serialOK = FALSE
        /\ screenOK = FALSE /\ resets = 0 /\ passes = 0
Allocate == /\ stage = "capture" /\ stage' = "upload" /\ allocated' = TRUE
            /\ UNCHANGED <<owned, received, hashOK, serialOK, screenOK, resets, passes>>
Submit == /\ stage = "upload" /\ ~owned /\ owned' = TRUE
          /\ UNCHANGED <<stage, allocated, received, hashOK, serialOK, screenOK, resets, passes>>
Complete == /\ stage = "upload" /\ owned /\ owned' = FALSE
            /\ UNCHANGED <<stage, allocated, received, hashOK, serialOK, screenOK, resets, passes>>
Receive == /\ stage = "upload" /\ \E n \in 1..ChunkCount : received' = received \cup {n}
           /\ UNCHANGED <<stage, owned, allocated, hashOK, serialOK, screenOK, resets, passes>>
Verify == /\ stage = "upload" /\ received = 1..ChunkCount /\ ~owned
          /\ hashOK' = TRUE /\ serialOK' = TRUE /\ screenOK' = TRUE /\ stage' = "verified"
          /\ UNCHANGED <<allocated, received, owned, resets, passes>>
Fail == /\ stage \in {"capture", "upload"} /\ stage' = "quarantine"
        /\ UNCHANGED <<owned, allocated, received, hashOK, serialOK, screenOK, resets, passes>>
Reset == /\ stage \in {"verified", "quarantine"} /\ resets = 0 /\ resets' = 1
         /\ owned' = FALSE /\ allocated' = FALSE /\ stage' = "reset"
         /\ UNCHANGED <<received, hashOK, serialOK, screenOK, passes>>
Accept == /\ stage = "reset" /\ hashOK /\ serialOK /\ screenOK /\ passes = 0
          /\ passes' = 1 /\ UNCHANGED <<stage, owned, allocated, received, hashOK, serialOK, screenOK, resets>>
Next == Allocate \/ Submit \/ Complete \/ Receive \/ Verify \/ Fail \/ Reset \/ Accept
TypeOK == /\ stage \in {"capture", "upload", "verified", "quarantine", "reset"}
          /\ owned \in BOOLEAN /\ allocated \in BOOLEAN /\ received \subseteq 1..ChunkCount
          /\ hashOK \in BOOLEAN /\ serialOK \in BOOLEAN /\ screenOK \in BOOLEAN
          /\ resets \in 0..1 /\ passes \in 0..1
DMAOwnedRetained == owned => allocated
NoEarlyAccept == passes > 0 => (resets = 1 /\ received = 1..ChunkCount /\ hashOK /\ serialOK /\ screenOK)
Spec == Init /\ [][Next]_vars
=============================================================================
