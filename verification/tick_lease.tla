----------------------------- MODULE tick_lease -----------------------------
EXTENDS Naturals
\* Author: chatgpt. One CPU leaf, serialized transaction drain/mutate/publish.
CONSTANT DrainBeforeMutate
VARIABLES owner, pending, permit, leaf, phase, charged, accepted, bad
vars == <<owner,pending,permit,leaf,phase,charged,accepted,bad>>
Init == /\ owner = 1 /\ pending = 0 /\ permit = TRUE /\ leaf = FALSE
        /\ phase = "idle" /\ charged = 0 /\ accepted = 0 /\ bad = FALSE
FastTick == /\ ~leaf /\ permit /\ pending = 0 /\ accepted < 3
            /\ pending' = owner /\ permit' = FALSE /\ accepted' = accepted + 1
            /\ UNCHANGED <<owner,leaf,phase,charged,bad>>
Acquire == /\ phase = "idle" /\ leaf' = TRUE /\ phase' = "drain"
           /\ UNCHANGED <<owner,pending,permit,charged,accepted,bad>>
Drain == /\ phase = "drain" /\ phase' = "mutate"
         /\ bad' = (bad \/ (pending # 0 /\ pending # owner))
         /\ charged' = charged + IF pending # 0 THEN 1 ELSE 0
         /\ pending' = IF DrainBeforeMutate THEN 0 ELSE pending
         /\ UNCHANGED <<owner,permit,leaf,accepted>>
Mutate == /\ phase = "mutate" /\ phase' = "publish"
          /\ owner' = 3-owner
          /\ bad' = (bad \/ (pending # 0))
          /\ UNCHANGED <<pending,permit,leaf,charged,accepted>>
Publish == /\ phase = "publish" /\ phase' = "idle" /\ leaf' = FALSE
           /\ permit' = TRUE
           /\ UNCHANGED <<owner,pending,charged,accepted,bad>>
Next == FastTick \/ Acquire \/ Drain \/ Mutate \/ Publish
Spec == Init /\ [][Next]_vars
Safety == /\ ~bad /\ charged + (IF pending # 0 THEN 1 ELSE 0) = accepted
          /\ (phase # "idle" => leaf)
=============================================================================
