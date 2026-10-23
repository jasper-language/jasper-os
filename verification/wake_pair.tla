---------------------------- MODULE wake_pair ----------------------------
EXTENDS Naturals, Sequences
\* Author: chatgpt. Serialized metadata, one task, two rounds (Token comparison is tested in Rust, not modeled).
CONSTANT ClearPending
VARIABLES round, pending, emitted
vars == <<round,pending,emitted>>
Init == /\ round = 0 /\ pending = 0 /\ emitted = <<>>
Begin == /\ pending = 0 /\ round < 2
         /\ round' = round + 1 /\ pending' = round + 1
         /\ UNCHANGED emitted
Finish == /\ pending # 0 /\ Len(emitted) < 3
          /\ emitted' = Append(emitted,pending)
          /\ pending' = IF ClearPending THEN 0 ELSE pending
          /\ UNCHANGED round
Stale == UNCHANGED vars
Next == Begin \/ Finish \/ Stale
Spec == Init /\ [][Next]_vars
Safety == /\ round \in 0..2 /\ pending \in 0..2
          /\ \A i,j \in 1..Len(emitted): (i # j => emitted[i] # emitted[j])
=============================================================================
