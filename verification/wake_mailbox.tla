---------------------------- MODULE wake_mailbox ----------------------------
EXTENDS Naturals, Sequences, FiniteSets
\* Author: chatgpt. Capacity one; two live slots with two generations each.
CONSTANT CheckGeneration, FallbackFull
Slots == {1,2}
VARIABLES queue, accepted, finished, current, bad
vars == <<queue,accepted,finished,current,bad>>
Init == /\ queue = <<>> /\ accepted = {} /\ finished = {}
        /\ current = [s \in Slots |-> 1] /\ bad = FALSE
Queued == {queue[i]: i \in 1..Len(queue)}
Token(s) == <<s,current[s]>>
Request(s) == /\ Token(s) \notin accepted
              /\ accepted' = accepted \cup {Token(s)}
              /\ queue' = IF Len(queue) < 1 THEN Append(queue,Token(s)) ELSE queue
              /\ finished' = IF Len(queue) = 1 /\ FallbackFull THEN finished \cup {Token(s)} ELSE finished
              /\ UNCHANGED <<current,bad>>
Deliver == /\ Len(queue) > 0
           /\ bad' = (bad \/ (~CheckGeneration /\ Head(queue)[2] # current[Head(queue)[1]]))
           /\ finished' = finished \cup {Head(queue)}
           /\ queue' = Tail(queue)
           /\ UNCHANGED <<accepted,current>>
Renew(s) == /\ current[s] = 1 /\ current' = [current EXCEPT ![s] = 2]
            /\ UNCHANGED <<queue,accepted,finished,bad>>
Next == (\E s \in Slots: Request(s) \/ Renew(s)) \/ Deliver
Spec == Init /\ [][Next]_vars
Safety == /\ ~bad /\ Len(queue) <= 1
          /\ accepted = Queued \cup finished /\ Queued \intersect finished = {}
=============================================================================
