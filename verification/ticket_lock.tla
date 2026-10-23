--------------------------- MODULE ticket_lock ---------------------------
EXTENDS Naturals, Sequences, FiniteSets
\* Author: chatgpt. 3 callers, modulus 4: outstanding tickets never wrap onto self.
Threads == {1,2,3}
VARIABLES next, serving, queue, owner, ticket
vars == <<next, serving, queue, owner, ticket>>
Init == /\ next = 0 /\ serving = 0 /\ queue = <<>> /\ owner = 0
        /\ ticket = [t \in Threads |-> 0]
Waiting == {queue[i]: i \in 1..Len(queue)}
Allocate(t) == /\ t # owner /\ t \notin Waiting
               /\ queue' = Append(queue, t)
               /\ ticket' = [ticket EXCEPT ![t] = next]
               /\ next' = (next + 1) % 4
               /\ UNCHANGED <<owner, serving>>
Take == /\ owner = 0 /\ Len(queue) > 0
        /\ ticket[Head(queue)] = serving
        /\ owner' = Head(queue) /\ queue' = Tail(queue)
        /\ UNCHANGED <<ticket, next, serving>>
Try(t) == /\ owner = 0 /\ queue = <<>> /\ next = serving
          /\ owner' = t /\ ticket' = [ticket EXCEPT ![t] = next]
          /\ next' = (next + 1) % 4
          /\ UNCHANGED <<queue, serving>>
Release == /\ owner # 0 /\ owner' = 0
           /\ serving' = (serving + 1) % 4
           /\ UNCHANGED <<ticket, next, queue>>
Next == (\E t \in Threads: Allocate(t) \/ Try(t)) \/ Take \/ Release
Spec == Init /\ [][Next]_vars
Safety == /\ (owner # 0 => ticket[owner] = serving)
          /\ owner \notin Waiting
          /\ \A i,j \in 1..Len(queue): i # j => ticket[queue[i]] # ticket[queue[j]]
          /\ \A i \in 1..Len(queue): owner # 0 => ticket[queue[i]] # ticket[owner]
=============================================================================
