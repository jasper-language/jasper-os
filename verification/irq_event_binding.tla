----------------------- MODULE irq_event_binding -----------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. One vector, two binding generations; pending survives rebind.
CONSTANT CheckGeneration
VARIABLES generation, bound, pending, sent, delivered, bad
vars == <<generation,bound,pending,sent,delivered,bad>>
Init == /\ generation = 1 /\ bound = TRUE /\ pending = {} /\ sent = {}
        /\ delivered = {} /\ bad = FALSE
Arrival == /\ bound /\ generation \notin sent
           /\ pending' = pending \cup {generation} /\ sent' = sent \cup {generation}
           /\ UNCHANGED <<generation,bound,delivered,bad>>
Close == /\ bound /\ bound' = FALSE
         /\ UNCHANGED <<generation,pending,sent,delivered,bad>>
Rebind == /\ ~bound /\ generation < 2 /\ generation' = generation + 1 /\ bound' = TRUE
          /\ UNCHANGED <<pending,sent,delivered,bad>>
Consume(g) == /\ g \in pending /\ pending' = pending \ {g}
              /\ LET accept == bound /\ (~CheckGeneration \/ g = generation)
                 IN /\ delivered' = IF accept THEN delivered \cup {g} ELSE delivered
                    /\ bad' = (bad \/ (accept /\ g # generation))
              /\ UNCHANGED <<generation,bound,sent>>
Next == Arrival \/ Close \/ Rebind \/ (\E g \in pending: Consume(g))
Spec == Init /\ [][Next]_vars
Safety == /\ ~bad /\ delivered \subseteq sent
=============================================================================
