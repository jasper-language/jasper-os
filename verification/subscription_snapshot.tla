---------------- MODULE subscription_snapshot ----------------
EXTENDS Naturals, Sequences
CONSTANT AtomicSubscribe, MarkOverflow
VARIABLES version, active, snap, cursor, queue, resync, captured, bad
vars == <<version,active,snap,cursor,queue,resync,captured,bad>>
Init == /\ version = 0 /\ active = FALSE /\ snap = 0 /\ cursor = 0
        /\ queue = <<>> /\ resync = FALSE /\ captured = FALSE /\ bad = FALSE
\* Split mode deliberately allows a publish between capture and enrollment.
Capture == /\ ~AtomicSubscribe /\ ~active /\ ~captured
           /\ snap' = version /\ captured' = TRUE
           /\ UNCHANGED <<version,active,cursor,queue,resync,bad>>
Subscribe == /\ ~active /\ (AtomicSubscribe \/ captured)
             /\ active' = TRUE
             /\ snap' = IF AtomicSubscribe THEN version ELSE snap
             /\ cursor' = IF AtomicSubscribe THEN version ELSE snap
             /\ queue' = <<>> /\ resync' = FALSE
             /\ bad' = (bad \/ (~AtomicSubscribe /\ snap # version))
             /\ UNCHANGED <<version,captured>>
Publish == /\ version < 4 /\ version' = version + 1
           /\ queue' = IF ~active \/ resync THEN queue
                         ELSE IF Len(queue) < 2 THEN Append(queue,version+1)
                         ELSE Tail(Append(queue,version+1))
           /\ resync' = (resync \/ (active /\ Len(queue) = 2 /\ MarkOverflow))
           /\ UNCHANGED <<active,snap,cursor,captured,bad>>
Wait == /\ active /\ (resync \/ Len(queue) > 0)
        /\ bad' = (bad \/ (IF resync THEN FALSE ELSE Head(queue) # cursor + 1))
        /\ cursor' = IF resync THEN version ELSE Head(queue)
        /\ queue' = IF resync THEN <<>> ELSE Tail(queue)
        /\ resync' = FALSE
        /\ UNCHANGED <<version,active,snap,captured>>
Close == /\ active /\ active' = FALSE /\ queue' = <<>>
         /\ resync' = FALSE /\ captured' = FALSE
         /\ UNCHANGED <<version,snap,cursor,bad>>
Next == Capture \/ Subscribe \/ Publish \/ Wait \/ Close
Spec == Init /\ [][Next]_vars
Safety == /\ ~bad /\ Len(queue) <= 2 /\ cursor <= version
===============================================================
