---------------- MODULE rt3_mutex_lifecycle ----------------
EXTENDS Naturals, TLC

\* A one-mutex/two-task projection of the production object + scheduler
\* protocol.  Task 1 owns the mutex, task 2 may wait, ownership is handed off
\* directly, and each blocked operation retains the object until it resumes.
CONSTANT RetainWaiter
VARIABLES owner, waiting, runnable, refs, closed, acquired, badWake, freed

vars == <<owner, waiting, runnable, refs, closed, acquired, badWake, freed>>

Init == /\ owner = 1
        /\ waiting = FALSE
        /\ runnable = [i \in {1,2} |-> TRUE]
        /\ refs = 1                         \* ownership reference
        /\ closed = FALSE
        /\ acquired = [i \in {1,2} |-> (i = 1)]
        /\ badWake = FALSE
        /\ freed = FALSE

Block == /\ ~closed /\ owner = 1 /\ ~waiting
         /\ waiting' = TRUE
         /\ runnable' = [runnable EXCEPT ![2] = FALSE]
         /\ refs' = refs + IF RetainWaiter THEN 1 ELSE 0
         /\ UNCHANGED <<owner, closed, acquired, badWake, freed>>

Unlock == /\ ~closed /\ owner = 1
          /\ IF waiting
                THEN /\ owner' = 2
                     /\ waiting' = FALSE
                     /\ runnable' = [runnable EXCEPT ![2] = TRUE]
                     /\ acquired' = [acquired EXCEPT ![1] = FALSE, ![2] = TRUE]
                     /\ refs' = refs - IF RetainWaiter THEN 1 ELSE 0
                     /\ badWake' = freed
                ELSE /\ owner' = 0
                     /\ acquired' = [acquired EXCEPT ![1] = FALSE]
                     /\ refs' = refs - 1
                     /\ UNCHANGED <<waiting, runnable, badWake>>
          /\ closed' = closed
          /\ freed' = (refs' = 0)

OwnerExit == /\ owner = 1
             /\ owner' = IF waiting THEN 2 ELSE 0
             /\ waiting' = FALSE
             /\ runnable' = [runnable EXCEPT ![2] = TRUE]
             /\ acquired' = [acquired EXCEPT ![1] = FALSE, ![2] = waiting]
             /\ refs' = refs - IF waiting /\ RetainWaiter THEN 1 ELSE 1
             /\ closed' = closed
             /\ badWake' = waiting /\ refs <= 1
             /\ freed' = (refs' = 0)

Close == /\ ~closed
         /\ closed' = TRUE
         /\ owner' = 0
         /\ waiting' = FALSE
         /\ runnable' = [runnable EXCEPT ![2] = TRUE]
         /\ acquired' = [i \in {1,2} |-> FALSE]
         /\ refs' = IF waiting /\ RetainWaiter THEN 1 ELSE 0
         /\ freed' = (refs' = 0)
         /\ badWake' = badWake \/ (waiting /\ ~RetainWaiter)

ResumeClosed == /\ closed /\ runnable[2] /\ refs = 1
                /\ refs' = 0
                /\ freed' = TRUE
                /\ UNCHANGED <<owner, waiting, runnable, closed, acquired, badWake>>

Next == Block \/ Unlock \/ OwnerExit \/ Close \/ ResumeClosed

Safety == /\ refs >= 0
          /\ ~(acquired[1] /\ acquired[2])
          /\ (waiting => ~runnable[2])
          /\ ~badWake
          /\ (freed => ~waiting)

Spec == Init /\ [][Next]_vars
=============================================================
