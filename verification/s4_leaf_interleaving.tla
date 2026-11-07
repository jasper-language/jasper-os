---------------------- MODULE s4_leaf_interleaving ----------------------
EXTENDS Naturals
\* Bounded owner-leaf migration with wake and PI messages racing migration.
CONSTANT BrokenGeneration
VARIABLES home, place, firstLock, secondLock,
          wakePending, wakeGeneration, wakeApplied,
          piPending, piGeneration, piRound, liveRound, piApplied
vars == <<home, place, firstLock, secondLock,
          wakePending, wakeGeneration, wakeApplied,
          piPending, piGeneration, piRound, liveRound, piApplied>>

Init == /\ home = 0 /\ place = "blocked"
        /\ firstLock = 2 /\ secondLock = 2
        /\ wakePending = TRUE /\ wakeGeneration \in {0, 1}
        /\ wakeApplied = 0
        /\ piPending = TRUE /\ piGeneration \in {0, 1}
        /\ piRound \in {0, 1} /\ liveRound = 1 /\ piApplied = 0

ConsumeWake ==
    /\ wakePending
    /\ wakePending' = FALSE
    /\ IF wakeGeneration = 1 \/ BrokenGeneration
          THEN /\ place' = IF home = 0 THEN "queue0" ELSE "queue1"
               /\ wakeApplied' = wakeApplied + 1
          ELSE /\ UNCHANGED <<place, wakeApplied>>
    /\ UNCHANGED <<home, firstLock, secondLock,
                    wakeGeneration, piPending, piGeneration,
                    piRound, liveRound, piApplied>>

LockFirst ==
    /\ place = "queue0" /\ home = 0 /\ firstLock = 2
    /\ firstLock' = 0
    /\ UNCHANGED <<home, place, secondLock, wakePending, wakeGeneration,
                    wakeApplied, piPending, piGeneration, piRound,
                    liveRound, piApplied>>
LockSecond ==
    /\ place = "queue0" /\ firstLock = 0 /\ secondLock = 2
    /\ secondLock' = 1
    /\ UNCHANGED <<home, place, firstLock, wakePending, wakeGeneration,
                    wakeApplied, piPending, piGeneration, piRound,
                    liveRound, piApplied>>
Detach ==
    /\ place = "queue0" /\ firstLock = 0 /\ secondLock = 1
    /\ place' = "transit"
    /\ UNCHANGED <<home, firstLock, secondLock, wakePending,
                    wakeGeneration, wakeApplied, piPending, piGeneration,
                    piRound, liveRound, piApplied>>
Commit ==
    /\ place = "transit"
    /\ home' = 1 /\ place' = "queue1"
    /\ firstLock' = 2 /\ secondLock' = 2
    /\ UNCHANGED <<wakePending, wakeGeneration, wakeApplied,
                    piPending, piGeneration, piRound, liveRound, piApplied>>

Dispatch ==
    /\ place \in {"queue0", "queue1"}
    /\ place' = IF home = 0 THEN "run0" ELSE "run1"
    /\ UNCHANGED <<home, firstLock, secondLock, wakePending,
                    wakeGeneration, wakeApplied, piPending, piGeneration,
                    piRound, liveRound, piApplied>>

ConsumePi ==
    /\ piPending
    /\ piPending' = FALSE
    /\ piApplied' = IF piGeneration = 1 /\ piRound = liveRound
                       THEN piApplied + 1 ELSE piApplied
    /\ UNCHANGED <<home, place, firstLock, secondLock, wakePending,
                    wakeGeneration, wakeApplied, piGeneration,
                    piRound, liveRound>>

Next == ConsumeWake \/ LockFirst \/ LockSecond \/ Detach \/ Commit
        \/ Dispatch \/ ConsumePi
Spec == Init /\ [][Next]_vars

TypeOk == /\ home \in {0, 1}
          /\ place \in {"blocked", "queue0", "queue1", "transit", "run0", "run1"}
          /\ firstLock \in {0, 2} /\ secondLock \in {1, 2}
Safety == /\ TypeOk
          /\ (place \in {"queue0", "run0"} => home = 0)
          /\ (place \in {"queue1", "run1"} => home = 1)
          /\ (place = "transit" => firstLock = 0 /\ secondLock = 1)
          /\ (secondLock = 1 => firstLock = 0)
          /\ wakeApplied <= 1
          /\ (wakeApplied = 1 => wakeGeneration = 1)
          /\ piApplied <= 1
          /\ (piApplied = 1 => piGeneration = 1 /\ piRound = liveRound)
=============================================================================
