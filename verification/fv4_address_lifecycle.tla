---------------------- MODULE fv4_address_lifecycle ----------------------
\* Composition model: one SHM memory object maps its frame into two processes,
\* aliases are removed concurrently, TLB acknowledgements gate frame release,
\* and a timed-out shootdown quarantines the frame instead of recycling it.
EXTENDS Naturals

CONSTANT UnsafeRelease

VARIABLES objectAlive, mapped, tableVersion, tlbView,
          pending, pendingGen, acked, tableGen, freed, quarantined
vars == <<objectAlive, mapped, tableVersion, tlbView,
          pending, pendingGen, acked, tableGen, freed, quarantined>>

Init ==
    /\ objectAlive = TRUE
    /\ mapped = [p \in {0,1} |-> TRUE]
    /\ tableVersion = [p \in {0,1} |-> 0]
    /\ tlbView = [p \in {0,1} |-> [c \in {0,1} |-> 0]]
    /\ pending = FALSE
    /\ pendingGen = 0
    /\ acked = {}
    /\ tableGen = 0
    /\ freed = 0
    /\ quarantined = 0

TypeOK ==
    /\ objectAlive \in BOOLEAN
    /\ mapped \in [ {0,1} -> BOOLEAN ]
    /\ tableVersion \in [ {0,1} -> 0..2 ]
    /\ tlbView \in [ {0,1} -> [ {0,1} -> 0..2 ] ]
    /\ pending \in BOOLEAN
    /\ pendingGen \in 0..2
    /\ acked \subseteq {0,1}
    /\ tableGen \in 0..2
    /\ freed \in 0..1
    /\ quarantined \in 0..1

\* Remove one process alias through the normal process-exit/unmap path.
Unmap(p) ==
    /\ objectAlive
    /\ mapped[p]
    /\ ~pending
    /\ tableGen < 2
    /\ mapped' = [mapped EXCEPT ![p] = FALSE]
    /\ tableVersion' = [tableVersion EXCEPT ![p] = tableGen + 1]
    /\ tableGen' = tableGen + 1
    /\ pending' = TRUE
    /\ pendingGen' = tableGen + 1
    /\ acked' = {p}
    /\ tlbView' = [tlbView EXCEPT ![p][p] = tableGen + 1]
    /\ UNCHANGED <<objectAlive, freed, quarantined>>

\* Every other process acknowledges the invalidation before release is legal.
Ack(c) ==
    /\ pending
    /\ c \in {0,1}
    /\ c \notin acked
    /\ acked' = acked \cup {c}
    /\ tlbView' = [tlbView EXCEPT ![c][c] = pendingGen]
    /\ UNCHANGED <<objectAlive, mapped, tableVersion,
                    pending, pendingGen, tableGen, freed, quarantined>>

FinishInvalidation ==
    /\ pending
    /\ acked = {0,1}
    /\ pending' = FALSE
    /\ UNCHANGED <<objectAlive, mapped, tableVersion, tlbView,
                    pendingGen, acked, tableGen, freed, quarantined>>

\* Object destruction may drop the object reference but cannot free mapped pages.
DestroyObject ==
    /\ objectAlive
    /\ ~mapped[0] /\ ~mapped[1]
    /\ objectAlive' = FALSE
    /\ UNCHANGED <<mapped, tableVersion, tlbView, pending,
                    pendingGen, acked, tableGen, freed, quarantined>>

\* A completed final alias invalidation returns the frame exactly once.
Release ==
    /\ ~objectAlive
    /\ ~mapped[0] /\ ~mapped[1]
    /\ pending
    /\ acked = {0,1}
    /\ \A c \in {0,1}: tlbView[c][c] >= pendingGen
    /\ freed = 0
    /\ freed' = 1
    /\ pending' = FALSE
    /\ UNCHANGED <<objectAlive, mapped, tableVersion, tlbView,
                    pendingGen, acked, tableGen, quarantined>>

\* A timed-out shootdown preserves the frame outside the allocator.
Quarantine ==
    /\ ~objectAlive
    /\ ~mapped[0] /\ ~mapped[1]
    /\ pending
    /\ acked /= {0,1}
    /\ freed = 0
    /\ quarantined = 0
    /\ quarantined' = 1
    /\ pending' = FALSE
    /\ UNCHANGED <<objectAlive, mapped, tableVersion, tlbView,
                    pendingGen, acked, tableGen, freed>>

\* Negative configuration: stale alias/tlb state released without acknowledgement.
UnsafeFree ==
    /\ UnsafeRelease
    /\ freed = 0
    /\ freed' = 1
    /\ UNCHANGED <<objectAlive, mapped, tableVersion, tlbView,
                    pending, pendingGen, acked, tableGen, quarantined>>

Next ==
    \/ \E p \in {0,1}: Unmap(p)
    \/ \E c \in {0,1}: Ack(c)
    \/ FinishInvalidation
    \/ DestroyObject
    \/ Release
    \/ Quarantine
    \/ UnsafeFree

Spec == Init /\ [][Next]_vars

AliasesRetainFrame ==
    (mapped[0] \/ mapped[1]) => freed = 0

MappedRequiresObject ==
    (mapped[0] \/ mapped[1]) => objectAlive

ReleasedNoStaleView ==
    freed = 1 => \A c \in {0,1}: tlbView[c][c] >= pendingGen

FrameAccountedOnce ==
    freed + quarantined <= 1

Safety ==
    /\ TypeOK
    /\ AliasesRetainFrame
    /\ MappedRequiresObject
    /\ ReleasedNoStaleView
    /\ FrameAccountedOnce
=============================================================================
