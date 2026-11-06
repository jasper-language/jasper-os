--------------------------- MODULE kobj_release ---------------------------
\* Abstract production release protocol: owner transition, typed closing hook,
\* internal-reference changes, cascade, generation reuse and iterative cleanup.
EXTENDS Naturals, FiniteSets

CONSTANT RequireHook
CONSTANT UniqueClose

Ids == 1..6
Slots == {"p", "c"}

SlotOf(id) == IF id % 2 = 1 THEN "p" ELSE "c"
GenOf(id) == (id + 1) \div 2
IdsOf(slot) == {id \in Ids : SlotOf(id) = slot}

VARIABLES current, phase, owners, refs, closed, hook_count, queue, stopped
vars == <<current, phase, owners, refs, closed, hook_count, queue, stopped>>

CurrentIds == {current[s] : s \in Slots}
IsCurrent(id) == id \in CurrentIds

Init ==
    /\ current = [p |-> 1, c |-> 2]
    /\ phase = [id \in Ids |-> IF id \in {1, 2} THEN "live" ELSE "vacant"]
    /\ owners = [id \in Ids |-> IF id \in {1, 2} THEN 1 ELSE 0]
    /\ refs = [id \in Ids |-> IF id = 2 THEN 1 ELSE 0]
    /\ closed = {}
    /\ hook_count = [id \in Ids |-> 0]
    /\ queue = {}
    /\ stopped = FALSE

\* Last owner transition is linearized before the closing hook.
ReleaseOwner(id) ==
    /\ IsCurrent(id)
    /\ phase[id] = "live"
    /\ owners[id] = 1
    /\ owners' = [owners EXCEPT ![id] = 0]
    /\ phase' = [phase EXCEPT ![id] = "closing"]
    /\ UNCHANGED <<current, refs, closed, hook_count, queue, stopped>>

\* Type-specific closing may release a child's internal reference. It is
\* bounded to one execution per generation in the positive model.
CloseType(id) ==
    /\ IsCurrent(id)
    /\ phase[id] = "closing"
    /\ (UniqueClose => id \notin closed)
    /\ closed' = closed \cup {id}
    /\ hook_count' = [hook_count EXCEPT ![id] = hook_count[id] + 1]
    /\ refs' = IF SlotOf(id) = "p" /\ refs[current["c"]] > 0
               THEN [refs EXCEPT ![current["c"]] = refs[current["c"]] - 1]
               ELSE refs
    /\ UNCHANGED <<current, phase, owners, queue, stopped>>

ReleaseInternal(id) ==
    /\ IsCurrent(id)
    /\ phase[id] \in {"live", "closing"}
    /\ refs[id] > 0
    /\ refs' = [refs EXCEPT ![id] = refs[id] - 1]
    /\ UNCHANGED <<current, phase, owners, closed, hook_count, queue, stopped>>

\* A closing object becomes dead only after its typed hook has completed and
\* all internal references are gone. Dead objects enter the cleanup queue.
FinishClosing(id) ==
    /\ IsCurrent(id)
    /\ phase[id] = "closing"
    /\ owners[id] = 0
    /\ refs[id] = 0
    /\ (RequireHook => id \in closed)
    /\ phase' = [phase EXCEPT ![id] = "dead"]
    /\ queue' = queue \cup {id}
    /\ UNCHANGED <<current, owners, refs, closed, hook_count, stopped>>

\* Cleanup happens after take_dead increments the slot generation. The old
\* identity is gone; only a later generation can occupy the slot.
Cleanup(id) ==
    /\ id \in queue
    /\ phase[id] = "dead"
    /\ queue' = queue \ {id}
    /\ phase' = [phase EXCEPT ![id] = "vacant"]
    /\ UNCHANGED <<current, owners, refs, closed, hook_count, stopped>>

NextId(slot) ==
    IF slot = "p"
    THEN IF current[slot] = 1 THEN 3 ELSE 5
    ELSE IF current[slot] = 2 THEN 4 ELSE 6

CanReuse(slot) ==
    /\ phase[current[slot]] = "vacant"
    /\ GenOf(current[slot]) < 3

Reuse(slot) ==
    LET next == NextId(slot) IN
    /\ ~stopped
    /\ CanReuse(slot)
    /\ current' = [current EXCEPT ![slot] = next]
    /\ phase' = [phase EXCEPT ![next] = "live"]
    /\ owners' = [owners EXCEPT ![next] = 1]
    /\ refs' = [refs EXCEPT ![next] = 0]
    /\ UNCHANGED <<closed, hook_count, queue, stopped>>

\* Duplicate or stale close requests have no lifecycle side effect.
RejectClose(id) ==
    /\ (phase[id] \notin {"live"} \/ owners[id] = 0)
    /\ UNCHANGED vars

\* Once every current owner has closed, external traffic can stop and the
\* remaining hook/ref/queue work is required to converge under strong fairness.
StopTraffic ==
    /\ ~stopped
    /\ \A id \in CurrentIds : owners[id] = 0
    /\ stopped' = TRUE
    /\ UNCHANGED <<current, phase, owners, refs, closed, hook_count, queue>>

ReleaseAny == \E id \in Ids : ReleaseOwner(id)
CloseAny == \E id \in Ids : CloseType(id)
InternalAny == \E id \in Ids : ReleaseInternal(id)
FinishAny == \E id \in Ids : FinishClosing(id)
CleanupAny == \E id \in Ids : Cleanup(id)
RejectAny == \E id \in Ids : RejectClose(id)
ReuseAny == \E slot \in Slots : Reuse(slot)

Next ==
    \/ ReleaseAny
    \/ CloseAny
    \/ InternalAny
    \/ FinishAny
    \/ CleanupAny
    \/ RejectAny
    \/ ReuseAny
    \/ StopTraffic

Fairness ==
    /\ SF_vars(ReleaseAny)
    /\ SF_vars(CloseAny)
    /\ SF_vars(InternalAny)
    /\ SF_vars(FinishAny)
    /\ SF_vars(CleanupAny)
    /\ SF_vars(StopTraffic)

Spec == Init /\ [][Next]_vars /\ Fairness

Safety ==
    /\ \A id \in Ids :
        /\ (phase[id] = "live" => owners[id] = 1)
        /\ (phase[id] = "closing" => owners[id] = 0)
        /\ (id \in queue => /\ phase[id] = "dead" /\ owners[id] = 0 /\ refs[id] = 0)
        /\ (phase[id] = "dead" => /\ id \in closed /\ owners[id] = 0 /\ refs[id] = 0)
        /\ hook_count[id] <= 1

QuiescenceDrain ==
    stopped ~> /\ queue = {}
                 /\ \A id \in CurrentIds : phase[id] = "vacant"

=============================================================================
