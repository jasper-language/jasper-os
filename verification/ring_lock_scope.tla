--------------------------- MODULE ring_lock_scope ---------------------------
\* Ring backend actions under the object-table transaction. Cancel, delivery,
\* close and exit race for the same request, but only one holder is visible.
\* The two negative controls permit either nested acquisition or a task block
\* while the table is held; the safety invariants must reject both.
EXTENDS Naturals

CONSTANTS AllowNestedAcquire, AllowBlocking

Ops == {"cancel", "deliver", "close", "exit"}

VARIABLES lock, holder, steps, pending, terminal, closing, quiesced,
          released, published, destroyed, decisions, publications, releases,
          nested, blocked

vars == <<lock, holder, steps, pending, terminal, closing, quiesced,
          released, published, destroyed, decisions, publications, releases,
          nested, blocked>>

Init ==
  /\ lock = "free"
  /\ holder = "none"
  /\ steps = 0
  /\ pending = Ops
  /\ terminal = "none"
  /\ closing = FALSE
  /\ quiesced = FALSE
  /\ released = FALSE
  /\ published = FALSE
  /\ destroyed = FALSE
  /\ decisions = 0
  /\ publications = 0
  /\ releases = 0
  /\ nested = FALSE
  /\ blocked = FALSE

\* All four sources enter through the same non-reentrant table lock. Entry
\* order is nondeterministic, so TLC covers every serialized interleaving.
Acquire(op) ==
  /\ op \in pending
  /\ lock = "free"
  /\ lock' = op
  /\ holder' = op
  /\ steps' = 0
  /\ pending' = pending \ {op}
  /\ nested' = FALSE
  /\ blocked' = FALSE
  /\ UNCHANGED <<terminal, closing, quiesced, released, published,
                destroyed, decisions, publications, releases>>

\* One bounded handler turn decides at most one terminal and releases the
\* backend resource before completion can be published.
Operate ==
  /\ lock # "free"
  /\ steps = 0
  /\ steps' = 1
  /\ terminal' = IF terminal = "none" THEN holder ELSE terminal
  /\ decisions' = IF terminal = "none" THEN decisions + 1 ELSE decisions
  /\ quiesced' = TRUE
  /\ released' = TRUE
  /\ releases' = IF released THEN releases ELSE releases + 1
  /\ closing' = (closing \/ (holder \in {"close", "exit"}))
  /\ UNCHANGED <<lock, holder, pending, published, destroyed, publications,
                nested, blocked>>

\* Negative control: recursively taking the same object-table lock while its
\* transaction is active.
ReenterTable ==
  /\ AllowNestedAcquire
  /\ lock # "free"
  /\ nested' = TRUE
  /\ steps' = steps + 1
  /\ UNCHANGED <<lock, holder, pending, terminal, closing, quiesced, released,
                published, destroyed, decisions, publications, releases, blocked>>

\* Negative control: yielding/sleeping with the object table held.
BlockTask ==
  /\ AllowBlocking
  /\ lock # "free"
  /\ blocked' = TRUE
  /\ steps' = steps + 1
  /\ UNCHANGED <<lock, holder, pending, terminal, closing, quiesced, released,
                published, destroyed, decisions, publications, releases, nested>>

\* Delivery publishes while it owns the table and only after backend release.
\* Close/exit suppress the completion record.
Publish ==
  /\ lock = "deliver"
  /\ terminal = "deliver"
  /\ released
  /\ ~closing
  /\ ~published
  /\ published' = TRUE
  /\ publications' = publications + 1
  /\ UNCHANGED <<lock, holder, steps, pending, terminal, closing, quiesced,
                released, destroyed, decisions, releases, nested, blocked>>

\* The transaction ends with the table free. A deliver result cannot skip its
\* publication; close/exit results are dropped instead.
Finish ==
  /\ lock # "free"
  /\ steps = 1
  /\ (terminal # "deliver" \/ closing \/ published)
  /\ lock' = "free"
  /\ holder' = "none"
  /\ UNCHANGED <<steps, pending, terminal, closing, quiesced, released,
                published, destroyed, decisions, publications, releases,
                nested, blocked>>

Destroy ==
  /\ lock = "free"
  /\ terminal # "none"
  /\ released
  /\ ~destroyed
  /\ (published \/ closing)
  /\ destroyed' = TRUE
  /\ UNCHANGED <<lock, holder, steps, pending, terminal, closing, quiesced,
                released, published, decisions, publications, releases,
                nested, blocked>>

Next ==
  \/ \E op \in Ops : Acquire(op)
  \/ Operate
  \/ ReenterTable
  \/ BlockTask
  \/ Publish
  \/ Finish
  \/ Destroy

Spec == Init /\ [][Next]_vars
        /\ WF_vars(\E op \in Ops : Acquire(op))
        /\ WF_vars(Operate)
        /\ WF_vars(Publish)
        /\ WF_vars(Finish)
        /\ WF_vars(Destroy)

SingleHolder == (lock = "free") <=> (holder = "none")
NoNestedObjectAcquire == ~nested
NoTaskBlockWhileLocked == ~blocked
BoundedBackendTurn == steps <= 1
TerminalAtMostOnce == decisions <= 1
ReleaseAtMostOnce == releases <= 1
CompletionAtMostOnce == publications <= 1
ReleaseBeforePublish == published => released
NoCompletionFromClose == published => terminal # "close" /\ terminal # "exit"
EventuallyReclaimed == <>destroyed
===============================================================================
