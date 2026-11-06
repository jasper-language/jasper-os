--------------------------- MODULE ring_backend_lifecycle ---------------------------
\* One running Ring request behind the object-table lock. The model separates backend
\* stopping from resource release and completion publication so an early publication
\* or a duplicate release violates a checked invariant.
EXTENDS Naturals

CONSTANTS UsesBuffer, AllowDoubleRelease, AllowEarlyBufferPublish

VARIABLES backend, terminal, quiesced, published, closing, destroyed,
          releases, decisions, publications, source

vars == <<backend, terminal, quiesced, published, closing, destroyed,
          releases, decisions, publications, source>>

Init ==
    /\ backend = "active"
    /\ terminal = "none"
    /\ quiesced = FALSE
    /\ published = FALSE
    /\ closing = FALSE
    /\ destroyed = FALSE
    /\ releases = 0
    /\ decisions = 0
    /\ publications = 0
    /\ source = "open"

Deliver ==
    /\ backend = "active"
    /\ terminal \in {"none", "cancelled"}
    /\ terminal' = IF terminal = "none" THEN "done" ELSE terminal
    /\ decisions' = IF terminal = "none" THEN decisions + 1 ELSE decisions
    /\ quiesced' = TRUE
    /\ UNCHANGED <<backend, published, closing, destroyed, releases, publications, source>>

Cancel ==
    /\ backend = "active"
    /\ terminal = "none"
    /\ terminal' = "cancelled"
    /\ decisions' = decisions + 1
    /\ UNCHANGED <<backend, quiesced, published, closing, destroyed, releases, publications, source>>

Close ==
    /\ source = "open"
    /\ ~destroyed
    /\ closing' = TRUE
    /\ source' = "closed"
    /\ terminal' = IF terminal = "none" THEN "cancelled" ELSE terminal
    /\ decisions' = IF terminal = "none" THEN decisions + 1 ELSE decisions
    /\ UNCHANGED <<backend, quiesced, published, destroyed, releases, publications>>

Exit ==
    /\ source = "open"
    /\ ~destroyed
    /\ closing' = TRUE
    /\ source' = "exited"
    /\ terminal' = IF terminal = "none" THEN "cancelled" ELSE terminal
    /\ decisions' = IF terminal = "none" THEN decisions + 1 ELSE decisions
    /\ UNCHANGED <<backend, quiesced, published, destroyed, releases, publications>>

AbortStop ==
    /\ backend = "active"
    /\ terminal = "cancelled"
    /\ ~quiesced
    /\ quiesced' = TRUE
    /\ UNCHANGED <<backend, terminal, published, closing, destroyed, releases,
                   decisions, publications, source>>

Release ==
    /\ quiesced
    /\ (backend = "active" \/ AllowDoubleRelease)
    /\ backend' = "released"
    /\ releases' = releases + 1
    /\ UNCHANGED <<terminal, quiesced, published, closing, destroyed,
                   decisions, publications, source>>

Publish ==
    /\ terminal # "none"
    /\ ~published
    /\ ~closing
    /\ (~UsesBuffer \/ backend = "released" \/ AllowEarlyBufferPublish)
    /\ published' = TRUE
    /\ publications' = publications + 1
    /\ UNCHANGED <<backend, terminal, quiesced, closing, destroyed,
                   releases, decisions, source>>

Destroy ==
    /\ backend = "released"
    /\ quiesced
    /\ (published \/ closing)
    /\ ~destroyed
    /\ destroyed' = TRUE
    /\ UNCHANGED <<backend, terminal, quiesced, published, closing,
                   releases, decisions, publications, source>>

Next == Deliver \/ Cancel \/ Close \/ Exit \/ AbortStop \/ Release \/ Publish \/ Destroy

Spec == Init /\ [][Next]_vars
       /\ WF_vars(Close)
       /\ WF_vars(Deliver)
       /\ WF_vars(AbortStop)
       /\ WF_vars(Release)
       /\ WF_vars(Destroy)

ReleaseAtMostOnce == releases <= 1
TerminalAtMostOnce == decisions <= 1 /\ publications <= 1
BufferPublishedOnlyAfterRelease == published => backend = "released"
DestroyedOnlyAfterRelease == destroyed => backend = "released" /\ quiesced
PublishedHasTerminal == published => terminal # "none"
EventuallyReclaimed == <>destroyed
===============================================================================
