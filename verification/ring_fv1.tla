--------------------------- MODULE ring_fv1 ---------------------------
EXTENDS Naturals
\* One running request. Fair backend finish/publication/reclamation are stated
\* assumptions, not derived from the Rust lock or device implementation.
VARIABLES abortable, usesBuffer, terminal, quiesced, closing, published,
          destroyed, decisions, publications
vars == <<abortable, usesBuffer, terminal, quiesced, closing, published,
          destroyed, decisions, publications>>
Init == /\ abortable \in BOOLEAN /\ usesBuffer \in BOOLEAN
        /\ terminal = "none" /\ quiesced = FALSE /\ closing = FALSE
        /\ published = FALSE /\ destroyed = FALSE
        /\ decisions = 0 /\ publications = 0
Finish == /\ ~destroyed /\ ~quiesced
          /\ quiesced' = TRUE
          /\ terminal' = IF terminal = "none" THEN "done" ELSE terminal
          /\ decisions' = IF terminal = "none" THEN decisions + 1 ELSE decisions
          /\ UNCHANGED <<abortable, usesBuffer, closing, published, destroyed, publications>>
Cancel == /\ ~destroyed /\ terminal = "none" /\ abortable
          /\ terminal' = "cancelled" /\ decisions' = decisions + 1
          /\ UNCHANGED <<abortable, usesBuffer, quiesced, closing, published, destroyed, publications>>
Close == /\ ~closing /\ closing' = TRUE
         /\ terminal' = IF abortable /\ terminal = "none" THEN "cancelled" ELSE terminal
         /\ decisions' = IF abortable /\ terminal = "none" THEN decisions + 1 ELSE decisions
         /\ UNCHANGED <<abortable, usesBuffer, quiesced, published, destroyed, publications>>
Publish == /\ ~destroyed /\ ~closing /\ ~published /\ terminal # "none"
           /\ (~usesBuffer \/ quiesced)
           /\ published' = TRUE /\ publications' = publications + 1
           /\ UNCHANGED <<abortable, usesBuffer, terminal, quiesced, closing, destroyed, decisions>>
Destroy == /\ ~destroyed /\ quiesced /\ (published \/ closing)
           /\ destroyed' = TRUE
           /\ UNCHANGED <<abortable, usesBuffer, terminal, quiesced, closing, published, decisions, publications>>
Next == Finish \/ Cancel \/ Close \/ Publish \/ Destroy
Unique == /\ decisions <= 1 /\ publications <= 1
BufferSafe == published /\ usesBuffer => quiesced
ReclaimSafe == destroyed => quiesced
Spec == Init /\ [][Next]_vars /\ WF_vars(Finish) /\ WF_vars(Publish) /\ WF_vars(Destroy)
EventuallyReclaimed == <>destroyed
=============================================================================
