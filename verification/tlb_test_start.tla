------------------------- MODULE tlb_test_start ------------------------
\* Author: chatgpt. Startup barrier for the TLB regression's two tasks.
\* Fair scheduling is an external assumption; there is no bounded-progress claim.
CONSTANT ReaderFirst
VARIABLES writerCreated, readerCreated, writerReady, readerReady, working
vars == <<writerCreated, readerCreated, writerReady, readerReady, working>>
Init == /\ writerCreated = FALSE /\ readerCreated = FALSE
        /\ writerReady = FALSE /\ readerReady = FALSE /\ working = FALSE
SpawnWriter == /\ ~writerCreated /\ (ReaderFirst => readerCreated) /\ writerCreated' = TRUE
               /\ UNCHANGED <<readerCreated, writerReady, readerReady, working>>
SpawnReader == /\ ~readerCreated /\ readerCreated' = TRUE
               /\ UNCHANGED <<writerCreated, writerReady, readerReady, working>>
RegisterWriter == /\ writerCreated /\ ~writerReady /\ writerReady' = TRUE
                  /\ UNCHANGED <<writerCreated, readerCreated, readerReady, working>>
RegisterReader == /\ readerCreated /\ ~readerReady /\ readerReady' = TRUE
                  /\ UNCHANGED <<writerCreated, readerCreated, writerReady, working>>
Begin == /\ writerReady /\ readerReady /\ ~working /\ working' = TRUE
         /\ UNCHANGED <<writerCreated, readerCreated, writerReady, readerReady>>
Next == SpawnWriter \/ SpawnReader \/ RegisterWriter \/ RegisterReader \/ Begin
NoEarlyWork == working => (writerCreated /\ readerCreated /\ writerReady /\ readerReady)
WriterHasPeer == writerCreated => readerCreated
Spec == Init /\ [][Next]_vars
=============================================================================
