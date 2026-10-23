-------------------------- MODULE rt_worker_teardown --------------------------
EXTENDS Naturals
\* Author: chatgpt. Configuration must finish before worker may exit.
CONSTANT CorrectOrder
VARIABLES stop, live, done, configured
vars == <<stop,live,done,configured>>
Init == /\ stop = FALSE /\ live = TRUE /\ done = FALSE /\ configured = FALSE
Disable == /\ ~done /\ done' = TRUE /\ configured' = live
           /\ UNCHANGED <<stop,live>>
Stop == /\ ~stop /\ (CorrectOrder => done)
        /\ stop' = TRUE /\ UNCHANGED <<live,done,configured>>
Exit == /\ stop /\ live /\ live' = FALSE
        /\ UNCHANGED <<stop,done,configured>>
Next == Disable \/ Stop \/ Exit
Spec == Init /\ [][Next]_vars
Safety == done => configured
=============================================================================
