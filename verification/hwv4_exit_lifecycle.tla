------------------------------- MODULE hwv4_exit_lifecycle -------------------------------
\* HWV-4 first slice: a cancelled vCPU-exit wait never acquires a second terminal.
EXTENDS Naturals

CONSTANT InjectDoubleTerminal

VARIABLES
    vcpu,
    exitSeen,
    pending,
    wait,
    completion,
    backend,
    bad

vars == <<vcpu, exitSeen, pending, wait, completion, backend, bad>>

Init ==
    /\ vcpu = "ready"
    /\ exitSeen = FALSE
    /\ pending = FALSE
    /\ wait = "waiting"
    /\ completion = "none"
    /\ backend = TRUE
    /\ bad = FALSE

Run ==
    /\ vcpu = "ready"
    /\ vcpu' = "running"
    /\ UNCHANGED <<exitSeen, pending, wait, completion, backend, bad>>

Exit ==
    /\ vcpu = "running"
    /\ ~exitSeen
    /\ exitSeen' = TRUE
    /\ pending' = TRUE
    /\ UNCHANGED <<vcpu, wait, completion, backend, bad>>

Cancel ==
    /\ wait = "waiting"
    /\ wait' = "cancelled"
    /\ completion' = "cancelled"
    /\ UNCHANGED <<vcpu, exitSeen, pending, backend, bad>>

CompleteWaiting ==
    /\ pending
    /\ wait = "waiting"
    /\ wait' = "completed"
    /\ pending' = FALSE
    /\ completion' = "done"
    /\ backend' = FALSE
    /\ UNCHANGED <<vcpu, exitSeen, bad>>

CompleteCancelled ==
    /\ pending
    /\ wait = "cancelled"
    /\ pending' = FALSE
    /\ backend' = FALSE
    /\ UNCHANGED <<vcpu, exitSeen, wait, completion, bad>>

DoubleTerminal ==
    /\ InjectDoubleTerminal
    /\ completion # "none"
    /\ completion' = "done"
    /\ bad' = TRUE
    /\ UNCHANGED <<vcpu, exitSeen, pending, wait, backend>>

Next ==
    \/ Run
    \/ Exit
    \/ Cancel
    \/ CompleteWaiting
    \/ CompleteCancelled
    \/ DoubleTerminal

Spec == Init /\ [][Next]_vars

OnlyOneTerminal ==
    completion \in {"none", "done", "cancelled"}

DoneNeedsExit == completion = "done" => exitSeen

NoBadTerminal == ~bad

Safety ==
    /\ OnlyOneTerminal
    /\ DoneNeedsExit
    /\ NoBadTerminal
    /\ (completion = "cancelled" => wait = "cancelled")
    /\ (backend = FALSE => pending = FALSE)

=============================================================================
