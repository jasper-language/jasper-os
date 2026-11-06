---- MODULE timer_identity_integration ----
\* One reusable task slot, one TimerId generation, one-shot expiry, exit and
\* stale-identity attempts. The model abstracts hardware and scheduler locks.
EXTENDS Naturals

CONSTANT MutateStale

VARIABLES live, timer_gen, phase, at, now, budget,
          arm_epoch, delivered_epoch, stale_attempts, stale_mutated

vars == <<live, timer_gen, phase, at, now, budget,
          arm_epoch, delivered_epoch, stale_attempts, stale_mutated>>

Init ==
    /\ live = FALSE
    /\ timer_gen = 0
    /\ phase = "free"
    /\ at = 0
    /\ now = 0
    /\ budget = 0
    /\ arm_epoch = 0
    /\ delivered_epoch = 0
    /\ stale_attempts = 0
    /\ stale_mutated = FALSE

Spawn ==
    /\ ~live
    /\ timer_gen < 3
    /\ live' = TRUE
    /\ timer_gen' = timer_gen + 1
    /\ phase' = "idle"
    /\ at' = 0
    /\ budget' = 1
    /\ arm_epoch' = 0
    /\ delivered_epoch' = 0
    /\ UNCHANGED <<now, stale_attempts, stale_mutated>>

Arm ==
    /\ live
    /\ arm_epoch < 3
    /\ phase' = "armed"
    /\ at' = now + 1
    /\ arm_epoch' = arm_epoch + 1
    /\ UNCHANGED <<live, timer_gen, now, budget, delivered_epoch, stale_attempts,
                  stale_mutated>>

Cancel ==
    /\ live
    /\ phase = "armed"
    /\ phase' = "idle"
    /\ at' = 0
    /\ UNCHANGED <<live, timer_gen, now, budget, arm_epoch,
                  delivered_epoch, stale_attempts, stale_mutated>>

Expire ==
    /\ live
    /\ phase = "armed"
    /\ now >= at
    /\ delivered_epoch /= arm_epoch
    /\ phase' = "idle"
    /\ delivered_epoch' = arm_epoch
    /\ UNCHANGED <<live, timer_gen, at, now, budget, arm_epoch, stale_attempts,
                  stale_mutated>>

Tick ==
    /\ now < 3
    /\ now' = now + 1
    /\ UNCHANGED <<live, timer_gen, phase, at, budget, arm_epoch,
                  delivered_epoch, stale_attempts, stale_mutated>>

Exit ==
    /\ live
    /\ live' = FALSE
    /\ phase' = "free"
    /\ at' = 0
    /\ budget' = 0
    /\ UNCHANGED <<timer_gen, now, arm_epoch, delivered_epoch, stale_attempts,
                  stale_mutated>>

\* A rejected stale identity may record an attempt but cannot change live
\* timer state. MutateStale is the intentional negative model.
Stale ==
    /\ stale_attempts < 2
    /\ stale_attempts' = stale_attempts + 1
    /\ stale_mutated' = stale_mutated \/ MutateStale
    /\ budget' = IF MutateStale THEN budget + 1 ELSE budget
    /\ UNCHANGED <<live, timer_gen, phase, at, now, arm_epoch, delivered_epoch>>

Stutter == UNCHANGED vars

Next == Spawn \/ Arm \/ Cancel \/ Expire \/ Tick \/ Exit \/ Stale \/ Stutter
Spec == Init /\ [][Next]_vars

BudgetExact == budget = IF live THEN 1 ELSE 0
LiveHasIdentity == live => timer_gen > 0
FreeHasNoArmedState == ~live => phase = "free"
AtMostOncePerArm == delivered_epoch <= arm_epoch
StaleNeverMutatesLive == stale_mutated = FALSE

====
