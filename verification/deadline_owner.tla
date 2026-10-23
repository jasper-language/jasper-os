--------------------------- MODULE deadline_owner ---------------------------
EXTENDS Naturals, FiniteSets
\* Author: chatgpt. One deadline migrates once between two stopped CPUs.
CONSTANT RemoveOld, NotifyDue, AllowRemote
CPUs == {0,1}
VARIABLES owner, members, active, now, moved, kicks, stopped, done, bad
vars == <<owner,members,active,now,moved,kicks,stopped,done,bad>>
Init == /\ owner = 1 /\ members = [c \in CPUs |-> IF c=1 THEN {1} ELSE {}]
        /\ active = TRUE /\ now = 0 /\ moved = FALSE /\ kicks = {}
        /\ stopped = CPUs /\ done = FALSE /\ bad = FALSE
Move == /\ active /\ ~moved /\ owner' = 1-owner /\ moved' = TRUE
        /\ members' = [c \in CPUs |-> IF c=1-owner THEN {1} ELSE IF RemoveOld THEN {} ELSE members[c]]
        /\ kicks' = IF now >= 1 THEN kicks \cup {1-owner} ELSE kicks
        /\ UNCHANGED <<active,now,stopped,done,bad>>
Tick == /\ now < 2 /\ now' = now+1
        /\ kicks' = IF NotifyDue /\ active /\ now+1 >= 1 THEN kicks \cup {owner} ELSE kicks
        /\ UNCHANGED <<owner,members,active,moved,stopped,done,bad>>
Consume(c) == /\ active /\ now >= 1 /\ (c=owner \/ AllowRemote)
              /\ (c \notin stopped \/ c \in kicks)
              /\ members' = [k \in CPUs |-> {}] /\ active' = FALSE
              /\ stopped' = stopped \ {c} /\ kicks' = kicks \ {c}
              /\ done' = TRUE /\ bad' = (bad \/ c # owner)
              /\ UNCHANGED <<owner,now,moved>>
Next == Move \/ Tick \/ (\E c \in CPUs: Consume(c))
Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Tick) /\ (\A c \in CPUs: WF_vars(Consume(c)))
Safety == /\ ~bad /\ owner \in CPUs
          /\ members = [c \in CPUs |-> IF active /\ c=owner THEN {1} ELSE {}]
          /\ (active /\ now >= 1 /\ owner \in stopped => owner \in kicks)
          /\ (done => ~active)
EventuallyDone == <>done
=============================================================================
