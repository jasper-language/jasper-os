---------------------- MODULE limit_observation ----------------------
EXTENDS Naturals, TLC
CONSTANT RewriteCutoff
VARIABLES phase, now, used, cutoff, saved, finishUsed, bad
vars == <<phase, now, used, cutoff, saved, finishUsed, bad>>
Init == /\ phase = "idle" /\ now = 0 /\ used = 0
        /\ cutoff = 0 /\ saved = 0 /\ finishUsed = 0 /\ bad = FALSE
Arm == /\ phase = "idle" /\ phase' = "armed"
       /\ UNCHANGED <<now, used, cutoff, saved, finishUsed, bad>>
Charge == /\ phase \in {"armed", "captured"} /\ used < 4
          /\ used' = used + 1
          /\ IF RewriteCutoff /\ phase = "captured"
                THEN /\ cutoff' = used' /\ bad' = TRUE
                ELSE /\ UNCHANGED <<cutoff, bad>>
          /\ UNCHANGED <<phase, now, saved, finishUsed>>
Tick == /\ phase \in {"armed", "captured"} /\ now < 3
        /\ now' = now + 1
        /\ IF phase = "armed" /\ now' = 2
              THEN /\ phase' = "captured" /\ cutoff' = used /\ saved' = used
              ELSE /\ UNCHANGED <<phase, cutoff, saved>>
        /\ UNCHANGED <<used, finishUsed, bad>>
Finish == /\ phase = "captured" /\ phase' = "finished"
          /\ finishUsed' = used
          /\ UNCHANGED <<now, used, cutoff, saved, bad>>
Next == Arm \/ Charge \/ Tick \/ Finish
Safety == /\ ~bad
          /\ (phase \in {"captured", "finished"} => cutoff = saved /\ cutoff <= used)
          /\ (phase = "finished" => cutoff + (finishUsed - cutoff) = finishUsed)
Spec == Init /\ [][Next]_vars
=======================================================================
