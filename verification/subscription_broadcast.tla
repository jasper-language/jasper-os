---------------- MODULE subscription_broadcast ----------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANT Policy, DropSecond
Subscribers == {1,2}
VARIABLES version, active, latest, cursor, queues, resync, bad
vars == <<version,active,latest,cursor,queues,resync,bad>>
Total(a,b) == (b*(b+1) - (a-1)*a) \div 2
Init == /\ version=0 /\ active={}
        /\ latest=[s \in Subscribers |-> 0] /\ cursor=latest
        /\ queues=[s \in Subscribers |-> <<>>]
        /\ resync=[s \in Subscribers |-> FALSE] /\ bad=FALSE
Subscribe(s) == /\ s \notin active /\ active'=active \cup {s}
                /\ latest'=[latest EXCEPT ![s]=version]
                /\ cursor'=[cursor EXCEPT ![s]=version]
                /\ queues'=[queues EXCEPT ![s]= <<>>]
                /\ resync'=[resync EXCEPT ![s]=FALSE]
                /\ UNCHANGED <<version,bad>>
NewQueue(s,n) == IF resync[s] THEN <<>>
 ELSE IF Policy="events" THEN
   IF Len(queues[s])=2 THEN <<>> ELSE Append(queues[s], [first |-> n,last |-> n,value |-> n])
 ELSE IF Len(queues[s])=0 THEN <<[first |-> n,last |-> n,value |-> n]>>
 ELSE <<[first |-> Head(queues[s]).first,last |-> n,
         value |-> IF Policy="state" THEN n ELSE Head(queues[s]).value+n]>>
Publish == /\ version<4 /\ version'=version+1
 /\ LET receives == IF DropSecond THEN active \ {2} ELSE active
    IN /\ latest'=[s \in Subscribers |-> IF s \in receives THEN version+1 ELSE latest[s]]
       /\ queues'=[s \in Subscribers |-> IF s \in receives THEN NewQueue(s,version+1) ELSE queues[s]]
       /\ resync'=[s \in Subscribers |-> resync[s] \/ (s \in receives /\ Policy="events" /\ Len(queues[s])=2)]
 /\ UNCHANGED <<active,cursor,bad>>
Wait(s) == /\ s \in active /\ (resync[s] \/ Len(queues[s])>0)
 /\ bad'=(bad \/ (IF resync[s] THEN FALSE ELSE Head(queues[s]).first # cursor[s]+1))
 /\ cursor'=[cursor EXCEPT ![s]=IF resync[s] THEN latest[s] ELSE Head(queues[s]).last]
 /\ queues'=[queues EXCEPT ![s]=IF resync[s] THEN <<>> ELSE Tail(queues[s])]
 /\ resync'=[resync EXCEPT ![s]=FALSE]
 /\ UNCHANGED <<version,active,latest>>
Close(s) == /\ s \in active /\ active'=active \ {s}
 /\ queues'=[queues EXCEPT ![s]= <<>>] /\ resync'=[resync EXCEPT ![s]=FALSE]
 /\ UNCHANGED <<version,latest,cursor,bad>>
Next == Publish \/ (\E s \in Subscribers: Subscribe(s) \/ Wait(s) \/ Close(s))
Spec == Init /\ [][Next]_vars
Safety == /\ ~bad /\ Cardinality(active)<=2
 /\ \A s \in active: /\ latest[s]=version /\ Len(queues[s])<=2
     /\ \A i \in 1..Len(queues[s]):
         LET e==queues[s][i] IN /\ e.first<=e.last /\ e.last<=version
           /\ e.value=IF Policy="count" THEN Total(e.first,e.last) ELSE e.last
===============================================================
